"""CWRUnix Discord bot: guild-scoped /reset-password backed by authentik."""

from __future__ import annotations

import logging
import os
import sys
from typing import TypeIs, cast, override
from urllib.parse import urlsplit, urlunsplit

import discord
import httpx
from discord import app_commands

log = logging.getLogger("cwrunix_bot")

DEFAULT_AUTHENTIK_PUBLIC_URL = "https://authentik-zeus.cwrunix.com"
REQUEST_TIMEOUT = 10.0
HTTP_OK = 200

GENERIC_ERROR_MSG = (
    "Something went wrong while generating your reset link. "
    "Please ping a club admin so we can look into it."
)
NO_CONNECTION_MSG = (
    "I couldn't find a CWRUnix account linked to your Discord account. "
    "Please contact a club admin (you may have never logged in via Discord)."
)
SUCCESS_MSG = (
    "Here's your password reset link:\n{link}\n\n"
    "This link is single-use and expires shortly. Do not share it with anyone."
)


class RecoveryError(Exception):
    """authentik returned a non-200 response (or a bad payload) for recovery."""


def _is_json_object(value: object) -> TypeIs[dict[str, object]]:
    """Narrow an unknown JSON value down to a JSON object.

    Returns:
        Whether the value is a JSON object.

    """
    return isinstance(value, dict)


def _require_env(name: str) -> str:
    """Read a required environment variable.

    Returns:
        The variable's value.

    Raises:
        SystemExit: If the variable is missing or empty.

    """
    value = os.environ.get(name)
    if not value:
        print(
            f"error: required environment variable {name} is not set",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return value


def _find_connection(
    connections: list[object], discord_id: str
) -> dict[str, object] | None:
    """Find the authentik source connection matching a Discord user ID.

    Returns:
        The matching connection object, or None if there is none.

    """
    for connection in connections:
        if not _is_json_object(connection):
            continue
        if connection.get("identifier") != discord_id:
            continue
        source = connection.get("source")
        if _is_json_object(source):
            slug = source.get("slug")
            if slug is not None and slug != "discord":
                continue
        return connection
    return None


async def find_user_pk(
    client: httpx.AsyncClient, authentik_url: str, discord_id: str
) -> int | None:
    """Look up the authentik user linked to a Discord user ID.

    Returns:
        The authentik user pk, or None if the Discord user has no connection.

    Raises:
        RecoveryError: If the matching connection has an unexpected shape.

    """
    page = 1
    while True:
        response = await client.get(
            f"{authentik_url}/api/v3/sources/user_connections/all/",
            params={"page": page},
        )
        _ = response.raise_for_status()
        data = cast("dict[str, object]", response.json())
        results = data.get("results")
        if not isinstance(results, list):
            return None
        connection = _find_connection(cast("list[object]", results), discord_id)
        if connection is not None:
            user_pk = connection.get("user")
            if isinstance(user_pk, bool) or not isinstance(user_pk, int):
                pk_type = type(user_pk).__name__
                msg = f"connection has unexpected user pk type: {pk_type}"
                raise RecoveryError(msg)
            return user_pk
        pagination = data.get("pagination")
        next_page = pagination.get("next") if _is_json_object(pagination) else None
        if (
            isinstance(next_page, bool)
            or not isinstance(next_page, (int, float))
            or not next_page
        ):
            return None
        page = int(next_page)


async def request_recovery_link(
    client: httpx.AsyncClient, authentik_url: str, user_pk: int
) -> str:
    """Ask authentik to generate a recovery link for a user.

    Returns:
        The recovery link.

    Raises:
        RecoveryError: If authentik does not return HTTP 200 with a link.

    """
    response = await client.post(
        f"{authentik_url}/api/v3/core/users/{user_pk}/recovery/",
        json={},
    )
    if response.status_code != HTTP_OK:
        msg = f"recovery endpoint returned HTTP {response.status_code}"
        raise RecoveryError(msg)
    data = cast("dict[str, object]", response.json())
    link = data.get("link")
    if not isinstance(link, str) or not link:
        msg = "recovery endpoint response did not contain a link"
        raise RecoveryError(msg)
    return link


def rewrite_link(link: str, public_url: str) -> str:
    """Rewrite a link's scheme+host to the public base URL if it differs.

    Returns:
        The (possibly rewritten) link.

    """
    if link.startswith(public_url):
        return link
    link_parts = urlsplit(link)
    public_parts = urlsplit(public_url)
    return urlunsplit(
        (
            public_parts.scheme,
            public_parts.netloc,
            link_parts.path,
            link_parts.query,
            link_parts.fragment,
        )
    )


class Bot(discord.Client):
    """Discord client hosting the guild-scoped /reset-password command."""

    def __init__(
        self,
        *,
        guild_id: int,
        authentik_url: str,
        authentik_token: str,
        public_url: str,
    ) -> None:
        """Set up the client, the command tree, and the authentik HTTP client."""
        super().__init__(intents=discord.Intents.default())
        self.guild: discord.Object = discord.Object(id=guild_id)
        self.authentik_url: str = authentik_url
        self.public_url: str = public_url
        self.api: httpx.AsyncClient = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {authentik_token}"},
            timeout=REQUEST_TIMEOUT,
        )
        self.tree: app_commands.CommandTree[Bot] = app_commands.CommandTree(self)

    @override
    async def setup_hook(self) -> None:
        """Register /reset-password and sync it to the configured guild."""
        command: app_commands.Command[app_commands.Group, ..., None] = (
            app_commands.Command(
                name="reset-password",
                description="Get a password reset link for your CWRUnix account.",
                callback=self._reset_password,
            )
        )
        _ = self.tree.add_command(command, guild=self.guild)
        synced = await self.tree.sync(guild=self.guild)
        log.info("Synced %d command(s) to guild %s", len(synced), self.guild.id)

    @override
    async def close(self) -> None:
        """Close the authentik HTTP client alongside the Discord connection."""
        await self.api.aclose()
        await super().close()

    async def _make_reset_link(self, discord_id: int) -> str | None:
        """Resolve a Discord user ID to a fresh recovery link.

        Returns:
            The rewritten recovery link, or None if the user has no connection.

        """
        user_pk = await find_user_pk(self.api, self.authentik_url, str(discord_id))
        if user_pk is None:
            return None
        link = await request_recovery_link(self.api, self.authentik_url, user_pk)
        return rewrite_link(link, self.public_url)

    async def _reset_password(self, interaction: discord.Interaction[Bot]) -> None:
        """Handle /reset-password: reply ephemerally with a recovery link."""
        _ = await interaction.response.defer(ephemeral=True)
        try:
            link = await self._make_reset_link(interaction.user.id)
        except RecoveryError:
            log.warning("authentik recovery failed", exc_info=True)
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        except httpx.HTTPError:
            log.exception("authentik API request failed")
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        except Exception:
            log.exception("unexpected error handling /reset-password")
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        else:
            if link is None:
                _ = await interaction.followup.send(NO_CONNECTION_MSG, ephemeral=True)
            else:
                _ = await interaction.followup.send(
                    SUCCESS_MSG.format(link=link), ephemeral=True
                )


def main() -> None:
    """Load config from the environment and run the bot.

    Raises:
        SystemExit: If a required environment variable is missing or invalid.

    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    token = _require_env("DISCORD_BOT_TOKEN")
    guild_raw = _require_env("DISCORD_GUILD_ID")
    try:
        guild_id = int(guild_raw)
    except ValueError:
        print(
            f"error: DISCORD_GUILD_ID must be an integer, got {guild_raw!r}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    authentik_url = _require_env("AUTHENTIK_URL").rstrip("/")
    authentik_token = _require_env("AUTHENTIK_TOKEN")
    public_url = os.environ.get(
        "AUTHENTIK_PUBLIC_URL", DEFAULT_AUTHENTIK_PUBLIC_URL
    ).rstrip("/")

    bot = Bot(
        guild_id=guild_id,
        authentik_url=authentik_url,
        authentik_token=authentik_token,
        public_url=public_url,
    )
    bot.run(token, log_handler=None)
