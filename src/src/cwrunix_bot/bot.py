"""CWRUnix Discord bot: /reset-password and /ssh-keys, backed by authentik."""

from __future__ import annotations

import base64
import binascii
import hashlib
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

SSH_KEY_ATTR = "sshPublicKey"
MAX_SSH_KEYS = 10
MAX_KEY_LEN = 4096
MAX_COMMENT_LEN = 128
MIN_KEY_PARTS = 2
MIN_BLOB_LEN = 16
MAX_BLOB_LEN = 2048
SSH_KEY_TYPES = frozenset(
    {
        "ssh-ed25519",
        "sk-ssh-ed25519@openssh.com",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-rsa",
    }
)


class RecoveryError(Exception):
    """authentik returned a non-200 response (or a bad payload) for recovery."""


class SshKeyError(Exception):
    """authentik returned an unexpected response while managing SSH keys."""


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


def validate_public_key(text: str) -> str | None:
    """Validate and canonicalize a single SSH public key line.

    Returns:
        The canonical "<type> <blob> [comment]" line, or None if invalid.

    """
    if "\n" in text or "\r" in text or len(text) > MAX_KEY_LEN:
        return None
    parts = text.split()
    if len(parts) < MIN_KEY_PARTS:
        return None
    key_type, blob = parts[0], parts[1]
    if key_type not in SSH_KEY_TYPES:
        return None
    try:
        raw = base64.b64decode(blob, validate=True)
    except binascii.Error:
        return None
    if not MIN_BLOB_LEN <= len(raw) <= MAX_BLOB_LEN:
        return None
    comment = " ".join(parts[2:])[:MAX_COMMENT_LEN]
    canonical = f"{key_type} {blob}"
    if comment:
        canonical += f" {comment}"
    return canonical


def key_fingerprint(canonical_key: str) -> str:
    """Compute the OpenSSH-style SHA256 fingerprint of a canonical key line.

    Returns:
        The fingerprint, e.g. "SHA256:abc...".

    """
    blob = canonical_key.split()[1]
    digest = hashlib.sha256(base64.b64decode(blob)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def describe_key(canonical_key: str) -> str:
    """Format a canonical key line as "<type> <fingerprint> [(comment)]".

    Returns:
        The human-readable one-line description.

    """
    parts = canonical_key.split()
    description = f"{parts[0]} {key_fingerprint(canonical_key)}"
    comment = " ".join(parts[2:])
    if comment:
        description += f" ({comment})"
    return description


async def fetch_user(
    client: httpx.AsyncClient, authentik_url: str, user_pk: int
) -> dict[str, object]:
    """Fetch the full authentik user object.

    Returns:
        The user object.

    """
    response = await client.get(f"{authentik_url}/api/v3/core/users/{user_pk}/")
    _ = response.raise_for_status()
    return cast("dict[str, object]", response.json())


def user_pk_of(user: dict[str, object]) -> int:
    """Extract the pk from a user object.

    Returns:
        The user's pk.

    Raises:
        SshKeyError: If the pk is missing or has an unexpected type.

    """
    pk = user.get("pk")
    if isinstance(pk, bool) or not isinstance(pk, int):
        pk_type = type(pk).__name__
        msg = f"user object has unexpected pk type: {pk_type}"
        raise SshKeyError(msg)
    return pk


def get_ssh_keys(user: dict[str, object]) -> list[str]:
    """Extract a user's SSH public keys as a list of key lines.

    Handles both the list shape the bot writes and a plain string set
    manually in the authentik admin UI.

    Returns:
        The list of key lines (possibly empty).

    """
    attributes = user.get("attributes")
    if not _is_json_object(attributes):
        return []
    value = attributes.get(SSH_KEY_ATTR)
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [
            key
            for key in cast("list[object]", value)
            if isinstance(key, str) and key.strip()
        ]
    return []


async def set_ssh_keys(
    client: httpx.AsyncClient,
    authentik_url: str,
    user: dict[str, object],
    keys: list[str],
) -> None:
    """Write the user's attributes back with a replaced SSH key list."""
    attributes = user.get("attributes")
    attrs = dict(attributes) if _is_json_object(attributes) else {}
    if keys:
        attrs[SSH_KEY_ATTR] = keys
    else:
        _ = attrs.pop(SSH_KEY_ATTR, None)
    response = await client.patch(
        f"{authentik_url}/api/v3/core/users/{user_pk_of(user)}/",
        json={"attributes": attrs},
    )
    _ = response.raise_for_status()


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
        """Register /reset-password and /ssh-keys, synced to the guild."""
        command: app_commands.Command[app_commands.Group, ..., None] = (
            app_commands.Command(
                name="reset-password",
                description="Get a password reset link for your CWRUnix account.",
                callback=self._reset_password,
            )
        )
        _ = self.tree.add_command(command, guild=self.guild)
        group = app_commands.Group(
            name="ssh-keys",
            description="Manage SSH login keys for your CWRUnix account.",
        )
        add: app_commands.Command[app_commands.Group, ..., None] = app_commands.Command(
            name="add",
            description="Add an SSH public key (ed25519, ecdsa, sk, or rsa).",
            callback=self._ssh_key_add,
        )
        group.add_command(add)
        list_cmd: app_commands.Command[app_commands.Group, ..., None] = (
            app_commands.Command(
                name="list",
                description="List your SSH public keys.",
                callback=self._ssh_key_list,
            )
        )
        group.add_command(list_cmd)
        remove: app_commands.Command[app_commands.Group, ..., None] = (
            app_commands.Command(
                name="remove",
                description="Remove a key by its number from /ssh-keys list.",
                callback=self._ssh_key_remove,
            )
        )
        group.add_command(remove)
        _ = self.tree.add_command(group, guild=self.guild)
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

    async def _resolve_keys(self, discord_id: int) -> tuple[int, list[str]] | None:
        """Resolve a Discord user ID to their authentik pk and SSH key list.

        Returns:
            (user pk, keys), or None if the user has no connection.

        """
        user_pk = await find_user_pk(self.api, self.authentik_url, str(discord_id))
        if user_pk is None:
            return None
        user = await fetch_user(self.api, self.authentik_url, user_pk)
        return user_pk_of(user), get_ssh_keys(user)

    async def _write_keys(self, user_pk: int, keys: list[str]) -> None:
        """Persist a replaced SSH key list for an authentik user."""
        user = await fetch_user(self.api, self.authentik_url, user_pk)
        await set_ssh_keys(self.api, self.authentik_url, user, keys)

    async def _add_key(self, discord_id: int, canonical: str) -> str | None:
        """Resolve the caller and append a canonical key to their account.

        Returns:
            A status message, or None if the user has no connection.

        """
        resolved = await self._resolve_keys(discord_id)
        if resolved is None:
            return None
        user_pk, keys = resolved
        if canonical in keys:
            return f"That key is already on your account:\n{describe_key(canonical)}"
        if len(keys) >= MAX_SSH_KEYS:
            return (
                f"You already have {MAX_SSH_KEYS} keys registered; "
                "remove one first with /ssh-keys remove."
            )
        keys.append(canonical)
        await self._write_keys(user_pk, keys)
        return (
            f"Added key:\n{describe_key(canonical)}\n"
            f"You now have {len(keys)} key(s). Allow a couple of minutes "
            "for the change to reach the servers."
        )

    async def _list_keys(self, discord_id: int) -> str | None:
        """Resolve the caller and format their key list.

        Returns:
            The formatted list, or None if the user has no connection.

        """
        resolved = await self._resolve_keys(discord_id)
        if resolved is None:
            return None
        _, keys = resolved
        if not keys:
            return "You have no SSH keys registered."
        return "\n".join(f"{i}. {describe_key(key)}" for i, key in enumerate(keys, 1))

    async def _remove_key(self, discord_id: int, number: int) -> str | None:
        """Resolve the caller and remove a key by its 1-based list index.

        Returns:
            A status message, or None if the user has no connection.

        """
        resolved = await self._resolve_keys(discord_id)
        if resolved is None:
            return None
        user_pk, keys = resolved
        if number < 1 or number > len(keys):
            return f"No key #{number}. Run /ssh-keys list to see your keys."
        removed = keys.pop(number - 1)
        await self._write_keys(user_pk, keys)
        return (
            f"Removed key:\n{describe_key(removed)}\nYou now have {len(keys)} key(s)."
        )

    async def _ssh_key_add(
        self, interaction: discord.Interaction[Bot], key: str
    ) -> None:
        """Handle /ssh-keys add: validate and append a public key."""
        _ = await interaction.response.defer(ephemeral=True)
        canonical = validate_public_key(key)
        if canonical is None:
            invalid_msg = (
                "That doesn't look like a valid SSH public key. Paste the full "
                "single-line contents of a `.pub` file (ed25519, ecdsa, sk, or "
                "rsa)."
            )
            _ = await interaction.followup.send(invalid_msg, ephemeral=True)
            return
        try:
            message = await self._add_key(interaction.user.id, canonical)
        except (SshKeyError, httpx.HTTPError):
            log.exception("authentik SSH key update failed")
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        except Exception:
            log.exception("unexpected error handling /ssh-keys add")
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        else:
            _ = await interaction.followup.send(
                NO_CONNECTION_MSG if message is None else message, ephemeral=True
            )

    async def _ssh_key_list(self, interaction: discord.Interaction[Bot]) -> None:
        """Handle /ssh-keys list: show the caller's keys, numbered."""
        _ = await interaction.response.defer(ephemeral=True)
        try:
            message = await self._list_keys(interaction.user.id)
        except (SshKeyError, httpx.HTTPError):
            log.exception("authentik SSH key lookup failed")
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        except Exception:
            log.exception("unexpected error handling /ssh-keys list")
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        else:
            _ = await interaction.followup.send(
                NO_CONNECTION_MSG if message is None else message, ephemeral=True
            )

    async def _ssh_key_remove(
        self, interaction: discord.Interaction[Bot], number: int
    ) -> None:
        """Handle /ssh-keys remove: delete a key by its list index."""
        _ = await interaction.response.defer(ephemeral=True)
        try:
            message = await self._remove_key(interaction.user.id, number)
        except (SshKeyError, httpx.HTTPError):
            log.exception("authentik SSH key update failed")
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        except Exception:
            log.exception("unexpected error handling /ssh-keys remove")
            _ = await interaction.followup.send(GENERIC_ERROR_MSG, ephemeral=True)
        else:
            _ = await interaction.followup.send(
                NO_CONNECTION_MSG if message is None else message, ephemeral=True
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
