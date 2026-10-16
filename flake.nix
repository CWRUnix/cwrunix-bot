{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    gitignore.url = "github:hercules-ci/gitignore.nix";
    uv2nix.url = "github:pyproject-nix/uv2nix";
    pybuild.url = "github:pyproject-nix/build-system-pkgs";
    pyproject.url = "github:pyproject-nix/pyproject.nix";
    appimage.url = "github:ralismark/nix-appimage";
  };
  outputs = {self, ...} @ inputs:
    inputs.flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = (import inputs.nixpkgs) {
          inherit system;
          config = {
          };
        };
        python = pkgs.python314;
        workspace = inputs.uv2nix.lib.workspace.loadWorkspace {
          workspaceRoot = ./src;
        };
        overlay = workspace.mkPyprojectOverlay {
          sourcePreference = "wheel";
        };
        pythonBase = pkgs.callPackage inputs.pyproject.build.packages {
          inherit python;
        };
        pythonSet = pythonBase.overrideScope (
          pkgs.lib.composeManyExtensions [
            inputs.pybuild.overlays.wheel
            overlay
          ]
        );
        venv = pythonSet.mkVirtualEnv "venv" workspace.deps.default;
        venvDev = pythonSet.mkVirtualEnv "venvDev" (workspace.deps.all or workspace.deps.default);
        inherit (pkgs.callPackages inputs.pyproject.build.util {}) mkApplication;

        treefmtconfig = inputs.treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs = {
            alejandra.enable = true;
            black.enable = true;
            toml-sort.enable = true;
            yamlfmt.enable = true;
            mdformat = {
              enable = true;
              plugins = ps: [
                ps.mdformat-gfm
              ];
              settings = {
                wrap = 88;
                end-of-line = "lf";
              };
            };
            prettier.enable = true;
            ruff-check.enable = true;
            ruff-format.enable = true;
            shellcheck.enable = true;
            shfmt.enable = true;
          };
          settings.formatter.shellcheck.excludes = [".envrc"];
        };
      in {
        devShells = rec {
          pyShell = pkgs.mkShell {
            packages = with pkgs;
              [
                nil
                nixd
                uv
                fuse
                ruff
                basedpyright
                act
              ]
              ++ [
                venvDev
              ];
            env = {
              UV_NO_SYNC = "1";
              UV_PYTHON = pythonSet.python.interpreter;
              UV_PYTHON_DOWNLOADS = "never";
            };
            shellHook = ''
              PROJ_ROOT=$(git rev-parse --show-toplevel)/src
              export PYTHONPATH="$PROJ_ROOT/src:${venvDev}/lib/*/site-packages:$PYTHONPATH"
              ln -sfn ${venvDev} $PROJ_ROOT/.venv
            '';
          };
          default = pyShell;
        };
        formatter = treefmtconfig.config.build.wrapper;
        packages = let
          cwrunix-bot = pkgs.callPackage ./nix/build.nix {inherit mkApplication pythonSet venv;};
        in {
          inherit cwrunix-bot;
          default = cwrunix-bot;
          appimage = inputs.appimage.bundlers.${system}.default cwrunix-bot;
        };
        checks = {
          formatting = treefmtconfig.config.build.check self;
          basedpyright-types = pkgs.stdenvNoCC.mkDerivation {
            name = "basedpyright-types";
            src = ./src;

            nativeBuildInputs = [
              venvDev
              pkgs.basedpyright
            ];

            buildPhase = ''
              ln -sfn ${venvDev} ./.venv
              basedpyright
            '';

            installPhase = "mkdir $out";
          };
        };
      }
    );
}
