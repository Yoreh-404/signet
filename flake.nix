{
  description = "Signet unified identity service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      # Pin the codeload archive to an immutable commit. Using the mutable
      # `stable` branch URL makes the lockfile's narHash drift whenever the
      # branch advances, which breaks `nix develop` before evaluation starts.
      url = "tarball+https://codeload.github.com/oxalica/rust-overlay/tar.gz/4748ec2f5ed4a881474ed4c98aa71a5308cdac8d";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    cargo2nix = {
      # Same rule for cargo2nix: release branches are mutable even when their
      # API is intentionally stable.
      url = "tarball+https://codeload.github.com/cargo2nix/cargo2nix/tar.gz/a709c74619e1a2b68ed12bb398e12fbe29d69657";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
      inputs.rust-overlay.follows = "rust-overlay";
    };
  };

  outputs = { self, nixpkgs, flake-utils, cargo2nix, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ cargo2nix.overlays.default ];
        };
        lib = pkgs.lib;
        # Conductor local builds intentionally consume dirty working trees.
        # A normal flake path is projected from Git and therefore drops
        # untracked workspace members such as the in-development `edge/`
        # crate. Prefer the explicit live checkout when Conductor supplies it.
        workspaceRoot = builtins.getEnv "OPENSPONGE_NIX_WORKSPACE_ROOT";
        sourceRoot =
          if workspaceRoot == ""
          then ./.
          else builtins.toPath workspaceRoot;
        source = builtins.path {
          name = "signet-source";
          path = sourceRoot;
          filter = path: type:
            let name = lib.baseNameOf path;
            in name != ".git"
              && name != "target"
              && name != "node_modules"
              && name != "dist";
        };
        frontendSource = builtins.path {
          name = "signet-frontend-source";
          path = sourceRoot + "/frontend";
          filter = path: type:
            let name = lib.baseNameOf path;
            in name != "node_modules" && name != "dist";
        };

        # Keep the lockfile portable in git, but retain only the native GNU
        # optional packages needed by the current Nix build platform.
        nativeRolldownBinding = if system == "aarch64-linux"
          then "node_modules/@rolldown/binding-linux-arm64-gnu"
          else "node_modules/@rolldown/binding-linux-x64-gnu";
        nativeRolldownName = if system == "aarch64-linux"
          then "@rolldown/binding-linux-arm64-gnu"
          else "@rolldown/binding-linux-x64-gnu";
        nativeLightningcssBinding = if system == "aarch64-linux"
          then "node_modules/lightningcss-linux-arm64-gnu"
          else "node_modules/lightningcss-linux-x64-gnu";
        nativeLightningcssName = if system == "aarch64-linux"
          then "lightningcss-linux-arm64-gnu"
          else "lightningcss-linux-x64-gnu";
        lockPatch = ''
          jq '
            def remove_platform($prefix; $keep):
              .packages |= with_entries(
                select(
                  ((.key | startswith($prefix)) and (.key != $keep)) | not
                )
              );
            remove_platform(
              "node_modules/@rolldown/binding-";
              "${nativeRolldownBinding}"
            )
            | remove_platform(
                "node_modules/lightningcss-";
                "${nativeLightningcssBinding}"
            )
            | del(.packages["node_modules/fsevents"])
            | .packages |= with_entries(
                if (.value.resolved? // "") != ""
                then .value.resolved |= sub("https://registry.npmjs.org/"; "https://registry.npmmirror.com/")
                else .
                end
              )
            | .packages["node_modules/rolldown"].optionalDependencies |=
                with_entries(select(.key == "${nativeRolldownName}"))
            | .packages["node_modules/lightningcss"].optionalDependencies |=
                with_entries(select(.key == "${nativeLightningcssName}"))
            | del(.packages["node_modules/vite"].optionalDependencies.fsevents)
          ' package-lock.json > package-lock.json.tmp
          mv package-lock.json.tmp package-lock.json
        '';

        frontendNpmDeps = pkgs.fetchNpmDeps {
          name = "signet-frontend-0.1.0-npm-deps";
          src = frontendSource;
          nativeBuildInputs = [ pkgs.jq ];
          postPatch = lockPatch;
          hash = "sha256-vnl6WHZE2zuJQKFBS8Qtqq23jj4G5ziBivDvX1YeruA=";
        };

        frontend = pkgs.buildNpmPackage {
          pname = "signet-frontend";
          version = "0.1.0";
          src = frontendSource;
          nativeBuildInputs = [ pkgs.jq ];
          postPatch = lockPatch;
          npmDeps = frontendNpmDeps;
          npmBuildScript = "build";

          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp -r dist $out/
            runHook postInstall
          '';
        };

        signetSource = pkgs.runCommand "signet-cargo-source" {} ''
          mkdir -p $out/frontend
          cp -r ${source}/. $out/
          cp -r ${frontend}/dist $out/frontend/dist
        '';

        rustPkgs = pkgs.rustBuilder.makePackageSet {
          rustVersion = "1.97.1";
          rootFeatures = [
            "sso-backend/default"
            "sso-backend/sqlite"
            "sso-backend/postgres"
            "sso-backend/mysql"
          ];
          packageFun = args: import ./Cargo.nix (args // { inherit pkgs; workspaceLockFile = ./Cargo.lock; });
          workspaceSrc = signetSource;
          # The source tree is augmented with the built frontend before Cargo
          # runs, so Cargo.nix cannot hash it during pure evaluation.
          ignoreLockHash = false;
          packageOverrides = pkgs:
            let
              inherit (pkgs.rustBuilder) overrides rustLib;
              nativeArchiveTools = drv: {
                nativeBuildInputs = (drv.nativeBuildInputs or []) ++ [
                  pkgs.llvmPackages_21.clang
                  pkgs.llvmPackages_21.llvm
                ];
                CC = "${pkgs.llvmPackages_21.clang}/bin/clang";
                CXX = "${pkgs.llvmPackages_21.clang}/bin/clang++";
                AR = "${pkgs.llvmPackages_21.llvm}/bin/llvm-ar";
                RANLIB = "${pkgs.llvmPackages_21.llvm}/bin/llvm-ranlib";
                "CC_x86_64-unknown-linux-gnu" = "${pkgs.llvmPackages_21.clang}/bin/clang";
                "CXX_x86_64-unknown-linux-gnu" = "${pkgs.llvmPackages_21.clang}/bin/clang++";
                "AR_x86_64-unknown-linux-gnu" = "${pkgs.llvmPackages_21.llvm}/bin/llvm-ar";
                "RANLIB_x86_64-unknown-linux-gnu" = "${pkgs.llvmPackages_21.llvm}/bin/llvm-ranlib";
              };
              sqliteNativeTools = rustLib.makeOverride {
                name = "libsqlite3-sys";
                overrideAttrs = drv: nativeArchiveTools drv;
              };
              ringNativeTools = rustLib.makeOverride {
                name = "ring";
                overrideAttrs = drv: nativeArchiveTools drv;
              };
              zstdNativeTools = rustLib.makeOverride {
                name = "zstd-sys";
                overrideAttrs = drv: nativeArchiveTools drv;
              };
              pqSys = rustLib.makeOverride {
                name = "pq-sys";
                overrideAttrs = drv: {
                  propagatedBuildInputs = (drv.propagatedBuildInputs or []) ++ [ pkgs.postgresql ];
                };
              };
              mysqlclientSys = rustLib.makeOverride {
                name = "mysqlclient-sys";
                overrideAttrs = drv: {
                  propagatedBuildInputs = (drv.propagatedBuildInputs or []) ++ [ pkgs.mariadb-connector-c ];
                };
              };
            in
              with overrides; [
                capLints
                cc
                sqliteNativeTools
                ringNativeTools
                zstdNativeTools
                openssl-sys
                pkg-config
                pqSys
                mysqlclientSys
              ];
        };

        rustNativeEnv =
          if pkgs.stdenv.hostPlatform.rust.rustcTarget == "x86_64-unknown-linux-gnu" then {
            RUSTFLAGS = "-C linker=${pkgs.llvmPackages_21.clang}/bin/clang -C link-arg=-fuse-ld=lld";
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "${pkgs.llvmPackages_21.clang}/bin/clang";
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-fuse-ld=lld";
            CC_x86_64_unknown_linux_gnu = "${pkgs.llvmPackages_21.clang}/bin/clang";
            CXX_x86_64_unknown_linux_gnu = "${pkgs.llvmPackages_21.clang}/bin/clang++";
            AR_x86_64_unknown_linux_gnu = "${pkgs.llvmPackages_21.llvm}/bin/llvm-ar";
            RANLIB_x86_64_unknown_linux_gnu = "${pkgs.llvmPackages_21.llvm}/bin/llvm-ranlib";
          } else if pkgs.stdenv.hostPlatform.rust.rustcTarget == "aarch64-unknown-linux-gnu" then {
            RUSTFLAGS = "-C linker=${pkgs.llvmPackages_21.clang}/bin/clang -C link-arg=-fuse-ld=lld";
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER = "${pkgs.llvmPackages_21.clang}/bin/clang";
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-fuse-ld=lld";
            CC_aarch64_unknown_linux_gnu = "${pkgs.llvmPackages_21.clang}/bin/clang";
            CXX_aarch64_unknown_linux_gnu = "${pkgs.llvmPackages_21.clang}/bin/clang++";
            AR_aarch64_unknown_linux_gnu = "${pkgs.llvmPackages_21.llvm}/bin/llvm-ar";
            RANLIB_aarch64_unknown_linux_gnu = "${pkgs.llvmPackages_21.llvm}/bin/llvm-ranlib";
          } else {};

        signetBinary = (rustPkgs.workspace.sso-backend {}).overrideAttrs (old: {
          # frontend/dist is produced by frontendNpmDeps above; do not make
          # the Rust sandbox invoke npm a second time.
          SSO_SKIP_FRONTEND_BUILD = "1";
          nativeBuildInputs = (old.nativeBuildInputs or []) ++ (with pkgs; [
            llvmPackages_21.clang
            llvmPackages_21.lld
            llvmPackages_21.llvm
            pkg-config
          ]);
          buildInputs = (old.buildInputs or []) ++ (with pkgs; [
            openssl
            sqlite
            postgresql
            mariadb-connector-c
          ]);
        } // rustNativeEnv);
        signet = pkgs.runCommand "signet-runtime" {} ''
          mkdir -p $out/bin
          ln -s ${signetBinary}/bin/sso-backend $out/bin/signet
        '';

        edgeBinary = (rustPkgs.workspace.signet-edge {}).overrideAttrs (old: {
          nativeBuildInputs = (old.nativeBuildInputs or []) ++ (with pkgs; [
            llvmPackages_21.clang
            llvmPackages_21.lld
            llvmPackages_21.llvm
          ]);
        } // rustNativeEnv);
        edge = pkgs.runCommand "signet-edge-runtime" {} ''
          mkdir -p $out/bin
          ln -s ${edgeBinary}/bin/signet-edge $out/bin/signet-edge
        '';

        # Keep the compiler closure out of the image.  cargo2nix embeds
        # references to Rust source/toolchain paths in the release binary;
        # these are not needed to start Signet and would otherwise pull the
        # full Rust toolchain into dockerTools' runtime closure.
        signetRuntime = pkgs.runCommand "signet-runtime-binary" {
          nativeBuildInputs = [ pkgs.nukeReferences ];
        } ''
          mkdir -p $out/bin
          cp -L ${signetBinary}/bin/sso-backend $out/bin/signet
          nuke-refs \
            -e ${pkgs.glibc} \
            -e ${pkgs.stdenv.cc.cc.lib} \
            -e ${pkgs.openssl} \
            -e ${pkgs.sqlite} \
            -e ${pkgs.postgresql} \
            -e ${pkgs.mariadb-connector-c} \
            $out/bin/signet
        '';

        edgeRuntime = pkgs.runCommand "signet-edge-runtime-binary" {
          nativeBuildInputs = [ pkgs.nukeReferences ];
        } ''
          mkdir -p $out/bin
          cp -L ${edgeBinary}/bin/signet-edge $out/bin/signet-edge
          nuke-refs \
            -e ${pkgs.glibc} \
            -e ${pkgs.stdenv.cc.cc.lib} \
            $out/bin/signet-edge
        '';

        runtimeConfig = pkgs.runCommand "signet-runtime-config" {} ''
          mkdir -p $out/app/config
          sed 's/host = "127.0.0.1"/host = "0.0.0.0"/' \
            ${source}/config/default.toml > $out/app/config/default.toml
        '';

        image = pkgs.dockerTools.buildLayeredImage {
          name = "signet";
          tag = "local";
          contents = [
            signetRuntime
            runtimeConfig
            pkgs.cacert
            pkgs.curl
            pkgs.fakeNss
            pkgs.openssl
            pkgs.sqlite
            pkgs.postgresql
            pkgs.mariadb-connector-c
          ];
          extraCommands = ''
            mkdir -p app/data
          '';
          config = {
            Cmd = [ "${signetRuntime}/bin/signet" ];
            WorkingDir = "/app";
            # The Rust build links OpenSSL/SQLite/PostgreSQL/MariaDB
            # dynamically, while the minimal image has no conventional /lib
            # search path. MariaDB Connector/C keeps libmariadb.so under a
            # nested lib/mariadb directory, which makeLibraryPath does not
            # include, so keep that directory explicit as well.
            Env = [
              "SSO_CONFIG=/app/config/default.toml"
              "LD_LIBRARY_PATH=${lib.makeLibraryPath [ pkgs.openssl pkgs.sqlite pkgs.postgresql pkgs.mariadb-connector-c ]}:${pkgs.mariadb-connector-c}/lib/mariadb"
            ];
            ExposedPorts = { "8080/tcp" = {}; };
            Volumes = { "/app/data" = {}; };
          };
        };

        edgeImage = pkgs.dockerTools.buildLayeredImage {
          name = "signet-edge";
          tag = "local";
          contents = [
            edgeRuntime
            pkgs.cacert
            pkgs.fakeNss
          ];
          config = {
            Cmd = [ "${edgeRuntime}/bin/signet-edge" ];
            User = "65532:65532";
            Env = [
              "SIGNET_EDGE_BIND_HOST=0.0.0.0"
            ];
            ExposedPorts = { "4180/tcp" = {}; };
          };
        };
      in {
        packages = {
          inherit signet edge frontend image edgeImage;
          default = image;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            nodejs_22
            pkg-config
            openssl
            sqlite
            postgresql
            mariadb-connector-c
            git
            llvmPackages_21.clang
            llvmPackages_21.lld
            llvmPackages_21.llvm
            sccache
          ];
          LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
          shellHook = ''
            export LD_LIBRARY_PATH="${lib.makeLibraryPath [ pkgs.openssl pkgs.sqlite pkgs.postgresql pkgs.mariadb-connector-c ]}:${pkgs.mariadb-connector-c}/lib/mariadb:$LD_LIBRARY_PATH"
            export RUSTFLAGS="''${RUSTFLAGS:+$RUSTFLAGS }-C link-arg=-fuse-ld=lld"
            export CC_x86_64_unknown_linux_gnu="${pkgs.llvmPackages_21.clang}/bin/clang"
            export CXX_x86_64_unknown_linux_gnu="${pkgs.llvmPackages_21.clang}/bin/clang++"
            export AR_x86_64_unknown_linux_gnu="${pkgs.llvmPackages_21.llvm}/bin/llvm-ar"
            export RANLIB_x86_64_unknown_linux_gnu="${pkgs.llvmPackages_21.llvm}/bin/llvm-ranlib"
            export CC_aarch64_unknown_linux_gnu="${pkgs.llvmPackages_21.clang}/bin/clang"
            export CXX_aarch64_unknown_linux_gnu="${pkgs.llvmPackages_21.clang}/bin/clang++"
            export AR_aarch64_unknown_linux_gnu="${pkgs.llvmPackages_21.llvm}/bin/llvm-ar"
            export RANLIB_aarch64_unknown_linux_gnu="${pkgs.llvmPackages_21.llvm}/bin/llvm-ranlib"
            source ${./scripts/opensponge-cargo-cache.sh}
          '';
        };
      }
    );
}
