{
  description = "Signet unified identity service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;
        source = lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let name = lib.baseNameOf path;
            in name != ".git"
              && name != "target"
              && name != "node_modules"
              && name != "dist";
        };
        frontendSource = lib.cleanSourceWith {
          src = ./frontend;
          filter = path: type:
            let name = lib.baseNameOf path;
            in name != "node_modules" && name != "dist";
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
          } else {};

        frontend = pkgs.buildNpmPackage {
          pname = "signet-frontend";
          version = "0.1.0";
          src = frontendSource;
          npmDepsHash = "sha256-ehCn5rQPuTtIUpjVU1SdmyZ5qxT0I6m6EHkDEC1sgUE=";
          npmBuildScript = "build";

          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp -r dist $out/
            runHook postInstall
          '';
        };

        signet = pkgs.rustPlatform.buildRustPackage ({
          pname = "signet";
          version = "0.1.0";
          src = source;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "sso-backend" "--bin" "sso-backend" ];
          doCheck = false;
          nativeBuildInputs = with pkgs; [
            llvmPackages_21.clang
            llvmPackages_21.lld
            llvmPackages_21.llvm
            pkg-config
          ];
          buildInputs = with pkgs; [
            openssl
            sqlite
            postgresql
            mariadb-connector-c
          ];
          LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
          SSO_SKIP_FRONTEND_BUILD = "1";

          preBuild = ''
            mkdir -p frontend
            cp -r ${frontend}/dist frontend/dist
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            cp "$(find target -type f -path '*/release/sso-backend' -perm -0100 -print -quit)" $out/bin/signet
            runHook postInstall
          '';
        } // rustNativeEnv);

        runtimeConfig = pkgs.runCommand "signet-runtime-config" {} ''
          mkdir -p $out/app/config
          sed 's/host = "127.0.0.1"/host = "0.0.0.0"/' \
            ${source}/config/default.toml > $out/app/config/default.toml
        '';

        image = pkgs.dockerTools.buildLayeredImage {
          name = "signet";
          tag = "local";
          contents = [
            signet
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
            Cmd = [ "${signet}/bin/signet" ];
            WorkingDir = "/app";
            # The Rust build links OpenSSL/SQLite dynamically, while the
            # minimal image has no conventional /lib search path. Keep the
            # runtime search path explicit so the binary can resolve the
            # libraries already included in the image.
            Env = [
              "SSO_CONFIG=/app/config/default.toml"
              "LD_LIBRARY_PATH=${lib.makeLibraryPath [ pkgs.openssl pkgs.sqlite ]}"
            ];
            ExposedPorts = { "8080/tcp" = {}; };
            Volumes = { "/app/data" = {}; };
          };
        };
      in {
        packages = {
          inherit signet frontend image;
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
            source ${./scripts/opensponge-cargo-cache.sh}
          '';
        };
      }
    );
}
