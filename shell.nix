{ system ? builtins.currentSystem
, pkgs ? let
    flake = builtins.getFlake (toString ./.);
  in import flake.inputs.nixpkgs {
    inherit system;
  }
}:

pkgs.mkShell {
  packages = with pkgs; [
    cargo
    rustc
    rustfmt
    clippy
    pkg-config
    openssl
    sqlite
    postgresql
    mariadb-connector-c
    nodejs_22
    llvmPackages_21.clang
    llvmPackages_21.lld
    llvmPackages_21.llvm
    sccache
  ];

  shellHook = ''
    export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
    export CC=${pkgs.llvmPackages_21.clang}/bin/clang
    export CXX=${pkgs.llvmPackages_21.clang}/bin/clang++
    export AR=${pkgs.llvmPackages_21.llvm}/bin/llvm-ar
    export RANLIB=${pkgs.llvmPackages_21.llvm}/bin/llvm-ranlib
    export AR_x86_64_unknown_linux_gnu=${pkgs.llvmPackages_21.llvm}/bin/llvm-ar
    export RANLIB_x86_64_unknown_linux_gnu=${pkgs.llvmPackages_21.llvm}/bin/llvm-ranlib
    export PQ_LIB_DIR=${pkgs.postgresql.lib}/lib
    export PQ_INCLUDE_DIR=${pkgs.postgresql}/include
    export MYSQLCLIENT_LIB_DIR=${pkgs.mariadb-connector-c}/lib
    export MYSQLCLIENT_INCLUDE_DIR=${pkgs.mariadb-connector-c}/include/mariadb
    export LD_LIBRARY_PATH=${pkgs.openssl.out}/lib:${pkgs.postgresql.lib}/lib:${pkgs.mariadb-connector-c}/lib/mariadb:${pkgs.sqlite.out}/lib:$LD_LIBRARY_PATH
    source ${./scripts/opensponge-cargo-cache.sh}
    echo "Signet dev shell: cargo, node, sqlite, libpq, mysqlclient are available"
  '';
}
