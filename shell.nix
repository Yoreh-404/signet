{ system ? builtins.currentSystem
, pkgs ? (builtins.getFlake (toString ./. )).legacyPackages.${system}
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
    export PQ_LIB_DIR=${pkgs.postgresql.lib}/lib
    export PQ_INCLUDE_DIR=${pkgs.postgresql}/include
    export MYSQLCLIENT_LIB_DIR=${pkgs.mariadb-connector-c}/lib
    export MYSQLCLIENT_INCLUDE_DIR=${pkgs.mariadb-connector-c}/include/mariadb
    source ${./scripts/opensponge-cargo-cache.sh}
    echo "Signet dev shell: cargo, node, sqlite, libpq, mysqlclient are available"
  '';
}
