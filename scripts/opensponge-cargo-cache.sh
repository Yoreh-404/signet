#!/usr/bin/env bash

# Initialise the shared Cargo/sccache cache used by the OpenSponge Rust
# projects. The target directory is shared only by compatible compilation
# identities; Cargo still keeps package, feature, profile, and fingerprint
# boundaries inside the directory.

opensponge_cargo_cache_init() {
  if ! command -v rustc >/dev/null 2>&1; then
    return 0
  fi

  local cache_root rustc_identity target_triple cache_material cache_variant
  local native_cc native_cxx native_ar native_ranlib native_linker
  cache_root="${OPENSPONGE_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/opensponge}"
  rustc_identity="$(rustc -vV 2>/dev/null || true)"
  target_triple="${CARGO_BUILD_TARGET:-$(printf '%s\n' "$rustc_identity" | sed -n 's/^host: //p')}"
  target_triple="$(printf '%s' "$target_triple" | tr -c '[:alnum:]_.-' '_')"

  # Match the target-qualified compiler contract in .cargo/config.toml. Do
  # not use the generic CC/CXX values for x86_64, otherwise a host shell can
  # accidentally make the shared target incompatible with the Nix toolchain.
  case "$target_triple" in
    x86_64-unknown-linux-gnu)
      native_cc="${CC_x86_64_unknown_linux_gnu:-${CC:-clang}}"
      native_cxx="${CXX_x86_64_unknown_linux_gnu:-${CXX:-clang++}}"
      native_ar="${AR_x86_64_unknown_linux_gnu:-${AR:-llvm-ar}}"
      native_ranlib="${RANLIB_x86_64_unknown_linux_gnu:-${RANLIB:-llvm-ranlib}}"
      native_linker="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-clang}"
      ;;
    *)
      native_cc="${CC:-}"
      native_cxx="${CXX:-}"
      native_ar="${AR:-}"
      native_ranlib="${RANLIB:-}"
      native_linker="${CARGO_TARGET_LINKER:-}"
      ;;
  esac

  cache_material="$({
    printf 'rustc=%s\n' "$rustc_identity"
    printf 'target=%s\n' "$target_triple"
    printf 'rustflags=%s\n' "${RUSTFLAGS:-}"
    printf 'encoded-rustflags=%s\n' "${CARGO_ENCODED_RUSTFLAGS:-}"
    printf 'cc=%s\n' "$native_cc"
    printf 'cxx=%s\n' "$native_cxx"
    printf 'ar=%s\n' "$native_ar"
    printf 'ranlib=%s\n' "$native_ranlib"
    printf 'linker=%s\n' "$native_linker"
    if [ "$target_triple" = "x86_64-unknown-linux-gnu" ]; then
      printf 'cargo-config-rustflags=-C link-arg=-fuse-ld=lld\n'
    fi
    for tool in "$native_cc" "$native_cxx" "$native_ar" "$native_ranlib" "$native_linker"; do
      if [ -z "$tool" ]; then
        continue
      fi
      printf 'tool=%s path=%s\n' "$tool" "$(command -v "$tool" 2>/dev/null || true)"
      if command -v "$tool" >/dev/null 2>&1; then
        "$tool" --version 2>&1 | sed -n '1,4p'
      fi
    done
  } | sha256sum | cut -c1-16)"
  cache_variant="${OPENSPONGE_CARGO_CACHE_VARIANT:-${target_triple}-${cache_material}}"

  if [ -z "${CARGO_HOME:-}" ]; then
    export CARGO_HOME="$cache_root/cargo-home"
  fi
  export PATH="$CARGO_HOME/bin:${PATH:-}"
  export CARGO_REGISTRIES_CRATES_IO_PROTOCOL="${CARGO_REGISTRIES_CRATES_IO_PROTOCOL:-sparse}"
  export CARGO_NET_RETRY="${CARGO_NET_RETRY:-5}"
  export CARGO_HTTP_TIMEOUT="${CARGO_HTTP_TIMEOUT:-120}"
  export CARGO_HTTP_MULTIPLEXING="${CARGO_HTTP_MULTIPLEXING:-false}"
  if [ -z "${CARGO_TARGET_DIR:-}" ] && [ "${OPENSPONGE_DISABLE_SHARED_CARGO_TARGET:-0}" != "1" ]; then
    export CARGO_TARGET_DIR="$cache_root/cargo-target/$cache_variant"
  fi
  if [ -z "${SCCACHE_DIR:-}" ]; then
    export SCCACHE_DIR="$cache_root/sccache"
  fi
  if [ -z "${RUSTC_WRAPPER:-}" ] && command -v sccache >/dev/null 2>&1; then
    export RUSTC_WRAPPER=sccache
  fi

  mkdir -p "$CARGO_HOME" "$SCCACHE_DIR"
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    mkdir -p "$CARGO_TARGET_DIR"
  fi

  if [ "${OPENSPONGE_CARGO_CACHE_QUIET:-0}" != "1" ]; then
    printf 'OpenSponge Rust cache: target=%s sccache=%s\n' \
      "${CARGO_TARGET_DIR:-project-default}" "${SCCACHE_DIR:-disabled}"
  fi

  if [ -n "${GITHUB_ENV:-}" ]; then
    for variable in CARGO_HOME CARGO_TARGET_DIR SCCACHE_DIR CARGO_REGISTRIES_CRATES_IO_PROTOCOL CARGO_NET_RETRY CARGO_HTTP_TIMEOUT CARGO_HTTP_MULTIPLEXING RUSTC_WRAPPER; do
      printf '%s=%s\n' "$variable" "${!variable:-}" >> "$GITHUB_ENV"
    done
  fi
  if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$CARGO_HOME/bin" >> "$GITHUB_PATH"
  fi
}

opensponge_cargo_cache_init
unset -f opensponge_cargo_cache_init
