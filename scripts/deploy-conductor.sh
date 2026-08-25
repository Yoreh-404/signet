#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
conductor_root="${OPENSPONGE_CONDUCTOR_ROOT:-$repo_root/../opensponge-conductor}"
if [[ "$conductor_root" != /* ]]; then
  conductor_root="$repo_root/$conductor_root"
fi
[[ -x "$conductor_root/scripts/conductor.sh" ]] \
  || { echo "opensponge-conductor not found: $conductor_root" >&2; exit 1; }
exec "$conductor_root/scripts/conductor.sh" deploy --service signet "$@"
