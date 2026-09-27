#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${SIGNET_SMOKE_BINARY:-$ROOT/target/release/sso-backend}"

if [[ ! -x "$BINARY" ]]; then
  echo "missing Signet binary: $BINARY" >&2
  exit 1
fi

if [[ "${SIGNET_SMOKE_IN_NETNS:-0}" != "1" ]]; then
  if ! command -v unshare >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1; then
    echo "unshare and ip are required for the isolated multi-replica smoke" >&2
    exit 1
  fi
  exec unshare -n env SIGNET_SMOKE_IN_NETNS=1 SIGNET_SMOKE_BINARY="$BINARY" bash "$0"
fi

ip link set lo up

tmp="$(mktemp -d /tmp/signet-multireplica-smoke.XXXXXX)"
pid_a=""
pid_b=""
cleanup() {
  set +e
  [[ -n "$pid_a" ]] && kill "$pid_a" 2>/dev/null
  [[ -n "$pid_b" ]] && kill "$pid_b" 2>/dev/null
  [[ -n "$pid_a" ]] && wait "$pid_a" 2>/dev/null
  [[ -n "$pid_b" ]] && wait "$pid_b" 2>/dev/null
  rm -rf "$tmp"
}
trap cleanup EXIT

config_a="$tmp/a.toml"
config_b="$tmp/b.toml"
cp "$ROOT/config/default.toml" "$config_a"
sed '0,/port = 8080/s//port = 8081/' "$ROOT/config/default.toml" >"$config_b"

db="$tmp/signet.sqlite3"
base_a="http://127.0.0.1:8080"
base_b="http://127.0.0.1:8081"
cookie_jar="$tmp/cookies.txt"

start_instance() {
  local config="$1"
  local log="$2"
  SSO_CONFIG="$config" \
    SSO_DATABASE_KIND=sqlite \
    SSO_DATABASE_URL="$db" \
    SSO_PUBLIC_BASE_URL="$base_a" \
    SSO_ISSUER="$base_a" \
    SSO_AUTO_REGISTRATION_STARTUP_SCAN=false \
    SSO_SIGNING_KEY_SYNC_SECONDS=1 \
    RUST_LOG=warn \
    "$BINARY" >"$log" 2>&1 &
  echo $!
}

wait_ready() {
  local base="$1"
  local pid="$2"
  local log="$3"
  for _ in $(seq 1 120); do
    if curl -fsS "$base/api/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$log" >&2
      return 1
    fi
    sleep 0.1
  done
  cat "$log" >&2
  return 1
}

json_field() {
  local field="$1"
  node -e '
    const field = process.argv[1];
    let body = "";
    process.stdin.on("data", chunk => body += chunk);
    process.stdin.on("end", () => {
      const value = JSON.parse(body)[field];
      if (value === undefined || value === null) process.exit(2);
      process.stdout.write(String(value));
    });
  ' "$field"
}

jwks_etag() {
  curl -fsS -D - -o /dev/null "$1/oauth2/jwks" \
    | tr -d '\r' \
    | awk -F': ' 'tolower($1) == "etag" { print $2; exit }'
}

pid_a="$(start_instance "$config_a" "$tmp/a.log")"
wait_ready "$base_a" "$pid_a" "$tmp/a.log"

curl -fsS \
  -c "$cookie_jar" \
  -H "Origin: $base_a" \
  -H 'Content-Type: application/json' \
  -X POST "$base_a/api/register" \
  --data-binary '{"email":"replica-smoke@example.test","username":"replica-smoke","display_name":"Replica Smoke","password":"R8!vQ4@kN6#sP2"}' \
  >/dev/null

csrf="$(curl -fsS -b "$cookie_jar" "$base_a/api/csrf" | json_field csrf_token)"

pid_b="$(start_instance "$config_b" "$tmp/b.log")"
wait_ready "$base_b" "$pid_b" "$tmp/b.log"

etag_before_a="$(jwks_etag "$base_a")"
etag_before_b="$(jwks_etag "$base_b")"
if [[ -z "$etag_before_a" || "$etag_before_a" != "$etag_before_b" ]]; then
  echo "replicas did not start from the same JWKS ETag" >&2
  exit 1
fi

started_ms="$(date +%s%3N)"
curl -fsS \
  -b "$cookie_jar" \
  -H "Origin: $base_a" \
  -H "X-CSRF-Token: $csrf" \
  -H 'Content-Type: application/json' \
  -X POST "$base_a/api/admin/signing-keys" \
  --data-binary '{"kid":"replica-smoke-key"}' \
  >/dev/null

etag_after_a="$(jwks_etag "$base_a")"
if [[ "$etag_after_a" == "$etag_before_a" ]]; then
  echo "primary replica did not publish the rotated key" >&2
  exit 1
fi

deadline=$((SECONDS + 8))
etag_after_b="$etag_before_b"
while (( SECONDS < deadline )); do
  etag_after_b="$(jwks_etag "$base_b")"
  [[ "$etag_after_b" == "$etag_after_a" ]] && break
  sleep 0.05
done

if [[ "$etag_after_b" != "$etag_after_a" ]]; then
  echo "secondary replica did not converge to the rotated JWKS" >&2
  echo "primary log:" >&2
  tail -n 40 "$tmp/a.log" >&2
  echo "secondary log:" >&2
  tail -n 40 "$tmp/b.log" >&2
  exit 1
fi

finished_ms="$(date +%s%3N)"
propagation_ms=$((finished_ms - started_ms))
key_count="$(curl -fsS "$base_b/oauth2/jwks" | node -e '
  let body = "";
  process.stdin.on("data", chunk => body += chunk);
  process.stdin.on("end", () => process.stdout.write(String(JSON.parse(body).keys.length)));
')"
conditional_status="$(curl -sS -o /dev/null -w '%{http_code}' -H "If-None-Match: $etag_after_b" "$base_b/oauth2/jwks")"

if [[ "$key_count" -lt 2 ]]; then
  echo "secondary replica JWKS does not include the retired and active keys" >&2
  exit 1
fi
if [[ "$conditional_status" != "304" ]]; then
  echo "secondary replica conditional JWKS request returned $conditional_status instead of 304" >&2
  exit 1
fi

printf 'multi-replica signing-key sync: ok propagation_ms=%s keys=%s conditional=%s\n' \
  "$propagation_ms" "$key_count" "$conditional_status"
