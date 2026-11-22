#!/usr/bin/env python3
"""Write isolated three-phase Signet integration config; never start services."""
import argparse
import json
import os
import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit


def fixture_origin(value):
    uri = urlsplit(value)
    canonical = {"sso.yoreh.cn", "axon-next.yoreh.cn"}
    if (uri.scheme != "https" or not uri.hostname
            or not (uri.hostname.endswith(".test") or uri.hostname in canonical)
            or uri.username or uri.password or uri.path or uri.query or uri.fragment):
        raise argparse.ArgumentTypeError("use a canonical HTTPS fixture origin")
    return value


def update_section(text, heading, values):
    pattern = re.compile(rf"(^\[{re.escape(heading)}\]\s*$)(.*?)(?=^\[|\Z)", re.M | re.S)
    found = pattern.search(text)
    if not found:
        raise ValueError(f"missing [{heading}]")
    body = found.group(2)
    for key, value in values.items():
        body = re.sub(rf"^{re.escape(key)}\s*=.*$", "", body, flags=re.M)
        body += "\n" + key + " = " + json.dumps(value)
    return text[:found.start()] + found.group(1) + body.rstrip() + "\n\n" + text[found.end():]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("bootstrap", "incumbent", "v2"), required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--db", type=Path)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--issuer", type=fixture_origin, required=True)
    parser.add_argument("--axon-origin", type=fixture_origin)
    parser.add_argument("--audience")
    parser.add_argument("--organization-id")
    parser.add_argument("--application-id", default="axon")
    parser.add_argument("--browser-client")
    parser.add_argument("--jwks", type=Path)
    parser.add_argument("--introspection-client")
    parser.add_argument("--enrollment-id")
    parser.add_argument("--revision", type=int)
    parser.add_argument("--digest")
    parser.add_argument("--activation-epoch", type=int)
    parser.add_argument("--canonical-origins-isolated", action="store_true")
    args = parser.parse_args()
    fixture_dir = os.environ.get("AXON_V2_FIXTURE_DIR")
    if fixture_dir:
        args.db = args.db or (Path(fixture_dir) / "signet-fixture.sqlite")
        args.out = args.out or (Path(fixture_dir) / f"signet-{args.phase}.toml")
    if not args.db or not args.out:
        parser.error("set AXON_V2_FIXTURE_DIR or specify --db and --out")
    if any(".yoreh.cn" in value for value in (args.issuer, args.axon_origin or "")) and not args.canonical_origins_isolated:
        parser.error("canonical names require --canonical-origins-isolated and fully loopback-resolved namespace")
    if args.db.exists() and args.phase == "bootstrap":
        parser.error("bootstrap fixture requires a fresh database path")
    if not 1024 <= args.port <= 65535:
        parser.error("use a non-privileged isolated port")
    root = Path(__file__).resolve().parent.parent
    text = (root / "config/default.toml").read_text()
    text = re.sub(r"^\[\[(?:bootstrap\.applications|external_oidc_providers)\]\].*?(?=^\[|\Z)", "", text, flags=re.M | re.S)
    text = update_section(text, "server", {
        "host": "127.0.0.1", "port": args.port, "public_base_url": args.issuer,
    })
    text = update_section(text, "database", {
        "kind": "sqlite", "url": str(args.db.resolve()),
    })
    text = update_section(text, "oidc", {"issuer": args.issuer, "skip_consent": True})
    text = update_section(text, "discovery", {"allow_private_networks": True})
    text = update_section(text, "discovery.auto_registration", {"enabled": False, "startup_scan": False})
    text = update_section(text, "bootstrap.admin", {
        "create_on_startup": args.phase == "bootstrap",
        "email": "fixture-admin@signet.test", "username": "fixture-admin", "password": "",
    })
    if args.phase != "bootstrap":
        if not all((args.axon_origin, args.audience, args.organization_id, args.browser_client, args.jwks)):
            parser.error("incumbent/v2 requires Axon origin, audience, org ID, browser client and public JWKS")
        jwks = json.dumps(json.loads(args.jwks.read_text()), separators=(",", ":"))
        text += "\n[[bootstrap.applications]]\n"
        for key, value in {
            "application_id": args.application_id, "organization_id": args.organization_id,
            "name": "Axon Fixture", "website_url": args.axon_origin,
            "management_mode": "website_managed", "fetch_secret_env": "AXON_FIXTURE_DISCOVERY_BEARER",
        }.items():
            text += f"{key} = {json.dumps(value)}\n"
        text += "\n[discovery.axon_admin_trust]\n"
        for key, value in {
            "origin": args.axon_origin, "organization_id": args.organization_id,
            "application_id": args.application_id, "client_id": args.browser_client,
            "audience": args.audience, "signing_public_jwks": jwks,
        }.items():
            text += f"{key} = {json.dumps(value)}\n"
    if args.phase == "v2":
        if not all((args.introspection_client, args.enrollment_id, args.revision, args.digest, args.activation_epoch)):
            parser.error("v2 requires introspection client, enrollment ID, approved revision/digest and activation epoch")
        permissions = json.loads((root / "backend/tests/fixtures/axon-admin-v2-catalog.json").read_text())
        text += "\n[discovery.axon_admin_v2]\n"
        for key, value in {
            "enrollment_id": args.enrollment_id, "revision": args.revision, "digest": args.digest,
            "permissions": permissions, "issuer": args.issuer,
            "introspection_client_id": args.introspection_client, "activation_epoch": args.activation_epoch,
        }.items():
            text += f"{key} = {json.dumps(value)}\n"
    tomllib.loads(text)
    args.out.write_text(text)


if __name__ == "__main__":
    main()
