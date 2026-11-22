#!/usr/bin/env python3
"""Seed exact fixture tenant and resource client through a TLS loopback Signet."""
import argparse
import http.cookiejar
import ipaddress
import json
import os
import socket
import ssl
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--resource-audience", required=True)
    parser.add_argument("--introspection-client", required=True)
    args = parser.parse_args()
    issuer = urlsplit(args.issuer)
    if (issuer.scheme != "https" or not issuer.hostname or issuer.path or issuer.query
            or issuer.fragment or issuer.username or issuer.password):
        parser.error("an exact HTTPS fixture issuer is required")
    if not (issuer.hostname.endswith(".test") or issuer.hostname == "sso.yoreh.cn"):
        parser.error("unrecognized fixture issuer")
    addresses = socket.getaddrinfo(issuer.hostname, issuer.port or 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(entry[4][0]).is_loopback for entry in addresses):
        parser.error("every resulting fixture address must be loopback")
    password = os.environ["SSO_BOOTSTRAP_ADMIN_PASSWORD"]
    client_secret = os.environ["AXON_FIXTURE_INTROSPECTION_SECRET"]
    opener = build_opener(
        ProxyHandler({}), HTTPCookieProcessor(http.cookiejar.CookieJar()),
        NoRedirect(),
        HTTPSHandler(context=ssl.create_default_context(cafile=args.ca)),
    )

    def call(path, method="GET", payload=None, csrf=None):
        headers = {"Origin": args.issuer, "Accept": "application/json"}
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode()
        with opener.open(Request(args.issuer + path, data=body, headers=headers, method=method), timeout=10) as response:
            return json.load(response)

    call("/api/login", "POST", {"email": "fixture-admin@signet.test", "password": password})
    csrf = call("/api/csrf")["csrf_token"]
    tenant = call("/api/me/organizations", "POST", {"slug": "v2-fixture", "name": "V2 Fixture"}, csrf)
    call("/api/me/organization-context", "PUT", {"organization_id": tenant["id"]}, csrf)
    app = call("/api/admin/applications", "POST", {
        "slug": "axon-v2-verifier", "name": "Axon V2 Verifier", "registration_mode": "disabled",
        "account_selection_mode": "optional", "is_active": True,
    }, csrf)
    client = call(f"/api/admin/applications/{app['id']}/oidc-clients", "POST", {
        "client_id": args.introspection_client, "client_name": "Axon V2 Verifier",
        "client_secret": client_secret, "redirect_uris": [args.issuer + "/unused"],
        "post_logout_redirect_uris": [], "scopes": ["openid"], "audience": args.resource_audience,
        "grant_types": ["authorization_code"], "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic", "require_pkce": True,
        "require_s256_pkce": True, "subject_type": "public", "sector_identifier_uri": "", "is_active": True,
    }, csrf)
    print(json.dumps({"organization_id": tenant["id"], "verifier_client_id": client["client_id"]}))


if __name__ == "__main__":
    main()
