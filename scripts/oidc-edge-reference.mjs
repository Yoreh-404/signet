#!/usr/bin/env node

// Signet cross-domain legacy edge reference implementation.
//
// This process is intentionally *not* a reverse proxy. Nginx/Traefik keeps
// ownership of business traffic; this sidecar only terminates OIDC Code+PKCE,
// stores a short-lived host-only edge session, and turns that session into a
// Signet IAP assertion through /api/iap/bearer-auth.

import http from "node:http";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

const IDENTITY_RESPONSE_HEADERS = [
  "x-gpt-sso-iap-application",
  "x-gpt-sso-iap-method",
  "x-auth-request-user",
  "x-auth-request-email",
  "x-auth-request-user-id",
  "x-auth-request-name",
  "x-forwarded-user",
  "x-forwarded-email",
  "x-signet-subject",
  "x-signet-email",
  "x-signet-name",
  "x-signet-organization",
  "x-signet-roles",
  "x-signet-permissions",
  "x-signet-assertion",
  "x-signet-assertion-audience",
  "x-signet-assertion-expires-in",
];

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function positiveInteger(raw, fallback, name) {
  if (raw == null || raw.trim() === "") return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function boolEnv(name) {
  return ["1", "true", "yes", "on"].includes(
    (process.env[name] || "").trim().toLowerCase(),
  );
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function decodeBase64url(value, name) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${name} must be unpadded base64url`);
  }
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.toString("base64url") !== value) {
      throw new Error("non-canonical base64url");
    }
    return decoded;
  } catch {
    throw new Error(`${name} must be canonical unpadded base64url`);
  }
}

function safeOrigin(raw, allowHttp, name) {
  const url = new URL(raw);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`${name} must be an origin without credentials/query/hash`);
  }
  if (url.pathname !== "/") {
    throw new Error(`${name} must not contain a path`);
  }
  if (url.protocol === "https:") return url.origin;
  const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname);
  if (allowHttp && url.protocol === "http:" && loopback) return url.origin;
  throw new Error(`${name} must use HTTPS (HTTP is allowed only for loopback test origins)`);
}

function normalizePath(raw, publicOrigin) {
  const value = raw?.trim() || "/";
  let url;
  try {
    url = new URL(value, publicOrigin);
  } catch {
    throw new Error("return_to is not a valid URL/path");
  }
  if (url.origin !== publicOrigin || url.username || url.password || url.hash) {
    throw new Error("return_to must stay on the protected site origin");
  }
  return `${url.pathname}${url.search}`;
}

function hostCookieName(raw, fallback, name) {
  const value = raw?.trim() || fallback;
  if (!/^__Host-[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(value)) {
    throw new Error(`${name} must be a valid __Host- cookie name`);
  }
  return value;
}

function parseCookies(header) {
  const result = new Map();
  for (const item of (header || "").split(";")) {
    const index = item.indexOf("=");
    if (index <= 0) continue;
    const name = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();
    if (name) result.set(name, value);
  }
  return result;
}

function cookie(name, value, maxAgeSeconds) {
  return `${name}=${value}; Path=/; Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}; HttpOnly; Secure; SameSite=Lax`;
}

function noStoreHeaders(extra = {}) {
  return {
    "cache-control": "no-store, private",
    pragma: "no-cache",
    ...extra,
  };
}

function send(res, status, headers = {}, body = "") {
  res.writeHead(status, noStoreHeaders(headers));
  res.end(body);
}

class UpstreamError extends Error {}

async function upstreamFetch(url, options, timeoutMs) {
  try {
    return await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    throw new UpstreamError(`upstream request failed: ${error?.message || error}`);
  }
}

function constantEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function buildCookieCodec(keys, publicOrigin) {
  const keyed = keys.map((key) => ({
    id: createHash("sha256").update(key).digest("base64url").slice(0, 12),
    key,
  }));

  function seal(payload, purpose) {
    const active = keyed[0];
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", active.key, nonce);
    cipher.setAAD(Buffer.from(`signet-edge:v1:${publicOrigin}:${purpose}`));
    const plaintext = Buffer.from(JSON.stringify(payload));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1.${active.id}.${base64url(nonce)}.${base64url(Buffer.concat([ciphertext, tag]))}`;
  }

  function open(value, purpose) {
    const parts = String(value || "").split(".");
    if (parts.length !== 4 || parts[0] !== "v1") return null;
    const material = keyed.find((item) => item.id === parts[1]);
    if (!material) return null;
    try {
      const nonce = decodeBase64url(parts[2], "cookie nonce");
      const encoded = decodeBase64url(parts[3], "cookie payload");
      if (nonce.length !== 12 || encoded.length <= 16) return null;
      const ciphertext = encoded.subarray(0, encoded.length - 16);
      const tag = encoded.subarray(encoded.length - 16);
      const decipher = createDecipheriv("aes-256-gcm", material.key, nonce);
      decipher.setAAD(Buffer.from(`signet-edge:v1:${publicOrigin}:${purpose}`));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const parsed = JSON.parse(plaintext.toString("utf8"));
      if (!parsed || typeof parsed !== "object") return null;
      return parsed;
    } catch {
      return null;
    }
  }

  return { seal, open };
}

async function oidcDiscovery(issuer, timeoutMs) {
  const response = await upstreamFetch(`${issuer}/.well-known/openid-configuration`, {
    redirect: "error",
    headers: { accept: "application/json" },
  }, timeoutMs);
  if (!response.ok) throw new Error(`OIDC discovery failed with HTTP ${response.status}`);
  const body = await response.json();
  if (String(body.issuer || "").replace(/\/$/, "") !== issuer) {
    throw new Error("OIDC discovery issuer mismatch");
  }
  for (const field of ["authorization_endpoint", "token_endpoint"]) {
    const endpoint = new URL(body[field]);
    if (
      endpoint.origin !== new URL(issuer).origin ||
      endpoint.protocol !== new URL(issuer).protocol ||
      endpoint.username ||
      endpoint.password ||
      endpoint.hash
    ) {
      throw new Error(`OIDC discovery ${field} must stay on the configured issuer origin`);
    }
  }
  return body;
}

function edgeConfig() {
  const allowHttp = boolEnv("SIGNET_EDGE_ALLOW_HTTP");
  const publicOrigin = safeOrigin(required("SIGNET_EDGE_PUBLIC_ORIGIN"), allowHttp, "SIGNET_EDGE_PUBLIC_ORIGIN");
  const issuer = safeOrigin(required("SIGNET_EDGE_ISSUER"), allowHttp, "SIGNET_EDGE_ISSUER");
  const rawKeys = required("SIGNET_EDGE_COOKIE_KEYS").split(",").map((value) => value.trim()).filter(Boolean);
  const keys = rawKeys.map((value, index) => {
    const decoded = decodeBase64url(value, `SIGNET_EDGE_COOKIE_KEYS[${index}]`);
    if (decoded.length !== 32) throw new Error("each SIGNET_EDGE_COOKIE_KEYS entry must decode to 32 bytes");
    return decoded;
  });
  if (keys.length === 0) throw new Error("SIGNET_EDGE_COOKIE_KEYS must contain at least one key");
  const scopes = (process.env.SIGNET_EDGE_SCOPES || "openid iap.assert")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (!scopes.includes("openid") || !scopes.includes("iap.assert")) {
    throw new Error("SIGNET_EDGE_SCOPES must include openid and iap.assert");
  }
  if (scopes.includes("offline_access")) {
    throw new Error("SIGNET_EDGE_SCOPES must not request offline_access; the edge keeps no refresh token");
  }
  return {
    allowHttp,
    publicOrigin,
    issuer,
    clientId: required("SIGNET_EDGE_CLIENT_ID"),
    bindHost: process.env.SIGNET_EDGE_BIND_HOST?.trim() || "127.0.0.1",
    bindPort: positiveInteger(process.env.SIGNET_EDGE_BIND_PORT, 4180, "SIGNET_EDGE_BIND_PORT"),
    upstreamTimeoutMs: positiveInteger(
      process.env.SIGNET_EDGE_UPSTREAM_TIMEOUT_MS,
      5_000,
      "SIGNET_EDGE_UPSTREAM_TIMEOUT_MS",
    ),
    maxSessionSeconds: positiveInteger(
      process.env.SIGNET_EDGE_MAX_SESSION_SECONDS,
      600,
      "SIGNET_EDGE_MAX_SESSION_SECONDS",
    ),
    scopes,
    sessionCookie: hostCookieName(
      process.env.SIGNET_EDGE_COOKIE_NAME,
      "__Host-signet_edge",
      "SIGNET_EDGE_COOKIE_NAME",
    ),
    stateCookie: hostCookieName(
      process.env.SIGNET_EDGE_STATE_COOKIE_NAME,
      "__Host-signet_edge_state",
      "SIGNET_EDGE_STATE_COOKIE_NAME",
    ),
    callbackPath: "/_signet/callback",
    startPath: "/_signet/start",
    authPath: "/_signet/auth",
    logoutPath: "/_signet/logout",
    keys,
  };
}

function requestTarget(req, config) {
  const original = req.headers["x-original-url"];
  const uri = req.headers["x-original-uri"];
  const candidate = Array.isArray(original) ? original[0] : original || uri || "/";
  const url = new URL(candidate, config.publicOrigin);
  if (url.origin !== config.publicOrigin || url.username || url.password || url.hash) {
    throw new Error("protected target must stay on SIGNET_EDGE_PUBLIC_ORIGIN");
  }
  return url;
}

function localLoginUrl(target, config) {
  const returnTo = `${target.pathname}${target.search}`;
  return `${config.startPath}?return_to=${encodeURIComponent(returnTo)}`;
}

async function run() {
  const config = edgeConfig();
  const codec = buildCookieCodec(config.keys, config.publicOrigin);
  const discovery = await oidcDiscovery(config.issuer, config.upstreamTimeoutMs);
  const redirectUri = `${config.publicOrigin}${config.callbackPath}`;
  const iapEndpoint = new URL("/api/iap/bearer-auth", config.issuer);

  const server = http.createServer(async (req, res) => {
    try {
      const requestUrl = new URL(req.url || "/", config.publicOrigin);
      if (requestUrl.pathname === "/healthz") {
        return send(res, 200, { "content-type": "application/json" }, JSON.stringify({ status: "ok" }));
      }

      if (requestUrl.pathname === config.startPath) {
        let returnTo;
        try {
          returnTo = normalizePath(
            requestUrl.searchParams.get("return_to") || "/",
            config.publicOrigin,
          );
        } catch {
          return send(res, 400, {}, "invalid return_to");
        }
        const state = base64url(randomBytes(24));
        const verifier = base64url(randomBytes(32));
        const challenge = base64url(createHash("sha256").update(verifier).digest());
        const stateCookie = codec.seal(
          { state, verifier, return_to: returnTo, exp: Math.floor(Date.now() / 1000) + 300 },
          "state",
        );
        const authorize = new URL(discovery.authorization_endpoint);
        authorize.searchParams.set("response_type", "code");
        authorize.searchParams.set("client_id", config.clientId);
        authorize.searchParams.set("redirect_uri", redirectUri);
        authorize.searchParams.set("scope", config.scopes.join(" "));
        authorize.searchParams.set("state", state);
        authorize.searchParams.set("code_challenge", challenge);
        authorize.searchParams.set("code_challenge_method", "S256");
        return send(
          res,
          302,
          {
            location: authorize.toString(),
            "set-cookie": cookie(config.stateCookie, stateCookie, 300),
          },
        );
      }

      if (requestUrl.pathname === config.callbackPath) {
        const cookies = parseCookies(req.headers.cookie);
        const transient = codec.open(cookies.get(config.stateCookie), "state");
        const code = requestUrl.searchParams.get("code") || "";
        const state = requestUrl.searchParams.get("state") || "";
        const now = Math.floor(Date.now() / 1000);
        if (
          requestUrl.searchParams.has("error") ||
          !transient ||
          transient.exp < now ||
          !code ||
          !constantEqual(String(transient.state || ""), state)
        ) {
          return send(res, 401, { "set-cookie": cookie(config.stateCookie, "", 0) }, "OIDC callback rejected");
        }
        const tokenResponse = await upstreamFetch(discovery.token_endpoint, {
          method: "POST",
          redirect: "error",
          headers: {
            accept: "application/json",
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: config.clientId,
            code,
            redirect_uri: redirectUri,
            code_verifier: String(transient.verifier || ""),
          }),
        }, config.upstreamTimeoutMs);
        if (!tokenResponse.ok) {
          return send(res, 502, { "set-cookie": cookie(config.stateCookie, "", 0) }, "OIDC token exchange failed");
        }
        let token;
        try {
          token = await tokenResponse.json();
        } catch {
          return send(res, 502, { "set-cookie": cookie(config.stateCookie, "", 0) }, "OIDC token response invalid");
        }
        const expiresIn = Number(token.expires_in);
        if (
          typeof token.access_token !== "string" ||
          !token.access_token ||
          String(token.token_type || "").toLowerCase() !== "bearer" ||
          !Number.isFinite(expiresIn) ||
          expiresIn <= 0
        ) {
          return send(res, 502, { "set-cookie": cookie(config.stateCookie, "", 0) }, "OIDC token response invalid");
        }
        const usableLifetime = Math.floor(expiresIn) - 5;
        if (usableLifetime <= 0) {
          return send(res, 502, { "set-cookie": cookie(config.stateCookie, "", 0) }, "OIDC access token expires too soon");
        }
        const sessionLifetime = Math.min(config.maxSessionSeconds, usableLifetime);
        const session = codec.seal(
          { access_token: token.access_token, exp: now + sessionLifetime },
          "session",
        );
        if (Buffer.byteLength(`${config.sessionCookie}=${session}`, "utf8") > 3800) {
          return send(res, 502, { "set-cookie": cookie(config.stateCookie, "", 0) }, "OIDC access token is too large for the sealed edge cookie");
        }
        return send(res, 302, {
          location: normalizePath(transient.return_to, config.publicOrigin),
          "set-cookie": [
            cookie(config.sessionCookie, session, sessionLifetime),
            cookie(config.stateCookie, "", 0),
          ],
        });
      }

      if (requestUrl.pathname === config.logoutPath) {
        return send(res, 302, {
          location: "/",
          "set-cookie": [
            cookie(config.sessionCookie, "", 0),
            cookie(config.stateCookie, "", 0),
          ],
        });
      }

      if (requestUrl.pathname === config.authPath) {
        let target;
        try {
          target = requestTarget(req, config);
        } catch {
          return send(res, 400, {}, "invalid protected target");
        }
        const cookies = parseCookies(req.headers.cookie);
        const session = codec.open(cookies.get(config.sessionCookie), "session");
        const now = Math.floor(Date.now() / 1000);
        if (!session || session.exp <= now || typeof session.access_token !== "string") {
          return send(res, 401, {
            "x-auth-request-redirect": localLoginUrl(target, config),
            "set-cookie": cookie(config.sessionCookie, "", 0),
          });
        }

        const endpoint = new URL(iapEndpoint);
        endpoint.searchParams.set("target", target.toString());
        const decision = await upstreamFetch(endpoint, {
          method: "GET",
          redirect: "error",
          headers: {
            authorization: `Bearer ${session.access_token}`,
            accept: "*/*",
            "x-original-method": String(req.headers["x-original-method"] || "GET"),
          },
        }, config.upstreamTimeoutMs);
        if (decision.status === 401) {
          return send(res, 401, {
            "x-auth-request-redirect": localLoginUrl(target, config),
            "set-cookie": cookie(config.sessionCookie, "", 0),
          });
        }
        if (decision.status === 403) return send(res, 403);
        if (decision.status !== 204) return send(res, 502, {}, "Signet IAP decision failed");
        if (
          !decision.headers.get("x-signet-assertion") ||
          !decision.headers.get("x-signet-subject") ||
          !decision.headers.get("x-signet-assertion-audience")
        ) {
          return send(res, 502, {}, "Signet IAP decision incomplete");
        }

        const headers = {};
        for (const name of IDENTITY_RESPONSE_HEADERS) {
          const value = decision.headers.get(name);
          if (value != null) headers[name] = value;
        }
        return send(res, 204, headers);
      }

      return send(res, 404, {}, "not found");
    } catch (error) {
      console.error("signet-edge request failed", error);
      return send(
        res,
        error instanceof UpstreamError ? 502 : 500,
        {},
        error instanceof UpstreamError ? "identity upstream unavailable" : "internal edge error",
      );
    }
  });

  server.listen(config.bindPort, config.bindHost, () => {
    console.log(`signet-edge listening on http://${config.bindHost}:${config.bindPort}`);
  });
}

function selfTest() {
  const origin = "https://legacy.example.test";
  const codec = buildCookieCodec([randomBytes(32)], origin);
  const sealed = codec.seal({ value: "secret", exp: 123 }, "session");
  const opened = codec.open(sealed, "session");
  if (opened?.value !== "secret" || codec.open(sealed, "state") !== null) {
    throw new Error("cookie codec self-test failed");
  }
  if (normalizePath("/a?b=1", origin) !== "/a?b=1") {
    throw new Error("return_to normalization self-test failed");
  }
  let rejected = false;
  try {
    normalizePath("https://evil.example/", origin);
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("cross-origin return_to self-test failed");
  rejected = false;
  try {
    normalizePath("/safe#fragment", origin);
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("fragment return_to self-test failed");
  if (hostCookieName("__Host-edge", "ignored", "test") !== "__Host-edge") {
    throw new Error("host cookie name self-test failed");
  }
  console.log("signet-edge self-test ok");
}

if (process.argv.includes("--self-test")) {
  selfTest();
} else {
  run().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
