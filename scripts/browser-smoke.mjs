#!/usr/bin/env node

import fs from "node:fs/promises";

const cdpBase = process.env.CDP_URL ?? "http://127.0.0.1:9222";
const appBase = process.env.APP_URL ?? "http://127.0.0.1:8080";
const screenshotDir = process.env.SCREENSHOT_DIR ?? ".logs/screenshots";
const scenario = process.env.SCENARIO ?? "public-auth";

class CdpClient {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
  }

  async connect() {
    await new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener("error", reject, { once: true });
    });
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (!message.id) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  close() {
    this.socket.close();
  }
}

async function waitFor(predicate, message, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out: ${message}`);
}

async function main() {
  const appUrl = new URL(appBase);
  const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
  if (scenario === "lifecycle") {
    if (!loopbackHosts.has(appUrl.hostname)) {
      throw new Error("The destructive lifecycle scenario is restricted to a loopback APP_URL");
    }
    if (process.env.ALLOW_DESTRUCTIVE_SMOKE !== "1") {
      throw new Error("Set ALLOW_DESTRUCTIVE_SMOKE=1 to run the destructive lifecycle scenario against a disposable database");
    }
  }

  const pages = await fetch(`${cdpBase}/json/list`).then((response) => response.json());
  const page = pages.find((candidate) => candidate.type === "page");
  if (!page) throw new Error("No Chromium page target is available");

  const cdp = new CdpClient(page.webSocketDebuggerUrl);
  await cdp.connect();
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Network.enable");

  const evaluate = async (expression) => {
    const result = await cdp.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description ?? "Browser evaluation failed");
    }
    return result.result.value;
  };

  if (scenario === "auth-ui-mock") {
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", {
      source: String.raw`(() => {
        const originalFetch = window.fetch.bind(window);
        const now = Math.floor(Date.now() / 1000);
        const user = (id, email, username, displayName, isAdmin = false) => ({
          id,
          email,
          username,
          display_name: displayName,
          phone: null,
          email_verified_at: now,
          phone_verified_at: null,
          is_admin: isAdmin,
          is_active: true,
          archived_at: null,
          last_login_at: now - 60,
          last_login_ip: "127.0.0.1",
          last_oidc_client_id: null,
          last_login_method: "password",
          created_at: now - 3600,
          updated_at: now,
          session_kind: "standard",
          login_code_level: null,
          permissions: [],
        });
        const client = (id, name, active = true) => ({
          id: "db-" + id,
          client_id: id,
          client_name: name,
          logo_uri: "https://assets.mock.example/" + id + ".svg",
          organization_id: null,
          organization_slug: null,
          organization_name: null,
          redirect_uris: ["https://example.invalid/callback"],
          post_logout_redirect_uris: [],
          scopes: ["openid", "profile", "email"],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "client_secret_basic",
          require_pkce: false,
          require_mfa: false,
          require_pushed_authorization_requests: false,
          require_s256_pkce: false,
          require_confidential_client: false,
          require_dpop: false,
          require_account_selection: false,
          trust_email_verified: false,
          authorization_details_types: [],
          subject_type: "public",
          sector_identifier_uri: "",
          jwks_uri: "",
          jwks: "",
          backchannel_logout_uri: "",
          backchannel_logout_session_required: false,
          frontchannel_logout_uri: "",
          frontchannel_logout_session_required: false,
          service_account_enabled: false,
          service_account_permissions: [],
          is_active: active,
          claim_mappers: [],
          created_at: now - 3600,
          updated_at: now,
        });
        const allPermissions = [
          "admin.read",
          "settings.manage",
          "users.read",
          "users.manage",
          "clients.read",
          "clients.manage",
          "iap.read",
          "iap.manage",
          "organizations.read",
          "organizations.manage",
          "authorization_codes.manage",
          "providers.manage",
          "audit.read",
          "security.manage",
        ];
        const admin = {
          ...user("admin-id", "admin@mock.example", "mock-admin", "Mock Admin", true),
          permissions: allPermissions,
        };
        const temporaryAdmin = {
          ...admin,
          session_kind: "temporary_authorization_code",
          login_code_level: "account_recovery",
          permissions: [],
        };
        const trialAdmin = {
          ...admin,
          session_kind: "trial_enrollment",
          login_code_level: "trial_enrollment",
          permissions: [],
        };
        // Deliberately keep the wire order and last-selection order different
        // from login recency. The unified auth strip must order by the latter.
        let accounts = [
          { account_ref: "account-alice", user: user("alice-id", "alice@mock.example", "alice", "Alice"), session_kind: "standard", current: true, last_login_at: now - 300, last_selected_at: now - 10 },
          { account_ref: "account-bob", user: user("bob-id", "bob@mock.example", "bob", "Bob"), session_kind: "temporary_authorization_code", current: false, last_login_at: now - 20, last_selected_at: now - 500 },
          { account_ref: "account-trial", user: { ...user("trial-id", "trial@mock.example", "trial-user", "Trial User"), session_kind: "trial_enrollment", login_code_level: "trial_enrollment" }, session_kind: "trial_enrollment", current: false, last_login_at: now - 120, last_selected_at: now - 200 },
        ];
        const clients = [client("app-one", "App One"), client("app-two", "App Two")];
        const organizationOptions = [
          { id: "org-club", slug: "mock-club", name: "Mock Club", is_active: true },
        ];
        const managedUsers = [
          admin,
          user("alice-id", "alice@mock.example", "alice", "Alice"),
        ];
        const response = (body, status = 200) => new Response(
          body === undefined ? null : JSON.stringify(body),
          { status, headers: { "content-type": "application/json" } },
        );
        const readLog = () => {
          try { return JSON.parse(sessionStorage.getItem("__gptSsoSmokeRequests") || "[]"); }
          catch { return []; }
        };
        if (new URLSearchParams(location.search).get("smoke_reset") === "1") {
          sessionStorage.removeItem("__gptSsoSmokeRequests");
        }
        const record = async (url, method, input, init) => {
          let rawBody = init?.body ?? null;
          if (rawBody === null && input instanceof Request && method !== "GET") {
            rawBody = await input.clone().text();
          }
          let body = rawBody;
          if (typeof rawBody === "string") {
            try { body = JSON.parse(rawBody); } catch {}
          }
          const headers = Object.fromEntries(new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).entries());
          const next = [...readLog(), { path: url.pathname + url.search, method, body, headers }];
          sessionStorage.setItem("__gptSsoSmokeRequests", JSON.stringify(next));
          window.__gptSsoSmokeRequests = next;
        };
        window.__gptSsoSmokeRequests = readLog();
        window.fetch = async (input, init = {}) => {
          const requestUrl = new URL(input instanceof Request ? input.url : String(input), location.origin);
          const method = String(init.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
          if (requestUrl.origin !== location.origin || !requestUrl.pathname.startsWith("/api/")) {
            return originalFetch(input, init);
          }
          await record(requestUrl, method, input, init);
          const path = requestUrl.pathname;
          if (path === "/api/public/bootstrap") return response({
            has_users: true,
            issuer: location.origin,
            registration: {
              allow_password_registration: true,
              require_email_verification: false,
              require_phone_verification: false,
              allow_external_oidc_registration: false,
              require_invitation: false,
              first_user_direct_admin: true,
              default_user_active: true,
            },
            login: {
              brand_logo_url: "https://assets.mock.example/signet.svg",
              email_domains: ["mock.example"],
              quick_links: [{
                id: "mock-destination",
                label: "Mock destination",
                url: "https://destination.mock.example/",
                icon: "link",
                is_active: true,
              }],
            },
            default_locale: "zh-CN",
            supported_locales: ["zh-CN", "en-US"],
            external_oidc_providers: [{
              slug: "mock-identity",
              display_name: "Mock Identity",
              start_url: "/api/external/mock-identity/start",
              email_domains: [],
              allow_login: true,
              allow_registration: true,
            }],
            ldap_providers: [],
          });
          if (path === "/api/public/authorization-code/inspect" && method === "POST") {
            const payload = typeof init.body === "string" ? JSON.parse(init.body) : {};
            const mode = String(payload.authorization_code || "").trim().toUpperCase();
            if (mode === "REG-MOCK") return response({
              mode: "registration",
              email_requirement: "must_match_code",
            });
            if (mode === "TRIAL-MOCK") return response({
              mode: "trial_enrollment",
              email_requirement: "new_identity",
            });
            if (mode === "LOGIN-MOCK") return response({ mode: "sign_in_only" });
            return response({ mode: "unavailable" });
          }
          if (path === "/api/me") {
            const params = new URLSearchParams(location.search);
            if (params.get("smoke_temporary_admin") === "1") return response(temporaryAdmin);
            if (params.get("smoke_trial_admin") === "1") return response(trialAdmin);
            return response(params.get("smoke_admin") === "1" ? admin : null);
          }
          if (path === "/api/mfa/status") return response({ enabled: false, totp_enabled: false, recovery_codes_remaining: 0, recovery_codes_total: 0 });
          if (path === "/api/passkeys") return response([]);
          if (path === "/api/me/consents") return response([]);
          if (path === "/api/me/sessions") return response([]);
          if (path === "/api/admin/overview") return response({ users: 3, active_users: 3, clients: 2, active_clients: 2, issuer: location.origin, database_kind: "mock" });
          if (path === "/api/admin/clients") return response(clients);
          if (path === "/api/admin/organization-options") return response(organizationOptions);
          if (path === "/api/admin/users" && method === "GET") return response(managedUsers);
          if (path === "/api/admin/users/import-csv" && method === "POST") {
            const rawCsv = typeof init.body === "string" ? init.body : "";
            const dryRun = requestUrl.searchParams.get("dry_run") !== "false";
            const invalid = rawCsv.includes("invalid@example.com");
            const rows = invalid
              ? [
                { row: 2, email: "valid@example.com", username: "valid", outcome: dryRun ? "would_create" : "not_committed" },
                { row: 3, email: "invalid@example.com", username: "invalid", outcome: "invalid", error: "mock invalid row" },
              ]
              : [
                { row: 2, email: "alex@example.com", username: "alex", outcome: dryRun ? "would_create" : "created", user_id: dryRun ? null : "imported-alex" },
              ];
            const result = {
              dry_run: dryRun,
              atomic: true,
              committed: !dryRun && !invalid,
              summary: {
                total: rows.length,
                created: !dryRun && !invalid ? 1 : 0,
                would_create: dryRun && !invalid ? 1 : dryRun && invalid ? 1 : 0,
                invalid: invalid ? 1 : 0,
              },
              rows,
            };
            return response(result, invalid ? 422 : 200);
          }
          if (path === "/api/admin/authorization-codes") return response([
            {
              id: "code-registration",
              can_reveal: true,
              code_prefix: "REG-MOCK",
              code_type: "registration",
              login_code_level: "account_recovery",
              allowed_client_ids: [],
              description: "Mock registration code",
              authorized_email: "new@mock.example",
              authorized_username: "new-user",
              authorized_display_name: "New User",
              expires_at: null,
              max_uses: 1,
              uses_count: 0,
              is_active: true,
              created_by: admin.id,
              created_at: now,
              updated_at: now,
              redemptions: [],
            },
            {
              id: "code-recovery",
              can_reveal: true,
              code_prefix: "REC-MOCK",
              code_type: "login",
              login_code_level: "account_recovery",
              allowed_client_ids: [],
              description: "Mock recovery code",
              authorized_email: null,
              authorized_username: "alice",
              authorized_display_name: "Alice",
              expires_at: null,
              max_uses: 1,
              uses_count: 0,
              is_active: true,
              created_by: admin.id,
              created_at: now,
              updated_at: now,
              redemptions: [],
            },
            {
              id: "code-universal",
              can_reveal: true,
              code_prefix: "ADM-MOCK",
              code_type: "login",
              login_code_level: "admin_universal",
              allowed_client_ids: ["app-one", "app-two"],
              description: "Mock universal code",
              authorized_email: null,
              authorized_username: null,
              authorized_display_name: null,
              expires_at: now + 600,
              max_uses: 2,
              uses_count: 0,
              is_active: true,
              created_by: admin.id,
              created_at: now,
              updated_at: now,
              redemptions: [],
            },
            {
              id: "code-trial",
              can_reveal: true,
              code_prefix: "TRY-MOCK",
              code_type: "login",
              login_code_level: "trial_enrollment",
              allowed_client_ids: ["app-one"],
              organization_id: "org-club",
              organization_role: "member",
              description: "Mock trial enrollment code",
              authorized_email: null,
              authorized_username: null,
              authorized_display_name: null,
              expires_at: now + 600,
              max_uses: 5,
              uses_count: 0,
              is_active: true,
              created_by: admin.id,
              created_at: now,
              updated_at: now,
              redemptions: [],
            },
          ]);
          if (path === "/api/browser-accounts/csrf") return response({ csrf_token: "mock-browser-csrf" });
          if (path === "/api/browser-accounts" && method === "GET") {
            const returnTo = requestUrl.searchParams.get("return_to") || "";
            const isSsoInteraction = returnTo.includes("interaction_request=");
            return response({
              accounts,
              client_name: isSsoInteraction ? "Mock Target App" : null,
              client_logo_uri: isSsoInteraction ? "https://assets.mock.example/target.svg" : null,
              login_hint: isSsoInteraction ? "alice@mock.example" : null,
              reauthentication_required: false,
            });
          }
          if (path === "/api/browser-accounts/select" && method === "POST") return response({ continue_to: "/smoke-account-selected" });
          if (path === "/api/browser-accounts/activate" && method === "POST") {
            const payload = typeof init.body === "string" ? JSON.parse(init.body) : {};
            accounts = accounts.map((account) => ({
              ...account,
              current: account.account_ref === payload.account_ref,
            }));
            return response({ continue_to: "/smoke-account-activated" });
          }
          if (path === "/api/browser-accounts/add/start" && method === "POST") {
            const payload = typeof init.body === "string" ? JSON.parse(init.body) : {};
            const returnTo = typeof payload.return_to === "string" ? payload.return_to : "/";
            return response({
              login_url: "/?auth=login&return_to=" + encodeURIComponent(returnTo) + "&force_login=1&account_flow=alf1.mock_add_account_flow_token_123456",
            });
          }
          if (path.startsWith("/api/browser-accounts/") && method === "DELETE") {
            const accountRef = decodeURIComponent(path.slice("/api/browser-accounts/".length));
            accounts = accounts.filter((account) => account.account_ref !== accountRef);
            return response({ ok: true });
          }
          if (path === "/api/browser-accounts/logout-all" && method === "POST") {
            accounts = [];
            return response({ ok: true });
          }
          if (path === "/api/csrf") return response({ csrf_token: "mock-session-csrf" });
          return response({ error: "unexpected_mock_request", message: method + " " + path }, 500);
        };
      })();`,
    });
  }

  const navigate = async (path) => {
    await cdp.send("Page.navigate", { url: new URL(path, appBase).href });
    await waitFor(
      async () => evaluate("document.readyState === 'complete' && Boolean(document.querySelector('#root > *'))"),
      `page render for ${path}`,
    );
  };

  const clickText = async (text) => {
    const clicked = await evaluate(`(() => {
      const target = [...document.querySelectorAll('button, a')]
        .find((element) => element.textContent.trim() === ${JSON.stringify(text)});
      if (!target) return false;
      target.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`Could not find clickable text: ${text}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  };

  const setEmail = async (value) => {
    const changed = await evaluate(`(() => {
      const input = document.querySelector('input[type=email]');
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    if (!changed) throw new Error("Email input was not found");
  };

  const inputByLabel = async (label, value) => {
    const changed = await evaluate(`(() => {
      const label = [...document.querySelectorAll('label')]
        .find((element) => element.textContent.trim() === ${JSON.stringify(label)});
      const input = label?.nextElementSibling;
      if (!(input instanceof HTMLInputElement)) return false;
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    if (!changed) throw new Error(`Input was not found for label: ${label}`);
  };

  const selectByLabel = async (label, value) => {
    const changed = await evaluate(`(() => {
      const label = [...document.querySelectorAll('label')]
        .find((element) => element.textContent.trim() === ${JSON.stringify(label)});
      const select = label?.nextElementSibling;
      if (!(select instanceof HTMLSelectElement)) return false;
      select.value = ${JSON.stringify(value)};
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return select.value === ${JSON.stringify(value)};
    })()`);
    if (!changed) throw new Error(`Select was not found for label: ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  };

  const clickFormButton = async (text) => {
    const clicked = await evaluate(`(() => {
      const target = [...document.querySelectorAll('form button')]
        .find((element) => element.textContent.trim() === ${JSON.stringify(text)});
      if (!target) return false;
      target.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`Could not find form button: ${text}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  };

  const cookieHeader = async () => {
    const { cookies } = await cdp.send("Network.getCookies", { urls: [appBase] });
    return cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
  };

  let csrfToken = null;
  const api = async (path, options = {}) => {
    const sessionCookie = await cookieHeader();
    const method = (options.method ?? "GET").toUpperCase();
    const protectedWrite = ["POST", "PUT", "PATCH", "DELETE"].includes(method)
      && (
        path.startsWith("/api/admin/")
        || path === "/api/logout"
        || path.startsWith("/api/me/")
        || path.startsWith("/api/mfa/")
        || path === "/api/passkeys/registration/start"
        || path === "/api/passkeys/registration/finish"
        || (method === "DELETE" && path.startsWith("/api/passkeys/"))
      );
    if (protectedWrite && !csrfToken) {
      const csrfResponse = await fetch(new URL("/api/csrf", appBase), {
        headers: {
          cookie: sessionCookie,
          origin: new URL(appBase).origin,
        },
      });
      if (!csrfResponse.ok) {
        throw new Error(`/api/csrf failed: ${csrfResponse.status} ${await csrfResponse.text()}`);
      }
      csrfToken = (await csrfResponse.json()).csrf_token;
    }
    const response = await fetch(new URL(path, appBase), {
      ...options,
      headers: {
        ...(options.body ? { "content-type": "application/json" } : {}),
        ...(sessionCookie ? { cookie: sessionCookie } : {}),
        origin: new URL(appBase).origin,
        ...(protectedWrite ? { "x-csrf-token": csrfToken } : {}),
        ...(options.headers ?? {}),
      },
    });
    if (!response.ok) throw new Error(`${path} failed: ${response.status} ${await response.text()}`);
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  };

  const selectUserFilter = async (value) => {
    const changed = await evaluate(`(() => {
      const select = document.querySelector('.filter-control select');
      if (!(select instanceof HTMLSelectElement)) return false;
      select.value = ${JSON.stringify(value)};
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`);
    if (!changed) throw new Error(`Could not set user filter: ${value}`);
  };

  const setPageSearch = async (value) => {
    const changed = await evaluate(`(() => {
      const input = document.querySelector('.search-control input[type=search]');
      if (!(input instanceof HTMLInputElement)) return false;
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    if (!changed) throw new Error("Current-page search input was not found");
  };

  const userRows = async () => evaluate(`(() => [...document.querySelectorAll('tbody tr')].map((row) => ({
    text: row.innerText,
    buttons: [...row.querySelectorAll('button')].map((button) => button.textContent.trim()),
  })))()`);

  const clickUserRowButton = async (email, text) => {
    const clicked = await evaluate(`(() => {
      const row = [...document.querySelectorAll('tbody tr')]
        .find((candidate) => candidate.innerText.includes(${JSON.stringify(email)}));
      const button = row && [...row.querySelectorAll('button')]
        .find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)});
      if (!button) return false;
      button.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`Could not click ${text} for ${email}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  };

  const screenshot = async (name, width, height) => {
    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width,
      height,
      deviceScaleFactor: 1,
      mobile: width < 700,
    });
    await waitFor(
      async () => evaluate(`window.innerWidth === ${width} && document.fonts.status === 'loaded'`),
      `responsive layout for ${width}x${height}`,
    );
    await new Promise((resolve) => setTimeout(resolve, 600));
    const result = await cdp.send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: false,
    });
    await fs.mkdir(screenshotDir, { recursive: true });
    await fs.writeFile(`${screenshotDir}/${name}.png`, Buffer.from(result.data, "base64"));
  };

  if (scenario === "auth-ui-mock") {
    const clearMockRequests = () => evaluate(`(() => {
      sessionStorage.setItem('__gptSsoSmokeRequests', '[]');
      window.__gptSsoSmokeRequests = [];
      return true;
    })()`);
    const mockRequests = () => evaluate(`JSON.parse(sessionStorage.getItem('__gptSsoSmokeRequests') || '[]')`);

    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: 1280,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await navigate("/?auth=login&smoke_reset=1&return_to=%2Foauth2%2Fauthorize%3Finteraction_request%3Dmock-login");
    await waitFor(async () => evaluate("document.body.innerText.includes('Signet')"), "mock login shell");
    if (!(await evaluate("document.body.innerText.includes('登录')"))) {
      await clickText("中文");
    }
    await waitFor(
      async () => evaluate(`document.querySelector('.account-switcher-add') instanceof HTMLButtonElement
        && document.querySelector('.unified-auth-header .auth-product-logo img') instanceof HTMLImageElement
        && document.querySelector('.unified-auth-header .auth-client-logo img') instanceof HTMLImageElement`),
      "unified login account strip",
    );
    const openInitialNewAccount = await evaluate(`(() => {
      const button = document.querySelector('.account-switcher-add');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!openInitialNewAccount) throw new Error("Unified login add-account icon was not available");
    await waitFor(async () => evaluate(`document.body.innerText.includes('登录或注册账户')
      && document.body.innerText.includes('密码登录')
      && document.querySelector('.auth-provider-button')?.textContent?.includes('Mock Identity')
      && document.body.innerText.includes('或继续使用')`), "password login method");
    await clickText("授权码登录");
    await waitFor(
      async () => evaluate(`(() => {
        const labels = [...document.querySelectorAll('label')].map((label) => label.textContent.trim());
        const email = [...document.querySelectorAll('label')].find((label) => label.textContent.trim() === '邮箱');
        const code = [...document.querySelectorAll('label')].find((label) => label.textContent.trim() === '授权码');
        return email?.nextElementSibling instanceof HTMLInputElement
          && email.nextElementSibling.type === 'email'
          && email.nextElementSibling.required
          && code?.nextElementSibling instanceof HTMLInputElement
          && code.nextElementSibling.type === 'password'
          && code.nextElementSibling.required
          && !labels.includes('用户名')
          && !labels.includes('登录授权码')
          && !labels.includes('使用体验入驻码创建新账号')
          && !labels.includes('新账号邮箱')
          && !labels.includes('新账号显示名')
          && !document.body.innerText.includes('体验入驻码只能创建新体验账号')
      })()`),
      "email-only authorization-code login form",
    );
    await clickText("密码登录");
    await waitFor(
      async () => evaluate("Boolean(document.querySelector('input[type=email]')) && document.body.innerText.includes('忘记了密码？')"),
      "password login form restored",
    );
    await clickText("重置密码");
    await waitFor(
      async () => evaluate(`(() => {
        const labels = [...document.querySelectorAll('label')].map((label) => label.textContent.trim());
        return labels.includes('重置验证码') && labels.includes('新密码');
      })()`),
      "password reset form from secondary action",
    );
    await clickText("已有账号？登录");
    await waitFor(async () => evaluate("document.body.innerText.includes('密码登录') && document.body.innerText.includes('还没有账号？')"), "return to login from reset");
    await clickText("创建账号");
    await waitFor(
      async () => evaluate(`(() => {
        const labels = [...document.querySelectorAll('label')].map((label) => label.textContent.trim());
        return labels.includes('注册授权码') && labels.includes('密码') && labels.includes('用户名');
      })()`),
      "full registration form with registration authorization code",
    );
    await clearMockRequests();
    await inputByLabel("注册授权码", "TRIAL-MOCK");
    await waitFor(
      async () => evaluate(`(() => {
        const labels = [...document.querySelectorAll('label')].map((label) => label.textContent.trim());
        return labels.includes('注册授权码')
          && labels.includes('邮箱')
          && !labels.includes('密码')
          && !labels.includes('用户名')
          && !labels.includes('手机号')
          && document.body.innerText.includes('体验入驻码只能使用尚未注册的邮箱');
      })()`),
      "server-classified trial enrollment form",
    );
    const inspectionRequests = await mockRequests();
    const trialInspection = inspectionRequests.find((request) =>
      request.path === "/api/public/authorization-code/inspect"
      && request.method === "POST"
      && request.body?.authorization_code === "TRIAL-MOCK"
    );
    if (!trialInspection) {
      throw new Error(`Authorization-code inspection request was not sent: ${JSON.stringify(inspectionRequests)}`);
    }
    await inputByLabel("注册授权码", "LOGIN-MOCK");
    await waitFor(
      async () => evaluate(`document.body.innerText.includes('此授权码仅用于登录') && document.body.innerText.includes('密码')`),
      "sign-in-only authorization-code guidance",
    );

    await navigate("/?smoke_admin=1&smoke_trial_form=1#/invitations");
    await waitFor(
      async () => evaluate("document.body.innerText.includes('授权码类型') && document.body.innerText.includes('Mock universal code')"),
      "mock authorization-code administration",
    );
    const mockedCodeRows = await evaluate("document.body.innerText");
    if (!mockedCodeRows.includes("账户恢复码") || !mockedCodeRows.includes("体验入驻码") || !mockedCodeRows.includes("管理员通用码") || !mockedCodeRows.includes("Mock Club") || !mockedCodeRows.includes("App One")) {
      throw new Error("Authorization-code level or application scope badges are missing");
    }
    await clickText("创建授权码");
    await waitFor(
      async () => evaluate("[...document.querySelectorAll('label')].some((label) => label.textContent.trim() === '授权码类型')"),
      "authorization-code create modal",
    );
    await selectByLabel("授权码类型", "login");
    await waitFor(async () => evaluate("document.body.innerText.includes('登录码权限级别')"), "login-code level selector");
    await selectByLabel("登录码权限级别", "admin_universal");
    await waitFor(
      async () => evaluate(`(() => {
        const group = document.querySelector('[role=group][aria-label="允许登录的应用"]');
        const maxUses = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '最大使用次数')?.nextElementSibling;
        return document.body.innerText.includes('高风险')
          && group?.querySelectorAll('input[type=checkbox]').length === 2
          && [...(group?.querySelectorAll('input[type=checkbox]') ?? [])].every((input) => !input.disabled)
          && maxUses instanceof HTMLInputElement
          && maxUses.min === '1';
      })()`),
      "administrator universal-code warning and application allowlist",
    );
    const editUniversal = await evaluate(`(() => {
      const row = [...document.querySelectorAll('tbody tr')]
        .find((candidate) => candidate.innerText.includes('Mock universal code'));
      const button = row && [...row.querySelectorAll('button')]
        .find((candidate) => candidate.textContent.trim() === '编辑');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!editUniversal) throw new Error("Mock universal authorization code was not editable");
    await waitFor(
      async () => evaluate(`(() => {
        const group = document.querySelector('[role=group][aria-label="允许登录的应用"]');
        const typeSelect = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '授权码类型')?.nextElementSibling;
        const levelSelect = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '登录码权限级别')?.nextElementSibling;
        const appInputs = [...(group?.querySelectorAll('input[type=checkbox]') ?? [])];
        return typeSelect instanceof HTMLSelectElement && typeSelect.disabled
          && levelSelect instanceof HTMLSelectElement && levelSelect.disabled
          && appInputs.length === 2
          && appInputs.every((input) => input.disabled && input.checked)
          && document.body.innerText.includes('允许应用仅能在创建时选择')
          && ![...document.querySelectorAll('label')].some((label) => label.textContent.includes('授权显示名'));
      })()`),
      "immutable administrator universal-code application scope",
    );
    const editRecovery = await evaluate(`(() => {
      const row = [...document.querySelectorAll('tbody tr')]
        .find((candidate) => candidate.innerText.includes('Mock recovery code'));
      const button = row && [...row.querySelectorAll('button')]
        .find((candidate) => candidate.textContent.trim() === '编辑');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!editRecovery) throw new Error("Mock recovery authorization code was not editable");
    await waitFor(
      async () => evaluate(`(() => {
        const username = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '用户名')?.nextElementSibling;
        return username instanceof HTMLInputElement
          && username.disabled
          && document.body.innerText.includes('绑定账号在创建后不可更改');
      })()`),
      "immutable account-recovery binding",
    );

    await navigate("/?smoke_admin=1&smoke_trial_form=2#/invitations");
    await waitFor(async () => evaluate("document.body.innerText.includes('Mock trial enrollment code')"), "authorization-code administration reset for trial enrollment");
    await clickText("创建授权码");
    await waitFor(
      async () => evaluate("[...document.querySelectorAll('label')].some((label) => label.textContent.trim() === '授权码类型')"),
      "trial-enrollment authorization-code create modal",
    );
    await selectByLabel("授权码类型", "login");
    await selectByLabel("登录码权限级别", "trial_enrollment");
    await waitFor(
      async () => evaluate(`(() => {
        const applications = document.querySelector('[role=group][aria-label="允许登录的应用"]');
        const organization = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '体验账号所属组织')?.nextElementSibling;
        const role = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '体验账号组织角色')?.nextElementSibling;
        const expires = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '过期时间')?.nextElementSibling;
        const maxUses = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '最大使用次数')?.nextElementSibling;
        return document.body.innerText.includes('只能创建新账号')
          && applications?.querySelectorAll('input[type=checkbox]').length === 2
          && organization instanceof HTMLSelectElement && !organization.disabled && organization.options.length === 2
          && role instanceof HTMLSelectElement && !role.disabled && role.options.length === 3
          && expires instanceof HTMLInputElement && expires.required
          && maxUses instanceof HTMLInputElement && maxUses.required;
      })()`),
      "trial-enrollment code scope and mandatory limits",
    );
    const editTrial = await evaluate(`(() => {
      const row = [...document.querySelectorAll('tbody tr')]
        .find((candidate) => candidate.innerText.includes('Mock trial enrollment code'));
      const button = row && [...row.querySelectorAll('button')]
        .find((candidate) => candidate.textContent.trim() === '编辑');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!editTrial) throw new Error("Mock trial enrollment code was not editable");
    await waitFor(
      async () => evaluate(`(() => {
        const applications = [...document.querySelectorAll('[role=group][aria-label="允许登录的应用"] input[type=checkbox]')];
        const organization = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '体验账号所属组织')?.nextElementSibling;
        const role = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '体验账号组织角色')?.nextElementSibling;
        return applications.length === 2 && applications.every((input) => input.disabled)
          && organization instanceof HTMLSelectElement && organization.disabled
          && role instanceof HTMLSelectElement && role.disabled
          && document.body.innerText.includes('组织、角色与允许应用仅能在创建时选择');
      })()`),
      "immutable trial-enrollment scope",
    );

    await navigate("/?smoke_admin=1#/users");
    await waitFor(async () => evaluate("document.body.innerText.includes('批量开通账户')"), "bulk provisioning toolbar");
    await clickText("批量开通账户");
    await waitFor(async () => evaluate("document.body.innerText.includes('先预演，再原子提交')"), "bulk provisioning modal");
    const filledCsv = await evaluate(`(() => {
      const label = [...document.querySelectorAll('label')]
        .find((candidate) => candidate.textContent.trim() === 'CSV 内容');
      const textarea = label?.nextElementSibling;
      if (!(textarea instanceof HTMLTextAreaElement)) return false;
      const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
      setter.call(textarea, 'email,username,display_name,organization_slug,organization_role,is_active\\nalex@example.com,alex,Alex Example,mock-club,member,true');
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    if (!filledCsv) throw new Error("Bulk provisioning CSV textarea was not available");
    await clearMockRequests();
    await clickFormButton("执行预演");
    await waitFor(async () => evaluate("document.body.innerText.includes('逐行导入结果') && document.body.innerText.includes('将创建')"), "bulk provisioning dry-run results");
    const bulkRequests = await mockRequests();
    const bulkRequest = bulkRequests.find((request) => request.path === "/api/admin/users/import-csv?dry_run=true" && request.method === "POST");
    if (!bulkRequest || bulkRequest.headers["content-type"] !== "text/csv" || !String(bulkRequest.body).includes("organization_role")) {
      throw new Error(`Bulk provisioning request contract is incorrect: ${JSON.stringify(bulkRequest)}`);
    }

    await navigate("/?smoke_admin=1#/users");
    await waitFor(
      async () => evaluate("document.querySelector('.account-switch-button') instanceof HTMLButtonElement"),
      "admin account switch button",
    );
    await clearMockRequests();
    const startedAccountSwitch = await evaluate(`(() => {
      const button = document.querySelector('.account-switch-button');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!startedAccountSwitch) throw new Error("Admin account switch button was not available");
    await waitFor(
      async () => evaluate(`(() => {
        const params = new URLSearchParams(location.search);
        return params.get('auth') === 'login'
          && params.get('force_login') === '1'
          && params.get('account_flow') === 'alf1.mock_add_account_flow_token_123456'
          && params.get('return_to') === '/?smoke_admin=1#/users'
          && document.querySelector('.unified-auth-forms')
          && document.querySelector('input[type=email]') instanceof HTMLInputElement;
      })()`),
      "account-flow-bound admin account login",
    );
    const accountSwitchRequests = await mockRequests();
    const accountSwitchStart = accountSwitchRequests.find((request) => request.path === "/api/browser-accounts/add/start" && request.method === "POST");
    if (
      !accountSwitchStart
      || accountSwitchStart.body?.return_to !== "/?smoke_admin=1#/users"
      || accountSwitchStart.headers["x-csrf-token"] !== "mock-browser-csrf"
    ) {
      throw new Error(`Admin account switch did not use the browser account flow: ${JSON.stringify(accountSwitchRequests)}`);
    }

    await navigate("/?smoke_temporary_admin=1#/users");
    await waitFor(
      async () => evaluate(`document.body.innerText.includes('临时恢复会话已登录') && location.hash === '#/account'`),
      "temporary recovery session restriction banner",
    );
    const temporarySessionUi = await evaluate(`(() => ({
      adminNavItems: document.querySelectorAll('nav button').length,
      canStartTotp: [...document.querySelectorAll('button')].some((button) => button.textContent.includes('设置 TOTP')),
      canRegisterPasskey: [...document.querySelectorAll('button')].some((button) => button.textContent.includes('注册 Passkey')),
      warning: document.querySelector('.temporary-session-banner')?.textContent || '',
    }))()`);
    if (temporarySessionUi.adminNavItems !== 0 || temporarySessionUi.canStartTotp || temporarySessionUi.canRegisterPasskey) {
      throw new Error(`Temporary administrator session exposed privileged UI: ${JSON.stringify(temporarySessionUi)}`);
    }
    if (!temporarySessionUi.warning.includes('15 分钟') || !temporarySessionUi.warning.includes('受限')) {
      throw new Error(`Temporary recovery warning is incomplete: ${JSON.stringify(temporarySessionUi)}`);
    }

    await navigate("/?smoke_trial_admin=1#/users");
    await waitFor(
      async () => evaluate(`document.body.innerText.includes('体验入驻账号已登录') && location.hash === '#/account'`),
      "trial enrollment session restriction banner",
    );
    const trialSessionUi = await evaluate(`(() => ({
      adminNavItems: document.querySelectorAll('nav button').length,
      canStartTotp: [...document.querySelectorAll('button')].some((button) => button.textContent.includes('设置 TOTP')),
      warning: document.querySelector('.temporary-session-banner')?.textContent || '',
    }))()`);
    if (trialSessionUi.adminNavItems !== 0 || trialSessionUi.canStartTotp || !trialSessionUi.warning.includes('受限')) {
      throw new Error(`Trial enrollment session exposed privileged UI: ${JSON.stringify(trialSessionUi)}`);
    }

    await navigate("/?smoke_temporary_admin=1&return_to=%2Fsmoke-temporary-oidc-continuation");
    await waitFor(
      async () => evaluate("location.pathname === '/smoke-temporary-oidc-continuation'"),
      "temporary recovery session OIDC continuation",
    );

    const chooserPath = "/?auth=select_account&return_to=%2Foauth2%2Fauthorize%3Finteraction_request%3Dmock-account-choice";
    await navigate(chooserPath);
    await waitFor(
      async () => evaluate(`(() => {
        const items = [...document.querySelectorAll('.account-switcher-item')];
        const names = items.map((item) => item.querySelector('.account-switcher-name')?.textContent?.trim());
        const selected = items.filter((item) => item.getAttribute('aria-current') === 'true');
        const selectedEmail = document.querySelector('.unified-auth-selection-email')?.textContent?.trim();
        const signIn = document.querySelector('.unified-auth-selection-actions .primary');
        return items.length === 3
          && names.join(',') === 'bob,trial,alice'
          && selected.length === 1
          && selected[0] === items[0]
          && selectedEmail === 'bob@mock.example'
          && signIn instanceof HTMLButtonElement
          && document.querySelector('.unified-auth-title h1')?.textContent?.trim() === '登录或注册账户'
          && document.querySelector('.quick-jump a[aria-label="Mock destination"]') instanceof HTMLAnchorElement
          && document.body.innerText.includes('Mock Target App')
          && !document.querySelector('.browser-account-card');
      })()`),
      "unified account page with most-recent login selected",
    );
    await screenshot("auth-ui-mock-selection-desktop", 1280, 900);
    const chooserAccessibility = await evaluate(`(() => ({
      nativeButtons: [...document.querySelectorAll('.account-switcher-item')].every((item) => item instanceof HTMLButtonElement),
      labelled: [...document.querySelectorAll('.account-switcher-item')].every((item) => Boolean(item.getAttribute('aria-label'))),
      semanticList: document.querySelector('.account-switcher-list') instanceof HTMLUListElement,
      listItems: document.querySelectorAll('.account-switcher-list > li').length,
      current: document.querySelectorAll('.account-switcher-item[aria-current=true]').length,
      add: document.querySelector('.account-switcher-add') instanceof HTMLButtonElement,
      names: [...document.querySelectorAll('.account-switcher-name')].map((item) => item.textContent.trim()),
    }))()`);
    if (
      !chooserAccessibility.nativeButtons
      || !chooserAccessibility.labelled
      || !chooserAccessibility.semanticList
      || chooserAccessibility.listItems !== 3
      || chooserAccessibility.current !== 1
      || !chooserAccessibility.add
      || chooserAccessibility.names.join(',') !== 'bob,trial,alice'
    ) {
      throw new Error(`Unified account strip accessibility or order is incomplete: ${JSON.stringify(chooserAccessibility)}`);
    }
    const initialAccountRequests = (await mockRequests()).filter((request) => request.path.startsWith("/api/browser-accounts"));

    await clearMockRequests();
    const pickedAlice = await evaluate(`(() => {
      const item = [...document.querySelectorAll('.account-switcher-item')]
        .find((candidate) => candidate.querySelector('.account-switcher-name')?.textContent?.trim() === 'alice');
      if (!(item instanceof HTMLButtonElement)) return false;
      item.click();
      return true;
    })()`);
    if (!pickedAlice) throw new Error("Account strip item was not selectable");
    await waitFor(
      async () => evaluate(`(() => {
        const selected = document.querySelector('.account-switcher-item[aria-current=true]');
        const name = selected?.querySelector('.account-switcher-name')?.textContent?.trim();
        const email = document.querySelector('.unified-auth-selection-email')?.textContent?.trim();
        const signIn = document.querySelector('.unified-auth-selection-actions .primary');
        return name === 'alice' && email === 'alice@mock.example' && signIn instanceof HTMLButtonElement;
      })()`),
      "selected account details and login button",
    );
    const pickRequests = await mockRequests();
    if (pickRequests.some((request) => request.method !== "GET" && request.path.startsWith("/api/browser-accounts"))) {
      throw new Error(`Choosing an account should not continue the authorization flow: ${JSON.stringify(pickRequests)}`);
    }

    await clearMockRequests();
    const confirmedSelection = await evaluate(`(() => {
      const button = document.querySelector('.unified-auth-selection-actions .primary');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!confirmedSelection) throw new Error("Selected account login button was not available");
    await waitFor(async () => {
      try { return await evaluate("location.pathname === '/smoke-account-selected'"); }
      catch { return false; }
    }, "account selection continuation");
    const selectionRequests = await mockRequests();
    const selection = selectionRequests.find((request) => request.path === "/api/browser-accounts/select" && request.method === "POST");
    if (!selection) throw new Error("Account selection request was not recorded");
    if (
      Object.keys(selection.body ?? {}).sort().join(",") !== "account_ref,return_to"
      || selection.body?.account_ref !== "account-alice"
      || JSON.stringify(selection.body).includes("client_id")
      || selection.headers["x-csrf-token"] !== "mock-browser-csrf"
    ) {
      throw new Error(`Account selection leaked or omitted fields: ${JSON.stringify(selection)}`);
    }

    await navigate(chooserPath);
    await waitFor(async () => evaluate("document.querySelectorAll('.account-switcher-item').length === 3"), "unified account page reload for add");
    await clearMockRequests();
    const openedAddAccount = await evaluate(`(() => {
      const button = document.querySelector('.account-switcher-add');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!openedAddAccount) throw new Error("Add-account icon was not available");
    await waitFor(
      async () => evaluate(`(() => {
        const params = new URLSearchParams(location.search);
        const email = [...document.querySelectorAll('label')]
          .find((label) => label.textContent.trim() === '邮箱')?.nextElementSibling;
        const methodTabs = [...document.querySelectorAll('.unified-auth-forms .segmented button')]
          .map((button) => button.textContent.trim());
        const secondaryActions = [...document.querySelectorAll('.auth-secondary-actions button')]
          .map((button) => button.textContent.trim());
        return location.pathname === '/'
          && params.get('auth') === 'select_account'
          && params.get('account_flow') === 'alf1.mock_add_account_flow_token_123456'
          && document.querySelectorAll('.account-switcher-item').length === 3
          && document.querySelector('.unified-auth-forms')
          && !document.querySelector('.unified-auth-selection')
          && email instanceof HTMLInputElement
          && email.type === 'email'
          && methodTabs.includes('密码登录')
          && methodTabs.includes('授权码登录')
          && secondaryActions.includes('创建账号')
          && secondaryActions.includes('重置密码')
          && document.querySelector('.auth-provider-button')?.textContent?.includes('Mock Identity');
      })()`),
      "inline add-account login and registration forms",
    );
    const addRequests = await mockRequests();
    const add = addRequests.find((request) => request.path === "/api/browser-accounts/add/start" && request.method === "POST");
    if (!add) throw new Error("Add-account request was not recorded");
    if (
      Object.keys(add.body ?? {}).join(",") !== "return_to"
      || JSON.stringify(add.body).includes("client_id")
      || add.headers["x-csrf-token"] !== "mock-browser-csrf"
    ) {
      throw new Error(`Add-account request leaked or omitted fields: ${JSON.stringify(add)}`);
    }
    await clickText("创建账号");
    await waitFor(
      async () => evaluate(`(() => {
        const labels = [...document.querySelectorAll('label')].map((label) => label.textContent.trim());
        return labels.includes('邮箱')
          && labels.includes('注册授权码')
          && document.querySelectorAll('.account-switcher-item').length === 3;
      })()`),
      "inline new-account registration form",
    );

    const inlineLoginPath = await evaluate("location.pathname + location.search");
    await navigate(inlineLoginPath);
    await waitFor(
      async () => evaluate(`(() => {
        const params = new URLSearchParams(location.search);
        return params.get('account_flow') === 'alf1.mock_add_account_flow_token_123456'
          && document.querySelectorAll('.account-switcher-item').length === 3
          && document.querySelector('.unified-auth-forms')
          && document.querySelector('input[type=email]') instanceof HTMLInputElement;
      })()`),
      "inline add-account form after refresh",
    );
    await screenshot("auth-ui-mock-form-desktop", 1280, 900);
    await screenshot("auth-ui-mock-form-mobile", 390, 844);
    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: 1280,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false,
    });

    const ordinaryLoginPath = "/?auth=login&return_to=%2Fsmoke-normal-login";
    await navigate(ordinaryLoginPath);
    await waitFor(
      async () => evaluate(`(() => {
        const items = [...document.querySelectorAll('.account-switcher-item')];
        const names = items.map((item) => item.querySelector('.account-switcher-name')?.textContent?.trim());
        const selected = document.querySelector('.account-switcher-item[aria-current=true]');
        const email = document.querySelector('.unified-auth-selection-email')?.textContent?.trim();
        return names.join(',') === 'bob,trial,alice'
          && selected === items[0]
          && email === 'bob@mock.example'
          && document.querySelector('.unified-auth-selection-actions .primary') instanceof HTMLButtonElement
          && document.querySelector('.quick-jump a[aria-label="Mock destination"]') instanceof HTMLAnchorElement
          && !document.querySelector('.unified-auth-header .auth-client-logo');
      })()`),
      "ordinary login page reusing the same account strip",
    );
    await clearMockRequests();
    const activated = await evaluate(`(() => {
      const button = document.querySelector('.unified-auth-selection-actions .primary');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!activated) throw new Error("Remembered-account login button was not available");
    await waitFor(async () => {
      try { return await evaluate("location.pathname === '/smoke-account-activated'"); }
      catch { return false; }
    }, "remembered account activation");
    const activationRequests = await mockRequests();
    const activation = activationRequests.find((request) => request.path === "/api/browser-accounts/activate" && request.method === "POST");
    if (!activation) throw new Error("Remembered-account activation request was not recorded");
    if (
      Object.keys(activation.body ?? {}).sort().join(",") !== "account_ref,return_to"
      || activation.body?.account_ref !== "account-bob"
      || JSON.stringify(activation.body).includes("client_id")
      || activation.headers["x-csrf-token"] !== "mock-browser-csrf"
    ) {
      throw new Error(`Remembered-account activation leaked or omitted fields: ${JSON.stringify(activation)}`);
    }

    const allBrowserAccountRequests = [
      ...initialAccountRequests,
      ...selectionRequests,
      ...addRequests,
      ...activationRequests,
    ];
    const endpointCoverage = {
      list: allBrowserAccountRequests.some((request) => request.method === "GET" && request.path.startsWith("/api/browser-accounts?")),
      csrf: allBrowserAccountRequests.some((request) => request.method === "GET" && request.path === "/api/browser-accounts/csrf"),
      select: Boolean(selection),
      activate: Boolean(activation),
      add: Boolean(add),
    };
    if (Object.values(endpointCoverage).some((covered) => !covered)) {
      throw new Error(`Browser-account mock endpoint coverage is incomplete: ${JSON.stringify(endpointCoverage)}`);
    }

    console.log(JSON.stringify({
      scenario,
      endpointCoverage,
      selectionBody: selection.body,
      activationBody: activation.body,
      addBody: add.body,
      status: "passed",
    }, null, 2));
    cdp.close();
    return;
  }

  if (scenario === "lifecycle") {
    await navigate("/?auth=register");
    await waitFor(async () => evaluate("document.body.innerText.includes('Signet')"), "lifecycle page shell");
    if (!(await evaluate("document.body.innerText.includes('首次启动')"))) {
      await clickText("中文");
    }
    await waitFor(async () => evaluate("document.body.innerText.includes('首次启动')"), "first administrator registration UI");
    await inputByLabel("邮箱", "admin@smoke.example");
    await inputByLabel("用户名", "smoke-admin");
    await inputByLabel("密码", "SmokePass123!");
    await clickFormButton("注册");
    await waitFor(
      async () => evaluate("document.body.innerText.includes('smoke-admin') && document.body.innerText.includes('用户')"),
      "administrator console",
    );
    const currentUser = await api("/api/me");
    if (!currentUser?.is_admin) throw new Error("First registered user is not an administrator");
    await screenshot("first-admin-desktop", 1280, 900);

    const csrfProbeEmail = "csrf-blocked@smoke.example";
    const csrfProbeBody = JSON.stringify({
      email: csrfProbeEmail,
      username: "csrf-blocked",
      display_name: "CSRF blocked",
      phone: null,
      password: "SmokePass123!",
      is_admin: false,
      is_active: true,
    });
    const sessionCookie = await cookieHeader();
    const issuedCsrf = await api("/api/csrf");
    csrfToken = issuedCsrf.csrf_token;
    const expectCsrfFailure = async (label, headers) => {
      const response = await fetch(new URL("/api/admin/users", appBase), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: sessionCookie,
          ...headers,
        },
        body: csrfProbeBody,
      });
      const body = await response.json().catch(() => null);
      if (response.status !== 403 || body?.error !== "csrf_failed") {
        throw new Error(`${label} was not rejected by CSRF protection: ${response.status} ${JSON.stringify(body)}`);
      }
    };
    await expectCsrfFailure("missing token", { origin: new URL(appBase).origin });
    await expectCsrfFailure("invalid token", {
      origin: new URL(appBase).origin,
      "x-csrf-token": "invalid-csrf-token",
    });
    await expectCsrfFailure("untrusted origin", {
      origin: "https://attacker.invalid",
      "x-csrf-token": csrfToken,
    });
    const usersAfterCsrfProbes = await api("/api/admin/users?status=all");
    if (usersAfterCsrfProbes.some((user) => user.email === csrfProbeEmail)) {
      throw new Error("A CSRF-rejected request still changed the database");
    }

    const protocolProbes = [
      ["OAuth token", "/oauth2/token", "application/x-www-form-urlencoded", "grant_type=client_credentials"],
      ["PAR", "/oauth2/par", "application/x-www-form-urlencoded", "client_id=missing"],
      ["DCR", "/connect/register", "application/json", "{}"],
      ["SCIM", "/scim/v2/Users", "application/json", "{}"],
      ["IAP", "/api/iap/forward-auth", "application/json", "{}"],
    ];
    for (const [label, path, contentType, body] of protocolProbes) {
      const response = await fetch(new URL(path, appBase), {
        method: "POST",
        headers: { "content-type": contentType },
        body,
      });
      const responseBody = await response.text();
      if (responseBody.includes("csrf_failed")) {
        throw new Error(`${label} protocol endpoint was incorrectly intercepted by CSRF protection`);
      }
    }

    const createUser = (email, username) => api("/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        email,
        username,
        display_name: username,
        phone: null,
        password: "SmokePass123!",
        is_admin: false,
        is_active: true,
      }),
    });
    const activeUser = await createUser("active@smoke.example", "active-user");
    const disabledUser = await createUser("disabled@smoke.example", "disabled-user");
    const archivedUser = await createUser("archived@smoke.example", "archived-user");
    await api(`/api/admin/users/${disabledUser.id}`, { method: "DELETE" });
    await api(`/api/admin/users/${archivedUser.id}`, { method: "DELETE" });
    await api(`/api/admin/users/${archivedUser.id}`, { method: "DELETE" });

    await navigate("/");
    await waitFor(async () => evaluate("document.body.innerText.includes('admin@smoke.example')"), "administrator page reload");
    await clickText("用户");
    await waitFor(async () => evaluate("document.querySelectorAll('tbody tr').length >= 3"), "live user list");
    const userTabHash = await evaluate("window.location.hash");
    if (userTabHash !== "#/users") throw new Error(`User tab deep link is incorrect: ${userTabHash}`);
    await setPageSearch(disabledUser.email);
    await waitFor(async () => {
      const rows = await userRows();
      return rows.length === 1 && rows[0].text.includes(disabledUser.email);
    }, "user page search");
    await setPageSearch("");
    await waitFor(async () => evaluate("document.querySelectorAll('tbody tr').length >= 3"), "cleared user page search");
    const liveRows = await userRows();
    const activeRow = liveRows.find((row) => row.text.includes(activeUser.email));
    const disabledRow = liveRows.find((row) => row.text.includes(disabledUser.email));
    if (!activeRow?.buttons.includes("禁用") || activeRow.buttons.includes("启用") || activeRow.buttons.includes("归档")) {
      throw new Error(`Active lifecycle actions are incorrect: ${JSON.stringify(activeRow)}`);
    }
    if (!disabledRow?.buttons.includes("启用") || !disabledRow.buttons.includes("归档") || disabledRow.buttons.includes("禁用")) {
      throw new Error(`Disabled lifecycle actions are incorrect: ${JSON.stringify(disabledRow)}`);
    }

    await selectUserFilter("all");
    await waitFor(async () => evaluate("document.body.innerText.includes('archived@smoke.example')"), "archived user in all filter");
    const allRows = await userRows();
    const archivedRow = allRows.find((row) => row.text.includes(archivedUser.email));
    if (!archivedRow?.buttons.includes("启用") || !archivedRow.buttons.includes("删除") || archivedRow.buttons.includes("编辑")) {
      throw new Error(`Archived lifecycle actions are incorrect: ${JSON.stringify(archivedRow)}`);
    }
    const visibleEmails = allRows
      .map((row) => row.text.match(/[\w.-]+@smoke\.example/)?.[0])
      .filter(Boolean);
    if (visibleEmails.at(-1) !== archivedUser.email) {
      throw new Error(`Archived user is not last in all-users filter: ${JSON.stringify(visibleEmails)}`);
    }
    await screenshot("users-lifecycle-desktop", 1280, 900);
    await screenshot("users-lifecycle-mobile", 390, 844);
    const mobileTableLayout = await evaluate(`(() => {
      const table = document.querySelector('.users-layout table');
      const head = table?.querySelector('thead');
      const body = table?.querySelector('tbody');
      const row = body?.querySelector('tr');
      const headRect = head?.getBoundingClientRect();
      return {
        table: table && getComputedStyle(table).display,
        head: head && getComputedStyle(head).display,
        headWidth: headRect?.width ?? null,
        headHeight: headRect?.height ?? null,
        body: body && getComputedStyle(body).display,
        row: row && getComputedStyle(row).display,
        viewportWidth: window.innerWidth,
        documentWidth: document.documentElement.scrollWidth,
      };
    })()`);
    if (
      mobileTableLayout.table !== "block"
      || mobileTableLayout.head === "none"
      || mobileTableLayout.headWidth > 1
      || mobileTableLayout.headHeight > 1
      || mobileTableLayout.body !== "grid"
      || mobileTableLayout.row !== "grid"
      || mobileTableLayout.documentWidth > mobileTableLayout.viewportWidth
    ) {
      throw new Error(`Mobile user table layout regressed: ${JSON.stringify(mobileTableLayout)}`);
    }
    const closedNavigation = await evaluate(`(() => {
      const sidebar = document.querySelector('#admin-navigation');
      const focusable = [...(sidebar?.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])') ?? [])];
      const previousFocus = document.activeElement;
      focusable[0]?.focus();
      const acceptedFocus = document.activeElement === focusable[0];
      if (previousFocus instanceof HTMLElement) previousFocus.focus();
      return {
        visibility: sidebar && getComputedStyle(sidebar).visibility,
        acceptedFocus,
        visibleFocusable: focusable.filter((element) => {
          const style = getComputedStyle(element);
          return style.visibility !== 'hidden' && style.display !== 'none';
        }).length,
      };
    })()`);
    if (closedNavigation.visibility !== "hidden" || closedNavigation.acceptedFocus || closedNavigation.visibleFocusable !== 0) {
      throw new Error(`Closed mobile navigation is still focusable: ${JSON.stringify(closedNavigation)}`);
    }
    const openedNavigation = await evaluate(`(() => {
      const button = document.querySelector('.mobile-menu-button');
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (!openedNavigation) throw new Error("Mobile navigation trigger was not found");
    await waitFor(
      async () => evaluate("document.querySelector('#admin-navigation')?.classList.contains('sidebar-open') && document.querySelector('#admin-navigation')?.contains(document.activeElement)"),
      "mobile navigation focus",
    );
    await evaluate("document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))");
    await waitFor(
      async () => evaluate("!document.querySelector('#admin-navigation')?.classList.contains('sidebar-open') && document.activeElement?.classList.contains('mobile-menu-button')"),
      "mobile navigation close and focus restore",
    );

    await clickUserRowButton(disabledUser.email, "启用");
    await waitFor(async () => {
      const rows = await userRows();
      return rows.find((row) => row.text.includes(disabledUser.email))?.buttons.includes("禁用");
    }, "disabled user enable action");
    await clickUserRowButton(activeUser.email, "禁用");
    await clickText("继续");
    await waitFor(async () => {
      const rows = await userRows();
      const row = rows.find((candidate) => candidate.text.includes(activeUser.email));
      return row?.buttons.includes("启用") && row?.buttons.includes("归档");
    }, "active user disable action");
    await clickUserRowButton(activeUser.email, "归档");
    await clickText("继续");
    await waitFor(async () => {
      const rows = await userRows();
      const row = rows.find((candidate) => candidate.text.includes(activeUser.email));
      return row?.buttons.includes("启用") && row?.buttons.includes("删除") && !row?.buttons.includes("编辑");
    }, "disabled user archive action");
    await clickUserRowButton(activeUser.email, "删除");
    await clickText("继续");
    await waitFor(async () => {
      const rows = await userRows();
      return !rows.some((row) => row.text.includes(activeUser.email));
    }, "archived user delete action");

    console.log(JSON.stringify({
      scenario,
      firstAdmin: currentUser.email,
      visibleEmails,
      status: "passed",
    }, null, 2));
    cdp.close();
    return;
  }

  await navigate("/?auth=login&return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Dopenai&login_hint=employee%40outside.example");
  await waitFor(async () => evaluate("document.body.innerText.includes('Signet')"), "public auth page shell");
  if (!(await evaluate("document.body.innerText.includes('登录')"))) {
    await clickText("中文");
  }
  await waitFor(async () => evaluate("document.body.innerText.includes('登录')"), "Chinese login UI");
  await setEmail("employee@outside.example");
  await clickText("创建账号");
  const registerEmail = await evaluate("document.querySelector('input[type=email]')?.value");
  if (registerEmail !== "employee@outside.example") {
    throw new Error(`Email was not preserved on register switch: ${registerEmail}`);
  }
  const hasAuthorizationCode = await evaluate("document.body.innerText.includes('授权码')");
  if (!hasAuthorizationCode) throw new Error("Registration page does not contain authorization code input");
  await clickText("EN");
  await waitFor(async () => evaluate("document.body.innerText.includes('Sign in')"), "English UI");
  const storedLocale = await evaluate("localStorage.getItem('gpt-sso-locale')");
  if (storedLocale !== "en-US") throw new Error(`Locale was not persisted: ${storedLocale}`);
  const quickLinks = await evaluate(`[...document.querySelectorAll('.quick-jump a')].map((link) => ({
    label: link.getAttribute('aria-label'),
    href: link.href,
    target: link.target,
  }))`);
  if (!quickLinks.some((link) => link.href.includes("chatgpt.com/auth/login?sso=true"))) {
    throw new Error("OpenAI quick link is missing");
  }
  if (quickLinks.some((link) => link.target !== "_blank")) {
    throw new Error("A quick link does not open outside the application");
  }
  await screenshot("auth-desktop", 1280, 900);
  await screenshot("auth-mobile", 390, 844);

  console.log(JSON.stringify({
    scenario: "public-auth",
    registerEmail,
    storedLocale,
    quickLinks,
    status: "passed",
  }, null, 2));
  cdp.close();
}

main().catch((error) => {
  console.error(error.stack ?? error.message);
  process.exit(1);
});
