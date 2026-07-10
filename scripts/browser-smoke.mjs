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

  const api = async (path, options = {}) => {
    const sessionCookie = await cookieHeader();
    const response = await fetch(new URL(path, appBase), {
      ...options,
      headers: {
        ...(options.body ? { "content-type": "application/json" } : {}),
        ...(sessionCookie ? { cookie: sessionCookie } : {}),
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
    const result = await cdp.send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: false,
    });
    await fs.mkdir(screenshotDir, { recursive: true });
    await fs.writeFile(`${screenshotDir}/${name}.png`, Buffer.from(result.data, "base64"));
  };

  if (scenario === "lifecycle") {
    await navigate("/?auth=register");
    await waitFor(async () => evaluate("document.body.innerText.includes('GPT SSO')"), "lifecycle page shell");
    if (!(await evaluate("document.body.innerText.includes('首次启动')"))) {
      await clickText("中文");
    }
    await waitFor(async () => evaluate("document.body.innerText.includes('首次启动')"), "first administrator registration UI");
    await inputByLabel("邮箱", "admin@smoke.example");
    await inputByLabel("用户名", "smoke-admin");
    await inputByLabel("密码", "SmokePass123!");
    await clickFormButton("注册");
    await waitFor(
      async () => evaluate("document.body.innerText.includes('admin@smoke.example') && document.body.innerText.includes('用户')"),
      "administrator console",
    );
    const currentUser = await api("/api/me");
    if (!currentUser?.is_admin) throw new Error("First registered user is not an administrator");
    await screenshot("first-admin-desktop", 1280, 900);

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

    await clickUserRowButton(disabledUser.email, "启用");
    await waitFor(async () => {
      const rows = await userRows();
      return rows.find((row) => row.text.includes(disabledUser.email))?.buttons.includes("禁用");
    }, "disabled user enable action");
    await clickUserRowButton(activeUser.email, "禁用");
    await waitFor(async () => {
      const rows = await userRows();
      const row = rows.find((candidate) => candidate.text.includes(activeUser.email));
      return row?.buttons.includes("启用") && row?.buttons.includes("归档");
    }, "active user disable action");
    await clickUserRowButton(activeUser.email, "归档");
    await waitFor(async () => {
      const rows = await userRows();
      const row = rows.find((candidate) => candidate.text.includes(activeUser.email));
      return row?.buttons.includes("启用") && row?.buttons.includes("删除") && !row?.buttons.includes("编辑");
    }, "disabled user archive action");
    await clickUserRowButton(activeUser.email, "删除");
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
  await waitFor(async () => evaluate("document.body.innerText.includes('GPT SSO')"), "public auth page shell");
  if (!(await evaluate("document.body.innerText.includes('登录')"))) {
    await clickText("中文");
  }
  await waitFor(async () => evaluate("document.body.innerText.includes('登录')"), "Chinese login UI");
  await setEmail("employee@outside.example");
  await clickText("注册");
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
