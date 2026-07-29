import type { TranslationKey } from "../i18n";
import type {
  AuthMode,
  ExternalProviderSummary,
  LogoutFrame,
  User
} from "../types";

export function deliverFrontchannelLogout(frames: LogoutFrame[] = []) {
  frames.forEach((frame) => {
    if (!frame.uri) return;
    const iframe = document.createElement("iframe");
    iframe.src = frame.uri;
    iframe.title = frame.client_id || "frontchannel-logout";
    iframe.style.display = "none";
    iframe.width = "0";
    iframe.height = "0";
    document.body.appendChild(iframe);
    window.setTimeout(() => iframe.remove(), 2500);
  });
}

export function normalizeDomain(value: string): string {
  return value.trim().replace(/^@+/, "").replace(/^\.+/, "").replace(/\.+$/, "").toLowerCase();
}

export function usableEmailDomain(value: string): string {
  const domain = normalizeDomain(value);
  if (!domain || domain.includes("@") || domain.includes("/") || domain.includes("\\") || /\s/.test(domain) || domain.split(".").some((part) => !part)) return "";
  return domain;
}

function emailDomain(value: string): string {
  const [, domain = ""] = value.trim().toLowerCase().split("@").slice(-2);
  return usableEmailDomain(domain);
}

function domainMatchesRule(domain: string, rule: string): boolean {
  const normalizedRule = usableEmailDomain(rule);
  return Boolean(normalizedRule && (domain === normalizedRule || domain.endsWith(`.${normalizedRule}`)));
}

export function findProviderForEmail(providers: ExternalProviderSummary[], email: string): ExternalProviderSummary | null {
  const domain = emailDomain(email);
  if (!domain) return null;
  let matched: { provider: ExternalProviderSummary; rule: string } | null = null;
  for (const provider of providers) {
    for (const rule of provider.email_domains) {
      const normalizedRule = usableEmailDomain(rule);
      if (!normalizedRule || !domainMatchesRule(domain, normalizedRule)) continue;
      if (!matched || normalizedRule.length > matched.rule.length) {
        matched = { provider, rule: normalizedRule };
      }
    }
  }
  return matched?.provider ?? null;
}

export function applyEmailDomain(email: string, domain: string): string {
  const suffix = usableEmailDomain(domain);
  if (!suffix) return email;
  const local = email.split("@")[0]?.trim() || randomLocalPart();
  return `${local}@${suffix}`;
}

export function randomLocalPart(): string {
  const time = Date.now().toString(36);
  const random = Math.random().toString(36).slice(2, 8);
  return `u${time}${random}`;
}

function currentLocalReturnTo(): string {
  const target = `${window.location.pathname}${window.location.search}${window.location.hash}` || "/";
  // The login UI itself is commonly reached as
  // `/?auth=login&return_to=/oauth2/authorize?...`. Preserve that inner
  // authorization request when handing control to an external IdP; otherwise
  // the server cannot determine which tenant application selected the IdP.
  const nestedReturnTo = localReturnTo(new URLSearchParams(window.location.search).get("return_to"));
  return nestedReturnTo ?? localReturnTo(target) ?? "/";
}

export function oidcStartUrl(
  startUrl: string,
  email: string,
  mode: "login" | "register",
  accountFlow?: string | null
): string {
  const separator = startUrl.includes("?") ? "&" : "?";
  const params = [`return_to=${encodeURIComponent(currentLocalReturnTo())}`, `mode=${mode}`];
  if (accountFlow) {
    params.push(`account_flow=${encodeURIComponent(accountFlow)}`);
  }
  const loginHint = normalizedAuthEmail(email);
  if (loginHint.includes("@")) {
    params.push(`login_hint=${encodeURIComponent(loginHint)}`);
  }
  return `${startUrl}${separator}${params.join("&")}`;
}

function localReturnTo(value: string | null): string | null {
  const target = value?.trim() ?? "";
  if (!target || target === "/" || !target.startsWith("/") || target.startsWith("//")) return null;
  if (target.includes("\\") || /[\r\n]/.test(target)) return null;
  return target;
}

function normalizedAuthEmail(value: string | null | undefined): string {
  return value?.trim().toLowerCase() ?? "";
}

export function loginHintRequiresAccountSwitch(user: User | null | undefined, loginHint: string): boolean {
  const hint = normalizedAuthEmail(loginHint);
  if (!user || !hint.includes("@")) return false;
  return normalizedAuthEmail(user.email) !== hint;
}

function loginHintFromReturnTo(returnTo: string | null): string {
  if (!returnTo?.startsWith("/oauth2/authorize?")) return "";
  const query = returnTo.slice("/oauth2/authorize?".length).split("#", 1)[0];
  return new URLSearchParams(query).get("login_hint")?.trim() ?? "";
}

type InitialAuthContext = {
  mode: AuthMode;
  isAuthPage: boolean;
  selectAccount: boolean;
  accountFlow: string | null;
  returnTo: string | null;
  loginHint: string;
  forceLogin: boolean;
  authError: string;
  authErrorCode: string;
  authErrorDetail: string;
};

export function initialAuthContext(): InitialAuthContext {
  const params = new URLSearchParams(window.location.search);
  const modeParam = params.get("auth");
  const isAuthPage = modeParam === "login"
    || modeParam === "register"
    || modeParam === "reset"
    || modeParam === "select_account";
  const selectAccount = modeParam === "select_account";
  const mode: AuthMode = modeParam === "register" || modeParam === "reset" ? modeParam : "login";
  const accountFlow = params.get("account_flow")?.trim() || null;
  const returnTo = localReturnTo(params.get("return_to"));
  const loginHint = params.get("login_hint")?.trim() || loginHintFromReturnTo(returnTo);
  const forceLogin = params.get("force_login") === "1";
  const authError = params.get("auth_error")?.trim() ?? "";
  const authErrorCode = params.get("auth_error_code")?.trim() ?? "";
  const authErrorDetail = params.get("auth_error_detail")?.trim() ?? "";
  return {
    mode,
    isAuthPage,
    selectAccount,
    accountFlow,
    returnTo,
    loginHint,
    forceLogin,
    authError,
    authErrorCode,
    authErrorDetail
  };
}

export function authContextError(
  context: InitialAuthContext,
  t: (key: TranslationKey) => string
): string {
  if (context.authError) return context.authError;
  if (context.authErrorCode === "company_email_required") {
    return context.authErrorDetail
      ? `${t("companyEmailRequired")}: ${context.authErrorDetail}`
      : t("companyEmailRequired");
  }
  return "";
}
