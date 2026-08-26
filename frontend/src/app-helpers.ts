import type { BrowserAccount } from "./types";
import type { TranslationKey } from "./i18n";

export function browserAccountShortName(account: BrowserAccount): string {
  return account.user.username.trim() || account.user.email.trim();
}

export function inlineAccountLoginFlow(loginUrl: string, expectedReturnTo: string): string | null {
  try {
    const target = new URL(loginUrl, window.location.origin);
    if (
      target.origin !== window.location.origin
      || target.searchParams.get("auth") !== "login"
      || target.searchParams.get("force_login") !== "1"
      || target.searchParams.get("return_to") !== expectedReturnTo
    ) {
      return null;
    }
    const flow = target.searchParams.get("account_flow")?.trim() ?? "";
    return /^alf1\.[A-Za-z0-9_-]{20,}$/.test(flow) ? flow : null;
  } catch {
    return null;
  }
}

export function matchesHttpUrl(url: URL): boolean {
  return (url.protocol === "http:" || url.protocol === "https:") && Boolean(url.host);
}

export function formatDiagnosticValue(
  value: string | number | boolean | string[],
  translate: (key: TranslationKey) => string
): string {
  if (Array.isArray(value)) return value.length > 0 ? value.join(", ") : "-";
  if (typeof value === "boolean") return value ? translate("active") : translate("disabled");
  return String(value);
}
