import type { ApplicationSection, Tab, Theme } from "../types";

const ALL_TABS: Tab[] = [
  "account",
  "overview",
  "users",
  "applications",
  "clients",
  "iap",
  "organizations",
  "invitations",
  "billing",
  "registration",
  "providers",
  "portal",
  "security",
  "settings"
];

const APPLICATION_SECTIONS: ApplicationSection[] = [
  "overview",
  "protocols",
  "login_adapters",
  "directory_sync",
  "authorization",
  "billing"
];

export type NavigationState = {
  tab: Tab;
  applicationId: string | null;
  applicationSection: ApplicationSection | null;
  billingOrder: string | null;
};

export function initialNavigation(): NavigationState {
  const rawHash = window.location.hash.replace(/^#\/?/, "");
  const [rawTab, rawQuery = ""] = rawHash.split("?", 2);
  const tabValue = rawTab as Tab;
  const tab = ALL_TABS.includes(tabValue) ? tabValue : rawTab ? "account" : "overview";
  const params = new URLSearchParams(rawQuery);
  const rawSection = params.get("section") as ApplicationSection | null;
  return {
    tab,
    applicationId: tab === "applications" ? params.get("application")?.trim() || null : null,
    applicationSection: tab === "applications" && rawSection && APPLICATION_SECTIONS.includes(rawSection)
      ? rawSection
      : null,
    billingOrder: params.get("billing_order")?.trim() || null
  };
}

export function initialTab(): Tab {
  return initialNavigation().tab;
}

export function initialTheme(): Theme {
  const saved = localStorage.getItem("gpt-sso-theme");
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
