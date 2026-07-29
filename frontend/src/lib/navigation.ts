import type { Tab, Theme } from "../types";

const ALL_TABS: Tab[] = [
  "account",
  "overview",
  "users",
  "applications",
  "clients",
  "iap",
  "organizations",
  "invitations",
  "registration",
  "providers",
  "portal",
  "security",
  "settings"
];

export function initialTab(): Tab {
  const value = window.location.hash.replace(/^#\/?/, "") as Tab;
  if (!value) return "overview";
  return ALL_TABS.includes(value) ? value : "account";
}

export function initialTheme(): Theme {
  const saved = localStorage.getItem("gpt-sso-theme");
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
