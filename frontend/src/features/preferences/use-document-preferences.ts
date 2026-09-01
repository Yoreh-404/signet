import { useEffect } from "react";
import type { Locale, Theme } from "../../types";

export function useDocumentPreferences(locale: Locale, theme: Theme) {
  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("gpt-sso-theme", theme);
  }, [theme]);
}
