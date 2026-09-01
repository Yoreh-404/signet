import { Globe2 } from "lucide-react";

import type { Locale } from "../../types";

type TopLanguageProps = {
  locale: Locale;
  supportedLocales: string[];
  switchLocale: (locale: Locale) => void;
  label: string;
  compact?: boolean;
};

export function TopLanguage({
  locale,
  supportedLocales,
  switchLocale,
  label,
  compact = false
}: TopLanguageProps) {
  return (
    <div className={compact ? "language-row compact-language" : "language-row"} role="group" aria-label={label}>
      <Globe2 size={16} />
      <span>{label}</span>
      {supportedLocales.includes("zh-CN") && <button type="button" className={locale === "zh-CN" ? "active" : ""} aria-pressed={locale === "zh-CN"} onClick={() => switchLocale("zh-CN")}>中文</button>}
      {supportedLocales.includes("en-US") && <button type="button" className={locale === "en-US" ? "active" : ""} aria-pressed={locale === "en-US"} onClick={() => switchLocale("en-US")}>EN</button>}
    </div>
  );
}
