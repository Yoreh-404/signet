import { SettingsSection } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { RuntimeSettings, SettingsSummary } from "../../types";

export type DiagnosticsPanelProps = {
  settings: SettingsSummary;
  runtimeSettings: RuntimeSettings;
  translate: (key: TranslationKey) => string;
};

function formatDiagnosticValue(
  value: string | number | boolean | string[],
  translate: (key: TranslationKey) => string
): string {
  if (Array.isArray(value)) return value.length > 0 ? value.join(", ") : "-";
  if (typeof value === "boolean") return value ? translate("active") : translate("disabled");
  return String(value);
}

export function DiagnosticsPanel({ settings, runtimeSettings, translate: t }: DiagnosticsPanelProps) {
  return (
    <div className="panel diagnostics-panel">
      <h3>{t("diagnostics")}</h3>
      <p className="muted">{t("diagnosticsHint")}</p>
      <SettingsSection title={t("diagnosticsRuntime")} collapsible={false}>
        <div className="settings-grid diagnostics-grid">
          <div className="setting-row"><span>{t("effectivePublicBaseUrl")}</span><strong>{runtimeSettings.effective_public_base_url}</strong></div>
          <div className="setting-row"><span>{t("effectiveIssuer")}</span><strong>{runtimeSettings.effective_issuer}</strong></div>
          <div className="setting-row"><span>{t("publicBaseUrl")}</span><strong>{settings.runtime_public_base_url}</strong></div>
          <div className="setting-row"><span>{t("trustProxyHeaders")}</span><strong>{formatDiagnosticValue(settings.runtime_trust_proxy_headers, t)}</strong></div>
        </div>
      </SettingsSection>
      <SettingsSection title={t("diagnosticsOidc")}>
        <div className="settings-grid diagnostics-grid">
          <div className="setting-row"><span>{t("issuer")}</span><strong>{settings.config_issuer}</strong></div>
          <div className="setting-row"><span>{t("scopes")}</span><strong>{formatDiagnosticValue(settings.supported_scopes, t)}</strong></div>
          <div className="setting-row"><span>{t("accessTokenTtl")}</span><strong>{settings.access_token_ttl_seconds}s</strong></div>
          <div className="setting-row"><span>{t("idTokenTtl")}</span><strong>{settings.id_token_ttl_seconds}s</strong></div>
          <div className="setting-row"><span>{t("refreshTokenTtl")}</span><strong>{settings.refresh_token_ttl_seconds}s</strong></div>
        </div>
      </SettingsSection>
      <SettingsSection title={t("diagnosticsStorage")}>
        <div className="settings-grid diagnostics-grid">
          <div className="setting-row"><span>{t("database")}</span><strong>{settings.database_kind}</strong></div>
          <div className="setting-row"><span>{t("databasePoolSize")}</span><strong>{settings.database_pool_size}</strong></div>
          <div className="setting-row"><span>{t("runMigrations")}</span><strong>{formatDiagnosticValue(settings.run_migrations, t)}</strong></div>
        </div>
      </SettingsSection>
      <SettingsSection title={t("diagnosticsSecurity")}>
        <div className="settings-grid diagnostics-grid">
          <div className="setting-row"><span>{t("cookieSecure")}</span><strong>{formatDiagnosticValue(settings.cookie_secure, t)}</strong></div>
          <div className="setting-row"><span>{t("cookieSameSite")}</span><strong>{settings.cookie_same_site}</strong></div>
          <div className="setting-row"><span>{t("corsAllowedOrigins")}</span><strong>{formatDiagnosticValue(settings.cors_allowed_origins, t)}</strong></div>
        </div>
      </SettingsSection>
    </div>
  );
}
