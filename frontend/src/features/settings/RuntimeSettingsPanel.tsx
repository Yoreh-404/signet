import type { FormEvent } from "react";

import { Check, Field, FormActions, SettingsSection } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { RuntimeSettings } from "../../types";

export type RuntimeSettingsPanelProps = {
  value: RuntimeSettings;
  busy: boolean;
  dirty: boolean;
  translate: (key: TranslationKey) => string;
  onChange: (value: RuntimeSettings) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
};

export function RuntimeSettingsPanel({
  value,
  busy,
  dirty,
  translate: t,
  onChange,
  onSubmit
}: RuntimeSettingsPanelProps) {
  return (
    <form className="panel configuration-form" onSubmit={onSubmit}>
      <h3>{t("runtimeSettings")}</h3>
      <p className="muted">{t("runtimeSettingsHint")}</p>
      <SettingsSection title={t("runtimeSettings")} description={t("runtimeSettingsHint")} collapsible={false}>
        <Field
          label={t("publicBaseUrl")}
          type="url"
          value={value.public_base_url}
          onChange={(nextValue) => onChange({ ...value, public_base_url: nextValue })}
          required
        />
        <Field
          label={t("issuer")}
          type="url"
          value={value.issuer}
          onChange={(nextValue) => onChange({ ...value, issuer: nextValue })}
        />
        <Check
          label={t("trustProxyHeaders")}
          checked={value.trust_proxy_headers}
          onChange={(nextValue) => onChange({ ...value, trust_proxy_headers: nextValue })}
        />
        <div className="info">
          <strong>{t("effectivePublicBaseUrl")}:</strong> {value.effective_public_base_url}<br />
          <strong>{t("effectiveIssuer")}:</strong> {value.effective_issuer}
        </div>
      </SettingsSection>
      <FormActions
        submitLabel={t("save")}
        busy={busy}
        dirty={dirty}
        statusLabel={dirty ? t("unsavedChanges") : undefined}
        savingLabel={t("saving")}
      />
    </form>
  );
}
