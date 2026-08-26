import type { FormEvent } from "react";

import { Check, FormActions, SettingsSection } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { RegistrationSettings } from "../../types";

export type RegistrationSettingsPanelProps = {
  value: RegistrationSettings;
  busy: boolean;
  dirty: boolean;
  translate: (key: TranslationKey) => string;
  onChange: (value: RegistrationSettings) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
};

export function RegistrationSettingsPanel({
  value,
  busy,
  dirty,
  translate: t,
  onChange,
  onSubmit
}: RegistrationSettingsPanelProps) {
  return (
    <form className="panel narrow configuration-form" onSubmit={onSubmit}>
      <h3>{t("registrationSettings")}</h3>
      <p className="muted">{t("registrationPolicyHint")}</p>
      <SettingsSection title={t("registrationSettings")} description={t("registrationPolicyHint")} collapsible={false}>
        <Check label={t("passwordRegistration")} checked={value.allow_password_registration} onChange={(allow_password_registration) => onChange({ ...value, allow_password_registration })} />
        <Check label={t("requireEmailVerification")} checked={value.require_email_verification} onChange={(require_email_verification) => onChange({ ...value, require_email_verification })} />
        <Check label={t("requirePhoneVerification")} checked={value.require_phone_verification} onChange={(require_phone_verification) => onChange({ ...value, require_phone_verification })} />
        <Check label={t("allowExternalOidc")} checked={value.allow_external_oidc_registration} onChange={(allow_external_oidc_registration) => onChange({ ...value, allow_external_oidc_registration })} />
        <Check label={t("requireInvitation")} checked={value.require_invitation} onChange={(require_invitation) => onChange({ ...value, require_invitation })} />
      </SettingsSection>
      <SettingsSection title={t("firstUserAdmin")} description={t("firstUserAdminHint")}>
        <Check label={t("firstUserAdmin")} checked={value.first_user_direct_admin} onChange={(first_user_direct_admin) => onChange({ ...value, first_user_direct_admin })} />
        <Check label={t("defaultUserActive")} checked={value.default_user_active} onChange={(default_user_active) => onChange({ ...value, default_user_active })} />
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
