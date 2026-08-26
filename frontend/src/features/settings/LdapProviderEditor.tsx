import type { FormEvent } from "react";

import {
  Check,
  Field,
  FormActions,
  Modal,
  SecretField,
  SelectField,
  SettingsSection
} from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { OrganizationOption } from "../../types";

export type LdapProviderForm = {
  id: string;
  slug: string;
  display_name: string;
  organization_id: string;
  url: string;
  starttls: boolean;
  bind_dn: string;
  bind_password: string;
  clear_bind_password: boolean;
  base_dn: string;
  user_filter: string;
  user_id_attribute: string;
  email_attribute: string;
  username_attribute: string;
  display_name_attribute: string;
  phone_attribute: string;
  is_active: boolean;
  allow_login: boolean;
  allow_registration: boolean;
};

export type LdapProviderEditorProps = {
  form: LdapProviderForm;
  organizationOptions: OrganizationOption[];
  busy: boolean;
  error: string;
  dirty: boolean;
  translate: (key: TranslationKey) => string;
  onChange: (form: LdapProviderForm) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
  onClose: () => void;
};

export function LdapProviderEditor({
  form,
  organizationOptions,
  busy,
  error,
  dirty,
  translate: t,
  onChange,
  onSubmit,
  onClose
}: LdapProviderEditorProps) {
  function updateForm(patch: Partial<LdapProviderForm>) {
    onChange({ ...form, ...patch });
  }

  return (
    <Modal
      title={form.id ? t("updateLdapProvider") : t("createLdapProvider")}
      closeLabel={t("close")}
      error={error}
      dismissible={!busy}
      onClose={onClose}
      wide
    >
      <form className="panel" onSubmit={onSubmit}>
        <SettingsSection title={t("providerBasics")} description={t("providerBasicsHint")} collapsible={false}>
          <Field label={t("slug")} value={form.slug} onChange={(value) => updateForm({ slug: value })} />
          <Field label={t("displayName")} value={form.display_name} onChange={(value) => updateForm({ display_name: value })} />
          <SelectField label={t("clientOrganization")} value={form.organization_id} onChange={(value) => updateForm({ organization_id: value })}>
            <option value="">{t("noOrganization")}</option>
            {organizationOptions.map((organization) => (
              <option key={organization.id} value={organization.id}>
                {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
              </option>
            ))}
          </SelectField>
        </SettingsSection>
        <SettingsSection title={t("directoryConnection")} description={t("directoryConnectionHint")}>
          <Field label={t("ldapUrl")} value={form.url} onChange={(value) => updateForm({ url: value })} />
          <Check label={t("startTls")} checked={form.starttls} onChange={(value) => updateForm({ starttls: value })} />
          <Field label={t("bindDn")} value={form.bind_dn} onChange={(value) => updateForm({ bind_dn: value })} />
          <SecretField
            label={t("bindPassword")}
            value={form.bind_password}
            onChange={(value) => updateForm({ bind_password: value })}
            revealLabel={t("revealSecret")}
            hideLabel={t("hideSecret")}
          />
          {form.id && (
            <Check label={t("clearBindPassword")} checked={form.clear_bind_password} onChange={(value) => updateForm({ clear_bind_password: value })} />
          )}
          <Field label={t("baseDn")} value={form.base_dn} onChange={(value) => updateForm({ base_dn: value })} />
          <Field label={t("ldapUserFilter")} value={form.user_filter} onChange={(value) => updateForm({ user_filter: value })} textarea />
        </SettingsSection>
        <SettingsSection title={t("directoryMapping")} description={t("directoryMappingHint")}>
          <div className="form-grid-2">
            <Field label={t("userIdAttribute")} value={form.user_id_attribute} onChange={(value) => updateForm({ user_id_attribute: value })} />
            <Field label={t("emailAttribute")} value={form.email_attribute} onChange={(value) => updateForm({ email_attribute: value })} />
            <Field label={t("usernameAttribute")} value={form.username_attribute} onChange={(value) => updateForm({ username_attribute: value })} />
            <Field label={t("displayNameAttribute")} value={form.display_name_attribute} onChange={(value) => updateForm({ display_name_attribute: value })} />
            <Field label={t("phoneAttribute")} value={form.phone_attribute} onChange={(value) => updateForm({ phone_attribute: value })} />
          </div>
        </SettingsSection>
        <SettingsSection title={t("providerAccess")} description={t("providerAccessHint")}>
          <Check label={t("active")} checked={form.is_active} onChange={(value) => updateForm({ is_active: value })} />
          <Check label={t("allowLogin")} checked={form.allow_login} onChange={(value) => updateForm({ allow_login: value })} />
          <Check label={t("allowRegistration")} checked={form.allow_registration} onChange={(value) => updateForm({ allow_registration: value })} />
        </SettingsSection>
        <FormActions
          submitLabel={t("save")}
          cancelLabel={t("cancel")}
          onCancel={onClose}
          busy={busy}
          dirty={dirty}
          statusLabel={dirty ? t("unsavedChanges") : undefined}
          savingLabel={t("saving")}
        />
      </form>
    </Modal>
  );
}
