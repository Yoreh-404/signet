import type { FormEvent } from "react";
import { Plus, RefreshCw } from "lucide-react";

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
import { emptyProviderForm } from "../../lib/form-defaults";
import type {
  ExternalProviderTemplate,
  OrganizationOption
} from "../../types";

export type ExternalOidcProviderForm = typeof emptyProviderForm;

export type ExternalOidcProviderEditorProps = {
  providerForm: ExternalOidcProviderForm;
  templates: ExternalProviderTemplate[];
  organizationOptions: OrganizationOption[];
  canManagePlatformProviders: boolean;
  busy: boolean;
  error: string;
  dirty: boolean;
  translate: (key: TranslationKey) => string;
  providerTemplateId: string;
  onChange: (value: ExternalOidcProviderForm) => void;
  onTemplateChange: (value: string) => void;
  onApplyTemplate: () => void;
  onDiscover: () => void;
  onCancel: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  providerRedirectPath: (slug: string) => string;
};

export function ExternalOidcProviderEditor({
  providerForm,
  templates,
  organizationOptions,
  canManagePlatformProviders,
  busy,
  error,
  dirty,
  translate: t,
  providerTemplateId,
  onChange,
  onTemplateChange,
  onApplyTemplate,
  onDiscover,
  onCancel,
  onSubmit,
  providerRedirectPath
}: ExternalOidcProviderEditorProps) {
  const update = (next: Partial<ExternalOidcProviderForm>) => onChange({ ...providerForm, ...next });

  return (
    <Modal
      title={providerForm.id ? t("updateProvider") : t("createProvider")}
      closeLabel={t("close")}
      error={error}
      dismissible={!busy}
      onClose={onCancel}
      wide
    >
      <form className="panel" onSubmit={onSubmit}>
        <SettingsSection title={t("providerBasics")} description={t("providerBasicsHint")} collapsible={false}>
          {templates.length > 0 && (
            <>
              <SelectField label={t("providerTemplate")} value={providerTemplateId} onChange={onTemplateChange}>
                <option value="">-</option>
                {templates.map((template) => (
                  <option key={template.id} value={template.id}>{template.display_name}</option>
                ))}
              </SelectField>
              <div className="actions">
                <button type="button" onClick={onApplyTemplate} disabled={busy || !providerTemplateId}>
                  <Plus size={14} />
                  {t("applyTemplate")}
                </button>
              </div>
            </>
          )}
          <Field label={t("slug")} value={providerForm.slug} onChange={(value) => update({ slug: value, redirect_path: providerRedirectPath(value) })} />
          <Field label={t("displayName")} value={providerForm.display_name} onChange={(value) => update({ display_name: value })} />
          {canManagePlatformProviders && (
            <SelectField label={t("clientOrganization")} value={providerForm.organization_id} onChange={(value) => update({ organization_id: value })}>
              <option value="">{t("noOrganization")}</option>
              {organizationOptions.map((organization) => (
                <option key={organization.id} value={organization.id}>
                  {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                </option>
              ))}
            </SelectField>
          )}
        </SettingsSection>
        <SettingsSection title={t("providerConnection")} description={t("providerConnectionHint")}>
          <Field label={t("issuer")} type="url" value={providerForm.issuer} onChange={(value) => onChange({ ...providerForm, issuer: value })} />
          <div className="actions">
            <button type="button" onClick={onDiscover} disabled={busy || !providerForm.issuer.trim()}>
              <RefreshCw size={14} />
              {t("discoverProvider")}
            </button>
          </div>
          <Field label={t("clientId")} value={providerForm.client_id} onChange={(value) => update({ client_id: value })} />
          <SecretField
            label={t("clientSecret")}
            value={providerForm.client_secret}
            onChange={(value) => update({ client_secret: value, clear_client_secret: false })}
            description={providerForm.id ? t("secretLeaveBlank") : undefined}
            revealLabel={t("revealSecret")}
            hideLabel={t("hideSecret")}
          />
          {providerForm.id && (
            <Check
              label={t("clearClientSecret")}
              checked={providerForm.clear_client_secret}
              onChange={(value) => update({ clear_client_secret: value, client_secret: value ? "" : providerForm.client_secret })}
            />
          )}
          <div className="form-grid-2">
            <Field label={t("authorizationEndpoint")} type="url" value={providerForm.authorization_endpoint} onChange={(value) => update({ authorization_endpoint: value })} />
            <Field label={t("tokenEndpoint")} type="url" value={providerForm.token_endpoint} onChange={(value) => update({ token_endpoint: value })} />
            <Field label={t("userinfoEndpoint")} type="url" value={providerForm.userinfo_endpoint} onChange={(value) => update({ userinfo_endpoint: value })} />
            <Field label={t("redirectPath")} value={providerForm.redirect_path} onChange={(value) => update({ redirect_path: value })} />
          </div>
          <Field label={t("scopes")} value={providerForm.scopes} onChange={(value) => update({ scopes: value })} />
          <Field label={t("providerEmailDomains")} value={providerForm.email_domains} onChange={(value) => update({ email_domains: value })} textarea />
        </SettingsSection>
        <SettingsSection title={t("providerAccess")} description={t("providerAccessHint")}>
          <Check label={t("active")} checked={providerForm.is_active} onChange={(value) => update({ is_active: value })} />
          <Check label={t("allowLogin")} checked={providerForm.allow_login} onChange={(value) => update({ allow_login: value })} />
          <Check label={t("allowRegistration")} checked={providerForm.allow_registration} onChange={(value) => update({ allow_registration: value })} />
        </SettingsSection>
        <FormActions
          submitLabel={t("save")}
          cancelLabel={t("cancel")}
          onCancel={onCancel}
          busy={busy}
          dirty={dirty}
          statusLabel={dirty ? t("unsavedChanges") : undefined}
          savingLabel={t("saving")}
        />
      </form>
    </Modal>
  );
}
