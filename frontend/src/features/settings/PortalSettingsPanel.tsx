import { Plus } from "lucide-react";
import { Check, Field, FormActions, SettingsSection, StatusBadge } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { LoginSettingsDraft, QuickLink } from "../../types";

export type QuickLinkForm = Pick<QuickLink, "id" | "label" | "url" | "is_active">;

export type PortalSettingsPanelProps = {
  state: {
    loginSettingsDraft: LoginSettingsDraft;
    quickLinkForm: QuickLinkForm;
  };
  actions: {
    updateLoginSettingsDraft: (draft: LoginSettingsDraft) => void;
    updateQuickLinkForm: (draft: QuickLinkForm) => void;
    persistLoginSettings: (draft: LoginSettingsDraft) => Promise<boolean>;
    saveQuickLinkDraft: () => Promise<void>;
    editQuickLink: (link: QuickLink) => void;
    deleteQuickLink: (id: string) => void;
    resetQuickLinkForm: () => void;
  };
  access: {
    busy: boolean;
    canManageSettings: boolean;
  };
  i18n: {
    t: (key: TranslationKey) => string;
  };
  dirty: {
    loginSettings: boolean;
    quickLinkForm: boolean;
  };
};

export function PortalSettingsPanel({
  state,
  actions,
  access,
  i18n,
  dirty
}: PortalSettingsPanelProps) {
  const { t } = i18n;
  const { loginSettingsDraft, quickLinkForm } = state;

  if (!access.canManageSettings) return null;

  return (
    <section className="split wide">
      <form
        className="panel configuration-form"
        onSubmit={(event) => {
          event.preventDefault();
          void actions.persistLoginSettings(loginSettingsDraft);
        }}
      >
        <h3>{t("loginSettings")}</h3>
        <p className="muted">{t("loginSettingsHint")}</p>
        <SettingsSection title={t("loginSettings")} description={t("loginSettingsHint")} collapsible={false}>
          <Field
            label={t("brandLogoUrl")}
            type="url"
            autoComplete="url"
            value={loginSettingsDraft.brand_logo_url}
            onChange={(value) => actions.updateLoginSettingsDraft({ ...loginSettingsDraft, brand_logo_url: value })}
          />
          <Field
            label={t("companyEmailDomains")}
            textarea
            value={loginSettingsDraft.email_domains}
            onChange={(value) => actions.updateLoginSettingsDraft({ ...loginSettingsDraft, email_domains: value })}
          />
        </SettingsSection>
        <FormActions
          submitLabel={t("save")}
          busy={access.busy}
          dirty={dirty.loginSettings}
          statusLabel={dirty.loginSettings ? t("unsavedChanges") : undefined}
          savingLabel={t("saving")}
        />
      </form>
      <form
        className="table-panel"
        onSubmit={(event) => {
          event.preventDefault();
          void actions.saveQuickLinkDraft();
        }}
      >
        <h3>
          {quickLinkForm.id ? t("updateQuickLink") : t("createQuickLink")}
          {dirty.quickLinkForm && <StatusBadge tone="warning">{t("unsavedChanges")}</StatusBadge>}
        </h3>
        <SettingsSection title={t("quickLinks")} description={t("loginSettingsHint")} collapsible={false}>
          <Field
            label={t("linkLabel")}
            value={quickLinkForm.label}
            onChange={(value) => actions.updateQuickLinkForm({ ...quickLinkForm, label: value })}
          />
          <Field
            label={t("linkUrl")}
            type="url"
            value={quickLinkForm.url}
            onChange={(value) => actions.updateQuickLinkForm({ ...quickLinkForm, url: value })}
          />
          <Check
            label={t("active")}
            checked={quickLinkForm.is_active}
            onChange={(value) => actions.updateQuickLinkForm({ ...quickLinkForm, is_active: value })}
          />
          <div className="actions">
            <button type="submit" disabled={access.busy}>
              <Plus size={14} />
              {quickLinkForm.id ? t("save") : t("create")}
            </button>
            {quickLinkForm.id && (
              <button type="button" onClick={actions.resetQuickLinkForm} disabled={access.busy}>{t("refresh")}</button>
            )}
          </div>
        </SettingsSection>
        <table>
          <thead><tr><th>{t("linkLabel")}</th><th>{t("linkUrl")}</th><th>{t("status")}</th><th></th></tr></thead>
          <tbody>
            {loginSettingsDraft.quick_links.map((link) => (
              <tr key={link.id}>
                <td>{link.label}</td>
                <td>{link.url}</td>
                <td>{link.is_active ? t("active") : t("disabled")}</td>
                <td className="actions">
                  <button type="button" onClick={() => actions.editQuickLink(link)} disabled={access.busy}>{t("edit")}</button>
                  <button type="button" onClick={() => actions.deleteQuickLink(link.id)} disabled={access.busy}>{t("delete")}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </form>
    </section>
  );
}
