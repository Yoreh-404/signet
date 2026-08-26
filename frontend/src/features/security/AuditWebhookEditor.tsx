import type { FormEvent } from "react";

import { Check, Field, FormActions, ListField, SettingsSection, SecretField } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { emptyAuditWebhookForm } from "../../lib/form-defaults";

export type AuditWebhookForm = typeof emptyAuditWebhookForm;

export type AuditWebhookEditorProps = {
  form: AuditWebhookForm;
  busy: boolean;
  dirty: boolean;
  canManage: boolean;
  translate: (key: TranslationKey) => string;
  onChange: (value: AuditWebhookForm) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onCancel: () => void;
};

export function AuditWebhookEditor({
  form,
  busy,
  dirty,
  canManage,
  translate: t,
  onChange,
  onSubmit,
  onCancel
}: AuditWebhookEditorProps) {
  if (!canManage) return null;

  const update = (next: Partial<AuditWebhookForm>) => onChange({ ...form, ...next });

  return (
    <form className="panel security-webhook-form" onSubmit={onSubmit}>
      <h3>{form.id ? t("updateAuditWebhook") : t("createAuditWebhook")}</h3>
      <SettingsSection title={t("providerBasics")} description={t("auditWebhooks")} collapsible={false}>
        <Field label={t("webhookName")} value={form.name} onChange={(value) => update({ name: value })} />
        <Field label={t("webhookUrl")} type="url" value={form.url} onChange={(value) => update({ url: value })} />
        <SecretField
          label={t("webhookSecret")}
          value={form.secret}
          onChange={(value) => update({ secret: value, clear_secret: false })}
          description={form.id ? t("secretLeaveBlank") : undefined}
          revealLabel={t("revealSecret")}
          hideLabel={t("hideSecret")}
        />
        {form.id && (
          <Check
            label={t("clearWebhookSecret")}
            checked={form.clear_secret}
            onChange={(value) => update({ clear_secret: value, secret: value ? "" : form.secret })}
          />
        )}
      </SettingsSection>
      <SettingsSection title={t("webhookActions")} description={t("webhookActions")}>
        <ListField
          label={t("webhookActions")}
          value={form.actions}
          onChange={(value) => update({ actions: value })}
          addLabel={t("addItem")}
          removeLabel={t("removeItem")}
        />
        <Field
          label={t("webhookTimeout")}
          type="number"
          value={String(form.timeout_seconds)}
          onChange={(value) => update({ timeout_seconds: Number(value) })}
        />
        <Check label={t("active")} checked={form.is_active} onChange={(value) => update({ is_active: value })} />
      </SettingsSection>
      <FormActions
        submitLabel={form.id ? t("save") : t("create")}
        busy={busy}
        dirty={dirty}
        statusLabel={dirty ? t("unsavedChanges") : undefined}
        savingLabel={t("saving")}
        cancelLabel={form.id ? t("clear") : undefined}
        onCancel={form.id ? onCancel : undefined}
      />
    </form>
  );
}
