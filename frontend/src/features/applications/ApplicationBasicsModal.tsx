import { Globe2, Save } from "lucide-react";
import type { FormEvent } from "react";
import { Check, Field, Modal, SelectField } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { emptyApplicationForm } from "../../lib/form-defaults";

type Translate = (key: TranslationKey) => string;
type ApplicationForm = typeof emptyApplicationForm;

export type ApplicationBasicsModalProps = {
  form: ApplicationForm;
  busy: boolean;
  error: string;
  dirty: boolean;
  translate: Translate;
  onChange: (form: ApplicationForm) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onClose: () => void;
};

export function ApplicationBasicsModal({
  form,
  busy,
  error,
  dirty,
  translate,
  onChange,
  onSubmit,
  onClose
}: ApplicationBasicsModalProps) {
  const update = <K extends keyof ApplicationForm>(key: K, value: ApplicationForm[K]) => {
    onChange({ ...form, [key]: value });
  };
  return (
    <Modal
      title={form.id ? translate("updateApplication") : translate("createApplication")}
      closeLabel={translate("close")}
      error={error}
      dismissible={!busy}
      onClose={onClose}
    >
      <form className="panel application-basics-form" onSubmit={onSubmit}>
        <div className="application-form-intro">
          <span className="application-hero-avatar"><Globe2 size={22} /></span>
          <div><strong>{translate("websiteApplication")}</strong><p>{translate("websiteApplicationHint")}</p></div>
        </div>
        <Field label={translate("applicationSlug")} value={form.slug} onChange={(value) => update("slug", value)} required />
        <Field label={translate("applicationName")} value={form.name} onChange={(value) => update("name", value)} required />
        <Field label={translate("websiteUrl")} type="url" value={form.website_url} onChange={(value) => update("website_url", value)} />
        <Field label={translate("description")} value={form.description} onChange={(value) => update("description", value)} textarea />
        <SelectField label={translate("applicationAccountSelection")} value={form.account_selection_mode} onChange={(value) => update("account_selection_mode", value as ApplicationForm["account_selection_mode"])}>
          <option value="optional">{translate("accountSelectionOptional")}</option>
          <option value="required">{translate("accountSelectionRequired")}</option>
        </SelectField>
        <Check label={translate("active")} checked={form.is_active} onChange={(value) => update("is_active", value)} />
        <div className="form-actions">
          <span className="form-actions-status" aria-live="polite">{dirty ? translate("unsavedChanges") : ""}</span>
          <div className="actions"><button type="submit" disabled={busy}><Save size={14} />{form.id ? translate("save") : translate("create")}</button></div>
        </div>
      </form>
    </Modal>
  );
}
