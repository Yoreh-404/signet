import type { FormEvent } from "react";

import { Field, FormActions, Modal } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { emptyEnterpriseForm } from "../../lib/form-defaults";

type EnterpriseForm = typeof emptyEnterpriseForm;
type Translate = (key: TranslationKey) => string;

export type EnterpriseCreateModalProps = {
  form: EnterpriseForm;
  busy: boolean;
  error: string;
  dirty: boolean;
  translate: Translate;
  onChange: (form: EnterpriseForm) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
  onClose: () => void;
};

export function EnterpriseCreateModal({
  form,
  busy,
  error,
  dirty,
  translate,
  onChange,
  onSubmit,
  onClose
}: EnterpriseCreateModalProps) {
  const update = <K extends keyof EnterpriseForm>(key: K, value: EnterpriseForm[K]) => {
    onChange({ ...form, [key]: value });
  };

  return (
    <Modal
      title={translate("createEnterprise")}
      closeLabel={translate("close")}
      error={error}
      dismissible={!busy}
      onClose={onClose}
    >
      <form className="panel" onSubmit={onSubmit}>
        <p className="muted">{translate("createEnterpriseHint")}</p>
        <Field label={translate("enterpriseSlug")} value={form.slug} onChange={(value) => update("slug", value)} />
        <Field label={translate("enterpriseName")} value={form.name} onChange={(value) => update("name", value)} />
        <Field label={translate("enterpriseDescription")} value={form.description} onChange={(value) => update("description", value)} textarea />
        <Field label={translate("enterpriseEmailDomains")} value={form.allowed_email_domains} onChange={(value) => update("allowed_email_domains", value)} textarea />
        <FormActions
          submitLabel={translate("createEnterprise")}
          cancelLabel={translate("cancel")}
          onCancel={onClose}
          busy={busy}
          dirty={dirty}
          statusLabel={dirty ? translate("unsavedChanges") : undefined}
          savingLabel={translate("saving")}
        />
      </form>
    </Modal>
  );
}
