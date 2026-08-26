import type { FormEvent } from "react";

import {
  Check,
  Field,
  FormActions,
  Modal
} from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { emptyUserForm } from "../../lib/form-defaults";

export type UserEditorForm = typeof emptyUserForm;

export type UserEditorModalProps = {
  form: UserEditorForm;
  busy: boolean;
  error: string;
  dirty: boolean;
  translate: (key: TranslationKey) => string;
  onChange: (form: UserEditorForm) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onClose: () => void;
};

export function UserEditorModal({
  form,
  busy,
  error,
  dirty,
  translate,
  onChange,
  onSubmit,
  onClose
}: UserEditorModalProps) {
  return (
    <Modal
      title={form.id ? translate("updateUser") : translate("createUser")}
      closeLabel={translate("close")}
      error={error}
      dismissible={!busy}
      onClose={onClose}
    >
      <form className="panel" onSubmit={onSubmit}>
        <Field label={translate("email")} value={form.email} onChange={(email) => onChange({ ...form, email })} />
        <Field label={translate("username")} value={form.username} onChange={(username) => onChange({ ...form, username })} />
        <Field label={translate("displayName")} value={form.display_name} onChange={(display_name) => onChange({ ...form, display_name })} />
        <Field label={translate("phone")} value={form.phone} onChange={(phone) => onChange({ ...form, phone })} />
        <Field label={translate("password")} type="password" value={form.password} onChange={(password) => onChange({ ...form, password })} />
        <Check label={translate("admin")} checked={form.is_admin} onChange={(is_admin) => onChange({ ...form, is_admin })} />
        {!form.id && <Check label={translate("active")} checked={form.is_active} onChange={(is_active) => onChange({ ...form, is_active })} />}
        <FormActions
          submitLabel={translate("save")}
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
