import { Trash2 } from "lucide-react";

import { Modal } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { PendingConfirmation } from "../../types";

type Translate = (key: TranslationKey) => string;

export type ConfirmationModalProps = {
  confirmation: PendingConfirmation;
  busy: boolean;
  error: string;
  translate: Translate;
  onClose: () => void;
  onConfirm: () => void | Promise<void>;
};

export function ConfirmationModal({
  confirmation,
  busy,
  error,
  translate,
  onClose,
  onConfirm
}: ConfirmationModalProps) {
  return (
    <Modal
      title={confirmation.title}
      closeLabel={translate("close")}
      error={error}
      dismissible={!busy}
      onClose={onClose}
    >
      <div className="confirm-dialog">
        <div className="confirm-icon"><Trash2 size={22} /></div>
        <p>{confirmation.description}</p>
        <div className="actions confirm-actions">
          <button type="button" onClick={onClose} disabled={busy}>{translate("cancel")}</button>
          <button type="button" className="danger-button" onClick={() => void onConfirm()} disabled={busy}>
            {translate("continue")}
          </button>
        </div>
      </div>
    </Modal>
  );
}
