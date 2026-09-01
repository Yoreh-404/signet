import { Archive, Ban, KeyRound, RotateCcw, Trash2 } from "lucide-react";
import type { TranslationKey } from "../../i18n";
import type { BulkUserAction } from "./user-lifecycle";

type Translate = (key: TranslationKey) => string;

export type UserBulkActionsToolbarProps = {
  selectedCount: number;
  availableActions: readonly BulkUserAction[];
  busy: boolean;
  translate: Translate;
  onAction: (action: BulkUserAction) => void;
  onClear: () => void;
};

export function UserBulkActionsToolbar({
  selectedCount,
  availableActions,
  busy,
  translate,
  onAction,
  onClear
}: UserBulkActionsToolbarProps) {
  if (selectedCount === 0) return null;
  const can = (action: BulkUserAction) => availableActions.includes(action);
  return (
    <div className="bulk-user-actions" aria-live="polite">
      <strong>{translate("selectedUsers").replace("{count}", String(selectedCount))}</strong>
      <div className="actions">
        {can("enable") && <button type="button" onClick={() => onAction("enable")} disabled={busy}><RotateCcw size={14} />{translate("bulkEnable")}</button>}
        {can("disable") && <button type="button" onClick={() => onAction("disable")} disabled={busy}><Ban size={14} />{translate("bulkDisable")}</button>}
        {can("archive") && <button type="button" onClick={() => onAction("archive")} disabled={busy}><Archive size={14} />{translate("bulkArchive")}</button>}
        {can("delete") && <button type="button" onClick={() => onAction("delete")} disabled={busy}><Trash2 size={14} />{translate("bulkDelete")}</button>}
        {can("reset_mfa") && <button type="button" onClick={() => onAction("reset_mfa")} disabled={busy}><KeyRound size={14} />{translate("bulkResetMfa")}</button>}
        <button type="button" onClick={onClear} disabled={busy}>{translate("clearSelection")}</button>
      </div>
    </div>
  );
}
