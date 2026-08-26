import type { ChangeEvent, FormEvent } from "react";
import { FileUp } from "lucide-react";

import { Check, Field, Modal, StatusBadge } from "../../components/ui";
import type { BulkUserImportResult } from "../../types";
import {
  BULK_USER_IMPORT_TEMPLATE,
  bulkImportOutcomeTone
} from "./user-lifecycle";
import type { TranslationKey } from "../../i18n";

export type BulkUserImportFormState = {
  csv: string;
  fileName: string;
  dryRun: boolean;
  commitConfirmed: boolean;
  result: BulkUserImportResult | null;
};

export type BulkUserImportModalProps = {
  open: boolean;
  form: BulkUserImportFormState;
  busy: boolean;
  error: string;
  translate: (key: TranslationKey) => string;
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
  onFileChange: (event: ChangeEvent<HTMLInputElement>) => void | Promise<void>;
  onCsvChange: (value: string) => void;
  onUseTemplate: () => void;
  onDryRunChange: (value: boolean) => void;
  onCommitConfirmedChange: (value: boolean) => void;
  onReset: () => void;
};

export function BulkUserImportModal({
  open,
  form,
  busy,
  error,
  translate: t,
  onClose,
  onSubmit,
  onFileChange,
  onCsvChange,
  onUseTemplate,
  onDryRunChange,
  onCommitConfirmedChange,
  onReset
}: BulkUserImportModalProps) {
  if (!open) return null;

  return (
    <Modal
      title={t("bulkUserImport")}
      closeLabel={t("close")}
      error={error}
      dismissible={!busy}
      onClose={onClose}
      wide
    >
      <form className="panel bulk-import-panel" onSubmit={onSubmit}>
        <div className="info bulk-import-intro">
          <strong>{t("bulkImportAtomicTitle")}</strong>
          <p>{t("bulkImportAtomicDescription")}</p>
        </div>
        <div className="field">
          <label htmlFor="bulk-user-import-file">{t("bulkImportFile")}</label>
          <input
            id="bulk-user-import-file"
            type="file"
            accept=".csv,text/csv"
            onChange={(event) => void onFileChange(event)}
          />
          <small className="field-description">
            {form.fileName ? `${t("bulkImportSelectedFile")}: ${form.fileName}` : t("bulkImportFileHint")}
          </small>
        </div>
        <Field
          label={t("bulkImportCsv")}
          textarea
          value={form.csv}
          onChange={onCsvChange}
          description={t("bulkImportCsvHint")}
        />
        <div className="bulk-import-template">
          <code>{BULK_USER_IMPORT_TEMPLATE}</code>
          <button type="button" onClick={onUseTemplate}>
            <FileUp size={14} />
            {t("bulkImportUseTemplate")}
          </button>
        </div>
        <Check
          label={t("bulkImportDryRun")}
          checked={form.dryRun}
          onChange={onDryRunChange}
        />
        {form.dryRun ? (
          <div className="info">{t("bulkImportDryRunHint")}</div>
        ) : (
          <div className="error bulk-import-commit-warning" role="alert">
            <strong>{t("bulkImportCommitWarning")}</strong>
            <Check
              label={t("bulkImportCommitConfirmation")}
              checked={form.commitConfirmed}
              onChange={onCommitConfirmedChange}
            />
          </div>
        )}
        <div className="actions bulk-import-actions">
          <button type="button" onClick={onReset} disabled={busy}>{t("clear")}</button>
          <button className="primary compact-primary" type="submit" disabled={busy}>
            <FileUp size={16} />
            {form.dryRun ? t("bulkImportRunDryRun") : t("bulkImportCommit")}
          </button>
        </div>
        {form.result && (
          <section className="bulk-import-results" aria-live="polite" aria-label={t("bulkImportResults")}>
            <div className="bulk-import-result-header">
              <h4>{t("bulkImportResults")}</h4>
              <StatusBadge tone={form.result.committed ? "success" : form.result.summary.invalid > 0 ? "danger" : "info"}>
                {form.result.committed ? t("bulkImportCommitted") : form.result.dry_run ? t("bulkImportDryRunResult") : t("bulkImportNotCommitted")}
              </StatusBadge>
            </div>
            <div className="bulk-import-summary">
              <span><strong>{form.result.summary.total}</strong>{t("bulkImportTotal")}</span>
              <span><strong>{form.result.summary.created}</strong>{t("bulkImportCreated")}</span>
              <span><strong>{form.result.summary.would_create}</strong>{t("bulkImportWouldCreate")}</span>
              <span><strong>{form.result.summary.invalid}</strong>{t("bulkImportInvalid")}</span>
            </div>
            <div className="bulk-import-result-table">
              <table>
                <thead>
                  <tr>
                    <th>{t("bulkImportRow")}</th>
                    <th>{t("email")}</th>
                    <th>{t("username")}</th>
                    <th>{t("status")}</th>
                    <th>{t("bulkImportUserId")}</th>
                    <th>{t("bulkImportError")}</th>
                  </tr>
                </thead>
                <tbody>
                  {form.result.rows.map((row) => (
                    <tr key={`${row.row}-${row.email ?? ""}-${row.username ?? ""}`}>
                      <td>{row.row}</td>
                      <td>{row.email ?? "-"}</td>
                      <td>{row.username ?? "-"}</td>
                      <td>
                        <StatusBadge tone={bulkImportOutcomeTone(row.outcome)}>
                          {t(
                            row.outcome === "created"
                              ? "bulkImportOutcomeCreated"
                              : row.outcome === "would_create"
                                ? "bulkImportOutcomeWouldCreate"
                                : row.outcome === "not_committed"
                                  ? "bulkImportOutcomeNotCommitted"
                                  : "bulkImportOutcomeInvalid"
                          )}
                        </StatusBadge>
                      </td>
                      <td><code>{row.user_id ?? "-"}</code></td>
                      <td>{row.error ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </form>
    </Modal>
  );
}
