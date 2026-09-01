import { useCallback } from "react";
import type { ChangeEvent, Dispatch, FormEvent, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import * as adminApi from "../../lib/api/admin";
import { ApiError } from "../../lib/api";
import { isBulkUserImportResult } from "../users/user-lifecycle";
import type { BulkUserImportResult } from "../../types";

type Options = {
  busy: boolean;
  csv: string;
  dryRun: boolean;
  commitConfirmed: boolean;
  setOpen: Dispatch<SetStateAction<boolean>>;
  setCsv: Dispatch<SetStateAction<string>>;
  setFileName: Dispatch<SetStateAction<string>>;
  setDryRun: Dispatch<SetStateAction<boolean>>;
  setCommitConfirmed: Dispatch<SetStateAction<boolean>>;
  setResult: Dispatch<SetStateAction<BulkUserImportResult | null>>;
  setImportError: Dispatch<SetStateAction<string>>;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  reloadUsers: () => Promise<void>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
};

export function useBulkUserImportActions({
  busy,
  csv,
  dryRun,
  commitConfirmed,
  setOpen,
  setCsv,
  setFileName,
  setDryRun,
  setCommitConfirmed,
  setResult,
  setImportError,
  setBusy,
  setError,
  setVerificationMessage,
  reloadUsers,
  translate,
  formatError
}: Options) {
  const openBulkUserImport = useCallback(() => {
    setOpen(true);
    setImportError("");
  }, [setImportError, setOpen]);

  const closeBulkUserImport = useCallback(() => {
    if (busy) return;
    setOpen(false);
    setImportError("");
  }, [busy, setImportError, setOpen]);

  const resetBulkUserImport = useCallback(() => {
    setCsv("");
    setFileName("");
    setDryRun(true);
    setCommitConfirmed(false);
    setResult(null);
    setImportError("");
  }, [setCommitConfirmed, setCsv, setDryRun, setFileName, setImportError, setResult]);

  const readBulkUserImportFile = useCallback(async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    try {
      const nextCsv = await file.text();
      setCsv(nextCsv);
      setFileName(file.name);
      setResult(null);
      setImportError("");
    } catch {
      setImportError(translate("bulkImportFileReadFailed"));
    }
  }, [setCsv, setFileName, setImportError, setResult, translate]);

  const submitBulkUserImport = useCallback(async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!csv.trim()) {
      setImportError(translate("bulkImportCsvRequired"));
      return;
    }
    if (!dryRun && !commitConfirmed) {
      setImportError(translate("bulkImportCommitConfirmationRequired"));
      return;
    }
    setBusy(true);
    setImportError("");
    try {
      const result = await adminApi.importAdminUsersCsv(csv, dryRun);
      setResult(result);
      if (result.committed) {
        setVerificationMessage(translate("bulkImportCompleted"));
        await reloadUsers();
      } else {
        setVerificationMessage(translate("bulkImportDryRunComplete"));
      }
    } catch (error) {
      if (error instanceof ApiError && isBulkUserImportResult(error.body)) {
        setResult(error.body);
        setImportError(translate("bulkImportValidationFailed"));
      } else {
        setImportError(formatError(error, "bulkImportFailed"));
      }
    } finally {
      setBusy(false);
    }
  }, [
    commitConfirmed,
    csv,
    dryRun,
    formatError,
    reloadUsers,
    setBusy,
    setImportError,
    setResult,
    setVerificationMessage,
    translate
  ]);

  return {
    openBulkUserImport,
    closeBulkUserImport,
    resetBulkUserImport,
    readBulkUserImportFile,
    submitBulkUserImport
  };
}
