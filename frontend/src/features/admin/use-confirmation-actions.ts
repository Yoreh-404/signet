import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import type { PendingConfirmation } from "../../types";

type Options = {
  pendingConfirmation: PendingConfirmation | null;
  setPendingConfirmation: Dispatch<SetStateAction<PendingConfirmation | null>>;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  formatError: (error: unknown, fallback: TranslationKey) => string;
  confirmActionTitle: string;
  confirmActionDescription: string;
  operationCompletedMessage: string;
};

export function useConfirmationActions({
  pendingConfirmation,
  setPendingConfirmation,
  setBusy,
  setError,
  setVerificationMessage,
  formatError,
  confirmActionTitle,
  confirmActionDescription,
  operationCompletedMessage
}: Options) {
  const requestConfirmation = useCallback((
    action: PendingConfirmation["action"],
    title = confirmActionTitle,
    description = confirmActionDescription
  ) => {
    setError("");
    setPendingConfirmation({ action, title, description });
  }, [confirmActionDescription, confirmActionTitle, setError, setPendingConfirmation]);

  const runPendingConfirmation = useCallback(async () => {
    if (!pendingConfirmation) return;
    setBusy(true);
    setError("");
    try {
      await pendingConfirmation.action();
      setPendingConfirmation(null);
      setVerificationMessage(operationCompletedMessage);
    } catch (error) {
      setError(formatError(error, "operationFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    formatError,
    operationCompletedMessage,
    pendingConfirmation,
    setBusy,
    setError,
    setPendingConfirmation,
    setVerificationMessage
  ]);

  return { requestConfirmation, runPendingConfirmation };
}
