import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { TranslationKey } from "../../i18n";

type UiActionOptions = {
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  formatError: (error: unknown, fallback: TranslationKey) => string;
};

export function useUiAction({ setBusy, setError, formatError }: UiActionOptions) {
  return useCallback(async (
    action: () => Promise<void>,
    fallback: TranslationKey = "operationFailed"
  ): Promise<boolean> => {
    setBusy(true);
    setError("");
    try {
      await action();
      return true;
    } catch (error) {
      setError(formatError(error, fallback));
      return false;
    } finally {
      setBusy(false);
    }
  }, [formatError, setBusy, setError]);
}
