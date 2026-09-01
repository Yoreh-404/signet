import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import type { Tab } from "../../types";

type RefreshOptions = {
  tab: Tab;
  setRefreshing: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  formatError: (error: unknown, fallback: TranslationKey) => string;
  translate: (key: TranslationKey) => string;
  reloadBilling: () => Promise<void>;
  reloadAccount: () => Promise<void>;
  reloadUsers: () => Promise<void>;
  reloadAdmin: (tab: Tab, options: { force: boolean }) => Promise<void>;
};

export function useAdminRefresh({
  tab,
  setRefreshing,
  setError,
  setVerificationMessage,
  formatError,
  translate,
  reloadBilling,
  reloadAccount,
  reloadUsers,
  reloadAdmin
}: RefreshOptions) {
  return useCallback(async () => {
    setError("");
    setRefreshing(true);
    try {
      switch (tab) {
        case "billing":
          await reloadBilling();
          break;
        case "account":
          await reloadAccount();
          break;
        case "users":
          await reloadUsers();
          break;
        default:
          await reloadAdmin(tab, { force: true });
          break;
      }
      setVerificationMessage(translate("operationCompleted"));
    } catch (error) {
      setError(formatError(error, "refreshFailed"));
    } finally {
      setRefreshing(false);
    }
  }, [
    formatError,
    reloadAccount,
    reloadAdmin,
    reloadBilling,
    reloadUsers,
    setError,
    setRefreshing,
    setVerificationMessage,
    tab,
    translate
  ]);
}
