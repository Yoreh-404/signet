import type { Dispatch, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import type { MfaStatus, Passkey, TotpSetup } from "../../types";
import { useAccountSecurityActions } from "./use-account-security-actions";
import type { AccountSecurityDataContract } from "./use-account-security-data";

type RunUiAction = (action: () => Promise<void>, fallback?: TranslationKey) => Promise<boolean>;

export type AccountSecurityFacadeOptions = {
  passkey: {
    name: string;
    setName: Dispatch<SetStateAction<string>>;
    setItems: Dispatch<SetStateAction<Passkey[]>>;
  };
  mfa: {
    setup: TotpSetup | null;
    setupCode: string;
    setSetup: Dispatch<SetStateAction<TotpSetup | null>>;
    setSetupCode: Dispatch<SetStateAction<string>>;
    setStatus: Dispatch<SetStateAction<MfaStatus | null>>;
    setRecoveryCodes: Dispatch<SetStateAction<string[]>>;
  };
  accountData: AccountSecurityDataContract;
  ui: {
    setError: Dispatch<SetStateAction<string>>;
    runUiAction: RunUiAction;
    formatError: (error: unknown, fallback: TranslationKey) => string;
  };
};

export function useAccountSecurityFacade({
  passkey,
  mfa,
  accountData,
  ui
}: AccountSecurityFacadeOptions) {
  return useAccountSecurityActions({
    passkeyName: passkey.name,
    setPasskeyName: passkey.setName,
    setPasskeys: passkey.setItems,
    totpSetup: mfa.setup,
    totpSetupCode: mfa.setupCode,
    setTotpSetup: mfa.setSetup,
    setTotpSetupCode: mfa.setSetupCode,
    setMfaStatus: mfa.setStatus,
    setNewRecoveryCodes: mfa.setRecoveryCodes,
    securityRefresh: accountData.securityRefresh,
    removeSession: accountData.removeSession,
    setError: ui.setError,
    runUiAction: ui.runUiAction,
    formatError: ui.formatError
  });
}
