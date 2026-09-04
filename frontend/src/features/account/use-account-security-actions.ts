import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { TranslationKey } from "../../i18n";
import * as accountApi from "../../lib/api/account";
import { passkeyCreationOptions, registrationCredentialJson } from "../../lib/webauthn";
import type { MfaStatus, Passkey, TotpSetup } from "../../types";
import type { AccountSecurityRefresh } from "./use-account-security-data";

type RunUiAction = (action: () => Promise<void>, fallback?: TranslationKey) => Promise<boolean>;

type Options = {
  passkeyName: string;
  setPasskeyName: Dispatch<SetStateAction<string>>;
  setPasskeys: Dispatch<SetStateAction<Passkey[]>>;
  totpSetup: TotpSetup | null;
  totpSetupCode: string;
  setTotpSetup: Dispatch<SetStateAction<TotpSetup | null>>;
  setTotpSetupCode: Dispatch<SetStateAction<string>>;
  setMfaStatus: Dispatch<SetStateAction<MfaStatus | null>>;
  setNewRecoveryCodes: Dispatch<SetStateAction<string[]>>;
  setError: Dispatch<SetStateAction<string>>;
  securityRefresh: AccountSecurityRefresh;
  removeSession: (id: string) => void;
  runUiAction: RunUiAction;
  formatError: (error: unknown, fallback: TranslationKey) => string;
};

export function useAccountSecurityActions({
  passkeyName,
  setPasskeyName,
  setPasskeys,
  totpSetup,
  totpSetupCode,
  setTotpSetup,
  setTotpSetupCode,
  setMfaStatus,
  setNewRecoveryCodes,
  setError,
  securityRefresh,
  removeSession,
  runUiAction,
  formatError
}: Options) {
  const registerPasskey = useCallback(async () => {
    await runUiAction(async () => {
      if (!navigator.credentials?.create || !window.PublicKeyCredential) {
        throw new Error("passkey registration is unavailable");
      }
      const start = await accountApi.startPasskeyRegistration(passkeyName || null);
      const credential = await navigator.credentials.create(passkeyCreationOptions(start.public_key));
      if (!credential || credential.type !== "public-key") {
        throw new Error("passkey registration failed");
      }
      const created = await accountApi.finishPasskeyRegistration({
        challengeId: start.challenge_id,
        name: passkeyName || null,
        credential: registrationCredentialJson(credential as PublicKeyCredential)
      });
      setPasskeys((current) => [created, ...current.filter((item) => item.id !== created.id)]);
      setPasskeyName("");
    }, "registerPasskeyFailed");
  }, [passkeyName, runUiAction, setPasskeyName, setPasskeys]);

  const deletePasskey = useCallback(async (id: string) => {
    await runUiAction(async () => {
      await accountApi.deletePasskey(id);
      setPasskeys((current) => current.filter((item) => item.id !== id));
    }, "deletePasskeyFailed");
  }, [runUiAction, setPasskeys]);

  const revokeMyConsent = useCallback(async (clientId: string) => {
    await runUiAction(async () => {
      await accountApi.revokeConsent(clientId);
      await securityRefresh.consents();
    }, "revokeAuthorizationFailed");
  }, [runUiAction, securityRefresh]);

  const revokeMySession = useCallback(async (sessionId: string) => {
    await runUiAction(async () => {
      await accountApi.revokeSession(sessionId);
      removeSession(sessionId);
    }, "revokeSessionFailed");
  }, [removeSession, runUiAction]);

  const startTotpSetup = useCallback(async () => {
    setNewRecoveryCodes([]);
    setTotpSetupCode("");
    await runUiAction(async () => {
      setTotpSetup(await accountApi.startTotpSetup());
    }, "startMfaSetupFailed");
  }, [runUiAction, setNewRecoveryCodes, setTotpSetup, setTotpSetupCode]);

  const confirmTotpSetup = useCallback(async () => {
    if (!totpSetup) return;
    await runUiAction(async () => {
      const result = await accountApi.confirmTotpSetup(totpSetup.setup_id, totpSetupCode);
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      setTotpSetup(null);
      setTotpSetupCode("");
      await securityRefresh.all();
    }, "confirmMfaSetupFailed");
  }, [runUiAction, securityRefresh, setMfaStatus, setNewRecoveryCodes, setTotpSetup, setTotpSetupCode, totpSetup, totpSetupCode]);

  const rotateRecoveryCodes = useCallback(async () => {
    await runUiAction(async () => {
      const result = await accountApi.rotateRecoveryCodes();
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      await securityRefresh.all();
    }, "rotateRecoveryCodesFailed");
  }, [runUiAction, securityRefresh, setMfaStatus, setNewRecoveryCodes]);

  const disableMfa = useCallback(async () => {
    setError("");
    try {
      const result = await accountApi.disableMfa();
      setMfaStatus(result);
      setTotpSetup(null);
      setNewRecoveryCodes([]);
      await securityRefresh.all();
    } catch (error) {
      const message = formatError(error, "disableMfaFailed");
      setError(message);
      throw new Error(message);
    }
  }, [formatError, securityRefresh, setError, setMfaStatus, setNewRecoveryCodes, setTotpSetup]);

  return {
    registerPasskey,
    deletePasskey,
    revokeMyConsent,
    revokeMySession,
    startTotpSetup,
    confirmTotpSetup,
    rotateRecoveryCodes,
    disableMfa
  };
}
