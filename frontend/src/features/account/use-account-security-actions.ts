import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { TranslationKey } from "../../i18n";
import * as accountApi from "../../lib/api/account";
import { passkeyCreationOptions, registrationCredentialJson } from "../../lib/webauthn";
import type { MfaStatus, Passkey, TotpSetup } from "../../types";

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
  loadAccountData: () => Promise<void>;
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
  loadAccountData,
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
      await loadAccountData();
    }, "revokeAuthorizationFailed");
  }, [loadAccountData, runUiAction]);

  const revokeMySession = useCallback(async (sessionId: string) => {
    await runUiAction(async () => {
      await accountApi.revokeSession(sessionId);
      await loadAccountData();
    }, "revokeSessionFailed");
  }, [loadAccountData, runUiAction]);

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
      await loadAccountData();
    }, "confirmMfaSetupFailed");
  }, [loadAccountData, runUiAction, setMfaStatus, setNewRecoveryCodes, setTotpSetup, setTotpSetupCode, totpSetup, totpSetupCode]);

  const rotateRecoveryCodes = useCallback(async () => {
    await runUiAction(async () => {
      const result = await accountApi.rotateRecoveryCodes();
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      await loadAccountData();
    }, "rotateRecoveryCodesFailed");
  }, [loadAccountData, runUiAction, setMfaStatus, setNewRecoveryCodes]);

  const disableMfa = useCallback(async () => {
    setError("");
    try {
      const result = await accountApi.disableMfa();
      setMfaStatus(result);
      setTotpSetup(null);
      setNewRecoveryCodes([]);
      await loadAccountData();
    } catch (error) {
      const message = formatError(error, "disableMfaFailed");
      setError(message);
      throw new Error(message);
    }
  }, [formatError, loadAccountData, setError, setMfaStatus, setNewRecoveryCodes, setTotpSetup]);

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
