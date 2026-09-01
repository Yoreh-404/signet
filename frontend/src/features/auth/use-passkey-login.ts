import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { TranslationKey } from "../../i18n";
import * as accountApi from "../../lib/api/account";
import { ApiError } from "../../lib/api";
import { authenticationCredentialJson, passkeyRequestOptions } from "../../lib/webauthn";
import type { OidcContinuationLoginResponse, User } from "../../types";
import { clearLoginChallengeState } from "./login-challenge-state";

type Options = {
  email: string;
  accountFlow: string | null;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setLoginMfaChallengeId: Dispatch<SetStateAction<string>>;
  setLoginMfaCode: Dispatch<SetStateAction<string>>;
  setLoginRecoveryAvailable: Dispatch<SetStateAction<boolean>>;
  setLoginCaptchaChallengeId: Dispatch<SetStateAction<string>>;
  setLoginCaptchaPrompt: Dispatch<SetStateAction<string>>;
  setLoginCaptchaAnswer: Dispatch<SetStateAction<string>>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
  finishInteractiveAuth: (user: User) => boolean;
  loadBootstrap: () => Promise<void>;
};

export function usePasskeyLogin({
  email,
  accountFlow,
  setBusy,
  setError,
  setLoginMfaChallengeId,
  setLoginMfaCode,
  setLoginRecoveryAvailable,
  setLoginCaptchaChallengeId,
  setLoginCaptchaPrompt,
  setLoginCaptchaAnswer,
  translate,
  formatError,
  finishInteractiveAuth,
  loadBootstrap
}: Options) {
  return useCallback(async () => {
    const normalizedEmail = email.trim();
    if (!normalizedEmail) {
      setError(translate("passkeyEmailRequired"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      if (!navigator.credentials?.get || !window.PublicKeyCredential) {
        throw new Error(translate("passkeyLoginFailed"));
      }
      const start = await accountApi.startPasskeyAuthentication(normalizedEmail, accountFlow);
      const credential = await navigator.credentials.get(passkeyRequestOptions(start.public_key));
      if (!credential || credential.type !== "public-key") {
        throw new Error(translate("passkeyLoginFailed"));
      }
      const result = await accountApi.finishPasskeyAuthentication<
        { user: User } | OidcContinuationLoginResponse
      >({
        challengeId: start.challenge_id,
        credential: authenticationCredentialJson(credential as PublicKeyCredential),
        accountFlow
      });
      if ("continue_to" in result) {
        window.location.assign(result.continue_to);
        return;
      }
      clearLoginChallengeState({
        setMfaChallengeId: setLoginMfaChallengeId,
        setMfaCode: setLoginMfaCode,
        setRecoveryAvailable: setLoginRecoveryAvailable,
        setCaptchaChallengeId: setLoginCaptchaChallengeId,
        setCaptchaPrompt: setLoginCaptchaPrompt,
        setCaptchaAnswer: setLoginCaptchaAnswer
      });
      if (finishInteractiveAuth(result.user)) return;
      await loadBootstrap();
    } catch (error) {
      setError(error instanceof ApiError && error.status === 401
        ? translate("passkeyLoginFailed")
        : formatError(error, "passkeyLoginFailed"));
    } finally {
      setBusy(false);
    }
  }, [accountFlow, email, finishInteractiveAuth, formatError, loadBootstrap, setBusy, setError, setLoginCaptchaAnswer, setLoginCaptchaChallengeId, setLoginCaptchaPrompt, setLoginMfaChallengeId, setLoginMfaCode, setLoginRecoveryAvailable, translate]);
}
