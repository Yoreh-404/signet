import { useCallback } from "react";
import type { Dispatch, FormEvent, SetStateAction } from "react";
import { api } from "../../lib/api";
import type { TranslationKey } from "../../i18n";
import type { LoginResponse, User } from "../../types";
import { clearLoginChallengeState } from "./login-challenge-state";

type Options = {
  email: string;
  password: string;
  mfaChallengeId: string;
  mfaCode: string;
  captchaChallengeId: string;
  captchaAnswer: string;
  returnTo: string | null;
  accountFlow: string | null;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setMfaChallengeId: Dispatch<SetStateAction<string>>;
  setMfaCode: Dispatch<SetStateAction<string>>;
  setRecoveryAvailable: Dispatch<SetStateAction<boolean>>;
  setCaptchaChallengeId: Dispatch<SetStateAction<string>>;
  setCaptchaPrompt: Dispatch<SetStateAction<string>>;
  setCaptchaAnswer: Dispatch<SetStateAction<string>>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
  finishInteractiveAuth: (user: User) => boolean;
  loadBootstrap: () => Promise<void>;
  request: typeof api;
};

export function usePasswordLogin({
  email,
  password,
  mfaChallengeId,
  mfaCode,
  captchaChallengeId,
  captchaAnswer,
  returnTo,
  accountFlow,
  setBusy,
  setError,
  setMfaChallengeId,
  setMfaCode,
  setRecoveryAvailable,
  setCaptchaChallengeId,
  setCaptchaPrompt,
  setCaptchaAnswer,
  translate,
  formatError,
  finishInteractiveAuth,
  loadBootstrap,
  request
}: Options) {
  return useCallback(async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await request<LoginResponse>("/api/login", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          mfa_challenge_id: mfaChallengeId || null,
          mfa_code: mfaCode || null,
          captcha_challenge_id: captchaChallengeId || null,
          captcha_answer: captchaAnswer || null,
          return_to: returnTo,
          account_flow: accountFlow
        })
      });
      if ("continue_to" in result) {
        window.location.assign(result.continue_to);
        return;
      }
      if (result.captcha_required) {
        setCaptchaChallengeId(result.captcha_challenge_id ?? "");
        setCaptchaPrompt(result.captcha_prompt ?? "");
        setCaptchaAnswer("");
        return;
      }
      if (result.mfa_required) {
        setMfaChallengeId(result.mfa_challenge_id ?? "");
        setRecoveryAvailable(result.recovery_available);
        setMfaCode("");
        setCaptchaChallengeId("");
        setCaptchaPrompt("");
        setCaptchaAnswer("");
        return;
      }
      if (!result.user) throw new Error(translate("loginFailed"));
      clearLoginChallengeState({
        setMfaChallengeId,
        setMfaCode,
        setRecoveryAvailable,
        setCaptchaChallengeId,
        setCaptchaPrompt,
        setCaptchaAnswer
      });
      if (finishInteractiveAuth(result.user)) return;
      await loadBootstrap();
    } catch (error) {
      setError(formatError(error, "loginFailed"));
    } finally {
      setBusy(false);
    }
  }, [accountFlow, captchaAnswer, captchaChallengeId, email, finishInteractiveAuth, formatError, loadBootstrap, mfaChallengeId, mfaCode, password, request, returnTo, setBusy, setCaptchaAnswer, setCaptchaChallengeId, setCaptchaPrompt, setError, setMfaChallengeId, setMfaCode, setRecoveryAvailable, translate]);
}
