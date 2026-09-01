import { useCallback } from "react";
import type { Dispatch, FormEvent, SetStateAction } from "react";
import { api } from "../../lib/api";
import { emptyPasswordResetForm, emptyRegisterForm } from "../../lib/form-defaults";
import type { TranslationKey } from "../../i18n";
import type { AuthMode } from "../../types";

type RegisterForm = typeof emptyRegisterForm;
type PasswordResetForm = typeof emptyPasswordResetForm;
type Translate = (key: TranslationKey) => string;
type RunUiAction = (action: () => Promise<void>, fallback?: TranslationKey) => Promise<boolean>;

type AuthVerificationActionsOptions = {
  authEmail: string;
  registerPhone: string;
  passwordResetForm: PasswordResetForm;
  setRegisterForm: Dispatch<SetStateAction<RegisterForm>>;
  setPasswordResetForm: Dispatch<SetStateAction<PasswordResetForm>>;
  setAuthMode: Dispatch<SetStateAction<AuthMode>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  runUiAction: RunUiAction;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  formatError: (error: unknown, fallback: TranslationKey) => string;
  translate: Translate;
  request: typeof api;
};

export function useAuthVerificationActions({
  authEmail,
  registerPhone,
  passwordResetForm,
  setRegisterForm,
  setPasswordResetForm,
  setAuthMode,
  setVerificationMessage,
  runUiAction,
  setBusy,
  setError,
  formatError,
  translate,
  request
}: AuthVerificationActionsOptions) {
  const sendVerification = useCallback(async (channel: "email" | "phone") => {
    const target = channel === "email" ? authEmail : registerPhone;
    await runUiAction(async () => {
      const result = await request<{ dev_code: string | null; expires_at: number }>(
        "/api/register/verification/start",
        { method: "POST", body: JSON.stringify({ channel, target }) }
      );
      setVerificationMessage(
        `${translate("codeSent")}${result.dev_code ? `: ${result.dev_code}. ${translate("copiedCodeHint")}` : ""}`
      );
      if (result.dev_code && channel === "email") {
        setRegisterForm((current) => ({ ...current, email_code: result.dev_code ?? "" }));
      }
      if (result.dev_code && channel === "phone") {
        setRegisterForm((current) => ({ ...current, phone_code: result.dev_code ?? "" }));
      }
    }, "sendVerificationFailed");
  }, [authEmail, registerPhone, request, runUiAction, setRegisterForm, setVerificationMessage, translate]);

  const sendPasswordResetCode = useCallback(async () => {
    await runUiAction(async () => {
      const result = await request<{ dev_code: string | null; expires_at: number }>(
        "/api/password-reset/start",
        { method: "POST", body: JSON.stringify({ email: authEmail }) }
      );
      setVerificationMessage(
        `${translate("codeSent")}${result.dev_code ? `: ${result.dev_code}. ${translate("copiedCodeHint")}` : ""}`
      );
      if (result.dev_code) {
        setPasswordResetForm((current) => ({ ...current, code: result.dev_code ?? "" }));
      }
    }, "sendResetCodeFailed");
  }, [authEmail, request, runUiAction, setPasswordResetForm, setVerificationMessage, translate]);

  const handlePasswordReset = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await request("/api/password-reset/complete", {
        method: "POST",
        body: JSON.stringify({
          email: authEmail,
          code: passwordResetForm.code,
          password: passwordResetForm.password
        })
      });
      setPasswordResetForm(emptyPasswordResetForm);
      setAuthMode("login");
      setVerificationMessage(translate("passwordResetComplete"));
    } catch (error) {
      setError(formatError(error, "resetPasswordFailed"));
    } finally {
      setBusy(false);
    }
  }, [authEmail, formatError, passwordResetForm, request, setAuthMode, setBusy, setError, setPasswordResetForm, setVerificationMessage, translate]);

  return { sendVerification, sendPasswordResetCode, handlePasswordReset };
}
