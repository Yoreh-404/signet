import { useCallback } from "react";
import type { Dispatch, FormEvent, SetStateAction } from "react";
import { api } from "../../lib/api";
import { emptyRegisterForm } from "../../lib/form-defaults";
import type { TranslationKey } from "../../i18n";
import type { AuthMode, Bootstrap, OidcContinuationLoginResponse, User } from "../../types";

type RegisterForm = typeof emptyRegisterForm;

type Options = {
  bootstrap: Bootstrap | null;
  form: RegisterForm;
  email: string;
  returnTo: string | null;
  accountFlow: string | null;
  trialEnrollment: boolean;
  setForm: Dispatch<SetStateAction<RegisterForm>>;
  setAuthMode: Dispatch<SetStateAction<AuthMode>>;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
  finishInteractiveAuth: (user: User) => boolean;
  loadBootstrap: () => Promise<void>;
  request: typeof api;
};

export function useRegistrationSubmit({
  bootstrap,
  form,
  email,
  returnTo,
  accountFlow,
  trialEnrollment,
  setForm,
  setBusy,
  setError,
  translate,
  formatError,
  finishInteractiveAuth,
  loadBootstrap,
  request
}: Options) {
  return useCallback(async (event: FormEvent) => {
    event.preventDefault();
    if (
      bootstrap?.has_users
      && !bootstrap.registration.allow_password_registration
      && !bootstrap.registration.require_invitation
      && !form.authorization_code.trim()
    ) {
      setError(translate("passwordRegistrationUnavailable"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const body: Record<string, string | null> = trialEnrollment
        ? {
            email,
            authorization_code: form.authorization_code.trim() || null,
            return_to: returnTo,
            account_flow: accountFlow
          }
        : {
            email,
            username: form.username,
            display_name: null,
            phone: form.phone || null,
            password: form.password,
            email_code: form.email_code || null,
            phone_code: form.phone_code || null,
            authorization_code: form.authorization_code.trim() || null,
            return_to: returnTo,
            account_flow: accountFlow
          };
      const result = await request<{ user: User; first_admin: boolean } | OidcContinuationLoginResponse>(
        "/api/register",
        { method: "POST", body: JSON.stringify(body) }
      );
      if ("continue_to" in result) {
        setForm(emptyRegisterForm);
        window.location.assign(result.continue_to);
        return;
      }
      if (finishInteractiveAuth(result.user)) return;
      setForm(emptyRegisterForm);
      await loadBootstrap();
    } catch (error) {
      setError(formatError(error, "registrationFailed"));
    } finally {
      setBusy(false);
    }
  }, [accountFlow, bootstrap, email, finishInteractiveAuth, form, formatError, loadBootstrap, request, returnTo, setBusy, setError, setForm, translate, trialEnrollment]);
}
