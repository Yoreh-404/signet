import { useCallback } from "react";
import type { Dispatch, FormEvent, SetStateAction } from "react";
import { api } from "../../lib/api";
import { emptyAuthorizationCodeLoginForm } from "../../lib/form-defaults";
import type { TranslationKey } from "../../i18n";
import type { LoginResponse, User } from "../../types";

type AuthorizationCodeLoginForm = typeof emptyAuthorizationCodeLoginForm;

type Options = {
  form: AuthorizationCodeLoginForm;
  returnTo: string | null;
  accountFlow: string | null;
  setForm: Dispatch<SetStateAction<AuthorizationCodeLoginForm>>;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
  finishInteractiveAuth: (user: User) => boolean;
  loadBootstrap: () => Promise<void>;
  request: typeof api;
};

export function useAuthorizationCodeLogin({
  form,
  returnTo,
  accountFlow,
  setForm,
  setBusy,
  setError,
  translate,
  formatError,
  finishInteractiveAuth,
  loadBootstrap,
  request
}: Options) {
  return useCallback(async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await request<LoginResponse>("/api/login/authorization-code", {
        method: "POST",
        body: JSON.stringify({
          email: form.email.trim(),
          authorization_code: form.authorization_code.trim(),
          return_to: returnTo,
          account_flow: accountFlow
        })
      });
      if (result.mode === "oidc_continuation") {
        setForm(emptyAuthorizationCodeLoginForm);
        window.location.assign(result.continue_to);
        return;
      }
      if (!result.user) throw new Error(translate("authorizationCodeLoginFailed"));
      setForm(emptyAuthorizationCodeLoginForm);
      if (finishInteractiveAuth(result.user)) return;
      await loadBootstrap();
    } catch (error) {
      setError(formatError(error, "authorizationCodeLoginFailed"));
    } finally {
      setBusy(false);
    }
  }, [accountFlow, finishInteractiveAuth, form, formatError, loadBootstrap, request, returnTo, setBusy, setError, setForm, translate]);
}
