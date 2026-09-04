import { useCallback } from "react";

import type { TranslationKey } from "../../i18n";
import { loginHintRequiresAccountSwitch } from "../../lib/auth-flow";
import type { User } from "../../types";

type Options = {
  transitionToAuthenticated: (user: User) => Promise<unknown>;
  authReturnTo: string | null;
  accountFlow: string | null;
  loginHint: string;
  isAuthPage: boolean;
  setSharedAuthEmail: (value: string) => void;
  setError: (value: string) => void;
  translate: (key: TranslationKey) => string;
};

export function useAuthSessionCompletion({
  transitionToAuthenticated,
  authReturnTo,
  accountFlow,
  loginHint,
  isAuthPage,
  setSharedAuthEmail,
  setError,
  translate
}: Options) {
  return useCallback((nextUser: User): boolean => {
    void transitionToAuthenticated(nextUser).catch(() => undefined);
    if (!authReturnTo) {
      if (isAuthPage) {
        window.location.replace("/");
        return true;
      }
      return false;
    }
    if (!accountFlow && loginHintRequiresAccountSwitch(nextUser, loginHint)) {
      setSharedAuthEmail(loginHint);
      setError(translate("authAccountSwitch"));
      return false;
    }
    window.location.assign(authReturnTo);
    return true;
  }, [accountFlow, authReturnTo, isAuthPage, loginHint, setError, setSharedAuthEmail, translate, transitionToAuthenticated]);
}
