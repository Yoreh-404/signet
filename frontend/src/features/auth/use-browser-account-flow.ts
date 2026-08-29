import { useCallback } from "react";

import type {
  BrowserAccount,
  BrowserAccountContinuation,
  BrowserAccountsContext,
  AuthMode,
  LoginMethod,
} from "../../types";
import { emptyAuthorizationCodeLoginForm } from "../../lib/form-defaults";
import { inlineAccountLoginFlow } from "../../app-helpers";
import type { TranslationKey } from "../../i18n";

type Translator = (key: TranslationKey) => string;

type BrowserAccountFlowOptions = {
  accountLoginFlow: string | null;
  accountLoginExpanded: boolean;
  authReturnTo: string | null;
  selectedBrowserAccount: BrowserAccount | null;
  continueWithBrowserAccount: BrowserAccountContinuation | null;
  setAccountLoginFlow: (value: string | null) => void;
  setAccountLoginExpanded: (value: boolean) => void;
  setSelectedBrowserAccount: (value: BrowserAccount | null) => void;
  setContinueWithBrowserAccount: (
    value: BrowserAccountContinuation | null | (() => BrowserAccountContinuation),
  ) => void;
  setBrowserAccountsContext: (value: BrowserAccountsContext | null) => void;
  setBrowserAccountContinuing: (value: boolean) => void;
  setAuthMode: (value: AuthMode) => void;
  setLoginMethod: (value: LoginMethod) => void;
  setLoginPassword: (value: string) => void;
  setAuthorizationCodeLoginForm: (value: typeof emptyAuthorizationCodeLoginForm) => void;
  setLoginMfaChallengeId: (value: string) => void;
  setLoginMfaCode: (value: string) => void;
  setLoginRecoveryAvailable: (value: boolean) => void;
  setLoginCaptchaChallengeId: (value: string) => void;
  setLoginCaptchaPrompt: (value: string) => void;
  setLoginCaptchaAnswer: (value: string) => void;
  setAuthEmail: (value: string) => void;
  setError: (value: string) => void;
  setVerificationMessage: (value: string) => void;
  t: Translator;
};

export function useBrowserAccountFlow({
  accountLoginFlow,
  accountLoginExpanded,
  authReturnTo,
  selectedBrowserAccount,
  continueWithBrowserAccount,
  setAccountLoginFlow,
  setAccountLoginExpanded,
  setSelectedBrowserAccount,
  setContinueWithBrowserAccount,
  setBrowserAccountsContext,
  setBrowserAccountContinuing,
  setAuthMode,
  setLoginMethod,
  setLoginPassword,
  setAuthorizationCodeLoginForm,
  setLoginMfaChallengeId,
  setLoginMfaCode,
  setLoginRecoveryAvailable,
  setLoginCaptchaChallengeId,
  setLoginCaptchaPrompt,
  setLoginCaptchaAnswer,
  setAuthEmail,
  setError,
  setVerificationMessage,
  t,
}: BrowserAccountFlowOptions) {
  const selectBrowserAccount = useCallback(
    (account: BrowserAccount, continuation: BrowserAccountContinuation) => {
      if (accountLoginFlow) {
        const currentUrl = new URL(window.location.href);
        currentUrl.searchParams.delete("account_flow");
        window.history.replaceState(
          window.history.state,
          "",
          `${currentUrl.pathname}${currentUrl.search}${currentUrl.hash}`,
        );
        setAccountLoginFlow(null);
      }
      setSelectedBrowserAccount(account);
      setContinueWithBrowserAccount(() => continuation);
      setAccountLoginExpanded(false);
      setError("");
      setVerificationMessage("");
    },
    [
      accountLoginFlow,
      setAccountLoginExpanded,
      setAccountLoginFlow,
      setContinueWithBrowserAccount,
      setError,
      setSelectedBrowserAccount,
      setVerificationMessage,
    ],
  );

  const handleBrowserAccountsLoaded = useCallback(
    (
      accounts: BrowserAccount[],
      context: BrowserAccountsContext,
      continuationForAccount?: (accountRef: string) => Promise<void>,
    ) => {
      setBrowserAccountsContext(context);
      if (accounts.length === 0) {
        setSelectedBrowserAccount(null);
        setContinueWithBrowserAccount(null);
        return;
      }
      if (accountLoginExpanded) return;
      const next =
        accounts.find((account) => account.account_ref === selectedBrowserAccount?.account_ref) ??
        accounts[0];
      setSelectedBrowserAccount(next);
      if (continuationForAccount) {
        setContinueWithBrowserAccount(() => () => continuationForAccount(next.account_ref));
      }
    },
    [
      accountLoginExpanded,
      selectedBrowserAccount?.account_ref,
      setBrowserAccountsContext,
      setContinueWithBrowserAccount,
      setSelectedBrowserAccount,
    ],
  );

  const continueSelectedBrowserAccount = useCallback(async () => {
    if (!continueWithBrowserAccount) return;
    setBrowserAccountContinuing(true);
    setError("");
    try {
      await continueWithBrowserAccount();
    } finally {
      setBrowserAccountContinuing(false);
    }
  }, [continueWithBrowserAccount, setBrowserAccountContinuing, setError]);

  const openAnotherAccountLogin = useCallback(
    (loginUrl: string) => {
      const accountFlow = inlineAccountLoginFlow(loginUrl, authReturnTo ?? "/");
      if (!accountFlow) throw new Error(t("browserAccountAddFailed"));
      const currentUrl = new URL(window.location.href);
      currentUrl.searchParams.set("account_flow", accountFlow);
      window.history.replaceState(
        window.history.state,
        "",
        `${currentUrl.pathname}${currentUrl.search}${currentUrl.hash}`,
      );
      setAccountLoginFlow(accountFlow);
      setAccountLoginExpanded(true);
      setSelectedBrowserAccount(null);
      setContinueWithBrowserAccount(null);
      setAuthMode("login");
      setLoginMethod("password");
      setLoginPassword("");
      setAuthorizationCodeLoginForm(emptyAuthorizationCodeLoginForm);
      setLoginMfaChallengeId("");
      setLoginMfaCode("");
      setLoginRecoveryAvailable(false);
      setLoginCaptchaChallengeId("");
      setLoginCaptchaPrompt("");
      setLoginCaptchaAnswer("");
      setError("");
      setVerificationMessage("");
    },
    [
      authReturnTo,
      setAccountLoginExpanded,
      setAccountLoginFlow,
      setAuthMode,
      setAuthorizationCodeLoginForm,
      setContinueWithBrowserAccount,
      setError,
      setLoginCaptchaAnswer,
      setLoginCaptchaChallengeId,
      setLoginCaptchaPrompt,
      setLoginMfaChallengeId,
      setLoginMfaCode,
      setLoginMethod,
      setLoginPassword,
      setLoginRecoveryAvailable,
      setSelectedBrowserAccount,
      setVerificationMessage,
      t,
    ],
  );

  return {
    selectBrowserAccount,
    handleBrowserAccountsLoaded,
    continueSelectedBrowserAccount,
    openAnotherAccountLogin,
    setSharedAuthEmail: setAuthEmail,
  };
}
