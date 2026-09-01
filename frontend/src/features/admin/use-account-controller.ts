import { useRef, useState } from "react";
import { initialAuthContext } from "../../lib/auth-flow";
import { emptyAuthorizationCodeLoginForm, emptyPasswordResetForm, emptyRegisterForm } from "../../lib/form-defaults";
import type {
  BrowserAccount,
  BrowserAccountContinuation,
  BrowserAccountsContext,
  AuthMode,
  LoginAuthorizationCodeLevel,
  LoginMethod,
  MfaStatus,
  MyConsent,
  MySession,
  Passkey,
  PendingConfirmation,
  PasskeyAuthenticationStart,
  PasskeyRegistrationStart,
  TotpSetup,
  User
} from "../../types";

export type InitialAuthContext = ReturnType<typeof initialAuthContext>;

export type AccountControllerOptions = {
  initialAuth: InitialAuthContext;
  initialError?: string;
};

/**
 * Local account/authentication state. Network commands stay in App because
 * they coordinate the session controller; this hook owns the fields those
 * commands mutate so the page does not become a second state store.
 */
export function useAccountController({ initialAuth, initialError = "" }: AccountControllerOptions) {
  const [mfaStatus, setMfaStatus] = useState<MfaStatus | null>(null);
  const [totpSetup, setTotpSetup] = useState<TotpSetup | null>(null);
  const [totpSetupCode, setTotpSetupCode] = useState("");
  const [newRecoveryCodes, setNewRecoveryCodes] = useState<string[]>([]);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [passkeyName, setPasskeyName] = useState("");
  const [myConsents, setMyConsents] = useState<MyConsent[]>([]);
  const [mySessions, setMySessions] = useState<MySession[]>([]);
  const [signingKeyKid, setSigningKeyKid] = useState("");
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm);
  const [passwordResetForm, setPasswordResetForm] = useState(emptyPasswordResetForm);
  const [authEmail, setAuthEmail] = useState(initialAuth.loginHint || "");
  const [loginMethod, setLoginMethod] = useState<LoginMethod>("password");
  const [authorizationCodeLoginForm, setAuthorizationCodeLoginForm] = useState(emptyAuthorizationCodeLoginForm);
  const [loginPassword, setLoginPassword] = useState("");
  const [loginMfaChallengeId, setLoginMfaChallengeId] = useState("");
  const [loginMfaCode, setLoginMfaCode] = useState("");
  const [loginRecoveryAvailable, setLoginRecoveryAvailable] = useState(false);
  const [loginCaptchaChallengeId, setLoginCaptchaChallengeId] = useState("");
  const [loginCaptchaPrompt, setLoginCaptchaPrompt] = useState("");
  const [loginCaptchaAnswer, setLoginCaptchaAnswer] = useState("");
  const [loginCustomDomain, setLoginCustomDomain] = useState("");
  const [registerCustomDomain, setRegisterCustomDomain] = useState("");
  const [resetCustomDomain, setResetCustomDomain] = useState("");
  const [authMode, setAuthMode] = useState<AuthMode>(initialAuth.mode);
  const [authReturnTo] = useState(initialAuth.returnTo);
  const [accountLoginExpanded, setAccountLoginExpanded] = useState(() => Boolean(initialAuth.accountFlow));
  const [accountLoginFlow, setAccountLoginFlow] = useState<string | null>(null);
  const [browserAccountsContext, setBrowserAccountsContext] = useState<BrowserAccountsContext | null>(null);
  const [selectedBrowserAccount, setSelectedBrowserAccount] = useState<BrowserAccount | null>(null);
  const [continueWithBrowserAccount, setContinueWithBrowserAccount] = useState<BrowserAccountContinuation | null>(null);
  const [browserAccountContinuing, setBrowserAccountContinuing] = useState(false);
  const [lastInvitationCode, setLastInvitationCode] = useState("");
  const [verificationMessage, setVerificationMessage] = useState("");
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);
  const authModeHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const [pendingConfirmation, setPendingConfirmation] = useState<PendingConfirmation | null>(null);

  return {
    mfaStatus,
    setMfaStatus,
    totpSetup,
    setTotpSetup,
    totpSetupCode,
    setTotpSetupCode,
    newRecoveryCodes,
    setNewRecoveryCodes,
    passkeys,
    setPasskeys,
    passkeyName,
    setPasskeyName,
    myConsents,
    setMyConsents,
    mySessions,
    setMySessions,
    signingKeyKid,
    setSigningKeyKid,
    registerForm,
    setRegisterForm,
    passwordResetForm,
    setPasswordResetForm,
    authEmail,
    setAuthEmail,
    loginMethod,
    setLoginMethod,
    authorizationCodeLoginForm,
    setAuthorizationCodeLoginForm,
    loginPassword,
    setLoginPassword,
    loginMfaChallengeId,
    setLoginMfaChallengeId,
    loginMfaCode,
    setLoginMfaCode,
    loginRecoveryAvailable,
    setLoginRecoveryAvailable,
    loginCaptchaChallengeId,
    setLoginCaptchaChallengeId,
    loginCaptchaPrompt,
    setLoginCaptchaPrompt,
    loginCaptchaAnswer,
    setLoginCaptchaAnswer,
    loginCustomDomain,
    setLoginCustomDomain,
    registerCustomDomain,
    setRegisterCustomDomain,
    resetCustomDomain,
    setResetCustomDomain,
    authMode,
    setAuthMode,
    authReturnTo,
    accountLoginExpanded,
    setAccountLoginExpanded,
    accountLoginFlow,
    setAccountLoginFlow,
    browserAccountsContext,
    setBrowserAccountsContext,
    selectedBrowserAccount,
    setSelectedBrowserAccount,
    continueWithBrowserAccount,
    setContinueWithBrowserAccount,
    browserAccountContinuing,
    setBrowserAccountContinuing,
    lastInvitationCode,
    setLastInvitationCode,
    verificationMessage,
    setVerificationMessage,
    error,
    setError,
    busy,
    setBusy,
    authModeHeadingRef,
    pendingConfirmation,
    setPendingConfirmation
  };
}

export type AccountController = ReturnType<typeof useAccountController>;
