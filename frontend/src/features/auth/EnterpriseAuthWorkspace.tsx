import { AtSign, Copy, Globe2, KeyRound, Link2, Mail, Moon, Phone, Shield, Shuffle, Sun, Users } from "lucide-react";
import type { FormEvent, ReactNode, Ref } from "react";
import { AuthorizationCodeLoginForm, LoginMethodSwitcher } from "../../components/LoginMethod";
import { AccountChooser } from "./AccountChooser";
import type { BrowserAccountSelectedHandler, BrowserAccountsLoadedHandler } from "./AccountChooser";
import { Field, StatusBadge } from "../../components/ui";
import { formatTime } from "../../lib/formatters";
import { applyEmailDomain, oidcStartUrl, usableEmailDomain } from "../../lib/auth-flow";
import type { BrowserAccount, BrowserAccountsContext, Bootstrap, ExternalProviderSummary, LoginMethod, Locale, QuickLink, Theme, AuthMode } from "../../types";
import type { TranslationKey } from "../../i18n";

export type EnterpriseAuthRegisterForm = {
  username: string;
  phone: string;
  password: string;
  email_code: string;
  phone_code: string;
  authorization_code: string;
};

export type EnterpriseAuthPasswordResetForm = {
  code: string;
  password: string;
};

export type EnterpriseAuthAuthorizationCodeLoginForm = {
  email: string;
  authorization_code: string;
};

type EnterpriseAuthWorkspaceProps = {
  bootstrap: Bootstrap;
  locale: Locale;
  supportedLocales: string[];
  switchLocale: (locale: Locale) => void;
  theme: Theme;
  onToggleTheme: () => void;
  title: string;
  headingRef: Ref<HTMLHeadingElement>;
  error: string;
  verificationMessage: string;
  authAccountSwitch: boolean;
  authFormsVisible: boolean;
  authMode: AuthMode;
  onAuthModeChange: (mode: AuthMode) => void;
  busy: boolean;
  authEmail: string;
  onAuthEmailChange: (value: string) => void;
  browserAccountsContext: BrowserAccountsContext | null;
  selectedBrowserAccount: BrowserAccount | null;
  browserAccountContinuing: boolean;
  continueWithBrowserAccount: boolean;
  onContinueSelectedBrowserAccount: () => void;
  authReturnTo: string | null;
  selectAccount: boolean;
  onBrowserAccountSelected: BrowserAccountSelectedHandler;
  onBrowserAccountsLoaded: BrowserAccountsLoadedHandler;
  onLoginAnother: (loginUrl: string) => void | Promise<void>;
  visibleExternalProviders: ExternalProviderSummary[];
  hasExternalProviderRow: boolean;
  accountFlow: string | null;
  loginDomainProvider: ExternalProviderSummary | null;
  registerDomainProvider: ExternalProviderSummary | null;
  loginMethod: LoginMethod;
  onLoginMethodChange: (method: LoginMethod) => void;
  loginPassword: string;
  onLoginPasswordChange: (value: string) => void;
  loginMfaChallengeId: string;
  loginMfaCode: string;
  onLoginMfaCodeChange: (value: string) => void;
  loginRecoveryAvailable: boolean;
  loginCaptchaChallengeId: string;
  loginCaptchaPrompt: string;
  loginCaptchaAnswer: string;
  onLoginCaptchaAnswerChange: (value: string) => void;
  loginCustomDomain: string;
  onLoginCustomDomainChange: (value: string) => void;
  registerCustomDomain: string;
  onRegisterCustomDomainChange: (value: string) => void;
  resetCustomDomain: string;
  onResetCustomDomainChange: (value: string) => void;
  registerForm: EnterpriseAuthRegisterForm;
  onRegisterFormChange: (form: EnterpriseAuthRegisterForm) => void;
  passwordResetForm: EnterpriseAuthPasswordResetForm;
  onPasswordResetFormChange: (form: EnterpriseAuthPasswordResetForm) => void;
  authorizationCodeLoginForm: EnterpriseAuthAuthorizationCodeLoginForm;
  onAuthorizationCodeLoginFormChange: (form: EnterpriseAuthAuthorizationCodeLoginForm) => void;
  registrationCodeVisible: boolean;
  registrationCodeRequired: boolean;
  registrationCodeMode?: string;
  registrationCodeHint: string;
  registrationCodeInspecting: boolean;
  registrationFieldsVisible: boolean;
  registrationCodeBlocksSubmit: boolean;
  passwordRegistrationUnavailable: boolean;
  onLogin: (event: FormEvent<HTMLFormElement>) => void;
  onPasskeyLogin: () => void;
  onAuthorizationCodeLogin: (event: FormEvent<HTMLFormElement>) => void;
  onPasswordReset: (event: FormEvent<HTMLFormElement>) => void;
  onRegister: (event: FormEvent<HTMLFormElement>) => void;
  onSendVerification: (channel: "email" | "phone") => void;
  onSendPasswordResetCode: () => void;
  onGenerateRegisterEmail: () => void;
  onCopyRegisterEmail: () => void;
  quickLinks: QuickLink[];
  t: (key: TranslationKey) => string;
};

export function EnterpriseAuthWorkspace({
  bootstrap, locale, supportedLocales, switchLocale, theme, onToggleTheme, title, headingRef, error,
  verificationMessage, authAccountSwitch, authFormsVisible, authMode, onAuthModeChange, busy, authEmail,
  onAuthEmailChange, browserAccountsContext, selectedBrowserAccount, browserAccountContinuing,
  continueWithBrowserAccount, onContinueSelectedBrowserAccount, authReturnTo, selectAccount,
  onBrowserAccountSelected, onBrowserAccountsLoaded, onLoginAnother, visibleExternalProviders,
  hasExternalProviderRow, accountFlow, loginDomainProvider, registerDomainProvider, loginMethod,
  onLoginMethodChange, loginPassword, onLoginPasswordChange, loginMfaChallengeId, loginMfaCode,
  onLoginMfaCodeChange, loginRecoveryAvailable, loginCaptchaChallengeId, loginCaptchaPrompt,
  loginCaptchaAnswer, onLoginCaptchaAnswerChange, loginCustomDomain, onLoginCustomDomainChange,
  registerCustomDomain, onRegisterCustomDomainChange, resetCustomDomain, onResetCustomDomainChange,
  registerForm, onRegisterFormChange, passwordResetForm, onPasswordResetFormChange,
  authorizationCodeLoginForm, onAuthorizationCodeLoginFormChange, registrationCodeVisible,
  registrationCodeRequired, registrationCodeMode, registrationCodeHint, registrationCodeInspecting,
  registrationFieldsVisible, registrationCodeBlocksSubmit, passwordRegistrationUnavailable, onLogin,
  onPasskeyLogin, onAuthorizationCodeLogin, onPasswordReset, onRegister, onSendVerification,
  onSendPasswordResetCode, onGenerateRegisterEmail, onCopyRegisterEmail, quickLinks, t
}: EnterpriseAuthWorkspaceProps) {
  const hasUsers = bootstrap.has_users;
  const shortName = selectedBrowserAccount
    ? selectedBrowserAccount.user.username.trim() || selectedBrowserAccount.user.email.trim()
    : "";

  return (
    <>
      <main className="unified-auth-page">
        <header className="unified-auth-header">
          <div className="unified-auth-header-brand" aria-label="Signet">
            <span className="auth-logo auth-product-logo" aria-hidden="true">
              <Shield size={18} />
              {bootstrap.login.brand_logo_url && <img src={bootstrap.login.brand_logo_url} alt="" referrerPolicy="no-referrer" onLoad={(event) => { event.currentTarget.dataset.loaded = "true"; }} onError={(event) => { event.currentTarget.hidden = true; }} />}
            </span>
            <span>Signet</span>
            {browserAccountsContext?.client_name && <>
              <span className="unified-auth-logo-separator" aria-hidden="true" />
              <span className="auth-logo auth-client-logo" role="img" aria-label={browserAccountsContext.client_name} title={browserAccountsContext.client_name}>
                <Globe2 size={18} aria-hidden="true" />
                {browserAccountsContext.client_logo_uri && <img src={browserAccountsContext.client_logo_uri} alt="" referrerPolicy="no-referrer" onLoad={(event) => { event.currentTarget.dataset.loaded = "true"; }} onError={(event) => { event.currentTarget.hidden = true; }} />}
              </span>
            </>}
          </div>
          <div className="auth-toolbar">
            <TopLanguage locale={locale} supportedLocales={supportedLocales} switchLocale={switchLocale} label={t("language")} />
            <button className="icon-button" type="button" onClick={onToggleTheme} title={theme === "dark" ? t("lightMode") : t("darkMode")} aria-label={theme === "dark" ? t("lightMode") : t("darkMode")}>
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            </button>
          </div>
        </header>
        <section className={`unified-auth-main${authFormsVisible ? " auth-form-mode" : ""}`}>
          <div className="unified-auth-content">
            <section className="unified-auth-title"><h1 ref={headingRef} tabIndex={-1}>{title}</h1></section>
            {error && <div className="error" role="alert">{error}</div>}
            {authAccountSwitch && <div className="info">{t("authAccountSwitch")}</div>}
            {verificationMessage && <div className="info" role="status" aria-live="polite">{verificationMessage}</div>}
            {!authFormsVisible && selectedBrowserAccount && <section className="unified-auth-selection" aria-label={`${t("useAccount")}: ${selectedBrowserAccount.user.email}`}>
              <span className="account-switcher-avatar" aria-hidden="true">{shortName.slice(0, 1).toLocaleUpperCase()}</span>
              {browserAccountsContext?.client_name && <p>{t("selectAccountForApplication")} · {browserAccountsContext.client_name}</p>}
              <h2>{shortName}</h2><p className="unified-auth-selection-email">{selectedBrowserAccount.user.email}</p>
              <div className="unified-auth-selection-meta">
                {selectedBrowserAccount.current && <StatusBadge tone="success">{t("currentAccount")}</StatusBadge>}
                {(selectedBrowserAccount.session_kind === "trial_enrollment" || selectedBrowserAccount.user.login_code_level === "trial_enrollment") && <StatusBadge tone="warning">{t("trialEnrollmentSessionBadge")}</StatusBadge>}
                {(selectedBrowserAccount.session_kind === "temporary_authorization_code" || selectedBrowserAccount.user.login_code_level === "account_recovery") && <StatusBadge tone="warning">{t("temporaryRecoverySessionBadge")}</StatusBadge>}
                <small>{t("lastLogin")}: {formatTime(selectedBrowserAccount.last_login_at, locale)}</small>
              </div>
              <div className="unified-auth-selection-actions"><button className="primary" type="button" disabled={browserAccountContinuing || !continueWithBrowserAccount} onClick={onContinueSelectedBrowserAccount}><KeyRound size={16} />{browserAccountContinuing ? t("loading") : t("signIn")}</button></div>
            </section>}
            {authFormsVisible && <div className="unified-auth-forms">
              {hasExternalProviderRow && <div className="auth-external-providers" role="group" aria-label={t("externalLogin")}>
                {visibleExternalProviders.map((provider) => <a key={provider.slug} className="auth-provider-button" href={oidcStartUrl(provider.start_url, authEmail, authMode === "login" ? "login" : "register", accountFlow)}><Link2 size={16} aria-hidden="true" /><span>{provider.display_name}</span></a>)}
              </div>}
              {hasExternalProviderRow && <div className="auth-method-divider"><span>{t("orContinueWith")}</span></div>}
              {authMode === "login" && hasUsers && <>
                <LoginMethodSwitcher value={loginMethod} onChange={onLoginMethodChange} disabled={busy} label={t("loginMethod")} passwordLabel={t("passwordLogin")} authorizationCodeLabel={t("authorizationCodeLogin")} />
                {loginMethod === "password" ? <form aria-busy={busy} onSubmit={onLogin}>
                  <EmailField label={t("email")} value={authEmail} onChange={onAuthEmailChange} domains={bootstrap.login.email_domains} customDomain={loginCustomDomain} onCustomDomainChange={onLoginCustomDomainChange} customLabel={t("customDomain")} applyLabel={t("applySuffix")} />
                  {loginDomainProvider && <a className="secondary-link" href={oidcStartUrl(loginDomainProvider.start_url, authEmail, "login", accountFlow)}><Link2 size={16} />{t("domainSsoLogin")} · {loginDomainProvider.display_name}</a>}
                  <Field label={t("password")} type="password" autoComplete="current-password" value={loginPassword} onChange={onLoginPasswordChange} />
                  {loginMfaChallengeId && <><Field label={t("mfaCode")} autoComplete="one-time-code" value={loginMfaCode} onChange={onLoginMfaCodeChange} /><small role="status" aria-live="polite">{t("mfaRequired")}{loginRecoveryAvailable ? ` · ${t("recoveryCodes")}` : ""}</small></>}
                  {loginCaptchaChallengeId && <><Field label={`${t("captchaAnswer")} · ${loginCaptchaPrompt}`} value={loginCaptchaAnswer} onChange={onLoginCaptchaAnswerChange} /><small role="status" aria-live="polite">{t("captchaRequired")}</small></>}
                  <button className="primary" type="submit" disabled={busy}>{t("signIn")}</button>
                  <button className="link-button" type="button" onClick={onPasskeyLogin} disabled={busy}><KeyRound size={14} />{t("passkeyLogin")}</button>
                </form> : <>
                  <div className="info authorization-code-purpose" role="note"><strong>{t("authorizationCodeLoginPurposeTitle")}</strong><p>{t("authorizationCodeLoginPurposeHint")}</p>{browserAccountsContext?.client_name && <small>{t("authorizationCodeLoginScopeHint").replace("{client}", browserAccountsContext.client_name)}</small>}</div>
                  <AuthorizationCodeLoginForm email={authorizationCodeLoginForm.email} authorizationCode={authorizationCodeLoginForm.authorization_code} onAuthorizationCodeChange={(value) => onAuthorizationCodeLoginFormChange({ ...authorizationCodeLoginForm, authorization_code: value })} onEmailChange={(value) => onAuthorizationCodeLoginFormChange({ ...authorizationCodeLoginForm, email: value })} onSubmit={onAuthorizationCodeLogin} busy={busy} emailLabel={t("email")} authorizationCodeLabel={t("loginAuthorizationCode")} hint={t("loginAuthorizationCodeHint")} submitLabel={t("authorizationCodeLogin")} />
                </>}
                <div className="auth-secondary-actions"><span>{t("noAccountPrompt")} {" "}<button type="button" onClick={() => onAuthModeChange("register")} disabled={busy}>{t("createAccount")}</button></span><span>{t("forgotPasswordPrompt")} {" "}<button type="button" onClick={() => onAuthModeChange("reset")} disabled={busy}>{t("resetPasswordAction")}</button></span></div>
              </>}
              {authMode === "reset" && hasUsers && <form aria-busy={busy} onSubmit={onPasswordReset}>
                <EmailField label={t("email")} value={authEmail} onChange={onAuthEmailChange} domains={bootstrap.login.email_domains} customDomain={resetCustomDomain} onCustomDomainChange={onResetCustomDomainChange} customLabel={t("customDomain")} applyLabel={t("applySuffix")} />
                <InlineCode icon={<Mail size={16} />} label={t("resetPasswordCode")} button={t("sendResetCode")} value={passwordResetForm.code} onChange={(value) => onPasswordResetFormChange({ ...passwordResetForm, code: value })} onSend={onSendPasswordResetCode} disabled={busy} />
                <Field label={t("newPassword")} type="password" autoComplete="new-password" value={passwordResetForm.password} onChange={(value) => onPasswordResetFormChange({ ...passwordResetForm, password: value })} />
                <button className="primary" type="submit" disabled={busy}>{t("completePasswordReset")}</button>
              </form>}
              {(authMode === "register" || !hasUsers) && <form aria-busy={busy} onSubmit={onRegister}>
                <EmailField label={t("email")} value={authEmail} onChange={onAuthEmailChange} domains={bootstrap.login.email_domains} customDomain={registerCustomDomain} onCustomDomainChange={onRegisterCustomDomainChange} customLabel={t("customDomain")} applyLabel={t("applySuffix")} />
                {registrationCodeVisible && <><Field label={t("registrationAuthorizationCode")} value={registerForm.authorization_code} onChange={(value) => onRegisterFormChange({ ...registerForm, authorization_code: value })} required={registrationCodeRequired} />{registerForm.authorization_code.trim() && registrationCodeHint && <div className={`authorization-code-hint ${registrationCodeMode ?? "checking"}`} role="status" aria-live="polite">{registrationCodeHint}</div>}</>}
                {registrationCodeMode !== "trial_enrollment" && registrationFieldsVisible && <>
                  {registerDomainProvider && <a className="secondary-link" href={oidcStartUrl(registerDomainProvider.start_url, authEmail, "register", accountFlow)}><Link2 size={16} />{t("domainSsoRegister")} · {registerDomainProvider.display_name}</a>}
                  <div className="email-actions"><button type="button" onClick={onGenerateRegisterEmail}><Shuffle size={14} />{t("randomEmail")}</button><button type="button" onClick={onCopyRegisterEmail}><Copy size={14} />{t("copyEmail")}</button></div>
                  {passwordRegistrationUnavailable && <div className="info">{t("passwordRegistrationUnavailable")}</div>}
                  {bootstrap.registration.require_email_verification && hasUsers && <InlineCode icon={<Mail size={16} />} label={t("emailCode")} button={t("sendEmailCode")} value={registerForm.email_code} onChange={(value) => onRegisterFormChange({ ...registerForm, email_code: value })} onSend={() => onSendVerification("email")} disabled={busy} />}
                  {bootstrap.registration.require_phone_verification && <><Field label={t("phone")} type="tel" autoComplete="tel" value={registerForm.phone} onChange={(value) => onRegisterFormChange({ ...registerForm, phone: value })} required /><InlineCode icon={<Phone size={16} />} label={t("phoneCode")} button={t("sendPhoneCode")} value={registerForm.phone_code} onChange={(value) => onRegisterFormChange({ ...registerForm, phone_code: value })} onSend={() => onSendVerification("phone")} disabled={busy} /></>}
                  <Field label={t("username")} autoComplete="username" value={registerForm.username} onChange={(value) => onRegisterFormChange({ ...registerForm, username: value })} /><Field label={t("password")} type="password" autoComplete="new-password" value={registerForm.password} onChange={(value) => onRegisterFormChange({ ...registerForm, password: value })} required />
                </>}
                <button className="primary" type="submit" disabled={busy || passwordRegistrationUnavailable || registrationCodeBlocksSubmit}>{t("register")}</button>
              </form>}
              {authMode !== "login" && hasUsers && <div className="auth-secondary-actions auth-secondary-actions-single"><button type="button" onClick={() => onAuthModeChange("login")} disabled={busy}>{t("openLogin")}</button></div>}
              {bootstrap.ldap_providers.length > 0 && (authMode !== "login" || loginMethod === "password") && <div className="external-list"><span>{t("directoryLogin")}</span>{bootstrap.ldap_providers.map((provider) => <span key={provider.slug} className="secondary-link"><Users size={16} />{provider.display_name}</span>)}</div>}
            </div>}
            <QuickJump links={quickLinks} />
          </div>
        </section>
        <AccountChooser returnTo={authReturnTo ?? "/"} locale={locale} t={t} selectedAccountRef={selectedBrowserAccount?.account_ref ?? null} selectionMode={selectAccount ? "select" : "activate"} onAccountSelected={onBrowserAccountSelected} onAccountsLoaded={onBrowserAccountsLoaded} onLoginAnother={onLoginAnother} />
      </main>
    </>
  );
}

function TopLanguage({ locale, supportedLocales, switchLocale, label }: { locale: Locale; supportedLocales: string[]; switchLocale: (locale: Locale) => void; label: string }) {
  return <label className="language-control"><span>{label}</span><select value={locale} onChange={(event) => switchLocale(event.target.value as Locale)}>{supportedLocales.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>;
}

function EmailField({ label, value, onChange, domains, customDomain, onCustomDomainChange, customLabel, applyLabel }: { label: string; value: string; onChange: (value: string) => void; domains: string[]; customDomain: string; onCustomDomainChange: (value: string) => void; customLabel: string; applyLabel: string }) {
  const customSuffix = usableEmailDomain(customDomain);
  return <div className="email-field"><Field label={label} value={value} onChange={onChange} type="email" autoComplete="email" required />{domains.length > 0 && <div className="domain-pills" role="group" aria-label={label}>{domains.map((domain) => <button type="button" key={domain} onClick={() => onChange(applyEmailDomain(value, domain))}>@{domain}</button>)}</div>}<div className="custom-domain"><input aria-label={customLabel} autoComplete="off" value={customDomain} placeholder={customLabel} onChange={(event) => onCustomDomainChange(event.target.value)} /><button type="button" disabled={!customSuffix} onClick={() => onChange(applyEmailDomain(value, customSuffix))}><AtSign size={14} />{applyLabel}</button></div></div>;
}

function InlineCode({ icon, label, button, value, onChange, onSend, disabled = false }: { icon: ReactNode; label: string; button: string; value: string; onChange: (value: string) => void; onSend: () => void; disabled?: boolean }) {
  return <div className="inline-code"><Field label={label} value={value} onChange={onChange} autoComplete="one-time-code" /><button type="button" onClick={onSend} disabled={disabled}>{icon}{button}</button></div>;
}

function QuickJump({ links }: { links: QuickLink[] }) {
  if (links.length === 0) return null;
  return <div className="quick-jump">{links.map((link) => <a className="quick-jump-link" key={`${link.id}:${link.url}`} href={link.url} target="_blank" rel="noreferrer" title={link.label} aria-label={link.label}><span>{Array.from(link.label.trim())[0]?.toLocaleUpperCase() ?? "?"}</span></a>)}</div>;
}
