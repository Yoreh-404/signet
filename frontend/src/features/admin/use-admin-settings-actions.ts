import { useCallback } from "react";
import type { Dispatch, FormEvent, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import * as adminApi from "../../lib/api/admin";
import { emptyAuditWebhookForm } from "../../lib/form-defaults";
import { splitList } from "../../lib/formatters";
import type { AuditWebhook, RegistrationSettings, RuntimeSettings, SecurityPolicy, Tab } from "../../types";

type AuditWebhookForm = typeof emptyAuditWebhookForm;

type Options = {
  securityPolicy: SecurityPolicy | null;
  setSecurityPolicy: Dispatch<SetStateAction<SecurityPolicy | null>>;
  setSecurityPolicyBaseline: Dispatch<SetStateAction<SecurityPolicy | null>>;
  signingKeyKid: string;
  setSigningKeyKid: Dispatch<SetStateAction<string>>;
  registrationSettings: RegistrationSettings | null;
  setRegistrationSettings: Dispatch<SetStateAction<RegistrationSettings | null>>;
  setRegistrationSettingsBaseline: Dispatch<SetStateAction<RegistrationSettings | null>>;
  runtimeSettings: RuntimeSettings | null;
  setRuntimeSettings: Dispatch<SetStateAction<RuntimeSettings | null>>;
  setRuntimeSettingsBaseline: Dispatch<SetStateAction<RuntimeSettings | null>>;
  auditWebhookForm: AuditWebhookForm;
  setAuditWebhookForm: Dispatch<SetStateAction<AuditWebhookForm>>;
  setAuditWebhookFormBaseline: Dispatch<SetStateAction<AuditWebhookForm>>;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  loadAdminData: (tab?: Tab, options?: { force?: boolean }) => Promise<void>;
  loadBootstrap: () => Promise<void>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
};

export function useAdminSettingsActions({
  securityPolicy,
  setSecurityPolicy,
  setSecurityPolicyBaseline,
  signingKeyKid,
  setSigningKeyKid,
  registrationSettings,
  setRegistrationSettings,
  setRegistrationSettingsBaseline,
  runtimeSettings,
  setRuntimeSettings,
  setRuntimeSettingsBaseline,
  auditWebhookForm,
  setAuditWebhookForm,
  setAuditWebhookFormBaseline,
  setBusy,
  setError,
  setVerificationMessage,
  loadAdminData,
  loadBootstrap,
  translate,
  formatError
}: Options) {
  const saveSecurityPolicy = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    if (!securityPolicy) return;
    setBusy(true);
    setError("");
    try {
      const updated = await adminApi.updateAdminSecurityPolicy({
        password_min_length: Number(securityPolicy.password_min_length),
        password_require_uppercase: Number(Boolean(securityPolicy.password_require_uppercase)),
        password_require_lowercase: Number(Boolean(securityPolicy.password_require_lowercase)),
        password_require_digit: Number(Boolean(securityPolicy.password_require_digit)),
        password_require_symbol: Number(Boolean(securityPolicy.password_require_symbol)),
        password_reject_user_info: Number(Boolean(securityPolicy.password_reject_user_info)),
        login_lockout_enabled: Number(Boolean(securityPolicy.login_lockout_enabled)),
        max_failed_login_attempts: Number(securityPolicy.max_failed_login_attempts),
        failure_window_seconds: Number(securityPolicy.failure_window_seconds),
        lockout_seconds: Number(securityPolicy.lockout_seconds),
        trusted_ip_cidrs: securityPolicy.trusted_ip_cidrs,
        require_mfa_outside_trusted_networks: securityPolicy.require_mfa_outside_trusted_networks,
        allowed_ip_cidrs: securityPolicy.allowed_ip_cidrs,
        blocked_ip_cidrs: securityPolicy.blocked_ip_cidrs,
        allowed_email_domains: securityPolicy.allowed_email_domains,
        blocked_email_domains: securityPolicy.blocked_email_domains,
        captcha_enabled: securityPolicy.captcha_enabled,
        captcha_after_failed_attempts: Number(securityPolicy.captcha_after_failed_attempts),
        captcha_ttl_seconds: Number(securityPolicy.captcha_ttl_seconds)
      });
      setSecurityPolicy(updated);
      setSecurityPolicyBaseline(updated);
      setVerificationMessage(translate("changesSaved"));
      await loadAdminData();
    } catch (error) {
      setError(formatError(error, "saveSecurityPolicyFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    formatError,
    loadAdminData,
    securityPolicy,
    setBusy,
    setError,
    setSecurityPolicy,
    setSecurityPolicyBaseline,
    setVerificationMessage,
    translate
  ]);

  const rotateSigningKey = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      await adminApi.rotateAdminSigningKey(signingKeyKid.trim() || null);
      setSigningKeyKid("");
      await loadAdminData();
    } catch (error) {
      const message = formatError(error, "rotateSigningKeyFailed");
      setError(message);
      throw new Error(message);
    } finally {
      setBusy(false);
    }
  }, [formatError, loadAdminData, setBusy, setError, setSigningKeyKid, signingKeyKid]);

  const saveRegistrationSettings = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    if (!registrationSettings) return;
    setBusy(true);
    setError("");
    try {
      const updated = await adminApi.updateAdminRegistrationSettings(registrationSettings);
      setRegistrationSettings(updated);
      setRegistrationSettingsBaseline(updated);
      setVerificationMessage(translate("changesSaved"));
      await loadBootstrap();
    } catch (error) {
      setError(formatError(error, "saveRegistrationSettingsFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    formatError,
    loadBootstrap,
    registrationSettings,
    setBusy,
    setError,
    setRegistrationSettings,
    setRegistrationSettingsBaseline,
    setVerificationMessage,
    translate
  ]);

  const saveRuntimeSettings = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    if (!runtimeSettings) return;
    setBusy(true);
    setError("");
    try {
      const updated = await adminApi.updateAdminRuntimeSettings({
        public_base_url: runtimeSettings.public_base_url,
        issuer: runtimeSettings.issuer || runtimeSettings.public_base_url,
        trust_proxy_headers: runtimeSettings.trust_proxy_headers
      });
      setRuntimeSettings(updated);
      setRuntimeSettingsBaseline(updated);
      setVerificationMessage(translate("changesSaved"));
      await loadAdminData();
    } catch (error) {
      setError(formatError(error, "saveRuntimeSettingsFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    formatError,
    loadAdminData,
    runtimeSettings,
    setBusy,
    setError,
    setRuntimeSettings,
    setRuntimeSettingsBaseline,
    setVerificationMessage,
    translate
  ]);

  const saveAuditWebhook = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = {
        name: auditWebhookForm.name,
        url: auditWebhookForm.url,
        secret: auditWebhookForm.secret || null,
        clear_secret: auditWebhookForm.clear_secret,
        actions: splitList(auditWebhookForm.actions),
        is_active: auditWebhookForm.is_active,
        timeout_seconds: Number(auditWebhookForm.timeout_seconds)
      };
      if (auditWebhookForm.id) {
        await adminApi.updateAdminAuditWebhook(auditWebhookForm.id, body);
      } else {
        await adminApi.createAdminAuditWebhook(body);
      }
      setAuditWebhookForm(emptyAuditWebhookForm);
      setAuditWebhookFormBaseline(emptyAuditWebhookForm);
      setVerificationMessage(translate("changesSaved"));
      await loadAdminData();
    } catch (error) {
      setError(formatError(error, "saveAuditWebhookFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    auditWebhookForm,
    formatError,
    loadAdminData,
    setAuditWebhookForm,
    setAuditWebhookFormBaseline,
    setBusy,
    setError,
    setVerificationMessage,
    translate
  ]);

  const editAuditWebhook = useCallback((webhook: AuditWebhook) => {
    const nextForm = {
      id: webhook.id,
      name: webhook.name,
      url: webhook.url,
      secret: "",
      clear_secret: false,
      actions: webhook.actions.join("\n"),
      is_active: webhook.is_active,
      timeout_seconds: webhook.timeout_seconds
    };
    setAuditWebhookForm(nextForm);
    setAuditWebhookFormBaseline(nextForm);
  }, [setAuditWebhookForm, setAuditWebhookFormBaseline]);

  const deleteAuditWebhook = useCallback(async (id: string) => {
    await adminApi.deleteAdminAuditWebhook(id);
    setAuditWebhookForm((current) => (current.id === id ? emptyAuditWebhookForm : current));
    setAuditWebhookFormBaseline((current) => (current.id === id ? emptyAuditWebhookForm : current));
    await loadAdminData();
  }, [loadAdminData, setAuditWebhookForm, setAuditWebhookFormBaseline]);

  return {
    saveSecurityPolicy,
    rotateSigningKey,
    saveRegistrationSettings,
    saveRuntimeSettings,
    saveAuditWebhook,
    editAuditWebhook,
    deleteAuditWebhook
  };
}
