import type { Dispatch, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import { emptyAuditWebhookForm, emptyQuickLinkForm } from "../../lib/form-defaults";
import type {
  LoginSettings,
  LoginSettingsDraft,
  QuickLink,
  RegistrationSettings,
  RuntimeSettings,
  SecurityPolicy,
  Tab
} from "../../types";
import { useAdminSettingsActions } from "./use-admin-settings-actions";
import { useLoginSettingsActions } from "./use-login-settings-actions";

type AuditWebhookForm = typeof emptyAuditWebhookForm;
type QuickLinkForm = typeof emptyQuickLinkForm;

export type SettingsActionsFacadeOptions = {
  policy: {
    value: SecurityPolicy | null;
    setValue: Dispatch<SetStateAction<SecurityPolicy | null>>;
    setBaseline: Dispatch<SetStateAction<SecurityPolicy | null>>;
  };
  signingKey: {
    kid: string;
    setKid: Dispatch<SetStateAction<string>>;
  };
  registration: {
    value: RegistrationSettings | null;
    setValue: Dispatch<SetStateAction<RegistrationSettings | null>>;
    setBaseline: Dispatch<SetStateAction<RegistrationSettings | null>>;
  };
  runtime: {
    value: RuntimeSettings | null;
    setValue: Dispatch<SetStateAction<RuntimeSettings | null>>;
    setBaseline: Dispatch<SetStateAction<RuntimeSettings | null>>;
  };
  audit: {
    form: AuditWebhookForm;
    setForm: Dispatch<SetStateAction<AuditWebhookForm>>;
    setBaseline: Dispatch<SetStateAction<AuditWebhookForm>>;
  };
  login: {
    settings: LoginSettingsDraft;
    quickLinkForm: QuickLinkForm;
    setSettings: Dispatch<SetStateAction<LoginSettings | null>>;
    setDraft: Dispatch<SetStateAction<LoginSettingsDraft>>;
    setBaseline: Dispatch<SetStateAction<LoginSettingsDraft | null>>;
    setQuickLinkForm: Dispatch<SetStateAction<QuickLinkForm>>;
    setQuickLinkBaseline: Dispatch<SetStateAction<QuickLinkForm>>;
  };
  lifecycle: {
    setBusy: Dispatch<SetStateAction<boolean>>;
    setError: Dispatch<SetStateAction<string>>;
    setVerificationMessage: Dispatch<SetStateAction<string>>;
    loadAdminData: (tab?: Tab, options?: { force?: boolean }) => Promise<void>;
    loadBootstrap: () => Promise<void>;
  };
  ui: {
    translate: (key: TranslationKey) => string;
    formatError: (error: unknown, fallback: TranslationKey) => string;
    changesSavedMessage: string;
    saveLoginSettingsFailedMessage: string;
  };
};

export function useSettingsActionsFacade({
  policy,
  signingKey,
  registration,
  runtime,
  audit,
  login,
  lifecycle,
  ui
}: SettingsActionsFacadeOptions) {
  const adminSettings = useAdminSettingsActions({
    securityPolicy: policy.value,
    setSecurityPolicy: policy.setValue,
    setSecurityPolicyBaseline: policy.setBaseline,
    signingKeyKid: signingKey.kid,
    setSigningKeyKid: signingKey.setKid,
    registrationSettings: registration.value,
    setRegistrationSettings: registration.setValue,
    setRegistrationSettingsBaseline: registration.setBaseline,
    runtimeSettings: runtime.value,
    setRuntimeSettings: runtime.setValue,
    setRuntimeSettingsBaseline: runtime.setBaseline,
    auditWebhookForm: audit.form,
    setAuditWebhookForm: audit.setForm,
    setAuditWebhookFormBaseline: audit.setBaseline,
    setBusy: lifecycle.setBusy,
    setError: lifecycle.setError,
    setVerificationMessage: lifecycle.setVerificationMessage,
    loadAdminData: lifecycle.loadAdminData,
    loadBootstrap: lifecycle.loadBootstrap,
    translate: ui.translate,
    formatError: ui.formatError
  });
  const loginSettings = useLoginSettingsActions({
    loginSettingsDraft: login.settings,
    quickLinkForm: login.quickLinkForm,
    setLoginSettings: login.setSettings,
    setLoginSettingsDraft: login.setDraft,
    setLoginSettingsBaseline: login.setBaseline,
    setQuickLinkForm: login.setQuickLinkForm,
    setQuickLinkFormBaseline: login.setQuickLinkBaseline,
    setBusy: lifecycle.setBusy,
    setError: lifecycle.setError,
    setVerificationMessage: lifecycle.setVerificationMessage,
    loadBootstrap: lifecycle.loadBootstrap,
    messageOr: (error: unknown, fallback: "saveLoginSettingsFailed") => ui.formatError(error, fallback),
    changesSavedMessage: ui.changesSavedMessage,
    saveLoginSettingsFailedMessage: ui.saveLoginSettingsFailedMessage
  });

  return { ...adminSettings, ...loginSettings };
}
