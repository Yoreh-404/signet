import { useState } from "react";
import { emptyAuditWebhookForm, emptyLdapProviderForm, emptyProviderForm, emptyQuickLinkForm } from "../../lib/form-defaults";
import { useLatestRequest } from "./use-latest-request";
import type {
  AuditWebhook,
  LdapProvider,
  LoginSettingsDraft,
  QuickLink,
  RegistrationSettings,
  RuntimeSettings,
  SecurityPolicy
} from "../../types";

export type AdminEditor = "user" | "organization" | "enterprise" | "application" | "invitation" | "provider" | "ldap" | "role" | "group" | null;

/** Owns platform/provider/security/settings drafts and their baselines. */
export function useSettingsController() {
  const [providerForm, setProviderForm] = useState(emptyProviderForm);
  const [providerFormBaseline, setProviderFormBaseline] = useState<typeof emptyProviderForm | null>(null);
  const [providerTemplateId, setProviderTemplateId] = useState("");
  const [ldapProviderForm, setLdapProviderForm] = useState(emptyLdapProviderForm);
  const [ldapProviderFormBaseline, setLdapProviderFormBaseline] = useState<typeof emptyLdapProviderForm | null>(null);
  const [auditWebhookForm, setAuditWebhookForm] = useState(emptyAuditWebhookForm);
  const [auditWebhookFormBaseline, setAuditWebhookFormBaseline] = useState<typeof emptyAuditWebhookForm>(emptyAuditWebhookForm);
  const [editor, setEditor] = useState<AdminEditor>(null);
  const [loginSettingsDraft, setLoginSettingsDraft] = useState<LoginSettingsDraft>({
    brand_logo_url: "",
    email_domains: "",
    quick_links: []
  });
  const [quickLinkForm, setQuickLinkForm] = useState(emptyQuickLinkForm);
  const [quickLinkFormBaseline, setQuickLinkFormBaseline] = useState(() => ({ ...emptyQuickLinkForm }));
  const providerDiscoveryRequest = useLatestRequest();
  const [settingsSnapshot, setSettingsSnapshot] = useState<RuntimeSettings | null>(null);
  const [registrationSnapshot, setRegistrationSnapshot] = useState<RegistrationSettings | null>(null);
  const [securitySnapshot, setSecuritySnapshot] = useState<SecurityPolicy | null>(null);
  const [auditSnapshot, setAuditSnapshot] = useState<AuditWebhook[]>([]);
  const [quickLinksSnapshot, setQuickLinksSnapshot] = useState<QuickLink[]>([]);

  return {
    providerForm,
    setProviderForm,
    providerFormBaseline,
    setProviderFormBaseline,
    providerTemplateId,
    setProviderTemplateId,
    ldapProviderForm,
    setLdapProviderForm,
    ldapProviderFormBaseline,
    setLdapProviderFormBaseline,
    auditWebhookForm,
    setAuditWebhookForm,
    auditWebhookFormBaseline,
    setAuditWebhookFormBaseline,
    editor,
    setEditor,
    loginSettingsDraft,
    setLoginSettingsDraft,
    quickLinkForm,
    setQuickLinkForm,
    quickLinkFormBaseline,
    setQuickLinkFormBaseline,
    providerDiscoveryRequest,
    settingsSnapshot,
    setSettingsSnapshot,
    registrationSnapshot,
    setRegistrationSnapshot,
    securitySnapshot,
    setSecuritySnapshot,
    auditSnapshot,
    setAuditSnapshot,
    quickLinksSnapshot,
    setQuickLinksSnapshot
  };
}

export type SettingsController = ReturnType<typeof useSettingsController>;
