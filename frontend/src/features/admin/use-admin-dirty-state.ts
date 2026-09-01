import { useMemo } from "react";
import { isDirtyDomain } from "./stable-domain-comparator";

export type AdminDirtyStateInput = {
  editor: string | null;
  userForm: unknown;
  userFormBaseline: unknown;
  enterpriseForm: unknown;
  enterpriseFormBaseline: unknown;
  organizationForm: unknown;
  organizationFormBaseline: unknown;
  organizationMemberRoles: unknown;
  organizationMemberRolesBaseline: unknown;
  providerForm: unknown;
  providerFormBaseline: unknown;
  ldapProviderForm: unknown;
  ldapProviderFormBaseline: unknown;
  applicationForm: unknown;
  applicationFormBaseline: unknown;
  invitationForm: unknown;
  invitationFormBaseline: unknown;
  roleForm: unknown;
  roleFormBaseline: unknown;
  groupForm: unknown;
  groupFormBaseline: unknown;
  auditWebhookForm: unknown;
  auditWebhookFormBaseline: unknown;
  registrationSettings: unknown;
  registrationSettingsBaseline: unknown;
  runtimeSettings: unknown;
  runtimeSettingsBaseline: unknown;
  loginSettingsDraft: unknown;
  loginSettingsBaseline: unknown;
  quickLinkForm: unknown;
  quickLinkFormBaseline: unknown;
  securityPolicy: unknown;
  securityPolicyBaseline: unknown;
};

export function useAdminDirtyState(input: AdminDirtyStateInput) {
  const {
    editor,
    userForm,
    userFormBaseline,
    enterpriseForm,
    enterpriseFormBaseline,
    organizationForm,
    organizationFormBaseline,
    organizationMemberRoles,
    organizationMemberRolesBaseline,
    providerForm,
    providerFormBaseline,
    ldapProviderForm,
    ldapProviderFormBaseline,
    applicationForm,
    applicationFormBaseline,
    invitationForm,
    invitationFormBaseline,
    roleForm,
    roleFormBaseline,
    groupForm,
    groupFormBaseline,
    auditWebhookForm,
    auditWebhookFormBaseline,
    registrationSettings,
    registrationSettingsBaseline,
    runtimeSettings,
    runtimeSettingsBaseline,
    loginSettingsDraft,
    loginSettingsBaseline,
    quickLinkForm,
    quickLinkFormBaseline,
    securityPolicy,
    securityPolicyBaseline
  } = input;

  return useMemo(() => {
    const dirty = {
      userForm: isDirtyDomain(userForm, userFormBaseline),
      enterpriseForm: isDirtyDomain(enterpriseForm, enterpriseFormBaseline),
      organizationForm: isDirtyDomain(organizationForm, organizationFormBaseline)
        || isDirtyDomain(organizationMemberRoles, organizationMemberRolesBaseline),
      providerForm: isDirtyDomain(providerForm, providerFormBaseline),
      ldapProviderForm: isDirtyDomain(ldapProviderForm, ldapProviderFormBaseline),
      applicationForm: isDirtyDomain(applicationForm, applicationFormBaseline),
      invitationForm: isDirtyDomain(invitationForm, invitationFormBaseline),
      roleForm: isDirtyDomain(roleForm, roleFormBaseline),
      groupForm: isDirtyDomain(groupForm, groupFormBaseline),
      auditWebhookForm: isDirtyDomain(auditWebhookForm, auditWebhookFormBaseline),
      registrationSettings: registrationSettings !== null
        && isDirtyDomain(registrationSettings, registrationSettingsBaseline),
      runtimeSettings: runtimeSettings !== null
        && isDirtyDomain(runtimeSettings, runtimeSettingsBaseline),
      loginSettings: isDirtyDomain(loginSettingsDraft, loginSettingsBaseline),
      quickLinkForm: isDirtyDomain(quickLinkForm, quickLinkFormBaseline),
      securityPolicy: securityPolicy !== null
        && isDirtyDomain(securityPolicy, securityPolicyBaseline)
    };
    const configurationFormsDirty = dirty.userForm
      || dirty.enterpriseForm
      || dirty.organizationForm
      || dirty.providerForm
      || dirty.ldapProviderForm
      || dirty.applicationForm
      || dirty.invitationForm
      || dirty.roleForm
      || dirty.groupForm
      || dirty.auditWebhookForm
      || dirty.registrationSettings
      || dirty.runtimeSettings
      || dirty.loginSettings
      || dirty.quickLinkForm
      || dirty.securityPolicy;
    const editorDirty = editor === "application" ? dirty.applicationForm
      : editor === "user" ? dirty.userForm
      : editor === "enterprise" ? dirty.enterpriseForm
      : editor === "organization" ? dirty.organizationForm
      : editor === "invitation" ? dirty.invitationForm
      : editor === "role" ? dirty.roleForm
      : editor === "group" ? dirty.groupForm
      : editor === "provider" ? dirty.providerForm
      : editor === "ldap" ? dirty.ldapProviderForm
      : false;
    return { ...dirty, configurationFormsDirty, editorDirty };
  }, [
    applicationForm,
    applicationFormBaseline,
    auditWebhookForm,
    auditWebhookFormBaseline,
    editor,
    enterpriseForm,
    enterpriseFormBaseline,
    groupForm,
    groupFormBaseline,
    invitationForm,
    invitationFormBaseline,
    ldapProviderForm,
    ldapProviderFormBaseline,
    loginSettingsBaseline,
    loginSettingsDraft,
    organizationForm,
    organizationFormBaseline,
    organizationMemberRoles,
    organizationMemberRolesBaseline,
    providerForm,
    providerFormBaseline,
    quickLinkForm,
    quickLinkFormBaseline,
    registrationSettings,
    registrationSettingsBaseline,
    roleForm,
    roleFormBaseline,
    runtimeSettings,
    runtimeSettingsBaseline,
    securityPolicy,
    securityPolicyBaseline,
    userForm,
    userFormBaseline
  ]);
}
