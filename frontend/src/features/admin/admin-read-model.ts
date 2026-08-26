import type {
  AccessGroup,
  AuditEvent,
  AuditWebhook,
  Client,
  ExternalProvider,
  ExternalProviderTemplate,
  Invitation,
  LdapProvider,
  LoginSettings,
  LoginSettingsDraft,
  Organization,
  OrganizationOption,
  Overview,
  PermissionInfo,
  RegistrationSettings,
  Role,
  RuntimeSettings,
  SecurityPolicy,
  SettingsSummary,
  SigningKey,
  TenantApplication,
  UserOption
} from "../../types";

export type AdminReadModel = {
  overview: Overview | null;
  userOptions: UserOption[];
  clients: Client[];
  applications: TenantApplication[];
  invitations: Invitation[];
  registrationSettings: RegistrationSettings | null;
  registrationSettingsBaseline: RegistrationSettings | null;
  providers: ExternalProvider[];
  providerTemplates: ExternalProviderTemplate[];
  ldapProviders: LdapProvider[];
  auditEvents: AuditEvent[];
  auditWebhooks: AuditWebhook[];
  permissionCatalog: PermissionInfo[];
  roles: Role[];
  groups: AccessGroup[];
  organizations: Organization[];
  organizationOptions: OrganizationOption[];
  signingKeys: SigningKey[];
  settings: SettingsSummary | null;
  runtimeSettings: RuntimeSettings | null;
  runtimeSettingsBaseline: RuntimeSettings | null;
  loginSettings: LoginSettings | null;
  loginSettingsBaseline: LoginSettingsDraft | null;
  securityPolicy: SecurityPolicy | null;
  securityPolicyBaseline: SecurityPolicy | null;
};

export type AdminReadModelUpdate<K extends keyof AdminReadModel> =
  | AdminReadModel[K]
  | ((current: AdminReadModel[K]) => AdminReadModel[K]);

export type AdminReadModelUpdater = <K extends keyof AdminReadModel>(
  key: K,
  update: AdminReadModelUpdate<K>
) => void;

export type AdminReadModelSetters = {
  [K in keyof AdminReadModel as `set${Capitalize<K & string>}`]:
    (update: AdminReadModelUpdate<K>) => void;
};

export function createEmptyAdminReadModel(): AdminReadModel {
  return {
    overview: null,
    userOptions: [],
    clients: [],
    applications: [],
    invitations: [],
    registrationSettings: null,
    registrationSettingsBaseline: null,
    providers: [],
    providerTemplates: [],
    ldapProviders: [],
    auditEvents: [],
    auditWebhooks: [],
    permissionCatalog: [],
    roles: [],
    groups: [],
    organizations: [],
    organizationOptions: [],
    signingKeys: [],
    settings: null,
    runtimeSettings: null,
    runtimeSettingsBaseline: null,
    loginSettings: null,
    loginSettingsBaseline: null,
    securityPolicy: null,
    securityPolicyBaseline: null
  };
}

function resolveAdminReadModelUpdate<K extends keyof AdminReadModel>(
  current: AdminReadModel[K],
  update: AdminReadModelUpdate<K>
): AdminReadModel[K] {
  if (typeof update === "function") {
    return (update as (current: AdminReadModel[K]) => AdminReadModel[K])(current);
  }
  return update;
}

function createAdminReadModelSetter<K extends keyof AdminReadModel>(
  key: K,
  updateReadModel: AdminReadModelUpdater
): (update: AdminReadModelUpdate<K>) => void {
  return (update) => updateReadModel(key, update);
}

export function createAdminReadModelSetters(updateReadModel: AdminReadModelUpdater): AdminReadModelSetters {
  return {
    setOverview: createAdminReadModelSetter("overview", updateReadModel),
    setUserOptions: createAdminReadModelSetter("userOptions", updateReadModel),
    setClients: createAdminReadModelSetter("clients", updateReadModel),
    setApplications: createAdminReadModelSetter("applications", updateReadModel),
    setInvitations: createAdminReadModelSetter("invitations", updateReadModel),
    setRegistrationSettings: createAdminReadModelSetter("registrationSettings", updateReadModel),
    setRegistrationSettingsBaseline: createAdminReadModelSetter("registrationSettingsBaseline", updateReadModel),
    setProviders: createAdminReadModelSetter("providers", updateReadModel),
    setProviderTemplates: createAdminReadModelSetter("providerTemplates", updateReadModel),
    setLdapProviders: createAdminReadModelSetter("ldapProviders", updateReadModel),
    setAuditEvents: createAdminReadModelSetter("auditEvents", updateReadModel),
    setAuditWebhooks: createAdminReadModelSetter("auditWebhooks", updateReadModel),
    setPermissionCatalog: createAdminReadModelSetter("permissionCatalog", updateReadModel),
    setRoles: createAdminReadModelSetter("roles", updateReadModel),
    setGroups: createAdminReadModelSetter("groups", updateReadModel),
    setOrganizations: createAdminReadModelSetter("organizations", updateReadModel),
    setOrganizationOptions: createAdminReadModelSetter("organizationOptions", updateReadModel),
    setSigningKeys: createAdminReadModelSetter("signingKeys", updateReadModel),
    setSettings: createAdminReadModelSetter("settings", updateReadModel),
    setRuntimeSettings: createAdminReadModelSetter("runtimeSettings", updateReadModel),
    setRuntimeSettingsBaseline: createAdminReadModelSetter("runtimeSettingsBaseline", updateReadModel),
    setLoginSettings: createAdminReadModelSetter("loginSettings", updateReadModel),
    setLoginSettingsBaseline: createAdminReadModelSetter("loginSettingsBaseline", updateReadModel),
    setSecurityPolicy: createAdminReadModelSetter("securityPolicy", updateReadModel),
    setSecurityPolicyBaseline: createAdminReadModelSetter("securityPolicyBaseline", updateReadModel)
  };
}

export function resolveAdminReadModelUpdateValue<K extends keyof AdminReadModel>(
  current: AdminReadModel[K],
  update: AdminReadModelUpdate<K>
): AdminReadModel[K] {
  return resolveAdminReadModelUpdate(current, update);
}
