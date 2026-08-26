import {
  arrayResponse,
  objectResponse,
  readCached,
  requestJson,
  writeJson
} from "./transport";
import { appendPathSegment } from "./path-helpers";
import type {
  ApiMutationOptions,
  CachedReadOptions
} from "./transport";
import type {
  AccessGroup,
  AuditEvent,
  AuditWebhook,
  BulkUserImportResult,
  Client,
  ExternalProvider,
  ExternalProviderDiscovery,
  ExternalProviderTemplate,
  Invitation,
  InvitationRedemptionsPage,
  IapApplication,
  LdapProvider,
  LoginSettings,
  LoginSettingsDraft,
  Organization,
  OrganizationMember,
  OrganizationMemberInvitationCreateResponse,
  OrganizationOption,
  Overview,
  PermissionInfo,
  Role,
  RegistrationSettings,
  RuntimeSettings,
  SecurityPolicy,
  SigningKey,
  TenantApplication,
  User,
  UserDetail,
  UserAccess,
  UserDirectoryPage,
  UserOption
} from "../../types";

export type AdminCachedReadOptions = CachedReadOptions;

export type AdminUserListQuery = {
  status?: "live" | "active" | "disabled" | "archived" | "authorization_code" | "all";
  organization_id?: string;
  linked_identity?: "all" | "linked" | "unlinked";
  search?: string;
  limit?: number;
};

export type AdminRedemptionListQuery = {
  cursor?: string;
  limit?: number;
};

export type UserLifecycleBatchAction = "enable" | "disable" | "archive" | "delete" | "reset_mfa";

export type UserLifecycleBatchResult = {
  ok: true;
  action: UserLifecycleBatchAction;
  count: number;
};

export type AdminUserMutation = {
  email: string;
  username: string;
  display_name: string | null;
  phone: string | null;
  password: string | null;
  is_admin: boolean;
  is_active: boolean;
};

export type AdminRoleMutation = {
  name: string;
  description: string | null;
  permissions: string[];
};

export type AdminGroupMutation = {
  name: string;
  description: string | null;
};

export type AdminOrganizationMutation = {
  slug: string;
  name: string;
  description: string | null;
  allowed_email_domains: string[];
  is_active: boolean;
};

export type AdminOrganizationMemberCreate = {
  email: string;
  role: string;
};

export type AdminOrganizationMembersReplace = {
  members: Array<{ user_id: string; role: string }>;
};

export type AdminOrganizationInvitationMutation = {
  email: string;
  display_name: string | null;
  description: string | null;
  expires_at: number;
  organization_role: string;
  is_active: boolean;
};

export type AdminMutationOptions = ApiMutationOptions;

export type AdminSecurityPolicyMutation = Omit<SecurityPolicy, "id" | "updated_at">;
export type AdminRegistrationSettingsMutation = RegistrationSettings;
export type AdminRuntimeSettingsMutation = Pick<RuntimeSettings, "public_base_url" | "issuer" | "trust_proxy_headers">;
export type AdminLoginSettingsMutation = {
  brand_logo_url: string;
  email_domains: string[];
  quick_links: LoginSettingsDraft["quick_links"];
};

export type AdminExternalProviderMutation = {
  slug: string;
  display_name: string;
  organization_id: string | null;
  issuer: string;
  client_id: string;
  client_secret: string;
  clear_client_secret: boolean;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  redirect_path: string;
  scopes: string[];
  email_domains: string[];
  is_active: boolean;
  allow_login: boolean;
  allow_registration: boolean;
};

export type AdminLdapProviderMutation = {
  slug: string;
  display_name: string;
  organization_id: string | null;
  url: string;
  starttls: boolean;
  bind_dn: string;
  bind_password: string | null;
  clear_bind_password: boolean;
  base_dn: string;
  user_filter: string;
  user_id_attribute: string;
  email_attribute: string;
  username_attribute: string;
  display_name_attribute: string;
  phone_attribute: string;
  is_active: boolean;
  allow_login: boolean;
  allow_registration: boolean;
};

export type AdminAuditWebhookMutation = {
  name: string;
  url: string;
  secret: string | null;
  clear_secret: boolean;
  actions: string[];
  is_active: boolean;
  timeout_seconds: number;
};

export type AdminAuthorizationCodeMutation = {
  code_type: "registration" | "login";
  login_code_level: "account_recovery" | "trial_enrollment" | "admin_universal" | null;
  allowed_client_ids: string[];
  organization_id: string | null;
  organization_role: string | null;
  description: string | null;
  authorized_email: string | null;
  authorized_username: string | null;
  authorized_display_name: string | null;
  expires_at: number | null;
  max_uses: number | null;
  is_active: boolean;
};

export type AdminAuthorizationCodeCreateResponse = {
  invitation: Invitation;
  code: string;
};

const ADMIN_PATH = "/api/admin";

export function adminUsersPath(query: AdminUserListQuery = {}): string {
  const params = new URLSearchParams();
  if (query.status) params.set("status", query.status);
  if (query.organization_id) params.set("organization_id", query.organization_id);
  if (query.linked_identity && query.linked_identity !== "all") {
    params.set("linked_identity", query.linked_identity);
  }
  if (query.search?.trim()) params.set("search", query.search.trim());
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  const encoded = params.toString();
  return `${ADMIN_PATH}/users${encoded ? `?${encoded}` : ""}`;
}

export function adminUserOptionsPath(query: Omit<AdminUserListQuery, "linked_identity"> = {}): string {
  const params = new URLSearchParams();
  if (query.status) params.set("status", query.status);
  if (query.organization_id) params.set("organization_id", query.organization_id);
  if (query.search?.trim()) params.set("search", query.search.trim());
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  const encoded = params.toString();
  return `${ADMIN_PATH}/user-options${encoded ? `?${encoded}` : ""}`;
}

export function adminClientsPath(): string {
  return `${ADMIN_PATH}/clients`;
}

export function adminApplicationsPath(): string {
  return `${ADMIN_PATH}/applications`;
}

export function adminOverviewPath(): string {
  return `${ADMIN_PATH}/overview`;
}

export function adminSigningKeysPath(): string {
  return `${ADMIN_PATH}/signing-keys`;
}

export function adminSecurityPolicyPath(): string {
  return `${ADMIN_PATH}/security-policy`;
}

export function adminRegistrationSettingsPath(): string {
  return `${ADMIN_PATH}/registration-settings`;
}

export function adminRuntimeSettingsPath(): string {
  return `${ADMIN_PATH}/runtime-settings`;
}

export function adminLoginSettingsPath(): string {
  return `${ADMIN_PATH}/login-settings`;
}

export function adminOrganizationOptionsPath(): string {
  return `${ADMIN_PATH}/organization-options`;
}

export function adminOrganizationsPath(): string {
  return `${ADMIN_PATH}/organizations`;
}

export function adminOrganizationPath(organizationId: string): string {
  return appendPathSegment(adminOrganizationsPath(), organizationId);
}

export function adminOrganizationMembersPath(organizationId: string): string {
  return `${adminOrganizationPath(organizationId)}/members`;
}

export function adminOrganizationMemberInvitationsPath(organizationId: string): string {
  return `${adminOrganizationPath(organizationId)}/member-invitations`;
}

export function createAdminOrganization(
  organization: AdminOrganizationMutation,
  options?: AdminMutationOptions
): Promise<Organization> {
  return writeJson<Organization, AdminOrganizationMutation>(
    adminOrganizationsPath(),
    "POST",
    organization,
    options,
    objectResponse
  );
}

export function updateAdminOrganization(
  organizationId: string,
  organization: AdminOrganizationMutation,
  options?: AdminMutationOptions
): Promise<Organization> {
  return writeJson<Organization, AdminOrganizationMutation>(
    adminOrganizationPath(organizationId),
    "PUT",
    organization,
    options,
    objectResponse
  );
}

export function deleteAdminOrganization(organizationId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(adminOrganizationPath(organizationId), "DELETE", undefined, options);
}

export function addAdminOrganizationMember(
  organizationId: string,
  member: AdminOrganizationMemberCreate,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, AdminOrganizationMemberCreate>(
    adminOrganizationMembersPath(organizationId),
    "POST",
    member,
    options
  );
}

export function replaceAdminOrganizationMembers(
  organizationId: string,
  members: AdminOrganizationMembersReplace,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, AdminOrganizationMembersReplace>(
    adminOrganizationMembersPath(organizationId),
    "PUT",
    members,
    options
  );
}

export function createAdminOrganizationInvitation(
  organizationId: string,
  invitation: AdminOrganizationInvitationMutation,
  options?: AdminMutationOptions
): Promise<OrganizationMemberInvitationCreateResponse> {
  return writeJson<OrganizationMemberInvitationCreateResponse, AdminOrganizationInvitationMutation>(
    adminOrganizationMemberInvitationsPath(organizationId),
    "POST",
    invitation,
    options,
    objectResponse
  );
}

export function deleteAdminOrganizationInvitation(
  organizationId: string,
  invitationId: string,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, undefined>(
    appendPathSegment(adminOrganizationMemberInvitationsPath(organizationId), invitationId),
    "DELETE",
    undefined,
    options
  );
}

export function adminExternalOidcProvidersPath(): string {
  return `${ADMIN_PATH}/external-oidc-providers`;
}

export function adminExternalOidcProviderTemplatesPath(): string {
  return `${ADMIN_PATH}/external-oidc-provider-templates`;
}

export function adminExternalOidcProviderDiscoveryPath(): string {
  return `${ADMIN_PATH}/external-oidc-provider-discovery`;
}

export function adminLdapProvidersPath(): string {
  return `${ADMIN_PATH}/ldap-providers`;
}

export function adminExternalOidcProviderPath(providerId: string): string {
  return appendPathSegment(adminExternalOidcProvidersPath(), providerId);
}

export function adminLdapProviderPath(providerId: string): string {
  return appendPathSegment(adminLdapProvidersPath(), providerId);
}

export function adminAuditEventsPath(): string {
  return `${ADMIN_PATH}/audit-events`;
}

export function adminAuditWebhooksPath(): string {
  return `${ADMIN_PATH}/audit-webhooks`;
}

export function adminAuditWebhookPath(webhookId: string): string {
  return appendPathSegment(adminAuditWebhooksPath(), webhookId);
}

export function adminPermissionsPath(): string {
  return `${ADMIN_PATH}/access/permissions`;
}

export function adminRolesPath(): string {
  return `${ADMIN_PATH}/access/roles`;
}

export function adminGroupsPath(): string {
  return `${ADMIN_PATH}/access/groups`;
}

export function adminIapApplicationsPath(): string {
  return `${ADMIN_PATH}/iap-applications`;
}

export function adminAuthorizationCodesPath(): string {
  return `${ADMIN_PATH}/authorization-codes`;
}

export function adminMutationPath(mutationId: string): string {
  return appendPathSegment(`${ADMIN_PATH}/mutations`, mutationId);
}

export function adminAuthorizationCodeRedemptionsPath(codeId: string, query: AdminRedemptionListQuery = {}): string {
  const params = new URLSearchParams();
  if (query.cursor) params.set("cursor", query.cursor);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  const encoded = params.toString();
  return `${appendPathSegment(adminAuthorizationCodesPath(), codeId)}/redemptions${encoded ? `?${encoded}` : ""}`;
}

export function adminAuthorizationCodePath(codeId: string): string {
  return appendPathSegment(adminAuthorizationCodesPath(), codeId);
}

export function adminAuthorizationCodeRevealPath(codeId: string): string {
  return `${adminAuthorizationCodePath(codeId)}/reveal`;
}

export function adminUserDetailPath(userId: string): string {
  return appendPathSegment(adminUsersPath(), userId);
}

export function adminBulkUserImportPath(dryRun: boolean): string {
  return `${ADMIN_PATH}/users/import-csv?dry_run=${dryRun ? "true" : "false"}`;
}

export function listAdminUsers(
  query: AdminUserListQuery = {},
  options?: AdminCachedReadOptions
): Promise<UserDirectoryPage> {
  return readCached<UserDirectoryPage>(adminUsersPath(query), options, objectResponse);
}

export function importAdminUsersCsv(
  csv: string,
  dryRun: boolean,
  options?: AdminMutationOptions
): Promise<BulkUserImportResult> {
  return requestJson<BulkUserImportResult>(adminBulkUserImportPath(dryRun), {
    ...options,
    method: "POST",
    headers: {
      ...options?.headers,
      "content-type": "text/csv"
    },
    body: csv
  });
}

export function listAdminUserOptions(
  query: Omit<AdminUserListQuery, "linked_identity"> = {},
  options?: AdminCachedReadOptions
): Promise<UserOption[]> {
  return readCached<UserOption[]>(adminUserOptionsPath(query), options, arrayResponse);
}

/** Legacy/global OIDC client list. Application OIDC clients belong in
 * `applications.ts` and use `/api/admin/applications/{id}/oidc-clients`. */
export function listAdminClients(options?: AdminCachedReadOptions): Promise<Client[]> {
  return readCached<Client[]>(adminClientsPath(), options, arrayResponse);
}

export function listAdminApplications(options?: AdminCachedReadOptions): Promise<TenantApplication[]> {
  return readCached<TenantApplication[]>(adminApplicationsPath(), options, arrayResponse);
}

export function getAdminOverview(options?: AdminCachedReadOptions): Promise<Overview> {
  return readCached<Overview>(adminOverviewPath(), options, objectResponse);
}

export function listAdminSigningKeys(options?: AdminCachedReadOptions): Promise<SigningKey[]> {
  return readCached<SigningKey[]>(adminSigningKeysPath(), options, arrayResponse);
}

export function updateAdminSecurityPolicy(
  policy: AdminSecurityPolicyMutation,
  options?: AdminMutationOptions
): Promise<SecurityPolicy> {
  return writeJson<SecurityPolicy, AdminSecurityPolicyMutation>(
    adminSecurityPolicyPath(),
    "PUT",
    policy,
    options,
    objectResponse
  );
}

export function rotateAdminSigningKey(
  kid: string | null,
  options?: AdminMutationOptions
): Promise<SigningKey> {
  return writeJson<SigningKey, { kid: string | null }>(
    adminSigningKeysPath(),
    "POST",
    { kid },
    options,
    objectResponse
  );
}

export function updateAdminRegistrationSettings(
  settings: AdminRegistrationSettingsMutation,
  options?: AdminMutationOptions
): Promise<RegistrationSettings> {
  return writeJson<RegistrationSettings, AdminRegistrationSettingsMutation>(
    adminRegistrationSettingsPath(),
    "PUT",
    settings,
    options,
    objectResponse
  );
}

export function updateAdminRuntimeSettings(
  settings: AdminRuntimeSettingsMutation,
  options?: AdminMutationOptions
): Promise<RuntimeSettings> {
  return writeJson<RuntimeSettings, AdminRuntimeSettingsMutation>(
    adminRuntimeSettingsPath(),
    "PUT",
    settings,
    options,
    objectResponse
  );
}

export function updateAdminLoginSettings(
  settings: AdminLoginSettingsMutation,
  options?: AdminMutationOptions
): Promise<LoginSettings> {
  return writeJson<LoginSettings, AdminLoginSettingsMutation>(
    adminLoginSettingsPath(),
    "PUT",
    settings,
    options,
    objectResponse
  );
}

export function listAdminOrganizationOptions(options?: AdminCachedReadOptions): Promise<OrganizationOption[]> {
  return readCached<OrganizationOption[]>(adminOrganizationOptionsPath(), options, arrayResponse);
}

export function listAdminOrganizations(options?: AdminCachedReadOptions): Promise<Organization[]> {
  return readCached<Organization[]>(adminOrganizationsPath(), options, arrayResponse);
}

export function listAdminOrganizationMembers(
  organizationId: string,
  options?: AdminCachedReadOptions
): Promise<OrganizationMember[]> {
  return readCached<OrganizationMember[]>(adminOrganizationMembersPath(organizationId), options, arrayResponse);
}

export function listAdminOrganizationMemberInvitations(
  organizationId: string,
  options?: AdminCachedReadOptions
): Promise<Invitation[]> {
  return readCached<Invitation[]>(adminOrganizationMemberInvitationsPath(organizationId), options, arrayResponse);
}

export function listAdminExternalOidcProviders(options?: AdminCachedReadOptions): Promise<ExternalProvider[]> {
  return readCached<ExternalProvider[]>(adminExternalOidcProvidersPath(), options, arrayResponse);
}

export function discoverAdminExternalOidcProvider(
  issuer: string,
  options?: AdminMutationOptions
): Promise<ExternalProviderDiscovery> {
  return writeJson<ExternalProviderDiscovery, { issuer: string }>(
    adminExternalOidcProviderDiscoveryPath(),
    "POST",
    { issuer },
    options,
    objectResponse
  );
}

export function createAdminExternalOidcProvider(
  provider: AdminExternalProviderMutation,
  options?: AdminMutationOptions
): Promise<ExternalProvider> {
  return writeJson<ExternalProvider, AdminExternalProviderMutation>(
    adminExternalOidcProvidersPath(),
    "POST",
    provider,
    options,
    objectResponse
  );
}

export function updateAdminExternalOidcProvider(
  providerId: string,
  provider: AdminExternalProviderMutation,
  options?: AdminMutationOptions
): Promise<ExternalProvider> {
  return writeJson<ExternalProvider, AdminExternalProviderMutation>(
    adminExternalOidcProviderPath(providerId),
    "PUT",
    provider,
    options,
    objectResponse
  );
}

export function deleteAdminExternalOidcProvider(providerId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(adminExternalOidcProviderPath(providerId), "DELETE", undefined, options);
}

export function listAdminExternalOidcProviderTemplates(
  options?: AdminCachedReadOptions
): Promise<ExternalProviderTemplate[]> {
  return readCached<ExternalProviderTemplate[]>(adminExternalOidcProviderTemplatesPath(), options, arrayResponse);
}

export function listAdminLdapProviders(options?: AdminCachedReadOptions): Promise<LdapProvider[]> {
  return readCached<LdapProvider[]>(adminLdapProvidersPath(), options, arrayResponse);
}

export function createAdminLdapProvider(
  provider: AdminLdapProviderMutation,
  options?: AdminMutationOptions
): Promise<LdapProvider> {
  return writeJson<LdapProvider, AdminLdapProviderMutation>(adminLdapProvidersPath(), "POST", provider, options, objectResponse);
}

export function updateAdminLdapProvider(
  providerId: string,
  provider: AdminLdapProviderMutation,
  options?: AdminMutationOptions
): Promise<LdapProvider> {
  return writeJson<LdapProvider, AdminLdapProviderMutation>(adminLdapProviderPath(providerId), "PUT", provider, options, objectResponse);
}

export function deleteAdminLdapProvider(providerId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(adminLdapProviderPath(providerId), "DELETE", undefined, options);
}

export function listAdminAuditEvents(options?: AdminCachedReadOptions): Promise<AuditEvent[]> {
  return readCached<AuditEvent[]>(adminAuditEventsPath(), options, arrayResponse);
}

export function listAdminAuditWebhooks(options?: AdminCachedReadOptions): Promise<AuditWebhook[]> {
  return readCached<AuditWebhook[]>(adminAuditWebhooksPath(), options, arrayResponse);
}

export function createAdminAuditWebhook(
  webhook: AdminAuditWebhookMutation,
  options?: AdminMutationOptions
): Promise<AuditWebhook> {
  return writeJson<AuditWebhook, AdminAuditWebhookMutation>(adminAuditWebhooksPath(), "POST", webhook, options, objectResponse);
}

export function updateAdminAuditWebhook(
  webhookId: string,
  webhook: AdminAuditWebhookMutation,
  options?: AdminMutationOptions
): Promise<AuditWebhook> {
  return writeJson<AuditWebhook, AdminAuditWebhookMutation>(adminAuditWebhookPath(webhookId), "PUT", webhook, options, objectResponse);
}

export function deleteAdminAuditWebhook(webhookId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(adminAuditWebhookPath(webhookId), "DELETE", undefined, options);
}

export function listAdminPermissions(options?: AdminCachedReadOptions): Promise<PermissionInfo[]> {
  return readCached<PermissionInfo[]>(adminPermissionsPath(), options, arrayResponse);
}

export function listAdminRoles(options?: AdminCachedReadOptions): Promise<Role[]> {
  return readCached<Role[]>(adminRolesPath(), options, arrayResponse);
}

export function listAdminGroups(options?: AdminCachedReadOptions): Promise<AccessGroup[]> {
  return readCached<AccessGroup[]>(adminGroupsPath(), options, arrayResponse);
}

/** Global IAP list; application-scoped IAP rules belong in `applications.ts`. */
export function listAdminIapApplications(options?: AdminCachedReadOptions): Promise<IapApplication[]> {
  return readCached<IapApplication[]>(adminIapApplicationsPath(), options, arrayResponse);
}

export function listAdminAuthorizationCodes(options?: AdminCachedReadOptions): Promise<Invitation[]> {
  return readCached<Invitation[]>(adminAuthorizationCodesPath(), options, arrayResponse);
}

export function createAdminAuthorizationCode(
  code: AdminAuthorizationCodeMutation,
  options?: AdminMutationOptions
): Promise<AdminAuthorizationCodeCreateResponse> {
  return writeJson<AdminAuthorizationCodeCreateResponse, AdminAuthorizationCodeMutation>(
    adminAuthorizationCodesPath(),
    "POST",
    code,
    options,
    objectResponse
  );
}

export function updateAdminAuthorizationCode(
  codeId: string,
  code: AdminAuthorizationCodeMutation,
  options?: AdminMutationOptions
): Promise<Invitation> {
  return writeJson<Invitation, AdminAuthorizationCodeMutation>(
    adminAuthorizationCodePath(codeId),
    "PUT",
    code,
    options,
    objectResponse
  );
}

export function deleteAdminAuthorizationCode(codeId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(adminAuthorizationCodePath(codeId), "DELETE", undefined, options);
}

export function revealAdminAuthorizationCode(
  codeId: string,
  options?: AdminMutationOptions
): Promise<{ code: string }> {
  return writeJson<{ code: string }, undefined>(adminAuthorizationCodeRevealPath(codeId), "POST", undefined, options, objectResponse);
}

export function listAdminAuthorizationCodeRedemptions(
  codeId: string,
  query: AdminRedemptionListQuery = {},
  options?: AdminCachedReadOptions
): Promise<InvitationRedemptionsPage> {
  return readCached<InvitationRedemptionsPage>(
    adminAuthorizationCodeRedemptionsPath(codeId, query),
    options,
    objectResponse
  );
}

export function getAdminUserDetail(userId: string, options?: AdminCachedReadOptions): Promise<UserDetail> {
  return readCached<UserDetail>(adminUserDetailPath(userId), options, objectResponse);
}

export function createAdminUser(
  user: AdminUserMutation,
  options?: AdminMutationOptions
): Promise<User> {
  return writeJson<User, AdminUserMutation>(adminUsersPath(), "POST", user, options, objectResponse);
}

export function updateAdminUser(
  userId: string,
  user: AdminUserMutation,
  options?: AdminMutationOptions
): Promise<User> {
  return writeJson<User, AdminUserMutation>(
    adminUserDetailPath(userId),
    "PUT",
    user,
    options,
    objectResponse
  );
}

export function createAdminRole(
  role: AdminRoleMutation,
  options?: AdminMutationOptions
): Promise<Role> {
  return writeJson<Role, AdminRoleMutation>(adminRolesPath(), "POST", role, options, objectResponse);
}

export function updateAdminRole(
  roleId: string,
  role: AdminRoleMutation,
  options?: AdminMutationOptions
): Promise<Role> {
  return writeJson<Role, AdminRoleMutation>(
    appendPathSegment(adminRolesPath(), roleId),
    "PUT",
    role,
    options,
    objectResponse
  );
}

export function deleteAdminRole(roleId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(appendPathSegment(adminRolesPath(), roleId), "DELETE", undefined, options);
}

export function createAdminGroup(
  group: AdminGroupMutation,
  options?: AdminMutationOptions
): Promise<AccessGroup> {
  return writeJson<AccessGroup, AdminGroupMutation>(adminGroupsPath(), "POST", group, options, objectResponse);
}

export function updateAdminGroup(
  groupId: string,
  group: AdminGroupMutation,
  options?: AdminMutationOptions
): Promise<AccessGroup> {
  return writeJson<AccessGroup, AdminGroupMutation>(
    appendPathSegment(adminGroupsPath(), groupId),
    "PUT",
    group,
    options,
    objectResponse
  );
}

export function updateAdminGroupRoles(
  groupId: string,
  roleIds: string[],
  options?: AdminMutationOptions
): Promise<AccessGroup> {
  return writeJson<AccessGroup, { role_ids: string[] }>(
    `${appendPathSegment(adminGroupsPath(), groupId)}/roles`,
    "PUT",
    { role_ids: roleIds },
    options,
    objectResponse
  );
}

export function updateAdminGroupMembers(
  groupId: string,
  userIds: string[],
  options?: AdminMutationOptions
): Promise<AccessGroup> {
  return writeJson<AccessGroup, { user_ids: string[] }>(
    `${appendPathSegment(adminGroupsPath(), groupId)}/members`,
    "PUT",
    { user_ids: userIds },
    options,
    objectResponse
  );
}

export function deleteAdminGroup(groupId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(appendPathSegment(adminGroupsPath(), groupId), "DELETE", undefined, options);
}

export function adminUserAccessPath(userId: string): string {
  return `${adminUserDetailPath(userId)}/access`;
}

export function getAdminUserAccess(
  userId: string,
  options?: AdminCachedReadOptions
): Promise<UserAccess> {
  return readCached<UserAccess>(adminUserAccessPath(userId), options, objectResponse);
}

export function updateAdminUserRoles(
  userId: string,
  roleIds: string[],
  options?: AdminMutationOptions
): Promise<UserAccess> {
  return writeJson<UserAccess, { role_ids: string[] }>(
    `${adminUserDetailPath(userId)}/roles`,
    "PUT",
    { role_ids: roleIds },
    options,
    objectResponse
  );
}

export function enableAdminUser(
  userId: string,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, undefined>(`${adminUserDetailPath(userId)}/enable`, "POST", undefined, options);
}

export function advanceAdminUserLifecycle(
  userId: string,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, undefined>(adminUserDetailPath(userId), "DELETE", undefined, options);
}

export function resetAdminUserMfa(
  userId: string,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, undefined>(`${adminUserDetailPath(userId)}/mfa/reset`, "POST", undefined, options);
}

export function applyAdminUserLifecycle(
  action: UserLifecycleBatchAction,
  userIds: string[],
  options?: AdminMutationOptions
): Promise<UserLifecycleBatchResult> {
  return writeJson<UserLifecycleBatchResult, { action: UserLifecycleBatchAction; user_ids: string[] }>(
    `${ADMIN_PATH}/users/bulk-lifecycle`,
    "POST",
    { action, user_ids: userIds },
    options,
    objectResponse
  );
}
