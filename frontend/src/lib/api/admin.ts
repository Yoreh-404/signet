import {
  arrayResponse,
  objectResponse,
  pathSegment,
  readCached,
  writeJson
} from "./transport";
import type {
  ApiMutationOptions,
  CachedReadOptions
} from "./transport";
import type {
  AccessGroup,
  AuditEvent,
  AuditWebhook,
  Client,
  ExternalProvider,
  ExternalProviderTemplate,
  Invitation,
  InvitationRedemptionsPage,
  IapApplication,
  LdapProvider,
  Organization,
  OrganizationMember,
  OrganizationOption,
  Overview,
  PermissionInfo,
  Role,
  SigningKey,
  TenantApplication,
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

export type AdminMutationOptions = ApiMutationOptions;

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

export function adminOrganizationOptionsPath(): string {
  return `${ADMIN_PATH}/organization-options`;
}

export function adminOrganizationsPath(): string {
  return `${ADMIN_PATH}/organizations`;
}

export function adminOrganizationPath(organizationId: string): string {
  return `${adminOrganizationsPath()}/${pathSegment(organizationId)}`;
}

export function adminOrganizationMembersPath(organizationId: string): string {
  return `${adminOrganizationPath(organizationId)}/members`;
}

export function adminOrganizationMemberInvitationsPath(organizationId: string): string {
  return `${adminOrganizationPath(organizationId)}/member-invitations`;
}

export function adminExternalOidcProvidersPath(): string {
  return `${ADMIN_PATH}/external-oidc-providers`;
}

export function adminExternalOidcProviderTemplatesPath(): string {
  return `${ADMIN_PATH}/external-oidc-provider-templates`;
}

export function adminLdapProvidersPath(): string {
  return `${ADMIN_PATH}/ldap-providers`;
}

export function adminAuditEventsPath(): string {
  return `${ADMIN_PATH}/audit-events`;
}

export function adminAuditWebhooksPath(): string {
  return `${ADMIN_PATH}/audit-webhooks`;
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
  return `${ADMIN_PATH}/mutations/${pathSegment(mutationId)}`;
}

export function adminAuthorizationCodeRedemptionsPath(codeId: string, query: AdminRedemptionListQuery = {}): string {
  const params = new URLSearchParams();
  if (query.cursor) params.set("cursor", query.cursor);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  const encoded = params.toString();
  return `${adminAuthorizationCodesPath()}/${pathSegment(codeId)}/redemptions${encoded ? `?${encoded}` : ""}`;
}

export function adminUserDetailPath(userId: string): string {
  return `${adminUsersPath()}/${pathSegment(userId)}`;
}

export function listAdminUsers(
  query: AdminUserListQuery = {},
  options?: AdminCachedReadOptions
): Promise<UserDirectoryPage> {
  return readCached<UserDirectoryPage>(adminUsersPath(query), options, objectResponse);
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

export function listAdminExternalOidcProviderTemplates(
  options?: AdminCachedReadOptions
): Promise<ExternalProviderTemplate[]> {
  return readCached<ExternalProviderTemplate[]>(adminExternalOidcProviderTemplatesPath(), options, arrayResponse);
}

export function listAdminLdapProviders(options?: AdminCachedReadOptions): Promise<LdapProvider[]> {
  return readCached<LdapProvider[]>(adminLdapProvidersPath(), options, arrayResponse);
}

export function listAdminAuditEvents(options?: AdminCachedReadOptions): Promise<AuditEvent[]> {
  return readCached<AuditEvent[]>(adminAuditEventsPath(), options, arrayResponse);
}

export function listAdminAuditWebhooks(options?: AdminCachedReadOptions): Promise<AuditWebhook[]> {
  return readCached<AuditWebhook[]>(adminAuditWebhooksPath(), options, arrayResponse);
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
