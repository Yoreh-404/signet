import {
  arrayResponse,
  objectResponse,
  readCached,
  writeJson
} from "./transport";
import { appendPathSegment } from "./path-helpers";
import type { AdminCachedReadOptions, AdminMutationOptions } from "./admin-shared";
import type {
  AccessGroup,
  AuditEvent,
  AuditWebhook,
  Invitation,
  InvitationRedemptionsPage,
  LoginSettings,
  LoginSettingsDraft,
  PermissionInfo,
  RegistrationSettings,
  Role,
  RuntimeSettings,
  SecurityPolicy,
  SigningKey
} from "../../types";

const ADMIN_PATH = "/api/admin";

export type AdminRoleMutation = {
  name: string;
  description: string | null;
  permissions: string[];
};

export type AdminGroupMutation = {
  name: string;
  description: string | null;
};

export type AdminSecurityPolicyMutation = Omit<SecurityPolicy, "id" | "updated_at">;
export type AdminRegistrationSettingsMutation = RegistrationSettings;
export type AdminRuntimeSettingsMutation = Pick<RuntimeSettings, "public_base_url" | "issuer" | "trust_proxy_headers">;
export type AdminLoginSettingsMutation = {
  brand_logo_url: string;
  email_domains: string[];
  quick_links: LoginSettingsDraft["quick_links"];
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

export type AdminRedemptionListQuery = {
  cursor?: string;
  limit?: number;
};

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

export function listAdminSigningKeys(options?: AdminCachedReadOptions): Promise<SigningKey[]> {
  return readCached<SigningKey[]>(adminSigningKeysPath(), options, arrayResponse);
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
