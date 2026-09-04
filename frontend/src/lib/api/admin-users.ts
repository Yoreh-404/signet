import {
  arrayResponse,
  objectResponse,
  readCached,
  requestJson,
  writeJson
} from "./transport";
import { appendPathSegment } from "./path-helpers";
import type { AdminCachedReadOptions, AdminMutationOptions } from "./admin-shared";
import type {
  AccessGroup,
  BulkUserImportResult,
  User,
  UserAccess,
  UserDetail,
  UserDirectoryPage,
  UserOption
} from "../../types";

const ADMIN_PATH = "/api/admin";

export type AdminUserListQuery = {
  status?: "live" | "active" | "disabled" | "archived" | "authorization_code" | "all";
  organization_id?: string;
  linked_identity?: "all" | "linked" | "unlinked";
  search?: string;
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
