import type { UserOrganization } from "../../types";

export type AdminPermissionState = {
  hasGlobalConsolePermission: boolean;
  canAdmin: boolean;
  canReadUsers: boolean;
  canManageUsers: boolean;
  canManageActiveOrganization: boolean;
  canReadOrganizations: boolean;
  canManageOrganizations: boolean;
  canManageAuthorizationCodes: boolean;
  canManageSettings: boolean;
  canManagePlatformProviders: boolean;
  canManageProviders: boolean;
  canReadAudit: boolean;
  canManageSecurity: boolean;
};

type AdminPermissionInput = {
  permissions: readonly string[];
  organization: Pick<UserOrganization, "kind" | "role"> | null;
  restrictedLoginCodeSession: boolean;
};

/**
 * Computes the console capability boundary from session facts only.
 *
 * Keeping this policy pure makes App a composition root instead of another
 * authorization implementation.  Every page receives the same capability
 * decision, while the server remains the final authority for each mutation.
 */
export function deriveAdminPermissions({
  permissions,
  organization,
  restrictedLoginCodeSession
}: AdminPermissionInput): AdminPermissionState {
  const has = (...required: string[]) => required.some((permission) => permissions.includes(permission));
  const canManageActiveOrganization = Boolean(
    organization
      && (
        has("organizations.manage")
        || (
          organization.kind !== "system"
          && (organization.role === "owner" || organization.role === "admin")
        )
      )
  );
  const hasGlobalConsolePermission = permissions.length > 0;
  const canAdmin = !restrictedLoginCodeSession
    && (hasGlobalConsolePermission || canManageActiveOrganization);
  const canManagePlatformProviders = has("providers.manage");

  return {
    hasGlobalConsolePermission,
    canAdmin,
    canReadUsers: has("users.read", "users.manage", "organizations.manage", "security.manage"),
    canManageUsers: has("users.manage"),
    canManageActiveOrganization,
    canReadOrganizations: has("organizations.read", "organizations.manage"),
    canManageOrganizations: has("organizations.manage"),
    canManageAuthorizationCodes: has("authorization_codes.manage"),
    canManageSettings: has("settings.manage"),
    canManagePlatformProviders,
    canManageProviders: canManagePlatformProviders || canManageActiveOrganization,
    canReadAudit: has("audit.read"),
    canManageSecurity: has("security.manage")
  };
}
