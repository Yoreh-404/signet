import { adminUserOptionsPath } from "../../lib/api/admin";
import type {
  AccessGroup,
  AuditEvent,
  AuditWebhook,
  PermissionInfo,
  Role,
  SecurityPolicy,
  SigningKey,
  UserOption
} from "../../types";
import { ignoreForbiddenRead, type AdminReadQueryContext } from "./admin-read-query";

export type AdminSecurityQueryOptions = AdminReadQueryContext & {
  canManageSecurity: boolean;
  canReadAudit: boolean;
};

export async function loadAdminSecurityQuery({
  loadCached,
  updateReadModel,
  canManageSecurity,
  canReadAudit
}: AdminSecurityQueryOptions): Promise<void> {
  if (!canManageSecurity && !canReadAudit) return;

  await Promise.all([
    canManageSecurity
      ? loadCached<SecurityPolicy>("/api/admin/security-policy", (next) => {
          updateReadModel("securityPolicy", next);
          updateReadModel("securityPolicyBaseline", next);
        })
      : Promise.resolve(undefined),
    canManageSecurity
      ? loadCached<SigningKey[]>("/api/admin/signing-keys", (next) => updateReadModel("signingKeys", next))
      : Promise.resolve(undefined),
    canManageSecurity
      ? loadCached<PermissionInfo[]>(
          "/api/admin/access/permissions",
          (next) => updateReadModel("permissionCatalog", next)
        )
      : Promise.resolve(undefined),
    canManageSecurity
      ? loadCached<Role[]>("/api/admin/access/roles", (next) => updateReadModel("roles", next))
      : Promise.resolve(undefined),
    canManageSecurity
      ? loadCached<AccessGroup[]>("/api/admin/access/groups", (next) => updateReadModel("groups", next))
      : Promise.resolve(undefined),
    canManageSecurity
      ? loadCached<UserOption[]>(
          adminUserOptionsPath({ status: "live", limit: 200 }),
          (next) => updateReadModel("userOptions", next)
        )
      : Promise.resolve(undefined),
    canReadAudit
      ? loadCached<AuditEvent[]>("/api/admin/audit-events", (next) => updateReadModel("auditEvents", next))
      : Promise.resolve(undefined),
    loadCached<AuditWebhook[]>(
      "/api/admin/audit-webhooks",
      (next) => updateReadModel("auditWebhooks", next)
    )
  ]);
}
