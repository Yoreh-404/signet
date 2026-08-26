import type {
  Client,
  ExternalProvider,
  LdapProvider,
  OrganizationOption,
  TenantApplication
} from "../../types";
import { ignoreForbiddenRead, type AdminReadQueryContext } from "./admin-read-query";

export type AdminApplicationsQueryOptions = AdminReadQueryContext & {
  canManageActiveOrganization: boolean;
  canManagePlatformProviders: boolean;
};

export async function loadAdminApplicationsQuery({
  loadCached,
  updateReadModel,
  canManageActiveOrganization,
  canManagePlatformProviders
}: AdminApplicationsQueryOptions): Promise<void> {
  if (!canManageActiveOrganization) return;

  await Promise.all([
    loadCached<TenantApplication[]>(
      "/api/admin/applications",
      (next) => updateReadModel("applications", next)
    ),
    loadCached<Client[]>("/api/admin/clients", (next) => updateReadModel("clients", next)).catch(ignoreForbiddenRead),
    loadCached<OrganizationOption[]>(
      "/api/admin/organization-options",
      (next) => updateReadModel("organizationOptions", next)
    ).catch(ignoreForbiddenRead),
    loadCached<ExternalProvider[]>(
      "/api/admin/external-oidc-providers",
      (next) => updateReadModel("providers", next)
    ).catch(ignoreForbiddenRead),
    canManagePlatformProviders
      ? loadCached<LdapProvider[]>(
          "/api/admin/ldap-providers",
          (next) => updateReadModel("ldapProviders", next)
        ).catch(ignoreForbiddenRead)
      : Promise.resolve(undefined)
  ]);
}
