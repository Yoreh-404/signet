import type { ExternalProvider, ExternalProviderTemplate, LdapProvider, OrganizationOption } from "../../types";
import type { AdminReadQueryContext } from "./admin-read-query";

export type AdminProvidersQueryOptions = AdminReadQueryContext & {
  canManagePlatformProviders: boolean;
};

export async function loadAdminProvidersQuery({
  loadCached,
  updateReadModel,
  canManagePlatformProviders
}: AdminProvidersQueryOptions): Promise<void> {
  const requests: Promise<unknown>[] = [
    loadCached<ExternalProvider[]>(
      "/api/admin/external-oidc-providers",
      (next) => updateReadModel("providers", next)
    ),
    loadCached<ExternalProviderTemplate[]>(
      "/api/admin/external-oidc-provider-templates",
      (next) => updateReadModel("providerTemplates", next)
    )
  ];
  if (canManagePlatformProviders) {
    requests.push(
      loadCached<LdapProvider[]>(
        "/api/admin/ldap-providers",
        (next) => updateReadModel("ldapProviders", next)
      ),
      loadCached<OrganizationOption[]>(
        "/api/admin/organization-options",
        (next) => updateReadModel("organizationOptions", next)
      )
    );
  }
  await Promise.all(requests);
}
