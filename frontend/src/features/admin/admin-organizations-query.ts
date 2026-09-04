import type { Organization } from "../../types";
import type { AdminReadQueryContext } from "./admin-read-query";
import { loadAdminUserOptionsQuery } from "./admin-user-options-query";

export type AdminOrganizationsQueryOptions = AdminReadQueryContext & {
  canReadOrganizations: boolean;
  canManageOrganizations: boolean;
};

export async function loadAdminOrganizationsQuery({
  loadCached,
  updateReadModel,
  canReadOrganizations,
  canManageOrganizations
}: AdminOrganizationsQueryOptions): Promise<void> {
  if (!canReadOrganizations) return;

  await Promise.all([
    loadCached<Organization[]>("/api/admin/organizations", (next) => {
      updateReadModel("organizations", next);
      updateReadModel(
        "organizationOptions",
        next.map(({ id, slug, name, kind, is_active }: Organization) => ({
          id,
          slug,
          name,
          kind,
          is_active
        }))
      );
    }),
    loadAdminUserOptionsQuery({
      loadCached,
      updateReadModel,
      enabled: canManageOrganizations
    })
  ]);
}
