import { adminUserOptionsPath } from "../../lib/api/admin";
import type { Organization, UserOption } from "../../types";
import type { AdminReadQueryContext } from "./admin-read-query";

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
    canManageOrganizations
      ? loadCached<UserOption[]>(
          adminUserOptionsPath({ status: "live", limit: 200 }),
          (next) => updateReadModel("userOptions", next)
        )
      : Promise.resolve(undefined)
  ]);
}
