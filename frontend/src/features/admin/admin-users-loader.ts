import type { OrganizationOption } from "../../types";
import { ignoreForbiddenRead, type AdminReadQueryContext } from "./admin-read-query";

export type AdminUsersLoaderOptions = AdminReadQueryContext & {
  canReadUsers: boolean;
};

export async function loadAdminUsers({
  loadCached,
  updateReadModel,
  canReadUsers
}: AdminUsersLoaderOptions): Promise<void> {
  if (!canReadUsers) return;

  await loadCached<OrganizationOption[]>(
    "/api/admin/organization-options",
    (next) => updateReadModel("organizationOptions", next)
  ).catch(ignoreForbiddenRead);
}
