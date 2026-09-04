import { adminUserOptionsPath } from "../../lib/api/admin";
import type { UserOption } from "../../types";
import type { AdminReadQueryContext } from "./admin-read-query";

export type AdminUserOptionsQueryOptions = AdminReadQueryContext & {
  enabled: boolean;
};

export async function loadAdminUserOptionsQuery({
  loadCached,
  updateReadModel,
  enabled
}: AdminUserOptionsQueryOptions): Promise<void> {
  if (!enabled) return;

  await loadCached<UserOption[]>(
    adminUserOptionsPath({ status: "live", limit: 200 }),
    (next) => updateReadModel("userOptions", next)
  );
}
