import type { Overview } from "../../types";
import type { AdminReadQueryContext } from "./admin-read-query";

export async function loadAdminOverview({ loadCached, updateReadModel }: AdminReadQueryContext): Promise<void> {
  await loadCached<Overview>("/api/admin/overview", (next) => updateReadModel("overview", next));
}
