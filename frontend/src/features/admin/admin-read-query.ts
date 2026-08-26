import { ApiError } from "../../lib/api";
import type { AdminReadModelUpdater } from "./use-admin-data-loader";

export type AdminCachedLoader = <T>(
  path: string,
  apply: (value: T) => void
) => Promise<T>;

export type AdminReadQueryContext = {
  loadCached: AdminCachedLoader;
  updateReadModel: AdminReadModelUpdater;
};

export function ignoreForbiddenRead(error: unknown): undefined {
  if (error instanceof ApiError && error.status === 403) return undefined;
  throw error;
}
