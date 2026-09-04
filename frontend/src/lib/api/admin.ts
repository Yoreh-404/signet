export * from "./admin-shared";
export * from "./admin-users";
export * from "./admin-organizations";
export * from "./admin-providers";
export * from "./admin-security";

import { arrayResponse, objectResponse, readCached } from "./transport";
import type {
  Client,
  IapApplication,
  Overview,
  TenantApplication
} from "../../types";
import type { AdminCachedReadOptions } from "./admin-shared";

const ADMIN_PATH = "/api/admin";

export function adminClientsPath(): string {
  return `${ADMIN_PATH}/clients`;
}

export function adminApplicationsPath(): string {
  return `${ADMIN_PATH}/applications`;
}

export function adminOverviewPath(): string {
  return `${ADMIN_PATH}/overview`;
}

export function adminIapApplicationsPath(): string {
  return `${ADMIN_PATH}/iap-applications`;
}

export function listAdminClients(options?: AdminCachedReadOptions): Promise<Client[]> {
  return readCached<Client[]>(adminClientsPath(), options, arrayResponse);
}

export function listAdminApplications(options?: AdminCachedReadOptions): Promise<TenantApplication[]> {
  return readCached<TenantApplication[]>(adminApplicationsPath(), options, arrayResponse);
}

export function getAdminOverview(options?: AdminCachedReadOptions): Promise<Overview> {
  return readCached<Overview>(adminOverviewPath(), options, objectResponse);
}

/** Global IAP list; application-scoped IAP rules belong in `applications.ts`. */
export function listAdminIapApplications(options?: AdminCachedReadOptions): Promise<IapApplication[]> {
  return readCached<IapApplication[]>(adminIapApplicationsPath(), options, arrayResponse);
}
