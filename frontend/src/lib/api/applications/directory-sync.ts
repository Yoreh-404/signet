import { arrayResponse, objectResponse, readCached, writeJson } from "../transport";
import { appendPathSegment } from "../path-helpers";
import type { ApiMutationOptions, ApiOkResponse, CachedReadOptions } from "../transport";
import type { ApplicationDirectorySyncRun, ApplicationScimToken } from "../../../types";
import { applicationPath } from "./base";

export function applicationDiscoveryPath(applicationId: string): string { return `${applicationPath(applicationId)}/discovery`; }
export function applicationDiscoverySyncPath(applicationId: string): string { return `${applicationDiscoveryPath(applicationId)}/sync`; }
export function applicationDiscoveryDiscoverPath(): string { return "/api/admin/application-discovery/discover"; }
export function applicationDirectorySyncRunsPath(applicationId: string): string { return `${applicationPath(applicationId)}/directory-sync/runs`; }
export function applicationDirectorySyncRunPath(applicationId: string, providerId: string): string {
  return `${appendPathSegment(`${applicationPath(applicationId)}/directory-sync`, providerId)}/run`;
}
export function applicationScimTokensPath(applicationId: string): string { return `${applicationPath(applicationId)}/scim-tokens`; }
export function applicationScimTokenPath(applicationId: string, tokenId: string): string { return appendPathSegment(applicationScimTokensPath(applicationId), tokenId); }

export type ApplicationDiscovery = {
  application_id: string; management_mode: string; website_url: string; discovery_url: string | null;
  fetch_secret_configured: boolean; signing_key_configured: boolean; last_verified_revision: number | null;
  last_verified_version: string | null; last_verified_digest: string | null; last_verified_expires_at: number | null;
  sync_status: string; last_fetched_at: number | null; last_success_at: number | null; last_error: string | null;
  snapshot_available: boolean; operator_disabled: boolean; created_at: number; updated_at: number;
};
export type ApplicationDiscoveryInput = { management_mode?: string; website_url?: string; fetch_secret?: string; signing_public_jwks?: string; operator_disabled?: boolean };
export type ApplicationDiscoveryDiscoverInput = { website_url: string; idempotency_key?: string };
export type ApplicationScimTokenInput = { scopes?: string[]; expires_at?: number | null };

export function getApplicationDiscovery(applicationId: string, options?: CachedReadOptions): Promise<ApplicationDiscovery> {
  return readCached<ApplicationDiscovery>(applicationDiscoveryPath(applicationId), options, objectResponse);
}
export function updateApplicationDiscovery(applicationId: string, input: ApplicationDiscoveryInput, options?: ApiMutationOptions): Promise<ApplicationDiscovery> {
  return writeJson<ApplicationDiscovery, ApplicationDiscoveryInput>(applicationDiscoveryPath(applicationId), "PUT", input, options);
}
export function syncApplicationDiscovery(applicationId: string, options?: ApiMutationOptions): Promise<ApplicationDiscovery> {
  return writeJson<ApplicationDiscovery, undefined>(applicationDiscoverySyncPath(applicationId), "POST", undefined, options);
}
export function discoverApplication(input: ApplicationDiscoveryDiscoverInput, options?: ApiMutationOptions): Promise<ApplicationDiscovery> {
  return writeJson<ApplicationDiscovery, ApplicationDiscoveryDiscoverInput>(applicationDiscoveryDiscoverPath(), "POST", input, options);
}
export function listApplicationDirectorySyncRuns(applicationId: string, options?: CachedReadOptions): Promise<ApplicationDirectorySyncRun[]> {
  return readCached<ApplicationDirectorySyncRun[]>(applicationDirectorySyncRunsPath(applicationId), options, arrayResponse);
}
export function runApplicationDirectorySync(applicationId: string, providerId: string, options?: ApiMutationOptions): Promise<ApplicationDirectorySyncRun> {
  return writeJson<ApplicationDirectorySyncRun, undefined>(applicationDirectorySyncRunPath(applicationId, providerId), "POST", undefined, options);
}
export function listApplicationScimTokens(applicationId: string, options?: CachedReadOptions): Promise<ApplicationScimToken[]> {
  return readCached<ApplicationScimToken[]>(applicationScimTokensPath(applicationId), options, arrayResponse);
}
export function createApplicationScimToken(applicationId: string, input: ApplicationScimTokenInput, options?: ApiMutationOptions): Promise<ApplicationScimToken> {
  return writeJson<ApplicationScimToken, ApplicationScimTokenInput>(applicationScimTokensPath(applicationId), "POST", input, options);
}
export function revokeApplicationScimToken(applicationId: string, tokenId: string, options?: ApiMutationOptions): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationScimTokenPath(applicationId, tokenId), "DELETE", undefined, options);
}
