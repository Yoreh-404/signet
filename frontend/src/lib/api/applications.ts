import {
  arrayResponse,
  objectResponse,
  readCached,
  writeJson
} from "./transport";
import { appendPathSegment } from "./path-helpers";
import type {
  ApiMutationOptions,
  ApiOkResponse,
  CachedReadOptions
} from "./transport";
import type {
  ApplicationBillingSettings,
  ApplicationClientBinding,
  ApplicationDirectorySyncRun,
  ApplicationEnrollmentCodeCreateResponse,
  ApplicationJwtClient,
  ApplicationModule,
  ApplicationModuleKey,
  ApplicationScimToken,
  Client,
  IapApplication,
  Invitation,
  TenantApplication
} from "../../types";

export type { ApiMutationOptions, ApiOkResponse, CachedReadOptions } from "./transport";

/** The application-management collection. This is intentionally not the
 * legacy global `/api/admin/clients` collection. */
export const APPLICATIONS_PATH = "/api/admin/applications";

export function applicationsPath(): string {
  return APPLICATIONS_PATH;
}

export function applicationPath(applicationId: string): string {
  return appendPathSegment(APPLICATIONS_PATH, applicationId);
}

export function applicationDiscoveryPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/discovery`;
}

export function applicationDiscoverySyncPath(applicationId: string): string {
  return `${applicationDiscoveryPath(applicationId)}/sync`;
}

export function applicationDiscoveryDiscoverPath(): string {
  return "/api/admin/application-discovery/discover";
}

export function applicationClientBindingsPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/client-bindings`;
}

export function applicationOidcClientsPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/oidc-clients`;
}

/** `clientId` is the application binding's database id, not an OIDC client_id. */
export function applicationOidcClientPath(applicationId: string, clientId: string): string {
  return appendPathSegment(applicationOidcClientsPath(applicationId), clientId);
}

export function applicationModulesPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/modules`;
}

export function applicationModulePath(applicationId: string, moduleKey: ApplicationModuleKey): string {
  return appendPathSegment(applicationModulesPath(applicationId), moduleKey);
}

export function applicationBillingSettingsPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/billing-settings`;
}

export function applicationIapRulesPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/iap-rules`;
}

export function applicationIapRulePath(applicationId: string, ruleId: string): string {
  return appendPathSegment(applicationIapRulesPath(applicationId), ruleId);
}

export function applicationDirectorySyncRunsPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/directory-sync/runs`;
}

export function applicationDirectorySyncRunPath(applicationId: string, providerId: string): string {
  return `${appendPathSegment(`${applicationPath(applicationId)}/directory-sync`, providerId)}/run`;
}

export function applicationJwtClientPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/jwt-client`;
}

export function applicationJwtSecretPath(applicationId: string): string {
  return `${applicationJwtClientPath(applicationId)}/secret`;
}

export function applicationJwtSecretsPath(applicationId: string): string {
  return `${applicationJwtClientPath(applicationId)}/secrets`;
}

export function applicationScimTokensPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/scim-tokens`;
}

export function applicationScimTokenPath(applicationId: string, tokenId: string): string {
  return appendPathSegment(applicationScimTokensPath(applicationId), tokenId);
}

export function applicationEnrollmentCodesPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/enrollment-codes`;
}

export function applicationEnrollmentCodePath(applicationId: string, codeId: string): string {
  return appendPathSegment(applicationEnrollmentCodesPath(applicationId), codeId);
}

export type ApplicationInput = {
  slug: string;
  name: string;
  website_url?: string | null;
  description?: string | null;
  account_selection_mode: "optional" | "required";
  unique_identity_factors: Array<"email" | "phone">;
  is_active: boolean;
};

export type ApplicationModuleInput = {
  config: Record<string, unknown>;
  is_enabled?: boolean;
};

export type ApplicationOidcClaimMapperInput = {
  claim_name: string;
  source: string;
  source_value: string;
  value_type: string;
  include_in_id_token: boolean;
  include_in_access_token: boolean;
  include_in_userinfo: boolean;
  is_active: boolean;
  sort_order?: number;
};

/** Payload accepted by the application-scoped OIDC client endpoints. */
export type ApplicationOidcClientInput = {
  client_id: string;
  client_name: string;
  logo_uri?: string;
  organization_id?: string | null;
  client_secret?: string | null;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  scopes: string[];
  audience?: string | null;
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  require_pkce: boolean;
  require_mfa?: boolean;
  require_pushed_authorization_requests?: boolean;
  require_s256_pkce?: boolean;
  require_confidential_client?: boolean;
  require_dpop?: boolean;
  require_account_selection?: boolean;
  trust_email_verified?: boolean;
  authorization_details_types?: string[];
  subject_type: string;
  sector_identifier_uri: string;
  jwks_uri?: string;
  jwks?: string;
  backchannel_logout_uri?: string;
  backchannel_logout_session_required?: boolean;
  frontchannel_logout_uri?: string;
  frontchannel_logout_session_required?: boolean;
  service_account_enabled?: boolean;
  service_account_permissions?: string[];
  is_active: boolean;
  claim_mappers?: ApplicationOidcClaimMapperInput[];
};

export type ApplicationDiscovery = {
  application_id: string;
  management_mode: string;
  website_url: string;
  discovery_url: string | null;
  fetch_secret_configured: boolean;
  signing_key_configured: boolean;
  last_verified_revision: number | null;
  last_verified_version: string | null;
  last_verified_digest: string | null;
  last_verified_expires_at: number | null;
  sync_status: string;
  last_fetched_at: number | null;
  last_success_at: number | null;
  last_error: string | null;
  snapshot_available: boolean;
  operator_disabled: boolean;
  created_at: number;
  updated_at: number;
};

export type ApplicationDiscoveryInput = {
  management_mode?: string;
  website_url?: string;
  fetch_secret?: string;
  signing_public_jwks?: string;
  operator_disabled?: boolean;
};

export type ApplicationDiscoveryDiscoverInput = {
  website_url: string;
  idempotency_key?: string;
};

export type ApplicationBillingSettingsInput = {
  accept_signet_balance?: boolean;
  wallet_mode?: "shared" | "isolated";
  supported_currencies?: string[];
};

export type ApplicationIapRuleInput = {
  slug: string;
  name: string;
  description?: string | null;
  external_host: string;
  path_prefix: string;
  required_organization_id?: string | null;
  required_organization_roles?: string[];
  required_permissions?: string[];
  is_active: boolean;
};

export type ApplicationJwtClientInput = {
  client_id: string;
  client_type?: "public" | "confidential";
  is_active?: boolean;
};

export type ApplicationJwtSecretRotationInput = {
  grace_seconds?: number;
};

export type ApplicationJwtSecretRotationResponse = {
  client_id: string;
  secret: string;
  created_at: number;
  grace_seconds: number;
};

export type ApplicationScimTokenInput = {
  scopes?: string[];
  expires_at?: number | null;
};

export type ApplicationEnrollmentCodeInput = {
  description?: string | null;
  account_kind?: "normal" | "restricted_trial";
  expires_at: number;
  max_uses: number;
  organization_role?: "owner" | "admin" | "member" | string;
  is_active?: boolean;
};

export function listApplications(options?: CachedReadOptions): Promise<TenantApplication[]> {
  return readCached<TenantApplication[]>(applicationsPath(), options, arrayResponse);
}

export function createApplication(
  input: ApplicationInput,
  options?: ApiMutationOptions
): Promise<TenantApplication> {
  return writeJson<TenantApplication, ApplicationInput>(applicationsPath(), "POST", input, options);
}

export function updateApplication(
  applicationId: string,
  input: ApplicationInput,
  options?: ApiMutationOptions
): Promise<TenantApplication> {
  return writeJson<TenantApplication, ApplicationInput>(applicationPath(applicationId), "PUT", input, options);
}

export function deleteApplication(applicationId: string, options?: ApiMutationOptions): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationPath(applicationId), "DELETE", undefined, options);
}

export function getApplicationDiscovery(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationDiscovery> {
  return readCached<ApplicationDiscovery>(applicationDiscoveryPath(applicationId), options, objectResponse);
}

export function updateApplicationDiscovery(
  applicationId: string,
  input: ApplicationDiscoveryInput,
  options?: ApiMutationOptions
): Promise<ApplicationDiscovery> {
  return writeJson<ApplicationDiscovery, ApplicationDiscoveryInput>(
    applicationDiscoveryPath(applicationId),
    "PUT",
    input,
    options
  );
}

export function syncApplicationDiscovery(
  applicationId: string,
  options?: ApiMutationOptions
): Promise<ApplicationDiscovery> {
  return writeJson<ApplicationDiscovery, undefined>(applicationDiscoverySyncPath(applicationId), "POST", undefined, options);
}

export function discoverApplication(
  input: ApplicationDiscoveryDiscoverInput,
  options?: ApiMutationOptions
): Promise<ApplicationDiscovery> {
  return writeJson<ApplicationDiscovery, ApplicationDiscoveryDiscoverInput>(
    applicationDiscoveryDiscoverPath(),
    "POST",
    input,
    options
  );
}

export function listApplicationClientBindings(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationClientBinding[]> {
  return readCached<ApplicationClientBinding[]>(applicationClientBindingsPath(applicationId), options, arrayResponse);
}

export function listApplicationOidcClients(
  applicationId: string,
  options?: CachedReadOptions
): Promise<Client[]> {
  return readCached<Client[]>(applicationOidcClientsPath(applicationId), options, arrayResponse);
}

export function createApplicationOidcClient(
  applicationId: string,
  input: ApplicationOidcClientInput,
  options?: ApiMutationOptions
): Promise<Client> {
  return writeJson<Client, ApplicationOidcClientInput>(applicationOidcClientsPath(applicationId), "POST", input, options);
}

export function updateApplicationOidcClient(
  applicationId: string,
  clientId: string,
  input: ApplicationOidcClientInput,
  options?: ApiMutationOptions
): Promise<Client> {
  return writeJson<Client, ApplicationOidcClientInput>(
    applicationOidcClientPath(applicationId, clientId),
    "PUT",
    input,
    options
  );
}

export function deleteApplicationOidcClient(
  applicationId: string,
  clientId: string,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(
    applicationOidcClientPath(applicationId, clientId),
    "DELETE",
    undefined,
    options
  );
}

/** Modules expose a collection GET; the backend intentionally has no
 * `/modules/{module_key}` GET endpoint. */
export function listApplicationModules(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationModule[]> {
  return readCached<ApplicationModule[]>(applicationModulesPath(applicationId), options, arrayResponse);
}

export function updateApplicationModule(
  applicationId: string,
  moduleKey: ApplicationModuleKey,
  input: ApplicationModuleInput,
  options?: ApiMutationOptions
): Promise<ApplicationModule> {
  return writeJson<ApplicationModule, ApplicationModuleInput>(
    applicationModulePath(applicationId, moduleKey),
    "PUT",
    input,
    options
  );
}

export function deleteApplicationModule(
  applicationId: string,
  moduleKey: ApplicationModuleKey,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationModulePath(applicationId, moduleKey), "DELETE", undefined, options);
}

export function getApplicationBillingSettings(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationBillingSettings> {
  return readCached<ApplicationBillingSettings>(applicationBillingSettingsPath(applicationId), options, objectResponse);
}

export function updateApplicationBillingSettings(
  applicationId: string,
  input: ApplicationBillingSettingsInput,
  options?: ApiMutationOptions
): Promise<ApplicationBillingSettings> {
  return writeJson<ApplicationBillingSettings, ApplicationBillingSettingsInput>(
    applicationBillingSettingsPath(applicationId),
    "PUT",
    input,
    options
  );
}

export function listApplicationIapRules(
  applicationId: string,
  options?: CachedReadOptions
): Promise<IapApplication[]> {
  return readCached<IapApplication[]>(applicationIapRulesPath(applicationId), options, arrayResponse);
}

export function createApplicationIapRule(
  applicationId: string,
  input: ApplicationIapRuleInput,
  options?: ApiMutationOptions
): Promise<IapApplication> {
  return writeJson<IapApplication, ApplicationIapRuleInput>(applicationIapRulesPath(applicationId), "POST", input, options);
}

export function updateApplicationIapRule(
  applicationId: string,
  ruleId: string,
  input: ApplicationIapRuleInput,
  options?: ApiMutationOptions
): Promise<IapApplication> {
  return writeJson<IapApplication, ApplicationIapRuleInput>(
    applicationIapRulePath(applicationId, ruleId),
    "PUT",
    input,
    options
  );
}

export function deleteApplicationIapRule(
  applicationId: string,
  ruleId: string,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationIapRulePath(applicationId, ruleId), "DELETE", undefined, options);
}

export function listApplicationDirectorySyncRuns(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationDirectorySyncRun[]> {
  return readCached<ApplicationDirectorySyncRun[]>(applicationDirectorySyncRunsPath(applicationId), options, arrayResponse);
}

export function runApplicationDirectorySync(
  applicationId: string,
  providerId: string,
  options?: ApiMutationOptions
): Promise<ApplicationDirectorySyncRun> {
  return writeJson<ApplicationDirectorySyncRun, undefined>(
    applicationDirectorySyncRunPath(applicationId, providerId),
    "POST",
    undefined,
    options
  );
}

export function getApplicationJwtClient(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationJwtClient | null> {
  return readCached<ApplicationJwtClient | null>(applicationJwtClientPath(applicationId), options, (value) =>
    value === null ? null : objectResponse<ApplicationJwtClient>(value)
  );
}

export function updateApplicationJwtClient(
  applicationId: string,
  input: ApplicationJwtClientInput,
  options?: ApiMutationOptions
): Promise<ApplicationJwtClient> {
  return writeJson<ApplicationJwtClient, ApplicationJwtClientInput>(applicationJwtClientPath(applicationId), "PUT", input, options);
}

export function rotateApplicationJwtSecret(
  applicationId: string,
  input: ApplicationJwtSecretRotationInput = {},
  options?: ApiMutationOptions
): Promise<ApplicationJwtSecretRotationResponse> {
  return writeJson<ApplicationJwtSecretRotationResponse, ApplicationJwtSecretRotationInput>(
    applicationJwtSecretPath(applicationId),
    "POST",
    input,
    options
  );
}

export function revokeApplicationJwtSecrets(
  applicationId: string,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationJwtSecretsPath(applicationId), "DELETE", undefined, options);
}

export function listApplicationScimTokens(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationScimToken[]> {
  return readCached<ApplicationScimToken[]>(applicationScimTokensPath(applicationId), options, arrayResponse);
}

export function createApplicationScimToken(
  applicationId: string,
  input: ApplicationScimTokenInput,
  options?: ApiMutationOptions
): Promise<ApplicationScimToken> {
  return writeJson<ApplicationScimToken, ApplicationScimTokenInput>(applicationScimTokensPath(applicationId), "POST", input, options);
}

export function revokeApplicationScimToken(
  applicationId: string,
  tokenId: string,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationScimTokenPath(applicationId, tokenId), "DELETE", undefined, options);
}

export function listApplicationEnrollmentCodes(
  applicationId: string,
  options?: CachedReadOptions
): Promise<Invitation[]> {
  return readCached<Invitation[]>(applicationEnrollmentCodesPath(applicationId), options, arrayResponse);
}

export function createApplicationEnrollmentCode(
  applicationId: string,
  input: ApplicationEnrollmentCodeInput,
  options?: ApiMutationOptions
): Promise<ApplicationEnrollmentCodeCreateResponse> {
  return writeJson<ApplicationEnrollmentCodeCreateResponse, ApplicationEnrollmentCodeInput>(
    applicationEnrollmentCodesPath(applicationId),
    "POST",
    input,
    options
  );
}

export function deleteApplicationEnrollmentCode(
  applicationId: string,
  codeId: string,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationEnrollmentCodePath(applicationId, codeId), "DELETE", undefined, options);
}
