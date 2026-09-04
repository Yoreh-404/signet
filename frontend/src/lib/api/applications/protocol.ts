import { arrayResponse, objectResponse, readCached, writeJson } from "../transport";
import { appendPathSegment } from "../path-helpers";
import type { ApiMutationOptions, ApiOkResponse, CachedReadOptions } from "../transport";
import type { ApplicationClientBinding, ApplicationJwtClient, Client, IapApplication } from "../../../types";
import { applicationPath } from "./base";

export function applicationClientBindingsPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/client-bindings`;
}

export function applicationOidcClientsPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/oidc-clients`;
}

export function applicationOidcClientPath(applicationId: string, clientId: string): string {
  return appendPathSegment(applicationOidcClientsPath(applicationId), clientId);
}

export function applicationIapRulesPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/iap-rules`;
}

export function applicationIapRulePath(applicationId: string, ruleId: string): string {
  return appendPathSegment(applicationIapRulesPath(applicationId), ruleId);
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

export type ApplicationJwtClientInput = { client_id: string; client_type?: "public" | "confidential"; is_active?: boolean };
export type ApplicationJwtSecretRotationInput = { grace_seconds?: number };
export type ApplicationJwtSecretRotationResponse = { client_id: string; secret: string; created_at: number; grace_seconds: number };

export function listApplicationClientBindings(applicationId: string, options?: CachedReadOptions): Promise<ApplicationClientBinding[]> {
  return readCached<ApplicationClientBinding[]>(applicationClientBindingsPath(applicationId), options, arrayResponse);
}

export function listApplicationOidcClients(applicationId: string, options?: CachedReadOptions): Promise<Client[]> {
  return readCached<Client[]>(applicationOidcClientsPath(applicationId), options, arrayResponse);
}

export function createApplicationOidcClient(applicationId: string, input: ApplicationOidcClientInput, options?: ApiMutationOptions): Promise<Client> {
  return writeJson<Client, ApplicationOidcClientInput>(applicationOidcClientsPath(applicationId), "POST", input, options);
}

export function updateApplicationOidcClient(applicationId: string, clientId: string, input: ApplicationOidcClientInput, options?: ApiMutationOptions): Promise<Client> {
  return writeJson<Client, ApplicationOidcClientInput>(applicationOidcClientPath(applicationId, clientId), "PUT", input, options);
}

export function deleteApplicationOidcClient(applicationId: string, clientId: string, options?: ApiMutationOptions): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationOidcClientPath(applicationId, clientId), "DELETE", undefined, options);
}

export function listApplicationIapRules(applicationId: string, options?: CachedReadOptions): Promise<IapApplication[]> {
  return readCached<IapApplication[]>(applicationIapRulesPath(applicationId), options, arrayResponse);
}

export function createApplicationIapRule(applicationId: string, input: ApplicationIapRuleInput, options?: ApiMutationOptions): Promise<IapApplication> {
  return writeJson<IapApplication, ApplicationIapRuleInput>(applicationIapRulesPath(applicationId), "POST", input, options);
}

export function updateApplicationIapRule(applicationId: string, ruleId: string, input: ApplicationIapRuleInput, options?: ApiMutationOptions): Promise<IapApplication> {
  return writeJson<IapApplication, ApplicationIapRuleInput>(applicationIapRulePath(applicationId, ruleId), "PUT", input, options);
}

export function deleteApplicationIapRule(applicationId: string, ruleId: string, options?: ApiMutationOptions): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationIapRulePath(applicationId, ruleId), "DELETE", undefined, options);
}

export function getApplicationJwtClient(applicationId: string, options?: CachedReadOptions): Promise<ApplicationJwtClient | null> {
  return readCached<ApplicationJwtClient | null>(applicationJwtClientPath(applicationId), options, (value) =>
    value === null ? null : objectResponse<ApplicationJwtClient>(value)
  );
}

export function updateApplicationJwtClient(applicationId: string, input: ApplicationJwtClientInput, options?: ApiMutationOptions): Promise<ApplicationJwtClient> {
  return writeJson<ApplicationJwtClient, ApplicationJwtClientInput>(applicationJwtClientPath(applicationId), "PUT", input, options);
}

export function rotateApplicationJwtSecret(applicationId: string, input: ApplicationJwtSecretRotationInput = {}, options?: ApiMutationOptions): Promise<ApplicationJwtSecretRotationResponse> {
  return writeJson<ApplicationJwtSecretRotationResponse, ApplicationJwtSecretRotationInput>(applicationJwtSecretPath(applicationId), "POST", input, options);
}

export function revokeApplicationJwtSecrets(applicationId: string, options?: ApiMutationOptions): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationJwtSecretsPath(applicationId), "DELETE", undefined, options);
}
