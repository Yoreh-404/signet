import type {
  ApplicationIapRuleInput,
  ApplicationInput,
  ApplicationOidcClientInput
} from "../../lib/api/applications";
import { emptyApplicationForm } from "../../lib/form-defaults";
import type { TenantApplication } from "../../types";
import type { IapRuleDraft } from "./IapModule";
import type { OidcClientDraft } from "./ApplicationOidcClients";

export function toApplicationForm(application: TenantApplication): typeof emptyApplicationForm {
  const protocolModule = application.modules?.find((module) => module.module_key === "protocols");
  const protocolConfig = protocolModule?.config && typeof protocolModule.config === "object"
    ? protocolModule.config
    : {};
  const websiteUrl = typeof protocolConfig.website_url === "string" ? protocolConfig.website_url : "";
  return {
    id: application.id,
    slug: application.slug,
    name: application.name,
    website_url: websiteUrl,
    description: application.description ?? "",
    account_selection_mode: application.account_selection_mode,
    unique_identity_factors: application.unique_identity_factors,
    is_active: application.is_active
  };
}

export function toApplicationPayload(
  form: typeof emptyApplicationForm
): ApplicationInput {
  return {
    slug: form.slug,
    name: form.name,
    website_url: form.website_url.trim() || null,
    description: form.description || null,
    account_selection_mode: form.account_selection_mode,
    unique_identity_factors: form.unique_identity_factors,
    is_active: form.is_active
  };
}

function tokenList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function toOidcClientPayload(
  draft: OidcClientDraft,
  organizationId: string
): ApplicationOidcClientInput {
  return {
    client_id: draft.client_id.trim(),
    client_name: draft.client_name.trim(),
    logo_uri: draft.logo_uri.trim(),
    organization_id: organizationId,
    client_secret: draft.client_secret.trim() || null,
    redirect_uris: draft.redirect_uris
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean),
    post_logout_redirect_uris: draft.post_logout_redirect_uris
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean),
    scopes: tokenList(draft.scopes),
    audience: draft.audience.trim() || null,
    grant_types: tokenList(draft.grant_types),
    response_types: tokenList(draft.response_types),
    token_endpoint_auth_method: draft.token_endpoint_auth_method,
    require_pkce: draft.require_pkce,
    require_mfa: draft.require_mfa,
    require_pushed_authorization_requests: draft.require_pushed_authorization_requests,
    require_s256_pkce: draft.require_s256_pkce,
    require_confidential_client: draft.require_confidential_client,
    require_dpop: draft.require_dpop,
    require_account_selection: draft.require_account_selection,
    trust_email_verified: draft.trust_email_verified,
    authorization_details_types: tokenList(draft.authorization_details_types),
    subject_type: draft.subject_type,
    sector_identifier_uri: draft.sector_identifier_uri.trim(),
    jwks_uri: draft.jwks_uri.trim(),
    jwks: draft.jwks.trim(),
    backchannel_logout_uri: draft.backchannel_logout_uri.trim(),
    backchannel_logout_session_required: draft.backchannel_logout_session_required,
    frontchannel_logout_uri: draft.frontchannel_logout_uri.trim(),
    frontchannel_logout_session_required: draft.frontchannel_logout_session_required,
    service_account_enabled: draft.service_account_enabled,
    service_account_permissions: tokenList(draft.service_account_permissions),
    is_active: draft.is_active,
    claim_mappers: draft.claim_mappers.map((mapper, index) => ({
      claim_name: mapper.claim_name,
      source: mapper.source,
      source_value: mapper.source_value,
      value_type: mapper.value_type,
      include_in_id_token: mapper.include_in_id_token,
      include_in_access_token: mapper.include_in_access_token,
      include_in_userinfo: mapper.include_in_userinfo,
      is_active: mapper.is_active,
      sort_order: mapper.sort_order ?? index
    }))
  };
}

export function toIapRulePayload(draft: IapRuleDraft): ApplicationIapRuleInput {
  return {
    slug: draft.slug.trim(),
    name: draft.name.trim(),
    description: draft.description.trim() || null,
    external_host: draft.external_host.trim(),
    path_prefix: draft.path_prefix.trim() || "/",
    required_organization_id: draft.required_organization_id || null,
    required_organization_roles: draft.required_organization_roles,
    required_permissions: draft.required_permissions
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean),
    is_active: draft.is_active
  };
}
