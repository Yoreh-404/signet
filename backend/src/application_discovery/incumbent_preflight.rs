//! Read-only validation for a separately approved incumbent admin lane.
//! Nothing calls it in production. A successful preflight cannot mint
//! credentials, change OIDC eligibility, or activate a policy.
#![allow(dead_code)]

use super::{MANAGEMENT_MODE_WEBSITE, axon_signer_pin, axon_v3_acceptance::VerifiedPolicy};
use crate::{AppState, auth, error::AppResult, util};
use axum_extra::extract::cookie::CookieJar;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// One exact binding from trusted operator state. Never populate this from
/// discovery metadata, an OAuth query, or a browser claim.
#[derive(Clone, Copy)]
pub(crate) struct IncumbentPin<'a> {
    pub application_db_id: &'a str,
    pub client_db_id: &'a str,
    pub host_sha256: &'a str,
    pub policy_sha256: &'a str,
    pub signer_pin: &'a str,
    pub revision: i64,
    pub generation: i64,
    pub withdrawn: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct RequestScope<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub resource: &'a str,
    pub redirected_to: &'a str,
    pub scope: &'a str,
    pub challenge_method: &'a str,
    pub challenge: &'a str,
}

fn hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|h| h.len() == 64
        && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// This is an admission precondition, not authorization. Any future caller
/// must obtain the pin and measured Host from its explicitly configured
/// control plane and recheck current state atomically when admitting a code.
pub(crate) async fn matches(
    state: &AppState, jar: &CookieJar, configured: Option<&IncumbentPin<'_>>,
    measured_host: &str, approved: &VerifiedPolicy, request: &RequestScope<'_>,
) -> AppResult<bool> {
    let Some(pin) = configured else { return Ok(false); };
    let policy = approved.policy();
    let callback = format!("{}/admin/api/auth/signet/callback", policy.origin);
    if pin.withdrawn || !hash(pin.host_sha256) || pin.host_sha256 != measured_host
        || pin.policy_sha256 != approved.sha256()
        || pin.revision != policy.revision || pin.generation != policy.generation
        || crate::dcr::is_website_client_id(request.client_id)
        || request.issuer != policy.issuer || request.client_id != policy.client_id
        || request.resource != policy.audience || request.redirected_to != callback
        || request.scope != "openid" || request.challenge_method != "S256"
        || URL_SAFE_NO_PAD.decode(request.challenge).ok().is_none_or(|value| value.len() != 32)
    { return Ok(false); }

    let Some(application) = state.db.find_application_by_id(pin.application_db_id).await? else { return Ok(false); };
    let Some(site) = state.db.find_application_discovery(pin.application_db_id).await? else { return Ok(false); };
    let Some(client) = state.db.find_client_by_client_id(request.client_id).await? else { return Ok(false); };
    let Some(binding) = state.db.find_application_client_binding_by_public_client_id(request.client_id)
        .await? else { return Ok(false); };
    let organization_active = state.db.find_organization_by_id(&policy.organization_id)
        .await?.is_some_and(|org| org.is_active == 1);
    if !organization_active || application.is_active != 1 || application.organization_id != policy.organization_id
        || application.slug != policy.application_id || site.management_mode != MANAGEMENT_MODE_WEBSITE
        || site.operator_disabled != 0 || site.website_url != policy.origin
        || axon_signer_pin(&site.signing_public_jwks).as_deref() != Some(pin.signer_pin)
        || binding.application_id != application.id || binding.client_db_id != pin.client_db_id
        || binding.is_active != 1 || !matches!(binding.protocol.as_str(), "oidc" | "oauth2_oidc")
        || client.id != pin.client_db_id || client.is_active != 1
        || client.organization_id.as_deref() != Some(policy.organization_id.as_str())
        || client.audience != policy.audience || client.redirect_uris()? != [callback]
        || client.token_endpoint_auth_method != "none" || client.require_pkce != 1 || client.require_s256_pkce != 1
        || client.scopes()? != ["openid"] || client.grant_types()? != ["authorization_code"]
        || client.response_types()? != ["code"]
    { return Ok(false); }

    let Some(session) = auth::session_from_cookie(state, jar).await? else { return Ok(false); };
    let Some(user) = state.db.find_user_by_id(&session.user_id).await? else { return Ok(false); };
    if user.is_admin != 1 || user.is_active != 1 || user.archived_at.is_some()
        || session.expires_at <= util::now_ts()
        || session.login_method.as_deref() == Some("authorization_code")
        || state.db.find_trial_enrollment_for_user(&user.id).await?.is_some()
    { return Ok(false); }
    Ok(true)
}
