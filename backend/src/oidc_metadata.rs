use super::absolute;
use crate::{
    AppState, assurance, authorization_details, client_assertion, dpop, error::AppResult,
    oidc_claims, subject,
};
use axum::{Json, extract::State, http::HeaderMap};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    pushed_authorization_request_endpoint: String,
    require_pushed_authorization_requests: bool,
    device_authorization_endpoint: String,
    token_endpoint: String,
    introspection_endpoint: String,
    revocation_endpoint: String,
    resource_parameter_supported: bool,
    authorization_details_parameter_supported: bool,
    authorization_details_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_endpoint: Option<String>,
    userinfo_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: String,
    backchannel_logout_supported: bool,
    backchannel_logout_session_supported: bool,
    frontchannel_logout_supported: bool,
    frontchannel_logout_session_supported: bool,
    response_types_supported: Vec<&'static str>,
    response_modes_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    authorization_signing_alg_values_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    dpop_signing_alg_values_supported: Vec<&'static str>,
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    request_object_signing_alg_values_supported: Vec<&'static str>,
    claims_parameter_supported: bool,
    acr_values_supported: Vec<&'static str>,
    scopes_supported: Vec<String>,
    claims_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
}

pub(super) async fn discovery(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<DiscoveryDocument>> {
    let issuer = state.effective_issuer(&headers).await?;
    let authorization_details_types_supported =
        authorization_details::supported_types_from_clients(&state.db.list_clients().await?)?;
    Ok(Json(DiscoveryDocument {
        issuer: issuer.clone(),
        authorization_endpoint: absolute(&issuer, &state.settings.oidc.authorization_endpoint),
        pushed_authorization_request_endpoint: absolute(&issuer, "/oauth2/par"),
        require_pushed_authorization_requests: false,
        device_authorization_endpoint: absolute(&issuer, "/oauth2/device_authorization"),
        token_endpoint: absolute(&issuer, &state.settings.oidc.token_endpoint),
        introspection_endpoint: absolute(&issuer, "/oauth2/introspect"),
        revocation_endpoint: absolute(&issuer, "/oauth2/revoke"),
        resource_parameter_supported: true,
        authorization_details_parameter_supported: true,
        authorization_details_types_supported,
        registration_endpoint: state
            .settings
            .oidc
            .allow_dynamic_client_registration
            .then(|| absolute(&issuer, "/connect/register")),
        userinfo_endpoint: absolute(&issuer, &state.settings.oidc.userinfo_endpoint),
        jwks_uri: absolute(&issuer, &state.settings.oidc.jwks_uri),
        end_session_endpoint: absolute(&issuer, &state.settings.oidc.end_session_endpoint),
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        frontchannel_logout_supported: true,
        frontchannel_logout_session_supported: true,
        response_types_supported: vec!["code"],
        response_modes_supported: crate::jarm::SUPPORTED_RESPONSE_MODES.to_vec(),
        grant_types_supported: vec![
            "authorization_code",
            "refresh_token",
            "client_credentials",
            crate::device::DEVICE_CODE_GRANT,
            crate::token_exchange::TOKEN_EXCHANGE_GRANT,
        ],
        subject_types_supported: vec![subject::SUBJECT_TYPE_PUBLIC, subject::SUBJECT_TYPE_PAIRWISE],
        id_token_signing_alg_values_supported: vec!["RS256"],
        authorization_signing_alg_values_supported: crate::jarm::SUPPORTED_SIGNING_ALGS.to_vec(),
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic",
            "client_secret_post",
            client_assertion::CLIENT_SECRET_JWT,
            client_assertion::PRIVATE_KEY_JWT,
            "none",
        ],
        token_endpoint_auth_signing_alg_values_supported:
            client_assertion::TOKEN_ENDPOINT_AUTH_SIGNING_ALGS.to_vec(),
        dpop_signing_alg_values_supported: dpop::SUPPORTED_SIGNING_ALGS.to_vec(),
        request_parameter_supported: true,
        request_uri_parameter_supported: true,
        request_object_signing_alg_values_supported: client_assertion::SUPPORTED_SIGNING_ALGS
            .to_vec(),
        claims_parameter_supported: true,
        acr_values_supported: assurance::SUPPORTED_ACR_VALUES.to_vec(),
        scopes_supported: state.settings.oidc.supported_scopes.clone(),
        claims_supported: oidc_claims::SUPPORTED_CLAIMS.to_vec(),
        code_challenge_methods_supported: vec!["plain", "S256"],
    }))
}

pub(super) async fn jwks(State(state): State<AppState>) -> Json<crate::jwt::Jwks> {
    Json(state.jwt.jwks())
}
