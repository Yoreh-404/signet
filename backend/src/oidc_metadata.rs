use super::absolute;
use crate::{AppState, assurance, client_assertion, dpop, error::AppResult, oidc_claims, subject};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
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
    let authorization_details_types_supported = state.oidc_authorization_details_types().await?;
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

pub(super) async fn jwks(
    State(state): State<AppState>,
    request_headers: HeaderMap,
) -> AppResult<Response> {
    let (jwks, etag) = state.jwt.jwks_snapshot()?;
    let etag = format!("\"{etag}\"");
    let cache_control = format!(
        "public, max-age={}, must-revalidate",
        state.settings.performance.public_jwks_cache_seconds
    );
    let mut response = if request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| if_none_match_matches(value, &etag))
    {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Json(jwks).into_response()
    };
    let headers = response.headers_mut();
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|_| {
            crate::error::AppError::Internal("generated JWKS ETag is invalid".to_string())
        })?,
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&cache_control).map_err(|_| {
            crate::error::AppError::Internal("generated JWKS cache policy is invalid".to_string())
        })?,
    );
    Ok(response)
}

fn if_none_match_matches(value: &str, current: &str) -> bool {
    let current = current.trim_start_matches("W/");
    value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == current)
}

#[cfg(test)]
mod tests {
    use super::if_none_match_matches;

    #[test]
    fn jwks_if_none_match_uses_weak_comparison_and_lists() {
        let current = "\"signet-jwks-abc\"";
        assert!(if_none_match_matches(current, current));
        assert!(if_none_match_matches("W/\"signet-jwks-abc\"", current));
        assert!(if_none_match_matches(
            "\"other\", W/\"signet-jwks-abc\"",
            current
        ));
        assert!(if_none_match_matches("*", current));
        assert!(!if_none_match_matches("\"other\"", current));
    }
}
