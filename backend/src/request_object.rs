use crate::{
    AppState, client_assertion,
    db::ClientRecord,
    error::{AppError, AppResult},
    oidc::{self, ResolvedAuthorizeRequest},
    util,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;

const MAX_REQUEST_OBJECT_TTL_SECONDS: i64 = 600;

#[derive(Debug, Deserialize)]
struct RequestObjectPreview {
    client_id: Option<String>,
    iss: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationRequestObject {
    iss: String,
    aud: Value,
    exp: i64,
    iat: Option<i64>,
    nbf: Option<i64>,
    jti: Option<String>,
    client_id: String,
    response_type: String,
    redirect_uri: String,
    scope: Option<String>,
    resource: Option<String>,
    authorization_details: Option<Value>,
    login_hint: Option<String>,
    prompt: Option<String>,
    max_age: Option<i64>,
    acr_values: Option<String>,
    claims: Option<Value>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    response_mode: Option<String>,
}

pub(crate) async fn resolve_authorization_request_object(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    request_object: &str,
    outer_client_id: Option<&str>,
) -> AppResult<ResolvedAuthorizeRequest> {
    let client_id = client_id_from_request_object(request_object)?;
    if outer_client_id.is_some_and(|outer| outer != client_id) {
        return Err(invalid_request_object(
            "outer client_id does not match signed request",
        ));
    }
    let client = state
        .db
        .find_client_by_client_id(&client_id)
        .await?
        .ok_or_else(|| invalid_request_object("client is unknown"))?;
    if client.is_active != 1 {
        return Err(invalid_request_object("client is inactive"));
    }
    resolve_authorization_request_object_for_client(state, headers, &client, request_object).await
}

pub(crate) async fn resolve_authorization_request_object_for_client(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    client: &ClientRecord,
    request_object: &str,
) -> AppResult<ResolvedAuthorizeRequest> {
    let audiences = request_object_audiences(state, headers).await?;
    let claims = client_assertion::verify_signed_client_jwt::<AuthorizationRequestObject>(
        client,
        request_object,
        &audiences,
        &["iss", "aud", "exp"],
        true,
    )
    .await
    .map_err(|_| invalid_request_object("signature or registered key is invalid"))?;
    request_from_claims(&client.client_id, claims)
}

fn request_from_claims(
    expected_client_id: &str,
    claims: AuthorizationRequestObject,
) -> AppResult<ResolvedAuthorizeRequest> {
    if claims.iss != expected_client_id || claims.client_id != expected_client_id {
        return Err(invalid_request_object(
            "request object issuer and client_id must match the client",
        ));
    }
    let now = util::now_ts();
    if claims.exp > now + MAX_REQUEST_OBJECT_TTL_SECONDS {
        return Err(invalid_request_object(
            "request object expires too far in the future",
        ));
    }
    if claims.iat.is_some_and(|iat| iat > now + 60) {
        return Err(invalid_request_object(
            "request object iat is in the future",
        ));
    }
    let _ = (&claims.aud, claims.nbf, &claims.jti);
    Ok(ResolvedAuthorizeRequest {
        source: crate::client_policy::AuthorizationRequestSource::RequestObject,
        response_type: required_claim(claims.response_type, "response_type")?,
        client_id: required_claim(claims.client_id, "client_id")?,
        redirect_uri: required_claim(claims.redirect_uri, "redirect_uri")?,
        scope: optional_claim(claims.scope),
        resource: oidc::normalize_resource(claims.resource.as_deref())?,
        authorization_details: claims.authorization_details.map(|value| value.to_string()),
        login_hint: optional_claim(claims.login_hint),
        prompt: optional_claim(claims.prompt),
        max_age: claims.max_age.map(oidc::validate_max_age).transpose()?,
        acr_values: oidc::normalize_acr_values_param(claims.acr_values.as_deref())?,
        claims: crate::oidc_claims::RequestedClaims::from_request_object_value(claims.claims)?,
        state: optional_claim(claims.state),
        nonce: optional_claim(claims.nonce),
        code_challenge: optional_claim(claims.code_challenge),
        code_challenge_method: optional_claim(claims.code_challenge_method),
        response_mode: optional_claim(claims.response_mode),
        account_selection_prompted: false,
    })
}

fn client_id_from_request_object(request_object: &str) -> AppResult<String> {
    let payload = jwt_payload(request_object)?;
    let preview = serde_json::from_slice::<RequestObjectPreview>(&payload)
        .map_err(|_| invalid_request_object("request object payload is invalid"))?;
    preview
        .client_id
        .or(preview.iss)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_request_object("request object client_id is required"))
}

async fn request_object_audiences(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> AppResult<Vec<String>> {
    let mut audiences = Vec::new();
    for issuer in state.accepted_issuers(headers).await? {
        audiences.push(issuer.trim_end_matches('/').to_string());
        audiences.push(absolute(
            &issuer,
            &state.settings.oidc.authorization_endpoint,
        ));
    }
    audiences.sort();
    audiences.dedup();
    Ok(audiences)
}

fn jwt_payload(token: &str) -> AppResult<Vec<u8>> {
    let mut parts = token.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| invalid_request_object("request object header is missing"))?;
    let payload = parts
        .next()
        .ok_or_else(|| invalid_request_object("request object payload is missing"))?;
    if parts.next().is_none() || parts.next().is_some() {
        return Err(invalid_request_object(
            "request object must be a compact JWT",
        ));
    }
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid_request_object("request object payload is not base64url"))
}

fn required_claim(value: String, field: &str) -> AppResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(invalid_request_object(&format!(
            "request object {field} is required"
        )))
    } else {
        Ok(value)
    }
}

fn optional_claim(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn absolute(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            }
        )
    }
}

fn invalid_request_object(message: &str) -> AppError {
    AppError::Oidc(format!("invalid request object: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestRequestObject<'a> {
        iss: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
        client_id: &'a str,
        response_type: &'a str,
        redirect_uri: &'a str,
        scope: &'a str,
        state: &'a str,
    }

    #[tokio::test]
    async fn signed_request_object_resolves_authorization_request() {
        let (client, private_pem) = client_with_key();
        let now = util::now_ts();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("request-key".to_string());
        let token = encode(
            &header,
            &TestRequestObject {
                iss: "jar-client",
                aud: "https://sso.example.com",
                exp: now + 120,
                iat: now,
                client_id: "jar-client",
                response_type: "code",
                redirect_uri: "https://app.example/callback",
                scope: "openid profile",
                state: "state-1",
            },
            &EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap(),
        )
        .unwrap();
        let claims = client_assertion::verify_signed_client_jwt::<AuthorizationRequestObject>(
            &client,
            &token,
            &["https://sso.example.com".to_string()],
            &["iss", "aud", "exp"],
            true,
        )
        .await
        .unwrap();
        let request = request_from_claims(&client.client_id, claims).unwrap();
        assert_eq!(request.client_id, "jar-client");
        assert_eq!(request.response_type, "code");
        assert_eq!(request.redirect_uri, "https://app.example/callback");
        assert_eq!(request.scope.as_deref(), Some("openid profile"));
        assert_eq!(request.state.as_deref(), Some("state-1"));
    }

    #[test]
    fn request_object_claims_and_acr_values_are_resolved() {
        let now = util::now_ts();
        let request = request_from_claims(
            "jar-client",
            AuthorizationRequestObject {
                iss: "jar-client".to_string(),
                aud: serde_json::json!("https://sso.example.com"),
                exp: now + 120,
                iat: Some(now),
                nbf: None,
                jti: None,
                client_id: "jar-client".to_string(),
                response_type: "code".to_string(),
                redirect_uri: "https://app.example/callback".to_string(),
                scope: Some("openid profile".to_string()),
                resource: None,
                authorization_details: None,
                login_hint: None,
                prompt: None,
                max_age: None,
                acr_values: Some(crate::assurance::ACR_MFA.to_string()),
                claims: Some(serde_json::json!({
                    "id_token": {
                        "amr": { "essential": true, "values": ["otp"] }
                    }
                })),
                state: None,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                response_mode: None,
            },
        )
        .unwrap();

        assert_eq!(
            request.acr_values.as_deref(),
            Some(crate::assurance::ACR_MFA)
        );
        assert_eq!(
            request.claims.unwrap().essential_id_token_values("amr"),
            vec!["otp".to_string()]
        );
    }

    #[test]
    fn request_object_client_id_can_be_read_before_verification() {
        let (_client, private_pem) = client_with_key();
        let now = util::now_ts();
        let token = encode(
            &Header::new(Algorithm::RS256),
            &TestRequestObject {
                iss: "jar-client",
                aud: "https://sso.example.com",
                exp: now + 120,
                iat: now,
                client_id: "jar-client",
                response_type: "code",
                redirect_uri: "https://app.example/callback",
                scope: "openid",
                state: "state-1",
            },
            &EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(client_id_from_request_object(&token).unwrap(), "jar-client");
    }

    fn client_with_key() -> (ClientRecord, String) {
        let private_pem = util::generate_rsa_private_key_pem().unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_pem).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": "request-key",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }]
        })
        .to_string();
        (
            ClientRecord {
                id: "client-db-id".to_string(),
                client_id: "jar-client".to_string(),
                client_secret_hash: None,
                client_name: "JAR Client".to_string(),
                organization_id: None,
                redirect_uris: serde_json::json!(["https://app.example/callback"]).to_string(),
                post_logout_redirect_uris: "[]".to_string(),
                scopes: serde_json::json!(["openid", "profile"]).to_string(),
                grant_types: serde_json::json!(["authorization_code"]).to_string(),
                response_types: serde_json::json!(["code"]).to_string(),
                token_endpoint_auth_method: "none".to_string(),
                require_pkce: 0,
                require_mfa: 0,
                require_pushed_authorization_requests: 0,
                require_s256_pkce: 0,
                require_confidential_client: 0,
                require_dpop: 0,
                require_account_selection: 0,
                trust_email_verified: 0,
                authorization_details_types: "[]".to_string(),
                subject_type: "public".to_string(),
                sector_identifier_uri: String::new(),
                jwks_uri: String::new(),
                jwks,
                backchannel_logout_uri: String::new(),
                backchannel_logout_session_required: 0,
                frontchannel_logout_uri: String::new(),
                frontchannel_logout_session_required: 0,
                service_account_enabled: 0,
                service_account_permissions: "[]".to_string(),
                is_active: 1,
                created_at: 1,
                updated_at: 1,
            },
            private_pem,
        )
    }
}
