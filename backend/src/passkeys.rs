use crate::{
    AppState, auth,
    db::{PasskeyRecord, PublicPasskey, UserRecord, WebauthnChallengeRecord},
    error::{AppError, AppResult},
    security_policy, util,
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    routing::{delete, get, post},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use url::Url;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Uuid, Webauthn,
    WebauthnBuilder,
};

const REGISTRATION_PURPOSE: &str = "passkey_registration";
const AUTHENTICATION_PURPOSE: &str = "passkey_authentication";
const WEBAUTHN_CHALLENGE_TTL_SECONDS: i64 = 300;

#[allow(async_fn_in_trait)]
pub trait PasskeyStore {
    async fn list_user_passkeys(&self, user_id: &str) -> AppResult<Vec<PasskeyRecord>>;
    async fn find_credential(&self, credential_id: &str) -> AppResult<Option<PasskeyRecord>>;
    async fn insert_user_passkey(
        &self,
        user_id: &str,
        credential_id: String,
        name: String,
        passkey_json: String,
    ) -> AppResult<PasskeyRecord>;
    async fn update_user_passkey_after_authentication(
        &self,
        id: &str,
        passkey_json: String,
    ) -> AppResult<PasskeyRecord>;
    async fn delete_user_passkey(&self, user_id: &str, id: &str) -> AppResult<()>;
}

impl PasskeyStore for crate::db::Db {
    async fn list_user_passkeys(&self, user_id: &str) -> AppResult<Vec<PasskeyRecord>> {
        self.list_passkeys(user_id).await
    }

    async fn find_credential(&self, credential_id: &str) -> AppResult<Option<PasskeyRecord>> {
        self.find_passkey_by_credential_id(credential_id).await
    }

    async fn insert_user_passkey(
        &self,
        user_id: &str,
        credential_id: String,
        name: String,
        passkey_json: String,
    ) -> AppResult<PasskeyRecord> {
        self.insert_passkey(user_id, credential_id, name, passkey_json)
            .await
    }

    async fn update_user_passkey_after_authentication(
        &self,
        id: &str,
        passkey_json: String,
    ) -> AppResult<PasskeyRecord> {
        self.update_passkey_after_authentication(id, passkey_json)
            .await
    }

    async fn delete_user_passkey(&self, user_id: &str, id: &str) -> AppResult<()> {
        self.delete_passkey(user_id, id).await
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/passkeys", get(list_passkeys))
        .route("/api/passkeys/registration/start", post(start_registration))
        .route(
            "/api/passkeys/registration/finish",
            post(finish_registration),
        )
        .route("/api/passkeys/{id}", delete(delete_passkey))
        .route(
            "/api/passkeys/authentication/start",
            post(start_authentication),
        )
        .route(
            "/api/passkeys/authentication/finish",
            post(finish_authentication),
        )
}

#[derive(Debug, Deserialize)]
struct StartRegistrationRequest {
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct StartRegistrationResponse {
    challenge_id: String,
    public_key: CreationChallengeResponse,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct FinishRegistrationRequest {
    challenge_id: String,
    name: Option<String>,
    credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
struct StartAuthenticationRequest {
    email: String,
}

#[derive(Debug, Serialize)]
struct StartAuthenticationResponse {
    challenge_id: String,
    public_key: RequestChallengeResponse,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct FinishAuthenticationRequest {
    challenge_id: String,
    credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
struct FinishAuthenticationResponse {
    user: auth::CurrentUserResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebauthnRuntimeConfig {
    pub origin: Url,
    pub rp_id: String,
}

impl WebauthnRuntimeConfig {
    pub fn from_public_base_url(public_base_url: &str) -> AppResult<Self> {
        let mut origin = Url::parse(public_base_url.trim())
            .map_err(|err| AppError::BadRequest(format!("invalid WebAuthn public URL: {err}")))?;
        match origin.scheme() {
            "http" | "https" => {}
            other => {
                return Err(AppError::BadRequest(format!(
                    "WebAuthn public URL must use http or https, got {other}"
                )));
            }
        }
        origin.set_path("");
        origin.set_query(None);
        origin.set_fragment(None);
        let host = origin
            .host_str()
            .ok_or_else(|| {
                AppError::BadRequest("WebAuthn public URL must include a host".to_string())
            })?
            .to_ascii_lowercase();
        if host.contains(':') {
            return Err(AppError::BadRequest(
                "WebAuthn RP ID cannot be an IPv6 literal".to_string(),
            ));
        }
        Ok(Self {
            origin,
            rp_id: host,
        })
    }

    pub fn build(&self) -> AppResult<Webauthn> {
        WebauthnBuilder::new(&self.rp_id, &self.origin)
            .map_err(webauthn_configuration_error)?
            .rp_name("GPT SSO")
            .build()
            .map_err(webauthn_configuration_error)
    }
}

async fn list_passkeys(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicPasskey>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let records = state.db.list_user_passkeys(&current.user.id).await?;
    Ok(Json(
        records.into_iter().map(PasskeyRecord::public).collect(),
    ))
}

async fn start_registration(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(payload): Json<StartRegistrationRequest>,
) -> AppResult<Json<StartRegistrationResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    let user_uuid = passkey_user_uuid(&current.user)?;
    let webauthn = webauthn_for_request(&state, &headers).await?;
    let records = state.db.list_user_passkeys(&current.user.id).await?;
    let exclude_credentials = existing_credential_ids(&records)?;
    let display_name = current
        .user
        .display_name
        .as_deref()
        .unwrap_or(current.user.username.as_str());
    let (public_key, registration_state) = webauthn
        .start_passkey_registration(
            user_uuid,
            &current.user.email,
            display_name,
            Some(exclude_credentials),
        )
        .map_err(webauthn_bad_request)?;
    let challenge = state
        .db
        .create_webauthn_challenge(
            Some(&current.user.id),
            REGISTRATION_PURPOSE,
            util::to_json(&registration_state)?,
            WEBAUTHN_CHALLENGE_TTL_SECONDS,
        )
        .await?;
    let _ = payload.name.as_deref();
    Ok(Json(StartRegistrationResponse {
        challenge_id: challenge.id,
        public_key,
        expires_at: challenge.expires_at,
    }))
}

async fn finish_registration(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(payload): Json<FinishRegistrationRequest>,
) -> AppResult<Json<PublicPasskey>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    let challenge = load_challenge(
        &state,
        &payload.challenge_id,
        REGISTRATION_PURPOSE,
        Some(&current.user.id),
    )
    .await?;
    state.db.consume_webauthn_challenge(&challenge.id).await?;
    let registration_state: PasskeyRegistration = util::from_json(&challenge.state_json)?;
    let webauthn = webauthn_for_request(&state, &headers).await?;
    let passkey = webauthn
        .finish_passkey_registration(&payload.credential, &registration_state)
        .map_err(webauthn_bad_request)?;
    let credential_id = credential_id_to_string(passkey.cred_id())?;
    if state.db.find_credential(&credential_id).await?.is_some() {
        return Err(AppError::BadRequest(
            "passkey credential is already registered".to_string(),
        ));
    }
    let record = state
        .db
        .insert_user_passkey(
            &current.user.id,
            credential_id,
            normalize_passkey_name(payload.name.as_deref()),
            util::to_json(&passkey)?,
        )
        .await?;
    Ok(Json(record.public()))
}

async fn delete_passkey(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    state.db.delete_user_passkey(&current.user.id, &id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn start_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<StartAuthenticationRequest>,
) -> AppResult<Json<StartAuthenticationResponse>> {
    let subject = security_policy::normalize_login_subject(&payload.email);
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
    auth::assert_login_entry_allowed(&state, &subject, request_ip.as_deref()).await?;
    let Some(user) = state.db.find_user_by_email(&subject).await? else {
        auth::record_login_failure(&state, request_ip, &headers, &subject, "unknown_user").await?;
        return Err(AppError::Unauthorized);
    };
    if user.is_active != 1 || user.archived_at.is_some() {
        auth::record_login_failure(&state, request_ip, &headers, &subject, "bad_credentials")
            .await?;
        return Err(AppError::Unauthorized);
    }
    let records = state.db.list_user_passkeys(&user.id).await?;
    if records.is_empty() {
        auth::record_login_failure(
            &state,
            request_ip,
            &headers,
            &subject,
            "passkey_unavailable",
        )
        .await?;
        return Err(AppError::Unauthorized);
    }
    let credentials = passkeys_from_records(&records)?;
    let webauthn = webauthn_for_request(&state, &headers).await?;
    let (public_key, authentication_state) = webauthn
        .start_passkey_authentication(&credentials)
        .map_err(webauthn_bad_request)?;
    let challenge = state
        .db
        .create_webauthn_challenge(
            Some(&user.id),
            AUTHENTICATION_PURPOSE,
            util::to_json(&authentication_state)?,
            WEBAUTHN_CHALLENGE_TTL_SECONDS,
        )
        .await?;
    Ok(Json(StartAuthenticationResponse {
        challenge_id: challenge.id,
        public_key,
        expires_at: challenge.expires_at,
    }))
}

async fn finish_authentication(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<FinishAuthenticationRequest>,
) -> AppResult<(CookieJar, Json<FinishAuthenticationResponse>)> {
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
    let challenge =
        load_challenge(&state, &payload.challenge_id, AUTHENTICATION_PURPOSE, None).await?;
    state.db.consume_webauthn_challenge(&challenge.id).await?;
    let user_id = challenge.user_id.as_deref().ok_or(AppError::Unauthorized)?;
    let Some(user) = state.db.find_user_by_id(user_id).await? else {
        return Err(AppError::Unauthorized);
    };
    let subject = security_policy::normalize_login_subject(&user.email);
    auth::assert_login_allowed(&state, &subject, request_ip.as_deref()).await?;
    if user.is_active != 1 || user.archived_at.is_some() {
        auth::record_login_failure(&state, request_ip, &headers, &subject, "bad_credentials")
            .await?;
        return Err(AppError::Unauthorized);
    }
    let authentication_state: PasskeyAuthentication = util::from_json(&challenge.state_json)?;
    let webauthn = webauthn_for_request(&state, &headers).await?;
    let auth_result =
        match webauthn.finish_passkey_authentication(&payload.credential, &authentication_state) {
            Ok(result) => result,
            Err(err) => {
                auth::record_login_failure(&state, request_ip, &headers, &subject, "bad_passkey")
                    .await?;
                return Err(webauthn_bad_request(err));
            }
        };
    let credential_id = credential_id_to_string(auth_result.cred_id())?;
    let Some(record) = state.db.find_credential(&credential_id).await? else {
        auth::record_login_failure(&state, request_ip, &headers, &subject, "unknown_passkey")
            .await?;
        return Err(AppError::Unauthorized);
    };
    if record.user_id != user.id {
        auth::record_login_failure(
            &state,
            request_ip,
            &headers,
            &subject,
            "passkey_user_mismatch",
        )
        .await?;
        return Err(AppError::Unauthorized);
    }
    let mut passkey: Passkey = util::from_json(&record.passkey_json)?;
    if passkey.update_credential(&auth_result).is_none() {
        auth::record_login_failure(
            &state,
            request_ip,
            &headers,
            &subject,
            "passkey_user_mismatch",
        )
        .await?;
        return Err(AppError::Unauthorized);
    }
    state
        .db
        .update_user_passkey_after_authentication(&record.id, util::to_json(&passkey)?)
        .await?;
    let jar = auth::issue_session(&state, jar, &headers, request_ip, &user, "passkey").await?;
    auth::clear_login_failures(&state, &subject).await?;
    Ok((
        jar,
        Json(FinishAuthenticationResponse {
            user: auth::current_user_response(&state, user).await?,
        }),
    ))
}

async fn webauthn_for_request(state: &AppState, headers: &HeaderMap) -> AppResult<Webauthn> {
    let public_base_url = state.effective_public_base_url(headers).await?;
    WebauthnRuntimeConfig::from_public_base_url(&public_base_url)?.build()
}

async fn load_challenge(
    state: &AppState,
    id: &str,
    purpose: &str,
    user_id: Option<&str>,
) -> AppResult<WebauthnChallengeRecord> {
    let Some(challenge) = state.db.find_webauthn_challenge(id).await? else {
        return Err(AppError::Unauthorized);
    };
    validate_challenge(&challenge, purpose, user_id)?;
    Ok(challenge)
}

fn validate_challenge(
    challenge: &WebauthnChallengeRecord,
    purpose: &str,
    user_id: Option<&str>,
) -> AppResult<()> {
    if challenge.purpose != purpose || challenge.consumed_at.is_some() {
        return Err(AppError::Unauthorized);
    }
    if challenge.expires_at < util::now_ts() {
        return Err(AppError::Unauthorized);
    }
    if let Some(expected_user_id) = user_id {
        if challenge.user_id.as_deref() != Some(expected_user_id) {
            return Err(AppError::Unauthorized);
        }
    }
    Ok(())
}

fn passkey_user_uuid(user: &UserRecord) -> AppResult<Uuid> {
    Uuid::parse_str(&user.id).map_err(|err| {
        AppError::Configuration(format!(
            "user id must be a UUID before registering passkeys: {err}"
        ))
    })
}

fn existing_credential_ids(records: &[PasskeyRecord]) -> AppResult<Vec<CredentialID>> {
    records
        .iter()
        .map(|record| {
            util::from_json::<Passkey>(&record.passkey_json)
                .map(|passkey| passkey.cred_id().clone())
        })
        .collect()
}

fn passkeys_from_records(records: &[PasskeyRecord]) -> AppResult<Vec<Passkey>> {
    records
        .iter()
        .map(|record| util::from_json::<Passkey>(&record.passkey_json))
        .collect()
}

fn credential_id_to_string(credential_id: &CredentialID) -> AppResult<String> {
    match serde_json::to_value(credential_id).map_err(|err| AppError::Internal(err.to_string()))? {
        Value::String(value) => Ok(value),
        other => Err(AppError::Internal(format!(
            "credential id serialized to unexpected JSON value: {other}"
        ))),
    }
}

fn normalize_passkey_name(value: Option<&str>) -> String {
    let name = value.map(str::trim).filter(|value| !value.is_empty());
    name.unwrap_or("Passkey").chars().take(80).collect()
}

fn webauthn_configuration_error(err: webauthn_rs::prelude::WebauthnError) -> AppError {
    AppError::Configuration(format!("invalid WebAuthn configuration: {err:?}"))
}

fn webauthn_bad_request(err: webauthn_rs::prelude::WebauthnError) -> AppError {
    AppError::BadRequest(format!("WebAuthn verification failed: {err:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_config_uses_origin_and_host_rp_id() {
        let config =
            WebauthnRuntimeConfig::from_public_base_url("https://oidc.example.com:8443/base")
                .unwrap();

        assert_eq!(config.rp_id, "oidc.example.com");
        assert_eq!(config.origin.as_str(), "https://oidc.example.com:8443/");
    }

    #[test]
    fn webauthn_config_rejects_invalid_or_unsupported_urls() {
        assert!(WebauthnRuntimeConfig::from_public_base_url("not a url").is_err());
        assert!(WebauthnRuntimeConfig::from_public_base_url("ftp://oidc.example.com").is_err());
    }

    #[test]
    fn passkey_name_has_default_and_limit() {
        assert_eq!(normalize_passkey_name(None), "Passkey");
        assert_eq!(
            normalize_passkey_name(Some("  Work laptop  ")),
            "Work laptop"
        );
        assert_eq!(normalize_passkey_name(Some(&"x".repeat(120))).len(), 80);
    }
}
