//! Server-side WeChat Mini Program identity bridge.
//!
//! The mini-program sends only the one-time `wx.login` code to Axon. Axon
//! forwards it here with a deployment-owned bridge credential. Signet alone
//! owns the WeChat AppSecret and the mapping from WeChat subjects to canonical
//! Signet users. The WeChat `session_key` is intentionally neither decoded
//! into a response DTO nor persisted.

use crate::{
    AppState, application_contract::ApplicationContract, applications, auth, authorization,
    config::WechatMiniSettings,
    db::{ApplicationRecord, NewUser, UserRecord, WECHAT_MINI_TYPE},
    error::{AppError, AppResult},
    registration_values::{external_subject_email_local_part, unique_username},
    util,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, header},
    routing::post,
};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::{fs, time::Duration};

const MAX_SECRET_BYTES: usize = 4096;
const WECHAT_HTTP_TIMEOUT: Duration = Duration::from_secs(8);

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/internal/wechat-mini/resolve", post(resolve))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRequest {
    code: String,
    /// Taken from the Mini Program runtime AppID. The one-time code is
    /// verified against that AppID at WeChat, never trusted on its own.
    #[serde(default)]
    app_id: Option<String>,
}

#[derive(Debug, Clone)]
struct SelectedProgram {
    app_id: String,
    app_secret_file: String,
    workspace: Option<String>,
    application: String,
    scopes: Vec<String>,
    allow_registration: bool,
    session_endpoint: String,
}

/// Provider-specific options stay in the WeChat adapter, not in the generic
/// database columns. Other auth adapters define their own typed options.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MiniProgramOptions {
    pub scopes: Vec<String>,
    pub allow_registration: bool,
}

/// Read the website-owned portion of an already verified, pinned Signet v3
/// manifest. The operator still controls which AppIDs possess credentials,
/// their maximum scopes, and whether anonymous enrollment is permitted.
fn website_owned_mini_policy(
    snapshot_json: &str,
    app_id: &str,
    permitted_scopes: &[String],
) -> AppResult<(Vec<String>, bool)> {
    let contract: ApplicationContract = serde_json::from_str(snapshot_json)
        .map_err(|_| AppError::Forbidden)?;
    contract.validate(util::now_ts()).map_err(|_| AppError::Forbidden)?;
    let declaration = contract.modules.authentication.wechat_mini.iter()
        .find(|item| item.app_id == app_id)
        .ok_or(AppError::Forbidden)?;
    let permitted = permitted_scopes.iter().map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if declaration.scopes.is_empty()
        || declaration.scopes.iter().any(|scope| !permitted.contains(scope.as_str()))
    {
        return Err(AppError::Forbidden);
    }
    Ok((declaration.scopes.clone(), declaration.allow_anonymous_sub_identity))
}

fn select_program(settings: &WechatMiniSettings, app_id: Option<&str>) -> AppResult<SelectedProgram> {
    let requested = app_id.map(str::trim).filter(|value| !value.is_empty());
    if let Some(app_id) = requested {
        if let Some(program) = settings.programs.iter().find(|program| program.app_id == app_id && program.enabled) {
            return Ok(SelectedProgram {
                app_id: program.app_id.clone(),
                app_secret_file: program.app_secret_file.clone(),
                workspace: Some(program.workspace.clone()),
                application: program.application.clone(),
                scopes: program.scopes.clone(),
                allow_registration: program.allow_registration,
                session_endpoint: settings.session_endpoint.clone(),
            });
        }
        if !settings.enabled || settings.app_id != app_id {
            return Err(AppError::NotFound);
        }
    } else if !settings.enabled || settings.programs.iter().any(|program| program.enabled) {
        // Without an AppID the request cannot safely choose between multiple
        // Mini Programs. Old single-program callers remain compatible.
        return Err(AppError::BadRequest("WeChat Mini Program app_id is required".into()));
    }
    Ok(SelectedProgram {
        app_id: settings.app_id.clone(),
        app_secret_file: settings.app_secret_file.clone(),
        workspace: None,
        application: settings.application_slug.clone(),
        scopes: settings.scopes.clone(),
        allow_registration: settings.allow_registration,
        session_endpoint: settings.session_endpoint.clone(),
    })
}

#[derive(Debug, Serialize)]
struct ResolveResponse {
    user_id: String,
    username: String,
    display_name: Option<String>,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WechatCodeSessionResponse {
    #[serde(default)]
    openid: Option<String>,
    #[serde(default)]
    unionid: Option<String>,
    #[serde(default)]
    errcode: Option<i64>,
}

async fn resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveRequest>,
) -> AppResult<Json<ResolveResponse>> {
    let settings = &state.settings.wechat_mini;
    authorize_bridge(settings.bridge_secret_file.as_str(), &headers)?;
    let db_credential = match request.app_id.as_deref() {
        Some(app_id) if !app_id.trim().is_empty() =>
            state.db.find_application_auth_credential(WECHAT_MINI_TYPE, app_id.trim()).await?,
        _ => None,
    };
    if db_credential.as_ref().is_some_and(|record| record.is_active != 1) {
        // Disabling a DB credential must not reactivate it through a stale
        // legacy container environment setting.
        return Err(AppError::NotFound);
    }
    let program = if let Some(record) = db_credential.as_ref() {
        let options: MiniProgramOptions =
            serde_json::from_str(&record.config_json)
                .map_err(|_| AppError::Configuration("invalid stored Mini Program options".into()))?;
        SelectedProgram {
            app_id: record.external_id.clone(),
            app_secret_file: String::new(),
            workspace: None,
            application: String::new(),
            scopes: options.scopes,
            allow_registration: options.allow_registration,
            session_endpoint: settings.session_endpoint.clone(),
        }
    } else {
        select_program(settings, request.app_id.as_deref())?
    };
    let code = normalized_login_code(&request.code)?;
    let application = if let Some(record) = db_credential.as_ref() {
        state.db.find_application_by_id(&record.application_id).await?
            .ok_or(AppError::NotFound)?
    } else if let Some(workspace) = program.workspace.as_deref() {
        let organization = state.db.list_organizations().await?.into_iter()
            .find(|organization| organization.slug == workspace && organization.is_active == 1)
            .ok_or(AppError::NotFound)?;
        state.db.find_application_by_slug_in_organization(&organization.id, &program.application).await?
            .ok_or(AppError::NotFound)?
    } else {
        state.db.find_active_application_by_slug(&program.application).await?
            .ok_or(AppError::NotFound)?
    };
    applications::ensure_application_runtime_active(&state, &application).await?;
    let mut scopes = program.scopes.clone();
    let mut allow_anonymous = program.allow_registration;
    if let Some(discovery) = state.db.find_application_discovery(&application.id).await?
        && discovery.management_mode == crate::application_discovery::MANAGEMENT_MODE_WEBSITE
    {
        // New multi-program mappings require an explicit website declaration.
        // A legacy single-program mapping is also governed by the website as
        // soon as its signed manifest starts declaring Mini Programs.
        let snapshot = discovery.snapshot_json.as_deref().ok_or(AppError::Forbidden)?;
        let site_declares_minis = serde_json::from_str::<serde_json::Value>(snapshot).ok()
            .and_then(|value| value.pointer("/modules/authentication/wechat_mini")
                .and_then(serde_json::Value::as_array).map(|items| !items.is_empty()))
            .unwrap_or(false);
        if db_credential.is_some() || program.workspace.is_some() || site_declares_minis {
            let (website_scopes, website_enrollment) = website_owned_mini_policy(
                snapshot, &program.app_id, &scopes,
            )?;
            scopes = website_scopes;
            allow_anonymous &= website_enrollment;
        }
    }
    let app_secret = if let Some(record) = db_credential.as_ref() {
        util::decrypt_application_auth_secret(
            &state.settings.discovery.encryption_key,
            &record.application_id, WECHAT_MINI_TYPE, &program.app_id,
            &record.secret_ciphertext,
        )?
    } else {
        read_secret_file(&program.app_secret_file, "WeChat AppSecret", 16)?
    };
    let session = exchange_code(
        &program.session_endpoint,
        &program.app_id,
        &app_secret,
        code,
    )
    .await?;
    let openid = session
        .openid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(AppError::Unauthorized)?;
    let unionid = session
        .unionid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let provider_slug = format!("wechat-mini:{}", program.app_id.trim());
    // A WeChat unionid is only meaningful within one Open Platform account.
    // jscode2session does not tell us that platform account identifier, so
    // scope the optional unionid link to this Mini Program instead of using a
    // global namespace that could merge unrelated WeChat applications.
    let union_provider_slug = format!("wechat-union:{}", program.app_id.trim());
    let user = resolve_canonical_user(
        &state,
        &provider_slug,
        &union_provider_slug,
        openid,
        unionid,
        allow_anonymous,
        &application,
    )
    .await?;
    if !authorization::check_login_access(&state, &application, &user.id)
        .await?
        .allowed
    {
        return Err(AppError::Forbidden);
    }
    state
        .db
        .record_login_event(
            &user.id,
            None,
            None,
            "wechat_mini",
            None,
            Some(provider_slug),
        )
        .await?;
    Ok(Json(ResolveResponse {
        user_id: user.id,
        username: user.username,
        display_name: user.display_name,
        scopes,
    }))
}

pub(crate) fn authorize_bridge(secret_file: &str, headers: &HeaderMap) -> AppResult<()> {
    let expected = read_secret_file(secret_file, "WeChat bridge secret", 32)?;
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();
    if supplied.is_empty() || !constant_time_eq(supplied.as_bytes(), expected.as_bytes()) {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

fn read_secret_file(path: &str, label: &str, min_len: usize) -> AppResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(AppError::Configuration(format!(
            "{label} file is not configured"
        )));
    }
    let raw = fs::read_to_string(path)
        .map_err(|_| AppError::Configuration(format!("{label} file is unreadable")))?;
    if raw.len() > MAX_SECRET_BYTES {
        return Err(AppError::Configuration(format!(
            "{label} file is too large"
        )));
    }
    let value = raw.trim().to_string();
    if value.len() < min_len || value.chars().any(char::is_control) {
        return Err(AppError::Configuration(format!("{label} is invalid")));
    }
    Ok(value)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn normalized_login_code(value: &str) -> AppResult<&str> {
    let value = value.trim();
    if value.len() < 6
        || value.len() > 512
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(AppError::BadRequest(
            "WeChat login code is invalid".to_string(),
        ));
    }
    Ok(value)
}

async fn exchange_code(
    endpoint: &str,
    app_id: &str,
    app_secret: &str,
    code: &str,
) -> AppResult<WechatCodeSessionResponse> {
    let mut url = reqwest::Url::parse(endpoint)
        .map_err(|_| AppError::Configuration("WeChat session endpoint is invalid".to_string()))?;
    url.query_pairs_mut()
        .append_pair("appid", app_id.trim())
        .append_pair("secret", app_secret)
        .append_pair("js_code", code)
        .append_pair("grant_type", "authorization_code");
    let client = reqwest::Client::builder()
        .timeout(WECHAT_HTTP_TIMEOUT)
        .redirect(Policy::none())
        .build()
        .map_err(|_| AppError::Internal("failed to initialize WeChat login client".to_string()))?;
    // Do not attach the request error to logs: reqwest error strings can
    // include the query URL, which contains both AppSecret and one-time code.
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| AppError::Internal("WeChat login request failed".to_string()))?;
    if !response.status().is_success() {
        return Err(AppError::Internal(
            "WeChat login service returned an unexpected HTTP status".to_string(),
        ));
    }
    let payload = response
        .json::<WechatCodeSessionResponse>()
        .await
        .map_err(|_| AppError::Internal("WeChat login response was invalid".to_string()))?;
    if payload.errcode.is_some_and(|code| code != 0) {
        return Err(AppError::Unauthorized);
    }
    Ok(payload)
}

async fn resolve_canonical_user(
    state: &AppState,
    provider_slug: &str,
    union_provider_slug: &str,
    openid: &str,
    unionid: Option<&str>,
    provider_allows_registration: bool,
    application: &ApplicationRecord,
) -> AppResult<UserRecord> {
    let app_identity = state.db.find_linked_identity(provider_slug, openid).await?;
    let union_identity = match unionid {
        Some(unionid) => {
            state
                .db
                .find_linked_identity(union_provider_slug, unionid)
                .await?
        }
        None => None,
    };
    if let (Some(app), Some(union)) = (&app_identity, &union_identity)
        && app.user_id != union.user_id
    {
        // Never guess how to merge two already-bound identities. An explicit
        // account-link operation must resolve this security conflict.
        return Err(AppError::Forbidden);
    }
    let existing_user_id = app_identity
        .as_ref()
        .map(|identity| identity.user_id.as_str())
        .or_else(|| {
            union_identity
                .as_ref()
                .map(|identity| identity.user_id.as_str())
        });
    let user = if let Some(user_id) = existing_user_id {
        state
            .db
            .find_user_by_id(user_id)
            .await?
            .ok_or(AppError::Unauthorized)?
    } else {
        // A site's explicit anonymous-sub-identity opt-in is required for
        // creating a new user from WeChat. Verified WeChat ownership alone is
        // not permission to register a Signet primary account.
        let registration = state.db.registration_settings().await?.public();
        if !provider_allows_registration
            || !registration.allow_external_oidc_registration
            || registration.require_invitation
            || state.db.user_count().await? == 0
            || !first_party_registration_allowed(application)
            || !state.db.anonymous_sub_identity_creation_allowed(&application.id).await?
        {
            return Err(AppError::Forbidden);
        }
        let email = format!(
            "{}@wechat-mini.external",
            external_subject_email_local_part(openid)
        );
        auth::assert_registration_allowed(state, Some(&email), None).await?;
        let new_user = NewUser {
            email: email.clone(),
            username: unique_username("wechat", openid),
            display_name: Some("WeChat User".to_string()),
            phone: None,
            password_hash: util::hash_password(&util::random_token(32))?,
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: false,
            is_active: registration.default_user_active,
            archived_at: None,
        };
        match state
            .db
            .insert_external_oidc_anonymous_sub_identity(
                new_user, provider_slug, openid, Some(email), &application.id,
            )
            .await
        {
            Ok(user) => user,
            Err(error) => {
                // `wx.login` can be retried concurrently. If another request
                // won the unique external-subject insert, resolve that durable
                // identity instead of creating a second Signet account.
                let Some(identity) = state.db.find_linked_identity(provider_slug, openid).await?
                else {
                    return Err(error);
                };
                state
                    .db
                    .find_user_by_id(&identity.user_id)
                    .await?
                    .ok_or(AppError::Unauthorized)?
            }
        }
    };
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(AppError::Unauthorized);
    }
    ensure_identity_link(state, provider_slug, openid, &user.id).await?;
    if let Some(unionid) = unionid {
        ensure_identity_link(state, union_provider_slug, unionid, &user.id).await?;
    }
    Ok(user)
}

fn first_party_registration_allowed(application: &ApplicationRecord) -> bool {
    if application.is_active != 1
        || application.access_mode != applications::ACCESS_ALL_SIGNET_USERS
    {
        return false;
    }
    matches!(
        application.registration_mode.as_str(),
        applications::REGISTRATION_DISABLED | applications::REGISTRATION_OPEN | applications::REGISTRATION_LEGACY
    )
}

async fn ensure_identity_link(
    state: &AppState,
    provider_slug: &str,
    external_subject: &str,
    user_id: &str,
) -> AppResult<()> {
    if let Some(existing) = state
        .db
        .find_linked_identity(provider_slug, external_subject)
        .await?
    {
        return if existing.user_id == user_id {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        };
    }
    match state
        .db
        .insert_linked_identity(user_id, provider_slug, external_subject, None)
        .await
    {
        Ok(()) => Ok(()),
        Err(error) => match state
            .db
            .find_linked_identity(provider_slug, external_subject)
            .await?
        {
            Some(existing) if existing.user_id == user_id => Ok(()),
            Some(_) => Err(AppError::Forbidden),
            None => Err(error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn website_manifest_limits_miniprogram_scopes_and_anonymous_registration() {
        let now = util::now_ts();
        let snapshot = serde_json::json!({
            "format": "signet-application/v3",
            "application_id": "axon",
            "revision": 1,
            "version": "test",
            "iss": "https://axon.example.org",
            "aud": "signet:application:axon",
            "iat": now - 5,
            "exp": now + 300,
            "modules": {
                "authentication": {
                    "registration_mode": "disabled",
                    "wechat_mini": [{
                        "app_id": "wx1234567890abcdef",
                        "scopes": ["axon-next:chat"],
                        "allow_anonymous_sub_identity": false
                    }]
                }
            }
        });
        let text = snapshot.to_string();
        let granted = vec!["axon-next:chat".to_owned(), "axon-next:trading".to_owned()];
        assert_eq!(
            website_owned_mini_policy(&text, "wx1234567890abcdef", &granted).unwrap(),
            (vec!["axon-next:chat".to_owned()], false)
        );
        assert!(website_owned_mini_policy(&text, "wxotherappid12", &granted).is_err());
        assert!(website_owned_mini_policy(&text, "wx1234567890abcdef", &["axon-next:models".into()]).is_err());
        let mut tampered = snapshot;
        tampered["modules"]["authentication"]["wechat_mini"][0]["app_secret"] =
            serde_json::json!("secret-not-permitted");
        assert!(website_owned_mini_policy(&tampered.to_string(), "wx1234567890abcdef", &granted).is_err());
    }

    #[test]
    fn multiple_mini_programs_require_exact_appid_selection() {
        use crate::config::WechatMiniProgramSettings;
        let mut settings = WechatMiniSettings::default();
        settings.programs = ["wx1234567890abcdef", "wxabcdef1234567890"]
            .into_iter()
            .map(|app_id| WechatMiniProgramSettings {
                enabled: true,
                app_id: app_id.to_owned(),
                app_secret_file: "/run/secrets/site-secret".into(),
                workspace: "team-a".into(),
                application: "axon".into(),
                scopes: vec!["axon-next:chat".into()],
                allow_registration: false,
            })
            .collect();
        assert!(select_program(&settings, None).is_err());
        assert!(select_program(&settings, Some("wxnotconfigured" )).is_err());
        let selected = select_program(&settings, Some("wxabcdef1234567890")).unwrap();
        assert_eq!(selected.workspace.as_deref(), Some("team-a"));
        assert_eq!(selected.app_id, "wxabcdef1234567890");
        assert!(!selected.allow_registration);
    }

    #[test]
    fn bridge_comparison_is_exact() {
        assert!(constant_time_eq(b"same-secret", b"same-secret"));
        assert!(!constant_time_eq(b"same-secret", b"same-secreu"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn login_code_rejects_whitespace_and_controls() {
        assert!(normalized_login_code("abcdef123456").is_ok());
        assert!(normalized_login_code("abc def").is_err());
        assert!(normalized_login_code("abc\ndef").is_err());
    }

    #[test]
    fn first_party_registration_never_opens_invitation_or_enterprise_apps() {
        let mut application = ApplicationRecord {
            id: "app-1".to_string(),
            organization_id: "org-1".to_string(),
            slug: "axon".to_string(),
            name: "Axon".to_string(),
            description: None,
            access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: "[]".to_string(),
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        };
        assert!(first_party_registration_allowed(&application));
        application.registration_mode = applications::REGISTRATION_INVITATION.to_string();
        assert!(!first_party_registration_allowed(&application));
        application.registration_mode = applications::REGISTRATION_ORGANIZATION_MEMBERS.to_string();
        assert!(!first_party_registration_allowed(&application));
        application.registration_mode = applications::REGISTRATION_DISABLED.to_string();
        application.access_mode = applications::ACCESS_ASSIGNED_ACCOUNTS.to_string();
        assert!(!first_party_registration_allowed(&application));
    }
}
