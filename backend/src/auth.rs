use crate::{
    AppState,
    access::{Permission, user_can_hold_permissions},
    auth_flow,
    captcha::{ArithmeticCaptchaProvider, CaptchaProvider, LoginCaptchaPrompt},
    config::SameSiteSetting,
    db::{LoginCodeLevel, PublicUser, SessionMetadata, SessionRecord, UserRecord},
    error::{AppError, AppResult},
    security_policy::{AccessSurface, NetworkAccessRiskContext, NetworkAccessRiskPolicy},
    util,
};
use axum::{extract::State, http::HeaderMap};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Serialize;
use time::Duration;

#[derive(Clone)]
pub struct CurrentUser {
    pub user: UserRecord,
    pub session_id: String,
    pub session_kind: AccountSessionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountSessionKind {
    Standard,
    TemporaryAuthorizationCode,
    TrialEnrollment,
}

pub const AUTHORIZATION_CODE_SESSION_TTL_SECONDS: i64 = 15 * 60;

pub fn authorization_code_session_ttl_seconds(
    state: &AppState,
    code_expires_at: Option<i64>,
) -> AppResult<i64> {
    let mut ttl = state
        .settings
        .security
        .session_ttl_seconds
        .min(AUTHORIZATION_CODE_SESSION_TTL_SECONDS);
    if let Some(expires_at) = code_expires_at {
        ttl = ttl.min(expires_at.saturating_sub(util::now_ts()));
    }
    if ttl <= 0 {
        return Err(AppError::Unauthorized);
    }
    Ok(ttl)
}

impl AccountSessionKind {
    pub(crate) fn for_active_user(
        user: &UserRecord,
        has_authorization_code_redemption: bool,
    ) -> Option<Self> {
        if user.is_active != 1 {
            return None;
        }
        if user.archived_at.is_some() {
            has_authorization_code_redemption.then_some(Self::TemporaryAuthorizationCode)
        } else {
            Some(Self::Standard)
        }
    }

    pub(crate) fn for_session(
        user: &UserRecord,
        session: &SessionRecord,
        has_authorization_code_redemption: bool,
    ) -> Option<Self> {
        Self::for_active_user(user, has_authorization_code_redemption).map(|kind| {
            if session.login_method.as_deref() == Some("authorization_code") {
                Self::TemporaryAuthorizationCode
            } else {
                kind
            }
        })
    }

    pub(crate) fn for_session_with_trial_enrollment(
        user: &UserRecord,
        session: &SessionRecord,
        has_authorization_code_redemption: bool,
        is_trial_enrollment: bool,
    ) -> Option<Self> {
        if is_trial_enrollment {
            (user.is_active == 1 && user.archived_at.is_none()).then_some(Self::TrialEnrollment)
        } else {
            Self::for_session(user, session, has_authorization_code_redemption)
        }
    }
}

pub trait AccountCapabilities {
    fn account_session_kind(&self) -> AccountSessionKind;

    fn is_temporary_authorization_code_session(&self) -> bool {
        self.account_session_kind() == AccountSessionKind::TemporaryAuthorizationCode
    }

    fn is_restricted_login_code_session(&self) -> bool {
        self.account_session_kind() != AccountSessionKind::Standard
    }

    fn can_mutate_account(&self) -> bool {
        self.account_session_kind() == AccountSessionKind::Standard
    }

    fn can_authorize_oauth_client(&self) -> bool {
        self.can_mutate_account()
    }
}

impl AccountCapabilities for CurrentUser {
    fn account_session_kind(&self) -> AccountSessionKind {
        self.session_kind
    }
}

pub async fn current_user_from_cookie(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<Option<CurrentUser>> {
    let Some(session) = session_from_cookie(state, jar).await? else {
        return Ok(None);
    };
    let Some(user) = state.db.find_user_by_id(&session.user_id).await? else {
        return Ok(None);
    };
    let trial_enrollment = state.db.find_trial_enrollment_for_user(&user.id).await?;
    if trial_enrollment
        .as_ref()
        .is_some_and(|enrollment| !enrollment.is_active_at(util::now_ts()))
    {
        state.db.delete_session(&session.id).await?;
        return Ok(None);
    }
    let has_redemption = if user.archived_at.is_some() {
        state.db.user_has_invitation_redemption(&user.id).await?
    } else {
        false
    };
    let Some(session_kind) = AccountSessionKind::for_session_with_trial_enrollment(
        &user,
        &session,
        has_redemption,
        trial_enrollment.is_some(),
    ) else {
        return Ok(None);
    };
    Ok(Some(CurrentUser {
        user,
        session_id: session.id,
        session_kind,
    }))
}

pub async fn session_from_cookie(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<Option<crate::db::SessionRecord>> {
    let Some(cookie) = jar.get(&state.settings.security.cookie_name) else {
        return Ok(None);
    };
    let Some(credential_id) = util::session_id_from_cookie(cookie.value()) else {
        return Ok(None);
    };
    let session = if let Some(session) = state.db.find_session_by_credential(&credential_id).await?
    {
        Some(session)
    } else {
        state.db.find_session(&credential_id).await?
    };
    let Some(session) = session else {
        return Ok(None);
    };
    if session.expires_at < util::now_ts() {
        state.db.delete_session(&session.id).await?;
        return Ok(None);
    }
    Ok(Some(session))
}

pub async fn require_current_user(state: &AppState, jar: &CookieJar) -> AppResult<CurrentUser> {
    current_user_from_cookie(state, jar)
        .await?
        .ok_or(AppError::Unauthorized)
}

pub fn ensure_account_mutable(user: &UserRecord) -> AppResult<()> {
    if user.archived_at.is_some() {
        Err(AppError::BadRequest(
            "archived accounts are read-only".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub fn ensure_current_account_mutable(current: &CurrentUser) -> AppResult<()> {
    if !current.can_mutate_account() {
        return Err(AppError::Forbidden);
    }
    ensure_account_mutable(&current.user)
}

pub fn session_metadata(
    ip_address: Option<String>,
    headers: &HeaderMap,
    method: &str,
) -> SessionMetadata {
    SessionMetadata {
        ip_address,
        user_agent: util::user_agent(headers),
        login_method: Some(method.to_string()),
    }
}

#[derive(Debug, Serialize)]
pub struct CurrentUserResponse {
    #[serde(flatten)]
    pub user: PublicUser,
    pub session_kind: AccountSessionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_code_level: Option<LoginCodeLevel>,
    pub permissions: Vec<String>,
}

pub async fn current_user_response(
    state: &AppState,
    user: UserRecord,
) -> AppResult<CurrentUserResponse> {
    current_user_response_with_kind(state, user, AccountSessionKind::Standard).await
}

pub async fn current_user_response_for_session(
    state: &AppState,
    current: CurrentUser,
) -> AppResult<CurrentUserResponse> {
    current_user_response_with_kind(state, current.user, current.session_kind).await
}

async fn current_user_response_with_kind(
    state: &AppState,
    user: UserRecord,
    session_kind: AccountSessionKind,
) -> AppResult<CurrentUserResponse> {
    let permissions =
        if session_kind != AccountSessionKind::Standard || !user_can_hold_permissions(&user) {
            Vec::new()
        } else if user.is_admin == 1 {
            Permission::ALL
                .iter()
                .map(|permission| permission.as_str().to_string())
                .collect()
        } else {
            state.db.list_effective_permissions(&user.id).await?
        };
    Ok(CurrentUserResponse {
        user: user.public(),
        session_kind,
        login_code_level: match session_kind {
            AccountSessionKind::Standard => None,
            AccountSessionKind::TemporaryAuthorizationCode => Some(LoginCodeLevel::AccountRecovery),
            AccountSessionKind::TrialEnrollment => Some(LoginCodeLevel::TrialEnrollment),
        },
        permissions,
    })
}

#[derive(Debug, Default)]
pub struct LoginEventContext {
    pub oidc_client_id: Option<String>,
    pub external_provider: Option<String>,
    pub account_flow: Option<String>,
    pub session_ttl_seconds: Option<i64>,
}

pub async fn issue_session(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    request_ip: Option<String>,
    user: &UserRecord,
    method: &str,
) -> AppResult<CookieJar> {
    issue_session_with_login_event(
        state,
        jar,
        headers,
        request_ip,
        user,
        method,
        LoginEventContext::default(),
    )
    .await
}

pub async fn issue_session_with_login_event(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    request_ip: Option<String>,
    user: &UserRecord,
    method: &str,
    login_event: LoginEventContext,
) -> AppResult<CookieJar> {
    if let Some(enrollment) = state.db.find_trial_enrollment_for_user(&user.id).await? {
        // Trial identities are intentionally code-only.  In particular, a
        // password reset, passkey, directory or external-IdP login must never
        // turn the account into an unrestricted SSO session.
        if !enrollment.is_active_at(util::now_ts()) || method != "trial_enrollment" {
            return Err(AppError::Unauthorized);
        }
    }
    let previous_session = session_from_cookie(state, &jar).await?;
    let account_flow = login_event
        .account_flow
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if account_flow
        .is_some_and(|value| value.len() > 512 || value.bytes().any(|byte| byte.is_ascii_control()))
    {
        return Err(AppError::Unauthorized);
    }
    let account_login_flow = if let Some(account_flow) = account_flow {
        let context_id = browser_context_id_from_jar(state, &jar).ok_or(AppError::Unauthorized)?;
        state
            .db
            .find_browser_context(&context_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let flow = state
            .db
            .consume_account_login_flow(&util::token_hash(account_flow), &context_id, &user.id)
            .await?;
        Some(flow)
    } else {
        None
    };
    let session_ttl_seconds = login_event
        .session_ttl_seconds
        .unwrap_or(state.settings.security.session_ttl_seconds)
        .min(state.settings.security.session_ttl_seconds)
        .max(1);
    let (session, cookie_value) = state
        .db
        .insert_session(
            &user.id,
            session_ttl_seconds,
            session_metadata(request_ip.clone(), headers, method),
        )
        .await?;
    let mut next_jar = jar;
    if let Some(flow) = account_login_flow.as_ref() {
        let reauthentication_completed =
            match crate::oidc::complete_browser_account_reauthentication(
                state,
                &flow.return_to,
                &user.id,
                &session.id,
                flow.created_at,
            )
            .await
            {
                Ok(completed) => completed,
                Err(err) => {
                    state.db.delete_session(&session.id).await?;
                    return Err(err);
                }
            };
        if flow.expected_user_id.is_some() && !reauthentication_completed {
            state.db.delete_session(&session.id).await?;
            return Err(AppError::Unauthorized);
        }
        if let Err(err) = state
            .db
            .attach_browser_context_account(&flow.browser_context_id, &user.id, &session.id)
            .await
        {
            state.db.delete_session(&session.id).await?;
            return Err(err);
        }
    } else if let Some(previous) = previous_session.as_ref()
        && previous.user_id == user.id
    {
        let existing_context_id = browser_context_id_from_jar(state, &next_jar);
        let existing_context = if let Some(context_id) = existing_context_id.as_deref() {
            state.db.find_browser_context(context_id).await?
        } else {
            None
        };
        let existing_account = if let (Some(context), Some(context_id)) =
            (existing_context.as_ref(), existing_context_id.as_deref())
        {
            state
                .db
                .find_browser_context_account_by_session(context_id, &previous.id)
                .await?
                .map(|_| context.id.clone())
        } else {
            None
        };
        if let Some(context_id) = existing_account {
            state
                .db
                .attach_browser_context_account(&context_id, &user.id, &session.id)
                .await?;
        } else {
            let (context_id, context_cookie) = create_browser_context(state).await?;
            state
                .db
                .attach_browser_context_account(&context_id, &user.id, &session.id)
                .await?;
            state.db.delete_session(&previous.id).await?;
            next_jar = next_jar.add(context_cookie);
        }
    } else {
        let (context_id, context_cookie) = create_browser_context(state).await?;
        state
            .db
            .attach_browser_context_account(&context_id, &user.id, &session.id)
            .await?;
        next_jar = next_jar.add(context_cookie);
    }
    state
        .db
        .record_login_event(
            &user.id,
            request_ip,
            util::user_agent(headers),
            method,
            login_event.oidc_client_id,
            login_event.external_provider,
        )
        .await?;
    let cookie = session_cookie(state, cookie_value, session_ttl_seconds);
    Ok(next_jar.add(cookie))
}

pub async fn assert_login_not_locked(state: &AppState, subject: &str) -> AppResult<()> {
    let policy = state.db.security_policy().await?;
    let summary = state
        .db
        .login_failure_summary(subject, policy.failure_window_seconds)
        .await?;
    auth_flow::assert_not_locked(&policy, summary)
}

pub async fn assert_login_entry_allowed(
    state: &AppState,
    subject: &str,
    ip_address: Option<&str>,
) -> AppResult<()> {
    let policy = state.db.security_policy().await?;
    let summary = state
        .db
        .login_failure_summary(subject, policy.failure_window_seconds)
        .await?;
    auth_flow::login_entry_flow().evaluate(&auth_flow::login_entry_context(
        &policy, subject, ip_address, summary,
    ))
}

pub async fn login_captcha_prompt_if_required(
    state: &AppState,
    subject: &str,
    ip_address: Option<&str>,
    challenge_id: Option<&str>,
    answer: Option<&str>,
) -> AppResult<Option<LoginCaptchaPrompt>> {
    let policy = state.db.security_policy().await?;
    let summary = state
        .db
        .login_failure_summary(subject, policy.failure_window_seconds)
        .await?;
    if auth_flow::login_captcha_decision(&policy, subject, ip_address, summary)?
        == auth_flow::LoginCaptchaDecision::NotRequired
    {
        return Ok(None);
    }
    if let (Some(challenge_id), Some(answer)) = (challenge_id, answer) {
        match state
            .db
            .consume_captcha_challenge(challenge_id, subject, answer)
            .await
        {
            Ok(()) => return Ok(None),
            Err(AppError::BadRequest(_)) => {}
            Err(err) => return Err(err),
        }
    }
    let challenge = ArithmeticCaptchaProvider.generate()?;
    state
        .db
        .create_captcha_challenge(
            subject,
            &challenge.prompt,
            &challenge.answer,
            policy.captcha_ttl_seconds,
        )
        .await
        .map(Into::into)
        .map(Some)
}

pub async fn assert_login_allowed(
    state: &AppState,
    subject: &str,
    ip_address: Option<&str>,
) -> AppResult<()> {
    let policy = state.db.security_policy().await?;
    auth_flow::access_risk_flow().evaluate(&auth_flow::access_risk_context(
        &policy,
        AccessSurface::Login,
        Some(subject),
        ip_address,
    ))
}

pub async fn assert_registration_allowed(
    state: &AppState,
    subject: Option<&str>,
    ip_address: Option<&str>,
) -> AppResult<()> {
    assert_registration_entry_allowed(state, subject, ip_address).await
}

pub async fn assert_registration_entry_allowed(
    state: &AppState,
    subject: Option<&str>,
    ip_address: Option<&str>,
) -> AppResult<()> {
    let policy = state.db.security_policy().await?;
    auth_flow::registration_entry_flow().evaluate(&auth_flow::registration_entry_context(
        &policy, subject, ip_address,
    ))
}

pub async fn assert_authorization_code_access_allowed(
    state: &AppState,
    ip_address: Option<&str>,
) -> AppResult<()> {
    let policy = state.db.security_policy().await?;
    policy.evaluate_network_access_risk(NetworkAccessRiskContext {
        surface: AccessSurface::Registration,
        ip_address,
    })
}

pub async fn assert_login_account_allowed(state: &AppState, user: &UserRecord) -> AppResult<()> {
    let policy = state.db.security_policy().await?;
    auth_flow::assert_login_account_allowed(&policy, user)
}

pub async fn record_login_failure(
    state: &AppState,
    ip_address: Option<String>,
    headers: &HeaderMap,
    subject: &str,
    reason: &str,
) -> AppResult<()> {
    state
        .db
        .record_login_failure(subject, ip_address, util::user_agent(headers), reason)
        .await
}

pub async fn clear_login_failures(state: &AppState, subject: &str) -> AppResult<()> {
    state.db.clear_login_failures(subject).await
}

pub fn session_cookie(state: &AppState, value: String, max_age_seconds: i64) -> Cookie<'static> {
    let mut cookie = Cookie::build((state.settings.security.cookie_name.clone(), value))
        .path("/")
        .http_only(true)
        .secure(state.settings.security.cookie_secure)
        .same_site(match state.settings.security.cookie_same_site {
            SameSiteSetting::Strict => SameSite::Strict,
            SameSiteSetting::Lax => SameSite::Lax,
            SameSiteSetting::None => SameSite::None,
        })
        .max_age(Duration::seconds(max_age_seconds))
        .build();
    if !state.settings.security.cookie_domain.trim().is_empty() {
        cookie.set_domain(state.settings.security.cookie_domain.clone());
    }
    cookie
}

pub fn expired_session_cookie(state: &AppState) -> Cookie<'static> {
    session_cookie(state, String::new(), 0)
}

const BROWSER_CONTEXT_COOKIE_PREFIX: &str = "bc1.";
const BROWSER_CONTEXT_ID_PREFIX: &str = "bc1id.";

pub fn browser_context_cookie_name(state: &AppState) -> String {
    format!("{}_accounts", state.settings.security.cookie_name)
}

pub fn browser_context_id_from_cookie(value: &str) -> Option<String> {
    let secret = value.strip_prefix(BROWSER_CONTEXT_COOKIE_PREFIX)?;
    if secret.is_empty() {
        return None;
    }
    Some(format!(
        "{BROWSER_CONTEXT_ID_PREFIX}{}",
        util::sha256_base64url(&format!("gpt-sso:browser-context:{secret}"))
    ))
}

pub fn browser_context_id_from_jar(state: &AppState, jar: &CookieJar) -> Option<String> {
    jar.get(&browser_context_cookie_name(state))
        .and_then(|cookie| browser_context_id_from_cookie(cookie.value()))
}

fn browser_context_cookie(
    state: &AppState,
    value: String,
    max_age_seconds: i64,
) -> Cookie<'static> {
    let mut cookie = Cookie::build((browser_context_cookie_name(state), value))
        .path("/")
        .http_only(true)
        .secure(state.settings.security.cookie_secure)
        .same_site(match state.settings.security.cookie_same_site {
            SameSiteSetting::Strict => SameSite::Strict,
            SameSiteSetting::Lax => SameSite::Lax,
            SameSiteSetting::None => SameSite::None,
        })
        .max_age(Duration::seconds(max_age_seconds))
        .build();
    if !state.settings.security.cookie_domain.trim().is_empty() {
        cookie.set_domain(state.settings.security.cookie_domain.clone());
    }
    cookie
}

pub fn expired_browser_context_cookie(state: &AppState) -> Cookie<'static> {
    browser_context_cookie(state, String::new(), 0)
}

pub async fn create_browser_context(state: &AppState) -> AppResult<(String, Cookie<'static>)> {
    let secret = util::random_token(32);
    let cookie_value = format!("{BROWSER_CONTEXT_COOKIE_PREFIX}{secret}");
    let context_id = browser_context_id_from_cookie(&cookie_value)
        .ok_or_else(|| AppError::Internal("failed to create browser context".to_string()))?;
    state
        .db
        .insert_browser_context(
            &context_id,
            &util::random_token(32),
            state.settings.security.session_ttl_seconds,
        )
        .await?;
    Ok((
        context_id,
        browser_context_cookie(
            state,
            cookie_value,
            state.settings.security.session_ttl_seconds,
        ),
    ))
}

pub async fn bearer_user_claims(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<crate::jwt::TokenClaims> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    let issuers = state.accepted_issuers(&headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let claims = state
        .jwt
        // This legacy helper has no resource context. Resource-bearing
        // endpoints must use the audience-aware JWT API instead.
        .verify_access_token_for_generic_bearer(token, &issuer_refs)?;
    if claims.cnf.is_some() {
        return Err(AppError::Unauthorized);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sqlite")]
    async fn test_state() -> (AppState, std::path::PathBuf) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-auth-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        (AppState { settings, db, jwt }, path)
    }

    fn user(is_active: i32, archived_at: Option<i64>) -> UserRecord {
        UserRecord {
            id: "user-id".to_string(),
            email: "alice@example.com".to_string(),
            username: "alice".to_string(),
            display_name: None,
            phone: None,
            password_hash: "hash".to_string(),
            email_verified_at: Some(1),
            phone_verified_at: None,
            is_admin: 0,
            is_active,
            archived_at,
            registration_source: "local".to_string(),
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn session(login_method: &str) -> SessionRecord {
        SessionRecord {
            id: "session-id".to_string(),
            user_id: "user-id".to_string(),
            csrf_token: "csrf".to_string(),
            ip_address: None,
            user_agent: None,
            login_method: Some(login_method.to_string()),
            expires_at: 600,
            created_at: 1,
        }
    }

    #[test]
    fn session_metadata_uses_resolved_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        let metadata = session_metadata(Some("192.0.2.10".to_string()), &headers, "password");

        assert_eq!(metadata.ip_address.as_deref(), Some("192.0.2.10"));
        assert_eq!(metadata.login_method.as_deref(), Some("password"));
    }

    #[test]
    fn account_session_kind_distinguishes_temporary_authorization_code_sessions() {
        assert_eq!(
            AccountSessionKind::for_active_user(&user(1, None), false),
            Some(AccountSessionKind::Standard)
        );
        assert_eq!(
            AccountSessionKind::for_active_user(&user(1, Some(100)), true),
            Some(AccountSessionKind::TemporaryAuthorizationCode)
        );
        assert_eq!(
            AccountSessionKind::for_active_user(&user(1, Some(100)), false),
            None
        );
        assert_eq!(
            AccountSessionKind::for_active_user(&user(0, None), false),
            None
        );
        assert_eq!(
            AccountSessionKind::for_session(&user(1, None), &session("authorization_code"), false,),
            Some(AccountSessionKind::TemporaryAuthorizationCode)
        );
        assert_eq!(
            AccountSessionKind::for_session(&user(1, None), &session("password"), false),
            Some(AccountSessionKind::Standard)
        );
        assert_eq!(
            AccountSessionKind::for_session_with_trial_enrollment(
                &user(1, None),
                &session("trial_enrollment"),
                false,
                true,
            ),
            Some(AccountSessionKind::TrialEnrollment)
        );
    }

    #[test]
    fn temporary_authorization_code_sessions_are_read_only_and_cannot_authorize_clients() {
        let current = CurrentUser {
            user: user(1, Some(100)),
            session_id: "session-id".to_string(),
            session_kind: AccountSessionKind::TemporaryAuthorizationCode,
        };

        assert!(current.is_temporary_authorization_code_session());
        assert!(!current.can_mutate_account());
        assert!(!current.can_authorize_oauth_client());

        let trial = CurrentUser {
            user: user(1, None),
            session_id: "trial-session".to_string(),
            session_kind: AccountSessionKind::TrialEnrollment,
        };
        assert!(trial.is_restricted_login_code_session());
        assert!(!trial.can_mutate_account());
        assert!(!trial.can_authorize_oauth_client());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn successful_reauthentication_replaces_the_current_browser_session() {
        let (state, path) = test_state().await;
        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "reauth@example.com".to_string(),
                username: "reauth".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let headers = HeaderMap::new();
        let first_jar = issue_session(&state, CookieJar::new(), &headers, None, &user, "password")
            .await
            .unwrap();
        let first = require_current_user(&state, &first_jar).await.unwrap();

        let second_jar = issue_session(&state, first_jar, &headers, None, &user, "password")
            .await
            .unwrap();
        let second = require_current_user(&state, &second_jar).await.unwrap();

        assert_ne!(first.session_id, second.session_id);
        assert!(
            state
                .db
                .find_session(&first.session_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state.db.list_user_sessions(&user.id).await.unwrap().len(),
            1
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn v2_alias_selects_the_original_session_without_changing_assurance() {
        let (state, path) = test_state().await;
        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "alias@example.com".to_string(),
                username: "alias".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let headers = HeaderMap::new();
        let jar = issue_session(&state, CookieJar::new(), &headers, None, &user, "passkey")
            .await
            .unwrap();
        let original = require_current_user(&state, &jar).await.unwrap();
        let original_session = state
            .db
            .find_session(&original.session_id)
            .await
            .unwrap()
            .unwrap();
        let context_id = browser_context_id_from_jar(&state, &jar).unwrap();
        let account = state
            .db
            .list_browser_context_accounts(&context_id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let (selected_session, alias_cookie_value) = state
            .db
            .mint_browser_account_session_credential(&context_id, &account.id)
            .await
            .unwrap();
        let alias_jar = jar.add(session_cookie(
            &state,
            alias_cookie_value,
            state.settings.security.session_ttl_seconds,
        ));
        let selected = require_current_user(&state, &alias_jar).await.unwrap();

        assert_eq!(selected.session_id, original.session_id);
        assert_eq!(selected_session.id, original_session.id);
        assert_eq!(selected_session.created_at, original_session.created_at);
        assert_eq!(selected_session.login_method.as_deref(), Some("passkey"));

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn authorization_code_session_stays_restricted_through_browser_alias() {
        let (state, path) = test_state().await;
        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "recovery-admin@example.com".to_string(),
                username: "recovery-admin".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: true,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let jar = issue_session_with_login_event(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &user,
            "authorization_code",
            LoginEventContext {
                session_ttl_seconds: Some(120),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let current = require_current_user(&state, &jar).await.unwrap();
        assert_eq!(
            current.session_kind,
            AccountSessionKind::TemporaryAuthorizationCode
        );
        assert!(!current.can_mutate_account());
        assert!(!current.can_authorize_oauth_client());
        let response = current_user_response_for_session(&state, current.clone())
            .await
            .unwrap();
        assert_eq!(
            response.session_kind,
            AccountSessionKind::TemporaryAuthorizationCode
        );
        assert!(response.permissions.is_empty());
        let original_session = state
            .db
            .find_session(&current.session_id)
            .await
            .unwrap()
            .unwrap();
        assert!(original_session.expires_at <= util::now_ts() + 120);

        let context_id = browser_context_id_from_jar(&state, &jar).unwrap();
        let account = state
            .db
            .list_browser_context_accounts(&context_id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let (aliased_session, alias_cookie_value) = state
            .db
            .mint_browser_account_session_credential(&context_id, &account.id)
            .await
            .unwrap();
        let alias_jar = jar.add(session_cookie(&state, alias_cookie_value, 120));
        let aliased = require_current_user(&state, &alias_jar).await.unwrap();
        assert_eq!(
            aliased.session_kind,
            AccountSessionKind::TemporaryAuthorizationCode
        );
        assert_eq!(aliased.session_id, original_session.id);
        assert_eq!(aliased_session.expires_at, original_session.expires_at);
        assert_eq!(
            aliased_session.login_method.as_deref(),
            Some("authorization_code")
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn account_flow_adds_another_user_and_same_user_reauth_replaces_only_itself() {
        let (state, path) = test_state().await;
        let make_user = |email: &str, username: &str| crate::db::NewUser {
            email: email.to_string(),
            username: username.to_string(),
            display_name: None,
            phone: None,
            password_hash: "test-hash".to_string(),
            email_verified_at: Some(util::now_ts()),
            phone_verified_at: None,
            is_admin: false,
            is_active: true,
            archived_at: None,
        };
        let alice = state
            .db
            .insert_user(make_user("alice-flow@example.com", "alice-flow"))
            .await
            .unwrap();
        let bob = state
            .db
            .insert_user(make_user("bob-flow@example.com", "bob-flow"))
            .await
            .unwrap();
        let headers = HeaderMap::new();
        let alice_jar = issue_session(&state, CookieJar::new(), &headers, None, &alice, "password")
            .await
            .unwrap();
        let alice_current = require_current_user(&state, &alice_jar).await.unwrap();
        let context_id = browser_context_id_from_jar(&state, &alice_jar).unwrap();
        let wrong_target_flow = format!("alf1.{}", util::random_token(24));
        state
            .db
            .insert_account_login_flow(
                &util::token_hash(&wrong_target_flow),
                &context_id,
                "/oauth2/authorize?interaction_request=reauth-test",
                Some(&alice.id),
                600,
            )
            .await
            .unwrap();
        assert!(
            issue_session_with_login_event(
                &state,
                alice_jar.clone(),
                &headers,
                None,
                &bob,
                "password",
                LoginEventContext {
                    account_flow: Some(wrong_target_flow.clone()),
                    ..Default::default()
                },
            )
            .await
            .is_err()
        );
        state
            .db
            .consume_account_login_flow(
                &util::token_hash(&wrong_target_flow),
                &context_id,
                &alice.id,
            )
            .await
            .unwrap();
        assert!(
            state
                .db
                .list_user_sessions(&bob.id)
                .await
                .unwrap()
                .is_empty()
        );
        let account_flow = format!("alf1.{}", util::random_token(24));
        state
            .db
            .insert_account_login_flow(
                &util::token_hash(&account_flow),
                &context_id,
                "/oauth2/authorize?interaction_request=test",
                None,
                600,
            )
            .await
            .unwrap();

        let bob_jar = issue_session_with_login_event(
            &state,
            alice_jar,
            &headers,
            None,
            &bob,
            "password",
            LoginEventContext {
                account_flow: Some(account_flow),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let first_bob = require_current_user(&state, &bob_jar).await.unwrap();
        assert_eq!(first_bob.user.id, bob.id);
        assert_eq!(
            browser_context_id_from_jar(&state, &bob_jar),
            Some(context_id.clone())
        );
        assert_eq!(
            state
                .db
                .list_browser_context_accounts(&context_id)
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(
            state
                .db
                .find_session(&alice_current.session_id)
                .await
                .unwrap()
                .is_some()
        );

        let reauthenticated_jar = issue_session(&state, bob_jar, &headers, None, &bob, "password")
            .await
            .unwrap();
        let second_bob = require_current_user(&state, &reauthenticated_jar)
            .await
            .unwrap();
        assert_ne!(first_bob.session_id, second_bob.session_id);
        assert!(
            state
                .db
                .find_session(&first_bob.session_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .db
                .find_session(&alice_current.session_id)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            state
                .db
                .list_browser_context_accounts(&context_id)
                .await
                .unwrap()
                .len(),
            2
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn failed_account_reauthentication_removes_the_unbound_new_session() {
        let (state, path) = test_state().await;
        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "failed-reauth@example.com".to_string(),
                username: "failed-reauth".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let jar = issue_session(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &user,
            "password",
        )
        .await
        .unwrap();
        let original_session = session_from_cookie(&state, &jar)
            .await
            .unwrap()
            .expect("initial session should exist");
        let context_id = browser_context_id_from_jar(&state, &jar).unwrap();
        let account_flow = format!("alf1.{}", util::random_token(24));
        state
            .db
            .insert_account_login_flow(
                &util::token_hash(&account_flow),
                &context_id,
                "/oauth2/authorize?interaction_request=missing-interaction",
                Some(&user.id),
                600,
            )
            .await
            .unwrap();

        assert!(
            issue_session_with_login_event(
                &state,
                jar,
                &HeaderMap::new(),
                None,
                &user,
                "password",
                LoginEventContext {
                    account_flow: Some(account_flow),
                    ..Default::default()
                },
            )
            .await
            .is_err()
        );
        let sessions = state.db.list_user_sessions(&user.id).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, original_session.id);
        let accounts = state
            .db
            .list_browser_context_accounts(&context_id)
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].session_id, original_session.id);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn ordinary_different_user_login_starts_a_fresh_browser_context() {
        let (state, path) = test_state().await;
        let make_user = |email: &str, username: &str| crate::db::NewUser {
            email: email.to_string(),
            username: username.to_string(),
            display_name: None,
            phone: None,
            password_hash: "test-hash".to_string(),
            email_verified_at: Some(util::now_ts()),
            phone_verified_at: None,
            is_admin: false,
            is_active: true,
            archived_at: None,
        };
        let alice = state
            .db
            .insert_user(make_user("alice-fresh@example.com", "alice-fresh"))
            .await
            .unwrap();
        let bob = state
            .db
            .insert_user(make_user("bob-fresh@example.com", "bob-fresh"))
            .await
            .unwrap();
        let headers = HeaderMap::new();
        let alice_jar = issue_session(&state, CookieJar::new(), &headers, None, &alice, "password")
            .await
            .unwrap();
        let alice_session = require_current_user(&state, &alice_jar)
            .await
            .unwrap()
            .session_id;
        let alice_context = browser_context_id_from_jar(&state, &alice_jar).unwrap();
        let bob_jar = issue_session(&state, alice_jar, &headers, None, &bob, "password")
            .await
            .unwrap();
        let bob_context = browser_context_id_from_jar(&state, &bob_jar).unwrap();

        assert_ne!(alice_context, bob_context);
        assert_eq!(
            state
                .db
                .list_browser_context_accounts(&bob_context)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            state
                .db
                .find_session(&alice_session)
                .await
                .unwrap()
                .is_some()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
