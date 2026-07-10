use crate::{
    AppState,
    access::{Permission, user_can_hold_permissions},
    auth_flow,
    captcha::{ArithmeticCaptchaProvider, CaptchaProvider, LoginCaptchaPrompt},
    config::SameSiteSetting,
    db::{PublicUser, SessionMetadata, UserRecord},
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
    TemporaryArchived,
}

impl AccountSessionKind {
    fn for_active_user(user: &UserRecord, has_authorization_code_redemption: bool) -> Option<Self> {
        if user.is_active != 1 {
            return None;
        }
        if user.archived_at.is_some() {
            has_authorization_code_redemption.then_some(Self::TemporaryArchived)
        } else {
            Some(Self::Standard)
        }
    }
}

pub trait AccountCapabilities {
    fn account_session_kind(&self) -> AccountSessionKind;

    fn is_temporary_archived_account(&self) -> bool {
        self.account_session_kind() == AccountSessionKind::TemporaryArchived
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
    let Some(cookie) = jar.get(&state.settings.security.cookie_name) else {
        return Ok(None);
    };
    let Some(session) = state.db.find_session(cookie.value()).await? else {
        return Ok(None);
    };
    if session.expires_at < util::now_ts() {
        state.db.delete_session(cookie.value()).await?;
        return Ok(None);
    }
    let Some(user) = state.db.find_user_by_id(&session.user_id).await? else {
        return Ok(None);
    };
    let has_redemption = if user.archived_at.is_some() {
        state.db.user_has_invitation_redemption(&user.id).await?
    } else {
        false
    };
    let Some(session_kind) = AccountSessionKind::for_active_user(&user, has_redemption) else {
        return Ok(None);
    };
    Ok(Some(CurrentUser {
        user,
        session_id: session.id,
        session_kind,
    }))
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
    pub permissions: Vec<String>,
}

pub async fn current_user_response(
    state: &AppState,
    user: UserRecord,
) -> AppResult<CurrentUserResponse> {
    let permissions = if !user_can_hold_permissions(&user) {
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
        permissions,
    })
}

pub async fn issue_session(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    request_ip: Option<String>,
    user: &UserRecord,
    method: &str,
) -> AppResult<CookieJar> {
    issue_session_with_login_event(state, jar, headers, request_ip, user, method, None, None).await
}

pub async fn issue_session_with_login_event(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    request_ip: Option<String>,
    user: &UserRecord,
    method: &str,
    oidc_client_id: Option<String>,
    external_provider: Option<String>,
) -> AppResult<CookieJar> {
    let session = state
        .db
        .insert_session(
            &user.id,
            state.settings.security.session_ttl_seconds,
            session_metadata(request_ip.clone(), headers, method),
        )
        .await?;
    state
        .db
        .record_login_event(
            &user.id,
            request_ip,
            util::user_agent(headers),
            method,
            oidc_client_id,
            external_provider,
        )
        .await?;
    let cookie = session_cookie(
        state,
        session.id,
        state.settings.security.session_ttl_seconds,
    );
    Ok(jar.add(cookie))
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
        .verify_access_token_with_issuers(token, &issuer_refs)?;
    if claims.cnf.is_some() {
        return Err(AppError::Unauthorized);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
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
    fn account_session_kind_distinguishes_temporary_archived_accounts() {
        assert_eq!(
            AccountSessionKind::for_active_user(&user(1, None), false),
            Some(AccountSessionKind::Standard)
        );
        assert_eq!(
            AccountSessionKind::for_active_user(&user(1, Some(100)), true),
            Some(AccountSessionKind::TemporaryArchived)
        );
        assert_eq!(
            AccountSessionKind::for_active_user(&user(1, Some(100)), false),
            None
        );
        assert_eq!(
            AccountSessionKind::for_active_user(&user(0, None), false),
            None
        );
    }

    #[test]
    fn temporary_archived_sessions_are_read_only_and_cannot_authorize_clients() {
        let current = CurrentUser {
            user: user(1, Some(100)),
            session_id: "session-id".to_string(),
            session_kind: AccountSessionKind::TemporaryArchived,
        };

        assert!(current.is_temporary_archived_account());
        assert!(!current.can_mutate_account());
        assert!(!current.can_authorize_oauth_client());
    }
}
