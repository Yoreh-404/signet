use crate::{
    AppState, applications, auth,
    db::{BrowserContextAccountRecord, BrowserContextRecord, PublicUser, UserRecord},
    error::{AppError, AppResult},
    redirects, util,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

const ACCOUNT_LOGIN_FLOW_TTL_SECONDS: i64 = 600;
const ACCOUNT_LOGIN_FLOW_PREFIX: &str = "alf1.";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/browser-accounts", get(list_accounts))
        .route("/api/browser-accounts/csrf", get(context_csrf))
        .route("/api/browser-accounts/select", post(select_account))
        .route("/api/browser-accounts/activate", post(activate_account))
        .route("/api/browser-accounts/add/start", post(start_add_account))
        .route(
            "/api/browser-accounts/logout-all",
            post(logout_all_accounts),
        )
        .route(
            "/api/browser-accounts/{account_ref}",
            delete(remove_account),
        )
}

#[derive(Debug, Deserialize)]
struct AccountContextQuery {
    return_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct BrowserAccountResponse {
    account_ref: String,
    user: PublicUser,
    session_kind: auth::AccountSessionKind,
    current: bool,
    /// The creation time of this browser-context session. Unlike
    /// `last_selected_at`, it only changes after a successful sign-in.
    last_login_at: i64,
    last_selected_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct BrowserAccountsResponse {
    accounts: Vec<BrowserAccountResponse>,
    client_name: Option<String>,
    client_logo_uri: Option<String>,
    login_hint: Option<String>,
    reauthentication_required: bool,
}

async fn list_accounts(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<AccountContextQuery>,
) -> AppResult<(CookieJar, Json<BrowserAccountsResponse>)> {
    let return_to = redirects::local_return_to(query.return_to.as_deref());
    let interaction = crate::oidc::browser_account_interaction_context(&state, &return_to).await?;
    let (jar, context, current) = ensure_browser_context(&state, jar).await?;
    let mut accounts = Vec::new();
    for account in state.db.list_browser_context_accounts(&context.id).await? {
        let Some(user) = state.db.find_user_by_id(&account.user_id).await? else {
            continue;
        };
        let Some(session) = state
            .db
            .find_session(&account.session_id)
            .await?
            .filter(|session| session.user_id == user.id && session.expires_at >= util::now_ts())
        else {
            continue;
        };
        let trial_enrollment = state.db.find_trial_enrollment_for_user(&user.id).await?;
        if trial_enrollment
            .as_ref()
            .is_some_and(|enrollment| !enrollment.is_active_at(util::now_ts()))
        {
            continue;
        }
        if let (Some(enrollment), Some(interaction)) =
            (trial_enrollment.as_ref(), interaction.as_ref())
            && !enrollment.allows_client(&interaction.client_id)?
        {
            // Do not offer a remembered trial identity for an application it
            // can never authorize. This keeps account selection actionable.
            continue;
        }
        if let Some(interaction) = interaction.as_ref() {
            let Some(client) = state
                .db
                .find_client_by_client_id(&interaction.client_id)
                .await?
            else {
                continue;
            };
            if !applications::user_can_authorize_client(&state, &client, &user).await? {
                // The active-account boundary and factor uniqueness are
                // enforced server-side. Hiding ineligible remembered
                // identities keeps the chooser actionable but is never the
                // only check.
                continue;
            }
        }
        let has_redemption = if user.archived_at.is_some() {
            state.db.user_has_invitation_redemption(&user.id).await?
        } else {
            false
        };
        let Some(session_kind) = auth::AccountSessionKind::for_session_with_trial_enrollment(
            &user,
            &session,
            has_redemption,
            trial_enrollment.is_some(),
        ) else {
            continue;
        };
        accounts.push(BrowserAccountResponse {
            account_ref: account.id,
            session_kind,
            current: current
                .as_ref()
                .is_some_and(|current| current.session_id == account.session_id),
            user: user.public(),
            last_login_at: session.created_at,
            last_selected_at: account.last_selected_at,
        });
    }
    Ok((
        jar,
        Json(BrowserAccountsResponse {
            accounts,
            client_name: interaction.as_ref().map(|value| value.client_name.clone()),
            client_logo_uri: interaction
                .as_ref()
                .and_then(|value| value.client_logo_uri.clone()),
            login_hint: interaction
                .as_ref()
                .and_then(|value| value.login_hint.clone()),
            reauthentication_required: interaction
                .as_ref()
                .is_some_and(|value| value.reauthentication_required),
        }),
    ))
}

#[derive(Debug, Serialize)]
struct ContextCsrfResponse {
    csrf_token: String,
}

async fn context_csrf(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<ContextCsrfResponse>)> {
    let (jar, context, _current) = ensure_browser_context(&state, jar).await?;
    Ok((
        jar,
        Json(ContextCsrfResponse {
            csrf_token: context.csrf_token,
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct SelectAccountRequest {
    account_ref: String,
    return_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct SelectAccountResponse {
    continue_to: String,
}

/// A browser-context account which has passed the same lifecycle and
/// restricted-session checks used by account selection. Keeping the validation
/// here ensures ordinary account activation cannot revive a disabled,
/// expired, or otherwise unusable remembered session.
struct ActiveBrowserAccount {
    account: BrowserContextAccountRecord,
    user: UserRecord,
}

async fn active_browser_account(
    state: &AppState,
    browser_context_id: &str,
    account_ref: &str,
) -> AppResult<ActiveBrowserAccount> {
    let account = state
        .db
        .find_browser_context_account(browser_context_id, account_ref.trim())
        .await?
        .ok_or(AppError::NotFound)?;
    let user = state
        .db
        .find_user_by_id(&account.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let trial_enrollment = state.db.find_trial_enrollment_for_user(&user.id).await?;
    if trial_enrollment
        .as_ref()
        .is_some_and(|enrollment| !enrollment.is_active_at(util::now_ts()))
    {
        return Err(AppError::Unauthorized);
    }
    let has_redemption = if user.archived_at.is_some() {
        state.db.user_has_invitation_redemption(&user.id).await?
    } else {
        false
    };
    let session = state
        .db
        .find_session(&account.session_id)
        .await?
        .filter(|session| session.user_id == user.id && session.expires_at >= util::now_ts())
        .ok_or(AppError::Unauthorized)?;
    auth::AccountSessionKind::for_session_with_trial_enrollment(
        &user,
        &session,
        has_redemption,
        trial_enrollment.is_some(),
    )
    .ok_or(AppError::Unauthorized)?;

    Ok(ActiveBrowserAccount { account, user })
}

async fn select_account(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<SelectAccountRequest>,
) -> AppResult<(CookieJar, Json<SelectAccountResponse>)> {
    let context = require_browser_context(&state, &jar).await?;
    let active = active_browser_account(&state, &context.id, &payload.account_ref).await?;
    let return_to = redirects::local_return_to(payload.return_to.as_deref());
    let continuation = crate::oidc::complete_browser_account_selection(
        &state,
        &return_to,
        &active.account.session_id,
    )
    .await?;
    if continuation.selected_user_id != active.user.id {
        return Err(AppError::Unauthorized);
    }
    let (session, cookie_value) = state
        .db
        .mint_browser_account_session_credential(&context.id, &active.account.id)
        .await?;
    let remaining = session.expires_at.saturating_sub(util::now_ts()).max(0);
    let jar = jar.add(auth::session_cookie(&state, cookie_value, remaining));
    let continue_to = if continuation.reauthentication_required {
        let account_flow = create_account_login_flow(
            &state,
            &context.id,
            &continuation.continue_to,
            Some(&continuation.selected_user_id),
        )
        .await?;
        selected_account_reauthentication_url(
            &continuation.continue_to,
            &active.user.email,
            &account_flow,
        )
    } else {
        continuation.continue_to
    };
    Ok((jar, Json(SelectAccountResponse { continue_to })))
}

fn selected_account_reauthentication_url(
    return_to: &str,
    email: &str,
    account_flow: &str,
) -> String {
    format!(
        "{}&account_flow={}",
        redirects::frontend_login_url(return_to, Some(email), true),
        util::url_encode(account_flow)
    )
}

#[derive(Debug, Deserialize)]
struct ActivateAccountRequest {
    account_ref: String,
    return_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct ActivateAccountResponse {
    continue_to: String,
}

/// Makes a remembered browser account the current session outside an OIDC
/// account-selection interaction. The session itself is not recreated, so
/// this is a switch rather than a new login and must not affect login time.
async fn activate_account(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ActivateAccountRequest>,
) -> AppResult<(CookieJar, Json<ActivateAccountResponse>)> {
    let context = require_browser_context(&state, &jar).await?;
    let active = active_browser_account(&state, &context.id, &payload.account_ref).await?;
    let (session, cookie_value) = state
        .db
        .mint_browser_account_session_credential(&context.id, &active.account.id)
        .await?;
    let remaining = session.expires_at.saturating_sub(util::now_ts()).max(0);
    let jar = jar.add(auth::session_cookie(&state, cookie_value, remaining));
    let continue_to = redirects::local_return_to(payload.return_to.as_deref());
    Ok((jar, Json(ActivateAccountResponse { continue_to })))
}

#[derive(Debug, Deserialize)]
struct AddAccountRequest {
    return_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct AddAccountResponse {
    login_url: String,
}

async fn start_add_account(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<AddAccountRequest>,
) -> AppResult<Json<AddAccountResponse>> {
    let context = require_browser_context(&state, &jar).await?;
    let return_to = redirects::local_return_to(payload.return_to.as_deref());
    let account_flow = create_account_login_flow(&state, &context.id, &return_to, None).await?;
    let login_url = format!(
        "{}&account_flow={}",
        redirects::frontend_login_url(&return_to, None, true),
        util::url_encode(&account_flow)
    );
    Ok(Json(AddAccountResponse { login_url }))
}

pub(crate) async fn create_account_login_flow(
    state: &AppState,
    browser_context_id: &str,
    return_to: &str,
    expected_user_id: Option<&str>,
) -> AppResult<String> {
    let account_flow = format!("{ACCOUNT_LOGIN_FLOW_PREFIX}{}", util::random_token(32));
    state
        .db
        .insert_account_login_flow(
            &util::token_hash(&account_flow),
            browser_context_id,
            return_to,
            expected_user_id,
            ACCOUNT_LOGIN_FLOW_TTL_SECONDS,
        )
        .await?;
    Ok(account_flow)
}

async fn remove_account(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(account_ref): Path<String>,
) -> AppResult<(CookieJar, StatusCode)> {
    let context = require_browser_context(&state, &jar).await?;
    let current_session = auth::session_from_cookie(&state, &jar).await?;
    let removed = state
        .db
        .remove_browser_context_account(&context.id, &account_ref)
        .await?;
    let jar = if current_session
        .as_ref()
        .is_some_and(|session| session.id == removed.session_id)
    {
        jar.add(auth::expired_session_cookie(&state))
    } else {
        jar
    };
    Ok((jar, StatusCode::NO_CONTENT))
}

async fn logout_all_accounts(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<(CookieJar, StatusCode)> {
    let context = require_browser_context(&state, &jar).await?;
    state.db.delete_browser_context(&context.id).await?;
    Ok((
        jar.add(auth::expired_session_cookie(&state))
            .add(auth::expired_browser_context_cookie(&state)),
        StatusCode::NO_CONTENT,
    ))
}

async fn require_browser_context(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<BrowserContextRecord> {
    let context_id = auth::browser_context_id_from_jar(state, jar).ok_or(AppError::Unauthorized)?;
    state
        .db
        .find_browser_context(&context_id)
        .await?
        .ok_or(AppError::Unauthorized)
}

pub(crate) async fn ensure_browser_context(
    state: &AppState,
    jar: CookieJar,
) -> AppResult<(CookieJar, BrowserContextRecord, Option<auth::CurrentUser>)> {
    let current = auth::current_user_from_cookie(state, &jar).await?;
    if let Some(context_id) = auth::browser_context_id_from_jar(state, &jar)
        && let Some(context) = state.db.find_browser_context(&context_id).await?
        && (current.is_none()
            || state
                .db
                .find_browser_context_account_by_session(
                    &context.id,
                    &current.as_ref().expect("checked above").session_id,
                )
                .await?
                .is_some())
    {
        return Ok((jar, context, current));
    }

    let (context_id, context_cookie) = auth::create_browser_context(state).await?;
    let mut jar = jar.add(context_cookie);
    if let Some(current) = current.as_ref() {
        let account = state
            .db
            .attach_browser_context_account(&context_id, &current.user.id, &current.session_id)
            .await?;
        let (session, cookie_value) = state
            .db
            .mint_browser_account_session_credential(&context_id, &account.id)
            .await?;
        let remaining = session.expires_at.saturating_sub(util::now_ts()).max(0);
        jar = jar.add(auth::session_cookie(state, cookie_value, remaining));
    }
    let context = state
        .db
        .find_browser_context(&context_id)
        .await?
        .ok_or_else(|| AppError::Internal("browser context creation failed".to_string()))?;
    Ok((jar, context, current))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_account_reauthentication_url_prefills_the_selected_email() {
        let location = selected_account_reauthentication_url(
            "/oauth2/authorize?interaction_request=request-123",
            "alice@example.com",
            "alf1.token_123",
        );
        let url = url::Url::parse(&format!("https://signet.example{location}")).unwrap();
        let query = url.query_pairs().collect::<Vec<_>>();

        assert!(query.contains(&("auth".into(), "login".into())));
        assert!(query.contains(&(
            "return_to".into(),
            "/oauth2/authorize?interaction_request=request-123".into()
        )));
        assert!(query.contains(&("login_hint".into(), "alice@example.com".into())));
        assert!(query.contains(&("force_login".into(), "1".into())));
        assert!(query.contains(&("account_flow".into(), "alf1.token_123".into())));
    }

    #[cfg(feature = "sqlite")]
    use crate::{
        config::DatabaseKind,
        db::{NewUser, SessionMetadata},
    };
    #[cfg(feature = "sqlite")]
    use std::path::PathBuf;

    #[cfg(feature = "sqlite")]
    fn test_user(
        email: &str,
        username: &str,
        is_active: bool,
        archived_at: Option<i64>,
    ) -> NewUser {
        NewUser {
            email: email.to_string(),
            username: username.to_string(),
            display_name: None,
            phone: None,
            password_hash: "test-hash".to_string(),
            email_verified_at: Some(util::now_ts()),
            phone_verified_at: None,
            is_admin: false,
            is_active,
            archived_at,
        }
    }

    #[cfg(feature = "sqlite")]
    async fn test_state() -> (AppState, PathBuf) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-browser-accounts-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        (AppState { settings, db, jwt }, path)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn activation_switches_to_an_active_context_account_and_returns_its_login_time() {
        let (state, path) = test_state().await;
        let user = state
            .db
            .insert_user(test_user("activate@example.com", "activate", true, None))
            .await
            .unwrap();
        let (session, _) = state
            .db
            .insert_session(&user.id, 600, SessionMetadata::default())
            .await
            .unwrap();
        let (context_id, context_cookie) = auth::create_browser_context(&state).await.unwrap();
        let account = state
            .db
            .attach_browser_context_account(&context_id, &user.id, &session.id)
            .await
            .unwrap();
        let jar = CookieJar::new().add(context_cookie);

        let (jar, Json(activation)) = activate_account(
            State(state.clone()),
            jar,
            Json(ActivateAccountRequest {
                account_ref: account.id.clone(),
                return_to: Some("https://attacker.example/redirect".to_string()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(activation.continue_to, "/");
        let current = auth::current_user_from_cookie(&state, &jar)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.user.id, user.id);

        let (_, Json(listed)) = list_accounts(
            State(state.clone()),
            jar,
            Query(AccountContextQuery { return_to: None }),
        )
        .await
        .unwrap();
        assert_eq!(listed.accounts.len(), 1);
        assert_eq!(listed.accounts[0].account_ref, account.id);
        assert_eq!(listed.accounts[0].last_login_at, session.created_at);
        assert!(listed.accounts[0].current);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn activation_rejects_disabled_or_unusable_context_accounts() {
        let (state, path) = test_state().await;
        let disabled_user = state
            .db
            .insert_user(test_user("disabled@example.com", "disabled", false, None))
            .await
            .unwrap();
        let archived_user = state
            .db
            .insert_user(test_user(
                "archived@example.com",
                "archived",
                true,
                Some(util::now_ts()),
            ))
            .await
            .unwrap();
        let (context_id, context_cookie) = auth::create_browser_context(&state).await.unwrap();
        let (disabled_session, _) = state
            .db
            .insert_session(&disabled_user.id, 600, SessionMetadata::default())
            .await
            .unwrap();
        let (archived_session, _) = state
            .db
            .insert_session(&archived_user.id, 600, SessionMetadata::default())
            .await
            .unwrap();
        let disabled_account = state
            .db
            .attach_browser_context_account(&context_id, &disabled_user.id, &disabled_session.id)
            .await
            .unwrap();
        let archived_account = state
            .db
            .attach_browser_context_account(&context_id, &archived_user.id, &archived_session.id)
            .await
            .unwrap();

        for account_ref in [disabled_account.id, archived_account.id] {
            let result = activate_account(
                State(state.clone()),
                CookieJar::new().add(context_cookie.clone()),
                Json(ActivateAccountRequest {
                    account_ref,
                    return_to: Some("/".to_string()),
                }),
            )
            .await;
            assert!(matches!(result, Err(AppError::Unauthorized)));
        }

        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
