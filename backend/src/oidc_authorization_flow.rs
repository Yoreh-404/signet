use super::{PromptBehavior, ResolvedAuthorizeRequest};
use crate::{
    AppState,
    assurance::{self, AssurancePolicy},
    auth,
    auth_flow,
    consent::OidcConsentPolicy,
    db::{ClientRecord, SessionRecord, UserRecord},
    error::AppResult,
    mfa_policy::MfaDecision,
    network_policy::TrustedNetworkPolicy,
};
use axum::http::HeaderMap;
use std::net::SocketAddr;

pub(super) struct AuthorizationHttpContext<'a> {
    pub(super) state: &'a AppState,
    pub(super) headers: &'a HeaderMap,
    pub(super) remote_addr: Option<SocketAddr>,
}

pub(super) trait AuthorizationSessionFreshness {
    fn needs_reauthentication(
        &self,
        prompt: PromptBehavior,
        max_age: Option<i64>,
        now: i64,
    ) -> bool;
}

impl AuthorizationSessionFreshness for SessionRecord {
    fn needs_reauthentication(
        &self,
        prompt: PromptBehavior,
        max_age: Option<i64>,
        now: i64,
    ) -> bool {
        prompt.force_login
            || max_age.is_some_and(|max_age| {
                max_age == 0 || now.saturating_sub(self.created_at) > max_age
            })
    }
}

pub(super) async fn requires_authorization_consent(
    state: &AppState,
    user: &UserRecord,
    client: &ClientRecord,
    requested_scopes: &[String],
) -> AppResult<bool> {
    let existing = state
        .db
        .find_client_grant(&user.id, &client.client_id)
        .await?;
    let skip =
        state.settings.oidc.skip_consent && !crate::dcr::is_website_client_id(&client.client_id);
    Ok(OidcConsentPolicy::new(skip).requires_prompt(existing.as_ref(), requested_scopes))
}

pub(super) async fn authorization_mfa_decision(
    context: &AuthorizationHttpContext<'_>,
    current: &auth::CurrentUser,
    client: &ClientRecord,
    session: &SessionRecord,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<MfaDecision> {
    let user_has_totp = context
        .state
        .db
        .find_totp_method(&current.user.id)
        .await?
        .is_some();
    let policy = context.state.db.security_policy().await?;
    let requested_assurance = request.requested_assurance()?;
    let ip = context.state.request_ip(context.headers, context.remote_addr).await?;
    decide_authorization_mfa(&policy, client, session, user_has_totp, ip.as_deref(), &requested_assurance)
}

/// Request IP must be resolved by AppState::request_ip (including the effective
/// proxy-trust cache), not taken from a caller-supplied header or fresh SQL row.
#[cfg(all(feature = "sqlite", feature = "axon-incumbent-storage"))]
pub(super) fn authorization_mfa_decision_on_conn(
    conn: &mut diesel::SqliteConnection,
    client: &ClientRecord,
    session: &SessionRecord,
    request: &ResolvedAuthorizeRequest,
    request_ip: Option<&str>,
) -> AppResult<MfaDecision> {
    let user_has_totp = crate::db::Db::sqlite_has_totp_on_conn(conn, &session.user_id)?;
    let policy = crate::db::Db::sqlite_security_policy_on_conn(conn)?;
    decide_authorization_mfa(&policy, client, session, user_has_totp, request_ip, &request.requested_assurance()?)
}

fn decide_authorization_mfa(
    policy: &crate::db::SecurityPolicyRecord,
    client: &ClientRecord,
    session: &SessionRecord,
    user_has_totp: bool,
    ip: Option<&str>,
    requested_assurance: &assurance::RequestedAssurance,
) -> AppResult<MfaDecision> {
    let policy_requires_mfa = policy.requires_mfa_for_ip(ip)?
        || assurance::DefaultAssurancePolicy.requires_mfa(requested_assurance);
    auth_flow::oidc_authorization_mfa_decision(
        policy,
        client,
        session,
        user_has_totp,
        policy_requires_mfa,
    )
}
