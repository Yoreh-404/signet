use super::{PromptBehavior, ResolvedAuthorizeRequest};
use crate::{
    AppState,
    assurance::{self, AssurancePolicy},
    auth,
    auth_domain::ApplicationAuthContext,
    auth_flow,
    consent::OidcConsentPolicy,
    db::{ClientRecord, NewApplicationAuthContext, SessionRecord, UserRecord},
    error::AppResult,
    mfa_policy::MfaDecision,
    network_policy::TrustedNetworkPolicy,
    util,
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
    Ok(OidcConsentPolicy::new(state.settings.oidc.skip_consent)
        .requires_prompt(existing.as_ref(), requested_scopes))
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
    let policy_requires_mfa = policy.requires_mfa_for_ip(
        context
            .state
            .request_ip(context.headers, context.remote_addr)
            .await?
            .as_deref(),
    )? || assurance::DefaultAssurancePolicy
        .requires_mfa(&requested_assurance);
    auth_flow::oidc_authorization_mfa_decision(
        &policy,
        client,
        session,
        user_has_totp,
        policy_requires_mfa,
    )
}

pub(super) async fn find_or_create_application_auth_context(
    state: &AppState,
    auth_domain_id: &str,
    user_id: &str,
    acr: &str,
    amr: &[String],
    authenticated_at: i64,
    now: i64,
) -> AppResult<String> {
    if let Some(existing) = state
        .db
        .find_application_auth_context(auth_domain_id, user_id)
        .await?
    {
        let existing_context = ApplicationAuthContext {
            id: existing.id,
            auth_domain_id: existing.auth_domain_id,
            user_id: existing.user_id,
            acr: existing.acr,
            amr: util::from_json(&existing.amr)?,
            authenticated_at: existing.authenticated_at,
            expires_at: existing.expires_at,
        };
        if existing_context.can_satisfy(Some(acr), now) {
            return Ok(existing_context.id);
        }
    }

    Ok(state
        .db
        .insert_application_auth_context(NewApplicationAuthContext {
            id: uuid::Uuid::new_v4().to_string(),
            auth_domain_id: auth_domain_id.to_string(),
            user_id: user_id.to_string(),
            acr: acr.to_string(),
            amr: amr.to_vec(),
            authenticated_at,
            expires_at: now + 3600,
        })
        .await?
        .id)
}
