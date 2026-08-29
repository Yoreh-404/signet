use crate::{
    AppState,
    applications::ApplicationRuntimeSnapshot,
    audit::{self, AuditOutcome, AuditSink},
    claim_mapper::{self, ClaimContext, ClaimOutputTarget},
    config::DelegatedAllowlistEntry,
    db::{AuthorizationPolicySnapshot, ClientGrantRecord, ClientRecord, UserRecord},
    dpop::{self, DpopBinding},
    error::{AppError, AppResult},
    jwt::TokenSubject,
    oauth_targets,
    service_accounts::ServiceAccountProfile,
};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const MIN_EXCHANGED_TOKEN_TTL_SECONDS: i64 = 300;
pub const MAX_EXCHANGED_TOKEN_TTL_SECONDS: i64 = 600;

#[derive(Debug, Clone)]
pub struct TokenExchangeInput {
    pub subject_token: String,
    pub subject_token_type: String,
    pub requested_token_type: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
    pub audience: Option<String>,
    pub actor_token: Option<String>,
    pub dpop: Option<DpopBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangedToken {
    pub access_token: String,
    pub issued_token_type: &'static str,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Value>,
}

pub trait TokenExchangePolicy {
    fn assert_client_allowed(&self, client: &ClientRecord) -> AppResult<()>;
    fn requested_scope(&self, client: &ClientRecord, subject_scope: &str) -> AppResult<String>;
    fn target_audience(&self, client: &ClientRecord) -> AppResult<String>;
}

pub struct DefaultTokenExchangePolicy<'a> {
    input: &'a TokenExchangeInput,
}

impl<'a> DefaultTokenExchangePolicy<'a> {
    pub fn new(input: &'a TokenExchangeInput) -> Self {
        Self { input }
    }
}

impl TokenExchangePolicy for DefaultTokenExchangePolicy<'_> {
    fn assert_client_allowed(&self, client: &ClientRecord) -> AppResult<()> {
        if client
            .grant_types()?
            .iter()
            .any(|value| value == TOKEN_EXCHANGE_GRANT)
        {
            Ok(())
        } else {
            Err(oauth_error(
                "unauthorized_client",
                "client cannot use token exchange grant",
            ))
        }
    }

    fn requested_scope(&self, client: &ClientRecord, subject_scope: &str) -> AppResult<String> {
        let subject_scopes = scope_set(subject_scope);
        let client_scopes = client.scopes()?.into_iter().collect::<BTreeSet<_>>();
        let explicit = self
            .input
            .scope
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let requested = explicit.map(scope_set).unwrap_or_else(|| {
            subject_scopes
                .intersection(&client_scopes)
                .cloned()
                .collect()
        });
        if explicit.is_some() && !requested.is_subset(&subject_scopes) {
            return Err(oauth_error(
                "invalid_scope",
                "token exchange cannot increase the subject token scope",
            ));
        }
        for scope in &requested {
            if scope.ends_with(".service") {
                return Err(oauth_error(
                    "invalid_scope",
                    "user tokens cannot request service scopes",
                ));
            }
            if !client_scopes.contains(scope) {
                return Err(oauth_error(
                    "invalid_scope",
                    &format!("client is not allowed to request scope: {scope}"),
                ));
            }
        }
        if requested.is_empty() {
            return Err(oauth_error(
                "invalid_scope",
                "token exchange produced an empty scope",
            ));
        }
        Ok(requested.into_iter().collect::<Vec<_>>().join(" "))
    }

    fn target_audience(&self, client: &ClientRecord) -> AppResult<String> {
        let resource = self
            .input
            .resource
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|resource| {
                oauth_targets::normalize_resource_value(resource).map_err(|error| {
                    oauth_error("invalid_target", &format!("resource is invalid: {error}"))
                })
            })
            .transpose()?;
        let audience = self
            .input
            .audience
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|audience| {
                oauth_targets::normalize_audience(audience)
                    .map_err(|_| oauth_error("invalid_target", "audience is invalid"))
            })
            .transpose()?;
        if let (Some(resource), Some(audience)) = (&resource, &audience)
            && resource != audience
        {
            return Err(oauth_error(
                "invalid_target",
                "resource and audience identify different targets",
            ));
        }
        let configured = (!client.audience.trim().is_empty()).then(|| client.audience.trim());
        let requested = resource.as_deref().or(audience.as_deref());
        // A delegating client may be configured with its own audience while
        // being explicitly allowlisted for several downstream resources.
        // The delegated allowlist below is the target boundary; the client
        // audience is only the fallback when no resource/audience was sent.
        Ok(requested
            .or(configured)
            .unwrap_or(client.client_id.as_str())
            .to_string())
    }
}

pub async fn exchange_token(
    state: &AppState,
    headers: &HeaderMap,
    issuer: &str,
    client: &ClientRecord,
    input: TokenExchangeInput,
) -> AppResult<ExchangedToken> {
    validate_token_type(&input)?;
    let policy = DefaultTokenExchangePolicy::new(&input);
    policy.assert_client_allowed(client)?;
    // Token exchange is intentionally deferred by `authenticate_client_at` so
    // this handler can keep the target runtime decision next to the token
    // claims it emits.  The snapshot also preserves the current legacy rule:
    // an unbound client remains eligible under the pre-Application policy.
    let target_runtime = load_target_runtime(state, client).await?;
    let target_audience = policy.target_audience(client)?;
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let subject_claims = state
        .jwt
        .verify_access_token_for_token_exchange(&input.subject_token, &issuer_refs)
        .map_err(|_| oauth_error("invalid_grant", "subject_token is invalid"))?;
    if subject_claims.sub == subject_claims.client_id
        || subject_claims.sub.starts_with("service-account:")
    {
        return Err(oauth_error(
            "invalid_grant",
            "service access tokens cannot be used as a user subject_token",
        ));
    }
    if token_exchange_forbidden_login_code_level(subject_claims.gpt_sso_login_code_level.as_deref())
    {
        return Err(oauth_error(
            "invalid_grant",
            "authorization-code login tokens cannot be used as subject_token",
        ));
    }
    if subject_claims.cnf.is_some() {
        // The token-endpoint proof is for the new target token and is not an
        // `ath` proof for the subject token. Until that possession check is
        // modeled explicitly, exchanging a DPoP-bound subject as a bearer
        // input would silently weaken its binding.
        return Err(oauth_error(
            "invalid_grant",
            "DPoP-bound subject tokens cannot be exchanged",
        ));
    }
    let subject_client = state
        .db
        .find_client_by_client_id(&subject_claims.client_id)
        .await?
        .ok_or_else(|| oauth_error("invalid_grant", "subject token client does not exist"))?;
    if subject_client.is_active != 1 {
        return Err(oauth_error(
            "invalid_grant",
            "subject token client is inactive",
        ));
    }
    let user = load_active_user(state, &subject_claims.sub, &client.client_id).await?;
    let source_policy = load_subject_policy(state, &subject_client, &user, &subject_claims).await?;
    let source_binding = source_policy
        .as_ref()
        .and_then(|policy| policy.binding.as_ref());
    let target_binding = target_runtime.as_ref().map(|runtime| &runtime.binding);
    if !same_application_boundary(source_binding, target_binding) {
        return Err(oauth_error(
            "invalid_target",
            "token exchange cannot cross application boundaries",
        ));
    }
    let scope = policy.requested_scope(client, &subject_claims.scope)?;
    assert_allowlisted_delegated_scope(
        &state.settings.oidc.delegated_allowlist,
        &client.client_id,
        &target_audience,
        &subject_claims.client_id,
        &scope,
    )?;
    let consent = find_delegation_consent(
        state,
        &user.id,
        &subject_claims.client_id,
        &client.client_id,
        &scope,
    )
    .await?;

    let actor = if let Some(actor_token) = input.actor_token.as_deref() {
        let actor_claims = state
            .jwt
            .verify_access_token_for_token_exchange(actor_token, &issuer_refs)
            .map_err(|_| oauth_error("invalid_grant", "actor_token is invalid"))?;
        if actor_claims.client_id != client.client_id {
            return Err(oauth_error(
                "invalid_grant",
                "actor_token was issued to a different client",
            ));
        }
        if !claims_match_binding(&actor_claims, target_binding)
            || !service_account_actor_is_live(client, &actor_claims)
        {
            return Err(oauth_error(
                "invalid_grant",
                "actor_token runtime boundary is unavailable",
            ));
        }
        serde_json::json!({
            "sub": actor_claims.sub,
            "client_id": actor_claims.client_id,
        })
    } else {
        serde_json::json!({ "sub": client.client_id })
    };

    let mapper_records = if let Some(runtime) = target_runtime.as_ref() {
        runtime.policy.claim_mappers.clone()
    } else {
        // Historical unbound clients do not have a runtime snapshot to carry
        // their mappers. Keep that compatibility path explicit; bound clients
        // reuse the already-loaded request-local policy graph.
        state.db.list_client_claim_mappers(&client.id).await?
    };
    let mut extra_claims = claim_mapper::mapped_claims(
        &mapper_records,
        &ClaimContext {
            user: &user,
            client,
            scope: &scope,
        },
        ClaimOutputTarget::AccessToken,
    )?;
    extra_claims.insert("act".to_string(), actor);
    extra_claims.insert(
        "grant_id".to_string(),
        Value::String(consent_grant_reference(&consent)),
    );
    if let Some(authorization_details) = subject_claims.authorization_details.clone() {
        extra_claims.insert("authorization_details".to_string(), authorization_details);
    }
    dpop::add_cnf_claim(&mut extra_claims, input.dpop.as_ref());
    if let Some(binding) = target_binding {
        extra_claims.insert(
            "application_id".to_string(),
            Value::String(binding.application_id.clone()),
        );
        extra_claims.insert(
            "authorization_profile_id".to_string(),
            Value::String(binding.authorization_profile_id.clone()),
        );
    }
    let ttl = exchanged_token_ttl(state.settings.oidc.access_token_ttl_seconds);
    let access_token = state.jwt.sign_access_token_with_issuer_and_claims(
        issuer,
        TokenSubject {
            user: &user,
            client_id: &client.client_id,
            audience: Some(&target_audience),
            scope: &scope,
            nonce: None,
            auth_time: subject_claims.auth_time,
        },
        ttl,
        extra_claims,
    )?;
    state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id.clone(),
            "token.exchange",
            AuditOutcome::Success,
            serde_json::json!({
                "subject_client_id": subject_claims.client_id,
                "subject": subject_claims.sub,
                "audience": target_audience,
                "scope": scope,
                "grant_id": consent_grant_reference(&consent),
            }),
        ))
        .await?;
    Ok(ExchangedToken {
        access_token,
        issued_token_type: ACCESS_TOKEN_TYPE,
        token_type: dpop::token_type(input.dpop.as_ref()),
        expires_in: ttl,
        scope,
        authorization_details: subject_claims.authorization_details,
    })
}

/// Loads the target's application boundary exactly once.  `ApplicationRuntimeSnapshot::load`
/// is intentionally not called after this read: doing so would reopen the
/// pool and could make the gate and the emitted application/profile claims
/// observe different bindings.  An absent binding is the legacy/unbound
/// policy and is represented by `None`.
async fn load_target_runtime(
    state: &AppState,
    client: &ClientRecord,
) -> AppResult<Option<ApplicationRuntimeSnapshot>> {
    let policy = state
        .db
        .load_client_runtime_snapshot(&client.id, Some("oauth2_oidc"))
        .await?;
    target_runtime_from_policy(policy, client)
}

fn target_runtime_from_policy(
    policy: AuthorizationPolicySnapshot,
    client: &ClientRecord,
) -> AppResult<Option<ApplicationRuntimeSnapshot>> {
    if policy.client_id.as_deref() != Some(client.id.as_str())
        || policy.client_organization_id.as_deref() != client.organization_id.as_deref()
        || !policy.client_active
    {
        return Err(oauth_error(
            "unauthorized_client",
            "target client is inactive",
        ));
    }
    let Some(binding) = policy.binding.clone() else {
        // Historical clients without an application binding keep the current
        // token-exchange behavior.  They have no application boundary to
        // compare, but a token carrying boundary claims is never accepted as
        // an implicit legacy token below.
        return Ok(None);
    };
    if !policy.is_interactive_client_runtime_active() {
        return Err(oauth_error(
            "unauthorized_client",
            "target client application is unavailable",
        ));
    }
    let application = policy.application.clone().ok_or_else(|| {
        oauth_error(
            "unauthorized_client",
            "target client application is unavailable",
        )
    })?;
    Ok(Some(ApplicationRuntimeSnapshot {
        policy,
        application,
        binding,
    }))
}

/// A bound source token must be authorized by the current user policy, not
/// just by the signed application/profile claims.  An unbound source keeps
/// the legacy path, but only when it really has no boundary claims; this
/// prevents a token issued while bound from surviving an unbind operation.
async fn load_subject_policy(
    state: &AppState,
    subject_client: &ClientRecord,
    user: &UserRecord,
    claims: &crate::jwt::TokenClaims,
) -> AppResult<Option<AuthorizationPolicySnapshot>> {
    let policy = state
        .db
        .load_client_policy_snapshot_for_protocol(&subject_client.id, &user.id, "oauth2_oidc")
        .await?;
    if policy.client_id.as_deref() != Some(subject_client.id.as_str())
        || policy.client_organization_id.as_deref() != subject_client.organization_id.as_deref()
        || !policy.client_active
        || policy.user_id != user.id
        || !policy.user_active
    {
        return Err(oauth_error(
            "invalid_grant",
            "subject token runtime boundary is unavailable",
        ));
    }
    let Some(binding) = policy.binding.as_ref() else {
        if !claims_match_binding(claims, None) {
            return Err(oauth_error(
                "invalid_grant",
                "subject token application boundary is invalid",
            ));
        }
        return Ok(None);
    };
    if !policy.is_authorizable
        || !policy.is_interactive_client_runtime_active()
        || policy.client_id.as_deref() != Some(subject_client.id.as_str())
        || policy.user_id != user.id
        || !claims_match_binding(claims, Some(binding))
    {
        return Err(oauth_error(
            "invalid_grant",
            "subject token runtime boundary is unavailable",
        ));
    }
    Ok(Some(policy))
}

fn claims_match_binding(
    claims: &crate::jwt::TokenClaims,
    binding: Option<&crate::db::ApplicationClientBindingRecord>,
) -> bool {
    match binding {
        Some(binding) => {
            claims.application_id.as_deref() == Some(binding.application_id.as_str())
                && claims.authorization_profile_id.as_deref()
                    == Some(binding.authorization_profile_id.as_str())
        }
        None => claims.application_id.is_none() && claims.authorization_profile_id.is_none(),
    }
}

fn same_application_boundary(
    source: Option<&crate::db::ApplicationClientBindingRecord>,
    target: Option<&crate::db::ApplicationClientBindingRecord>,
) -> bool {
    match (source, target) {
        (Some(source), Some(target)) => source.application_id == target.application_id,
        // A bound and an unbound client cannot be compared safely. Requiring
        // both sides to share the same explicit application prevents an
        // application-scoped subject from being delegated to a legacy target.
        (Some(_), None) | (None, Some(_)) => false,
        (None, None) => true,
    }
}

fn service_account_actor_is_live(client: &ClientRecord, claims: &crate::jwt::TokenClaims) -> bool {
    !claims.sub.starts_with("service-account:")
        || (client.service_account_enabled()
            && client
                .grant_types()
                .ok()
                .is_some_and(|grants| grants.iter().any(|grant| grant == "client_credentials"))
            && claims.sub == client.service_account_subject())
}

fn validate_token_type(input: &TokenExchangeInput) -> AppResult<()> {
    if input.subject_token_type != ACCESS_TOKEN_TYPE {
        return Err(oauth_error(
            "invalid_request",
            "only access_token subject_token_type is supported",
        ));
    }
    if let Some(requested) = input.requested_token_type.as_deref()
        && requested != ACCESS_TOKEN_TYPE
    {
        return Err(oauth_error(
            "invalid_request",
            "only access_token requested_token_type is supported",
        ));
    }
    Ok(())
}

fn assert_allowlisted_delegated_scope(
    allowlist: &[DelegatedAllowlistEntry],
    client_id: &str,
    audience: &str,
    subject_client_id: &str,
    scope: &str,
) -> AppResult<()> {
    let allowed = allowlist
        .iter()
        .filter(|entry| {
            entry
                .client_id
                .as_deref()
                .is_none_or(|value| value.trim() == client_id)
        })
        .filter(|entry| {
            entry
                .audience
                .as_deref()
                .is_none_or(|value| value.trim() == audience)
        })
        .filter(|entry| {
            entry
                .subject_client_id
                .as_deref()
                .is_none_or(|value| value.trim() == subject_client_id)
        })
        .flat_map(DelegatedAllowlistEntry::normalized_scopes)
        .collect::<BTreeSet<_>>();
    for requested in scope_set(scope) {
        if !allowed.contains(&requested) {
            return Err(oauth_error(
                "invalid_scope",
                &format!("delegated scope is not allowlisted: {requested}"),
            ));
        }
    }
    Ok(())
}

async fn find_delegation_consent(
    state: &AppState,
    user_id: &str,
    subject_client_id: &str,
    actor_client_id: &str,
    requested_scope: &str,
) -> AppResult<ClientGrantRecord> {
    let mut client_ids = vec![subject_client_id.to_string()];
    if actor_client_id != subject_client_id {
        client_ids.push(actor_client_id.to_string());
    }
    let grants = state.db.list_client_grants(user_id, &client_ids).await?;
    let grants = grants
        .into_iter()
        .map(|grant| (grant.client_id.clone(), grant))
        .collect::<BTreeMap<_, _>>();
    for client_id in client_ids {
        if let Some(consent) = grants.get(&client_id)
            && consent.revoked_at.is_none()
            && grants_all(&consent.granted_scopes, requested_scope)
        {
            return Ok(consent.clone());
        }
    }
    Err(oauth_error(
        "consent_required",
        "user consent is required for the delegated scope",
    ))
}

fn grants_all(granted_scopes: &str, requested_scope: &str) -> bool {
    let granted = scope_set(granted_scopes);
    scope_set(requested_scope)
        .iter()
        .all(|scope| granted.contains(scope))
}

pub fn consent_grant_reference(consent: &ClientGrantRecord) -> String {
    format!("consent:{}:{}", consent.client_id, consent.updated_at)
}

pub fn exchanged_token_ttl(access_token_ttl_seconds: i64) -> i64 {
    access_token_ttl_seconds.clamp(
        MIN_EXCHANGED_TOKEN_TTL_SECONDS,
        MAX_EXCHANGED_TOKEN_TTL_SECONDS,
    )
}

async fn load_active_user(
    state: &AppState,
    user_id: &str,
    target_client_id: &str,
) -> AppResult<UserRecord> {
    let user = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or_else(|| oauth_error("invalid_grant", "subject user does not exist"))?;
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(oauth_error("invalid_grant", "subject user is not active"));
    }
    if let Some(enrollment) = state.db.find_trial_enrollment_for_user(&user.id).await?
        && (!enrollment.is_active_at(crate::util::now_ts())
            || !enrollment.allows_client(target_client_id)?)
    {
        return Err(oauth_error(
            "invalid_grant",
            "subject user is not eligible for this client",
        ));
    }
    Ok(user)
}

fn scope_set(value: &str) -> BTreeSet<String> {
    value
        .split_whitespace()
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn token_exchange_forbidden_login_code_level(level: Option<&str>) -> bool {
    level.is_some()
}

fn oauth_error(error: &str, description: &str) -> AppError {
    AppError::oauth(error, description, StatusCode::BAD_REQUEST)
}

#[cfg(test)]
mod tests {
    use super::{
        assert_allowlisted_delegated_scope, claims_match_binding, same_application_boundary,
        token_exchange_forbidden_login_code_level,
    };
    use crate::{
        config::DelegatedAllowlistEntry, db::ApplicationClientBindingRecord, jwt::TokenClaims,
    };

    fn claims(application_id: Option<&str>, profile_id: Option<&str>) -> TokenClaims {
        TokenClaims {
            iss: "https://issuer.example".to_string(),
            sub: "user-1".to_string(),
            aud: "client-a".to_string(),
            exp: 2,
            iat: 1,
            jti: Some("jti-1".to_string()),
            token_use: "access_token".to_string(),
            client_id: "client-a".to_string(),
            application_id: application_id.map(str::to_string),
            authorization_profile_id: profile_id.map(str::to_string),
            scope: "openid".to_string(),
            email: "user@example.com".to_string(),
            email_verified: true,
            name: Some("User".to_string()),
            preferred_username: "user".to_string(),
            nonce: None,
            auth_time: None,
            sid: None,
            cnf: None,
            authorization_details: None,
            act: None,
            grant_id: None,
            gpt_sso_login_code_level: None,
        }
    }

    fn binding(application_id: &str, client_db_id: &str) -> ApplicationClientBindingRecord {
        ApplicationClientBindingRecord {
            application_id: application_id.to_string(),
            client_db_id: client_db_id.to_string(),
            protocol: "oidc".to_string(),
            authorization_profile_id: "profile-1".to_string(),
            auth_domain_id: "domain-1".to_string(),
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn ordinary_access_tokens_remain_eligible_for_exchange() {
        assert!(!token_exchange_forbidden_login_code_level(None));
    }

    #[test]
    fn privileged_login_code_tokens_cannot_be_exchanged() {
        assert!(token_exchange_forbidden_login_code_level(Some(
            "account_recovery"
        )));
        assert!(token_exchange_forbidden_login_code_level(Some(
            "admin_universal"
        )));
        assert!(token_exchange_forbidden_login_code_level(Some(
            "trial_enrollment"
        )));
        assert!(token_exchange_forbidden_login_code_level(Some(
            "future_login_code_level"
        )));
    }

    #[test]
    fn delegated_allowlist_is_bound_to_actor_target_and_source() {
        let allowlist = vec![DelegatedAllowlistEntry {
            client_id: Some("axon".to_string()),
            audience: Some("memory-atlas".to_string()),
            subject_client_id: Some("axon".to_string()),
            scopes: vec!["memory.code.index".to_string()],
            scope: None,
        }];
        assert!(
            assert_allowlisted_delegated_scope(
                &allowlist,
                "axon",
                "memory-atlas",
                "axon",
                "memory.code.index",
            )
            .is_ok()
        );
        assert!(
            assert_allowlisted_delegated_scope(
                &allowlist,
                "other",
                "memory-atlas",
                "axon",
                "memory.code.index",
            )
            .is_err()
        );
    }

    #[test]
    fn exchanged_ttl_is_always_five_to_ten_minutes() {
        assert_eq!(super::exchanged_token_ttl(900), 600);
        assert_eq!(super::exchanged_token_ttl(300), 300);
        assert_eq!(super::exchanged_token_ttl(60), 300);
    }

    #[test]
    fn bound_subject_claims_must_match_the_current_binding() {
        let current = binding("app-1", "client-db-1");
        assert!(claims_match_binding(
            &claims(Some("app-1"), Some("profile-1")),
            Some(&current),
        ));
        assert!(!claims_match_binding(
            &claims(Some("app-1"), Some("old-profile")),
            Some(&current),
        ));
        assert!(!claims_match_binding(
            &claims(Some("app-1"), Some("profile-1")),
            None,
        ));
    }

    #[test]
    fn only_two_bound_clients_must_share_an_application() {
        let source = binding("app-1", "source-db");
        let same_target = binding("app-1", "target-db");
        let other_target = binding("app-2", "target-db");
        assert!(same_application_boundary(Some(&source), Some(&same_target)));
        assert!(!same_application_boundary(
            Some(&source),
            Some(&other_target)
        ));
        assert!(!same_application_boundary(Some(&source), None));
        assert!(!same_application_boundary(None, Some(&other_target)));
        assert!(same_application_boundary(None, None));
    }
}
