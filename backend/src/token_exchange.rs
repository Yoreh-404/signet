use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    claim_mapper::{self, ClaimContext, ClaimOutputTarget},
    config::DelegatedAllowlistEntry,
    db::{ClientRecord, UserConsentRecord, UserRecord},
    error::{AppError, AppResult},
    jwt::TokenSubject,
};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

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
        let requested = explicit
            .map(scope_set)
            .unwrap_or_else(|| {
                subject_scopes
                    .intersection(&client_scopes)
                    .cloned()
                    .collect()
            });
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
            .map(normalize_resource)
            .transpose()?;
        let audience = self
            .input
            .audience
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(normalize_audience)
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
    let target_audience = policy.target_audience(client)?;
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let subject_claims = state
        .jwt
        .verify_access_token_for_token_exchange(&input.subject_token, &issuer_refs)
        .map_err(|_| oauth_error("invalid_grant", "subject_token is invalid"))?;
    if subject_claims.sub == subject_claims.client_id
        || subject_claims
            .sub
            .starts_with("service-account:")
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
    let user = load_active_user(state, &subject_claims.sub).await?;
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
        serde_json::json!({
            "sub": actor_claims.sub,
            "client_id": actor_claims.client_id,
        })
    } else {
        serde_json::json!({ "sub": client.client_id })
    };

    let mapper_records = state.db.list_client_claim_mappers(&client.id).await?;
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
        token_type: "Bearer",
        expires_in: ttl,
        scope,
        authorization_details: subject_claims.authorization_details,
    })
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

fn normalize_resource(resource: &str) -> AppResult<String> {
    let trimmed = resource.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(oauth_error("invalid_target", "resource is invalid"));
    }
    if let Ok(parsed) = url::Url::parse(trimmed)
        && parsed.fragment().is_some()
    {
        return Err(oauth_error(
            "invalid_target",
            "resource must not include a fragment",
        ));
    }
    Ok(trimmed.to_string())
}

fn normalize_audience(audience: &str) -> AppResult<String> {
    if audience.len() > 2048 || audience.chars().any(char::is_whitespace) {
        return Err(oauth_error("invalid_target", "audience is invalid"));
    }
    Ok(audience.to_string())
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
        .filter(|entry| entry.client_id.as_deref().is_none_or(|value| value.trim() == client_id))
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
) -> AppResult<UserConsentRecord> {
    let mut client_ids = vec![subject_client_id.to_string()];
    if actor_client_id != subject_client_id {
        client_ids.push(actor_client_id.to_string());
    }
    for client_id in client_ids {
        if let Some(consent) = state.db.find_user_consent(user_id, &client_id).await?
            && consent.revoked_at.is_none()
            && grants_all(&consent.granted_scopes, requested_scope)
        {
            return Ok(consent);
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

pub fn consent_grant_reference(consent: &UserConsentRecord) -> String {
    format!("consent:{}:{}", consent.client_id, consent.updated_at)
}

pub fn exchanged_token_ttl(access_token_ttl_seconds: i64) -> i64 {
    access_token_ttl_seconds
        .clamp(MIN_EXCHANGED_TOKEN_TTL_SECONDS, MAX_EXCHANGED_TOKEN_TTL_SECONDS)
}

async fn load_active_user(state: &AppState, user_id: &str) -> AppResult<UserRecord> {
    let user = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or_else(|| oauth_error("invalid_grant", "subject user does not exist"))?;
    if user.is_active == 1
        && user.archived_at.is_none()
        && state
            .db
            .find_trial_enrollment_for_user(&user.id)
            .await?
            .is_none_or(|enrollment| enrollment.is_active_at(crate::util::now_ts()))
    {
        Ok(user)
    } else {
        Err(oauth_error("invalid_grant", "subject user is not active"))
    }
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
        assert_allowlisted_delegated_scope,
        token_exchange_forbidden_login_code_level,
    };
    use crate::config::DelegatedAllowlistEntry;

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
        assert!(assert_allowlisted_delegated_scope(
            &allowlist,
            "axon",
            "memory-atlas",
            "axon",
            "memory.code.index",
        )
        .is_ok());
        assert!(assert_allowlisted_delegated_scope(
            &allowlist,
            "other",
            "memory-atlas",
            "axon",
            "memory.code.index",
        )
        .is_err());
    }

    #[test]
    fn exchanged_ttl_is_always_five_to_ten_minutes() {
        assert_eq!(super::exchanged_token_ttl(900), 600);
        assert_eq!(super::exchanged_token_ttl(300), 300);
        assert_eq!(super::exchanged_token_ttl(60), 300);
    }
}
