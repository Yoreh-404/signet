use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    claim_mapper::{self, ClaimContext, ClaimOutputTarget},
    db::{ClientRecord, UserRecord},
    error::{AppError, AppResult},
    jwt::TokenSubject,
};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};

pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Debug, Clone)]
pub struct TokenExchangeInput {
    pub subject_token: String,
    pub subject_token_type: String,
    pub requested_token_type: Option<String>,
    pub scope: Option<String>,
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
}

pub trait TokenExchangePolicy {
    fn assert_client_allowed(&self, client: &ClientRecord) -> AppResult<()>;
    fn requested_scope(&self, client: &ClientRecord, subject_scope: &str) -> AppResult<String>;
    fn assert_target(&self, client: &ClientRecord) -> AppResult<()>;
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
        let client_scopes = client.scopes()?;
        let requested = match self.input.scope.as_deref().map(str::trim) {
            Some(value) if !value.is_empty() => scope_set(value),
            _ => subject_scopes
                .iter()
                .filter(|scope| client_scopes.iter().any(|allowed| allowed == *scope))
                .cloned()
                .collect(),
        };
        for scope in &requested {
            if !subject_scopes.iter().any(|allowed| allowed == scope) {
                return Err(oauth_error(
                    "invalid_scope",
                    &format!("subject token does not include scope: {scope}"),
                ));
            }
            if !client_scopes.iter().any(|allowed| allowed == scope) {
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
        Ok(requested.join(" "))
    }

    fn assert_target(&self, client: &ClientRecord) -> AppResult<()> {
        if let Some(audience) = self.input.audience.as_deref()
            && audience != client.client_id
        {
            return Err(oauth_error(
                "invalid_target",
                "audience must match the authenticated client",
            ));
        }
        Ok(())
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
    policy.assert_target(client)?;
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let subject_claims = state
        .jwt
        .verify_access_token_with_issuers(&input.subject_token, &issuer_refs)
        .map_err(|_| oauth_error("invalid_grant", "subject_token is invalid"))?;
    if subject_claims.sub == subject_claims.client_id {
        return Err(oauth_error(
            "invalid_grant",
            "client credentials tokens cannot be used as subject_token",
        ));
    }
    if token_exchange_forbidden_login_code_level(subject_claims.gpt_sso_login_code_level.as_deref())
    {
        return Err(oauth_error(
            "invalid_grant",
            "authorization-code login tokens cannot be used as subject_token",
        ));
    }
    let user = load_active_user(state, &subject_claims.sub).await?;
    let scope = policy.requested_scope(client, &subject_claims.scope)?;
    let mapper_records = state.db.list_client_claim_mappers(&client.id).await?;
    let extra_claims = claim_mapper::mapped_claims(
        &mapper_records,
        &ClaimContext {
            user: &user,
            client,
            scope: &scope,
        },
        ClaimOutputTarget::AccessToken,
    )?;
    let access_token = state.jwt.sign_access_token_with_issuer_and_claims(
        issuer,
        TokenSubject {
            user: &user,
            client_id: &client.client_id,
            audience: None,
            scope: &scope,
            nonce: None,
            auth_time: subject_claims.auth_time,
        },
        state.settings.oidc.access_token_ttl_seconds,
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
                "scope": scope,
            }),
        ))
        .await?;
    Ok(ExchangedToken {
        access_token,
        issued_token_type: ACCESS_TOKEN_TYPE,
        token_type: "Bearer",
        expires_in: state.settings.oidc.access_token_ttl_seconds,
        scope,
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
    if input.actor_token.is_some() {
        return Err(oauth_error(
            "invalid_request",
            "actor_token is not supported",
        ));
    }
    Ok(())
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
            .is_none()
    {
        Ok(user)
    } else {
        Err(oauth_error("invalid_grant", "subject user is not active"))
    }
}

fn scope_set(value: &str) -> Vec<String> {
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
    use super::token_exchange_forbidden_login_code_level;

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
}
