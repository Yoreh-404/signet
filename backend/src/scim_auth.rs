use super::{SCIM_READ_SCOPE, SCIM_WRITE_SCOPE, ScimError};
use crate::{
    AppState,
    access::{Authorizer, Permission},
    applications,
    db::{ApplicationRecord, ScimApplicationContext, UserRecord},
    error::AppError,
    util,
};
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::Value;

#[derive(Debug)]
pub(super) struct ScimPrincipal {
    pub(super) user: Option<UserRecord>,
    pub(super) client_id: Option<String>,
    pub(super) application: Option<ApplicationRecord>,
    pub(super) token_id: Option<String>,
    pub(super) groups_enabled: bool,
    pub(super) organization_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScimAccess {
    Read,
    Write,
}

impl ScimAccess {
    pub(super) fn scope(self) -> &'static str {
        match self {
            Self::Read => SCIM_READ_SCOPE,
            Self::Write => SCIM_WRITE_SCOPE,
        }
    }
}

pub(super) async fn require_scim_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
    access: ScimAccess,
) -> Result<ScimPrincipal, ScimError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
        .ok_or_else(|| ScimError::bearer_invalid("missing bearer token"))?;
    let is_application_token = token.starts_with("scim_v1_");
    if let Some(principal) = application_scim_token_principal(state, token, access).await? {
        return Ok(principal);
    }
    if is_application_token {
        return Err(ScimError::bearer_invalid("invalid application SCIM token"));
    }
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let bootstrap_claims = state
        .jwt
        .verify_access_token_for_generic_bearer(token, &issuer_refs)
        .map_err(|_| ScimError::bearer_invalid("invalid bearer token"))?;
    if bootstrap_claims.cnf.is_some() {
        return Err(ScimError::bearer_invalid(
            "DPoP-bound tokens require a DPoP-capable resource endpoint",
        ));
    }
    if let Some(principal) =
        application_scim_principal(state, token, &issuer_refs, &bootstrap_claims, access).await?
    {
        return Ok(principal);
    }
    let runtime = state.db.runtime_settings().await?;
    let expected_audience = format!("{}/scim/v2", runtime.public_base_url.trim_end_matches('/'));
    let audiences = [expected_audience.clone()];
    let claims = state
        .jwt
        .verify_access_token_with_issuers_and_audiences(token, &issuer_refs, &audiences)
        .map_err(|_| ScimError::bearer_invalid("token audience is not valid for SCIM"))?;
    validate_scim_claims(&claims, &expected_audience, access)?;
    let user = state
        .db
        .find_user_by_id(&claims.sub)
        .await?
        .ok_or_else(|| ScimError::bearer_invalid("subject user not found"))?;
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(ScimError::bearer_invalid("subject user is not active"));
    }
    if state
        .db
        .find_trial_enrollment_for_user(&user.id)
        .await?
        .is_some()
    {
        return Err(ScimError::bearer_invalid(
            "trial enrollment accounts cannot access SCIM",
        ));
    }
    state.db.require_permission(&user, permission).await?;
    Ok(ScimPrincipal {
        user: Some(user),
        client_id: None,
        application: None,
        token_id: None,
        groups_enabled: true,
        organization_id: None,
    })
}

pub(super) async fn application_scim_token_principal(
    state: &AppState,
    raw_token: &str,
    access: ScimAccess,
) -> Result<Option<ScimPrincipal>, ScimError> {
    let token_hash = util::token_hash(raw_token);
    let Some(context) = state
        .db
        .find_scim_application_token_context(&token_hash)
        .await?
    else {
        return Ok(None);
    };
    let config = ensure_application_scim_enabled(&context.application)?;
    let token = context.token;
    let application = context.application.application;
    let scopes: Vec<String> = util::from_json(&token.scopes).map_err(ScimError::from)?;
    if !scopes.iter().any(|scope| scope == access.scope()) {
        return Err(ScimError::insufficient_scope(access.scope()));
    }
    state.db.touch_application_scim_token(&token_hash).await?;
    let organization_id = application.organization_id.clone();
    Ok(Some(ScimPrincipal {
        user: None,
        client_id: Some(format!("scim-token:{}", token.id)),
        application: Some(application),
        token_id: Some(token.id),
        groups_enabled: config
            .get("sync_groups")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        organization_id: Some(organization_id),
    }))
}

pub(super) async fn application_scim_principal(
    state: &AppState,
    raw_token: &str,
    issuers: &[&str],
    claims: &crate::jwt::TokenClaims,
    access: ScimAccess,
) -> Result<Option<ScimPrincipal>, ScimError> {
    let expected_subject = format!("service-account:{}", claims.client_id);
    if claims.sub != expected_subject {
        return Ok(None);
    }
    let Some(context) = state
        .db
        .find_scim_service_account_context(&claims.client_id)
        .await?
    else {
        return Err(ScimError::bearer_invalid("SCIM client is not registered"));
    };
    if !context.client_active || !context.service_account_enabled {
        return Err(ScimError::bearer_invalid(
            "SCIM service account is disabled",
        ));
    }
    if !claims
        .scope
        .split_ascii_whitespace()
        .any(|scope| scope == access.scope())
    {
        return Err(ScimError::insufficient_scope(access.scope()));
    }
    let application_context = context.application;
    let application = application_context.application.clone();
    let binding = &context.binding;
    if binding.application_id != application.id
        || binding.is_active != 1
        || binding.protocol != "oidc"
    {
        return Err(ScimError::bearer_invalid(
            "SCIM client is not bound to the OIDC application protocol",
        ));
    }
    let config = ensure_application_scim_enabled(&application_context)?;
    let expected_audience = config
        .get("scim_audience")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|audience| !audience.is_empty())
        .ok_or_else(|| ScimError::bearer_invalid("application SCIM audience is not configured"))?
        .to_string();
    let audiences = [expected_audience];
    let claims = state
        .jwt
        .verify_access_token_with_issuers_and_audiences(raw_token, issuers, &audiences)
        .map_err(|_| {
            ScimError::bearer_invalid(
                "token audience is not valid for this application SCIM source",
            )
        })?;
    if claims.sub != format!("service-account:{}", claims.client_id) {
        return Err(ScimError::bearer_invalid(
            "SCIM service account subject is invalid",
        ));
    }
    let required_permission = match access {
        ScimAccess::Read => Permission::UsersRead,
        ScimAccess::Write => Permission::UsersManage,
    };
    if !util::from_json::<Vec<String>>(&context.service_account_permissions)
        .map_err(ScimError::from)?
        .iter()
        .any(|permission| permission == required_permission.as_str())
    {
        return Err(ScimError::insufficient_scope(required_permission.as_str()));
    }
    let organization_id = application.organization_id.clone();
    Ok(Some(ScimPrincipal {
        user: None,
        client_id: Some(context.client_id),
        application: Some(application),
        token_id: None,
        groups_enabled: config
            .get("sync_groups")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        organization_id: Some(organization_id),
    }))
}

pub(super) fn ensure_scim_groups_enabled(principal: &ScimPrincipal) -> Result<(), ScimError> {
    if principal.groups_enabled {
        Ok(())
    } else {
        Err(ScimError::new(
            StatusCode::FORBIDDEN,
            Some("mutability"),
            "group synchronization is disabled for this application",
        ))
    }
}

pub(super) fn ensure_application_scim_enabled(
    context: &ScimApplicationContext,
) -> Result<serde_json::Map<String, Value>, ScimError> {
    if !context.runtime_active() {
        return Err(ScimError::bearer_invalid("SCIM application is disabled"));
    }
    if context.module.is_enabled != 1 {
        return Err(ScimError::bearer_invalid(
            "SCIM is not enabled for application",
        ));
    }
    let raw_config =
        serde_json::from_str::<Value>(&context.module.config_json).map_err(|error| {
            AppError::Internal(format!("application module config is invalid: {error}"))
        })?;
    let config = applications::normalize_module_config("directory_sync", raw_config)
        .map_err(ScimError::from)?
        .as_object()
        .cloned()
        .ok_or_else(|| {
            ScimError::from(AppError::Internal(
                "application module config is not an object".to_string(),
            ))
        })?;
    if config.get("scim_enabled").and_then(Value::as_bool) != Some(true) {
        return Err(ScimError::bearer_invalid(
            "SCIM is not enabled for application",
        ));
    }
    Ok(config)
}

pub(super) fn validate_scim_claims(
    claims: &crate::jwt::TokenClaims,
    expected_audience: &str,
    access: ScimAccess,
) -> Result<(), ScimError> {
    if claims.gpt_sso_login_code_level.is_some() {
        return Err(ScimError::bearer_invalid(
            "authorization-code login tokens cannot access SCIM",
        ));
    }
    if claims.aud != expected_audience {
        return Err(ScimError::bearer_invalid(
            "token audience is not valid for SCIM",
        ));
    }
    if claims.sub == claims.client_id || claims.sub.starts_with("service-account:") {
        return Err(ScimError::bearer_invalid(
            "client credential subjects are not supported by SCIM",
        ));
    }
    let required_scope = access.scope();
    if !claims
        .scope
        .split_ascii_whitespace()
        .any(|scope| scope == required_scope)
    {
        return Err(ScimError::insufficient_scope(required_scope));
    }
    Ok(())
}

pub(super) fn bearer_token(value: &str) -> Option<&str> {
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") || parts.next().is_some() {
        return None;
    }
    Some(token)
}
