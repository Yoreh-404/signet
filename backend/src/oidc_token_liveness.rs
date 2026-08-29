use super::load_oidc_user;
use crate::{
    AppState, applications,
    db::{ApplicationClientBindingRecord, ClientRecord},
    error::AppResult,
    jwt::TokenClaims,
    service_accounts::ServiceAccountProfile,
};

pub(super) async fn introspected_access_token_is_live(
    state: &AppState,
    source_client: Option<&ClientRecord>,
    claims: &TokenClaims,
) -> AppResult<bool> {
    let Some(source_client) = source_client else {
        return Ok(false);
    };

    // Machine tokens have no user policy graph, but they still carry the
    // application/profile boundary. Resolve the complete runtime snapshot
    // before reporting active so disabling the application, organization,
    // discovery revision, or binding invalidates an already signed token.
    if is_machine_token_claims(claims) {
        let runtime = match applications::ApplicationRuntimeSnapshot::load(
            state,
            source_client,
            None,
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(_) => return Ok(false),
        };
        if !token_claims_match_application_binding(claims, Some(&runtime.binding)) {
            return Ok(false);
        }
        if !service_account_claim_is_live(source_client, claims) {
            return Ok(false);
        }
        return Ok(true);
    }

    let user = match load_oidc_user(state, &claims.sub).await {
        Ok(user) => user,
        Err(_) => return Ok(false),
    };
    // Keep the policy snapshot next to the grant check so a stale outer
    // binding read cannot make the token appear active after an unbind or
    // rebind.
    let policy = match state
        .db
        .load_client_policy_snapshot_for_protocol(&source_client.id, &user.id, "oauth2_oidc")
        .await
    {
        Ok(policy) => policy,
        Err(_) => return Ok(false),
    };
    if let Some(binding) = policy.binding.as_ref() {
        if !policy.is_authorizable
            || !policy.is_interactive_client_runtime_active()
            || policy.client_id.as_deref() != Some(source_client.id.as_str())
            || policy.user_id != user.id
            || !token_claims_match_application_binding(claims, Some(binding))
        {
            return Ok(false);
        }
    } else if !token_claims_match_application_binding(claims, None) {
        return Ok(false);
    }
    introspected_user_grant_is_live(
        state,
        &user.id,
        &claims.client_id,
        &claims.scope,
        claims.grant_id.as_deref(),
    )
    .await
}

pub(super) fn is_machine_token_claims(claims: &TokenClaims) -> bool {
    claims.sub.starts_with("service-account:")
        || (claims.sub == claims.client_id && claims.email.is_empty())
}

pub(super) fn service_account_claim_is_live(client: &ClientRecord, claims: &TokenClaims) -> bool {
    client.service_account_enabled()
        && client
            .grant_types()
            .ok()
            .is_some_and(|grants| grants.iter().any(|grant| grant == "client_credentials"))
        && (claims.sub == client.service_account_subject()
            || (claims.sub == client.client_id && claims.email.is_empty()))
}

pub(super) fn token_claims_match_application_binding(
    claims: &TokenClaims,
    binding: Option<&ApplicationClientBindingRecord>,
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

pub(super) async fn introspected_user_grant_is_live(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scope: &str,
    grant_id: Option<&str>,
) -> AppResult<bool> {
    if let Some(grant_id) = grant_id
        && let Some(reference) = grant_id.strip_prefix("consent:")
        && let Some((grant_client_id, version)) = reference.rsplit_once(':')
    {
        let Ok(version) = version.parse::<i64>() else {
            return Ok(false);
        };
        let Some(consent) = state.db.find_client_grant(user_id, grant_client_id).await? else {
            return Ok(false);
        };
        return Ok(consent.revoked_at.is_none()
            && consent.updated_at == version
            && grants_all_scopes(&consent.granted_scopes, scope));
    }
    let Some(consent) = state.db.find_client_grant(user_id, client_id).await? else {
        // `skip_consent` creates an implicit authorization grant for ordinary
        // browser flows. Delegated exchanges always carry a consent:* grant
        // reference.
        return Ok(true);
    };
    Ok(consent.revoked_at.is_none() && grants_all_scopes(&consent.granted_scopes, scope))
}

pub(super) async fn introspected_refresh_grant_is_live(
    state: &AppState,
    user_id: &str,
    client_id: &str,
) -> AppResult<bool> {
    let Some(consent) = state.db.find_client_grant(user_id, client_id).await? else {
        return Ok(true);
    };
    Ok(consent.revoked_at.is_none())
}

fn grants_all_scopes(granted_scopes: &str, requested_scope: &str) -> bool {
    let granted = granted_scopes
        .split_whitespace()
        .collect::<std::collections::BTreeSet<_>>();
    requested_scope
        .split_whitespace()
        .all(|scope| granted.contains(scope))
}
