//! Request-scoped OIDC authorization materialization.
//!
//! A token response can contain both an access token and an ID token. They
//! project different mapper targets from the same authorization decision. The
//! snapshot is deliberately request-local: authorization changes must remain
//! visible on the next request, while one response must not observe a
//! half-updated policy graph between its projections.

use crate::{
    AppState, applications, authorization,
    claim_mapper::{self, ClaimContext, ClaimOutputTarget},
    db::{
        ApplicationAuthorizationProfileRecord, ApplicationClientBindingRecord, ApplicationRecord,
        ClientClaimMapperRecord, ClientRecord, UserRecord,
    },
    error::AppResult,
    oidc_claims::{DefaultEmailVerifiedClaimPolicy, EmailVerifiedClaimPolicy},
};
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub(crate) struct AuthorizationSnapshot {
    pub(crate) policy: authorization::AuthorizationPolicySnapshot,
    pub(crate) application: Option<ApplicationRecord>,
    pub(crate) binding: Option<ApplicationClientBindingRecord>,
    pub(crate) profile: Option<ApplicationAuthorizationProfileRecord>,
    pub(crate) mappers: Vec<ClientClaimMapperRecord>,
    pub(crate) entitlements: Option<authorization::ApplicationEntitlements>,
}

/// Client-connection claims without application/user entitlements.  Login
/// codes issued by the administrator-universal preview and service-adjacent
/// flows must not be turned into ordinary user-application authorization.
#[derive(Debug, Clone)]
pub(crate) struct ClientClaimsSnapshot {
    pub(crate) mappers: Vec<ClientClaimMapperRecord>,
}

impl AuthorizationSnapshot {
    pub(crate) async fn load(
        state: &AppState,
        client: &ClientRecord,
        user: &UserRecord,
    ) -> AppResult<Self> {
        let policy = state
            .db
            .load_client_policy_snapshot_for_protocol(&client.id, &user.id, "oauth2_oidc")
            .await?;
        if !policy.is_authorizable
            || !policy.is_interactive_client_runtime_active()
            || policy.client_id.as_deref() != Some(client.id.as_str())
        {
            return Err(crate::error::AppError::Forbidden);
        }
        let application = policy.application.clone();
        let binding = policy.binding.clone();
        let profile = policy.profile.clone();
        let entitlements = Some(authorization::resolve_entitlements_from_snapshot(
            &policy, user,
        )?);
        Ok(Self {
            policy: policy.clone(),
            application,
            binding,
            profile,
            mappers: policy.claim_mappers.clone(),
            entitlements,
        })
    }

    pub(crate) async fn load_runtime(
        state: &AppState,
        client: &ClientRecord,
    ) -> AppResult<applications::ApplicationRuntimeSnapshot> {
        applications::ApplicationRuntimeSnapshot::load(state, client, Some("oauth2_oidc")).await
    }

    pub(crate) fn claims_for_user(
        &self,
        client: &ClientRecord,
        user: &UserRecord,
        scope: &str,
        target: ClaimOutputTarget,
    ) -> AppResult<Map<String, Value>> {
        if let (Some(application), Some(binding)) =
            (self.application.as_ref(), self.binding.as_ref())
            && (binding.application_id != application.id || binding.client_db_id != client.id)
        {
            return Err(crate::error::AppError::Forbidden);
        }
        if let Some(profile) = self.profile.as_ref()
            && self
                .application
                .as_ref()
                .is_none_or(|application| profile.application_id != application.id)
        {
            return Err(crate::error::AppError::Forbidden);
        }
        if !self.policy.is_authorizable || self.policy.user_id != user.id {
            return Err(crate::error::AppError::Forbidden);
        }
        let mut claims = client_claims_for_user(&self.mappers, client, user, scope, target)?;
        if let Some(entitlements) = self.entitlements.as_ref() {
            claims.extend(entitlements.claims.clone());
            claims.insert(
                "policy_version".to_string(),
                Value::String(entitlements.policy_version.clone()),
            );
        }
        Ok(claims)
    }
}

impl ClientClaimsSnapshot {
    pub(crate) async fn load(state: &AppState, client: &ClientRecord) -> AppResult<Self> {
        Ok(Self {
            mappers: state.db.list_client_claim_mappers(&client.id).await?,
        })
    }

    pub(crate) fn claims_for_user(
        &self,
        client: &ClientRecord,
        user: &UserRecord,
        scope: &str,
        target: ClaimOutputTarget,
    ) -> AppResult<Map<String, Value>> {
        client_claims_for_user(&self.mappers, client, user, scope, target)
    }
}

fn client_claims_for_user(
    mappers: &[ClientClaimMapperRecord],
    client: &ClientRecord,
    user: &UserRecord,
    scope: &str,
    target: ClaimOutputTarget,
) -> AppResult<Map<String, Value>> {
    let mut claims = Map::new();
    claims.insert(
        "email_verified".to_string(),
        Value::Bool(DefaultEmailVerifiedClaimPolicy.email_verified(user, client)),
    );
    claims.extend(claim_mapper::mapped_claims(
        mappers,
        &ClaimContext {
            user,
            client,
            scope,
        },
        target,
    )?);
    Ok(claims)
}
