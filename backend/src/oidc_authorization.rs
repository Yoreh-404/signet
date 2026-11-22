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
        ApplicationClientBindingRecord, ApplicationRecord, ClientClaimMapperRecord, ClientRecord,
        UserRecord,
    },
    error::AppResult,
    oidc_claims::{DefaultEmailVerifiedClaimPolicy, EmailVerifiedClaimPolicy},
};
use serde_json::{Map, Value};

pub(crate) fn reserve_axon_admin_claim(state: &AppState, client: &ClientRecord) -> bool {
    crate::dcr::is_website_client_id(&client.client_id)
        || state.settings.discovery.axon_admin_trust.as_ref()
            .is_some_and(|trust| trust.client_id == client.client_id)
}

pub(crate) async fn apply_axon_admin_claim(
    state: &AppState,
    snapshot: &AuthorizationSnapshot,
    client: &ClientRecord,
    user: &UserRecord,
    audience: Option<&str>,
    public_session_id: &str,
    claims: &mut Map<String, Value>,
) -> AppResult<()> {
    let (Some(app), Some(binding)) = (&snapshot.application, &snapshot.binding) else {
        return Ok(());
    };
    if let Some((trust, pin, contract)) = trusted_axon_client(state, client, app, binding).await?
        && audience == Some(trust.audience.as_str()) && !public_session_id.is_empty()
    {
        project_verified_axon_session(&contract, trust, &pin, user.is_admin, public_session_id, claims);
    }
    Ok(())
}

async fn trusted_axon_client<'a>(
    state: &'a AppState,
    client: &ClientRecord,
    app: &ApplicationRecord,
    binding: &ApplicationClientBindingRecord,
) -> AppResult<Option<(&'a crate::config::AxonAdminTrust, String, Value)>> {
    let Some((trust, pin, row)) = trusted_axon_enrollment(state, client, app, binding).await? else {
        return Ok(None);
    };
    if row.sync_status != crate::application_discovery_contract::SYNC_STATUS_SYNCED
        || row.last_verified_digest.is_none()
        || row.last_verified_expires_at.is_none_or(|exp| exp <= crate::util::now_ts())
    {
        return Ok(None);
    }
    let Some(contract) = row.snapshot_json.as_deref().and_then(|raw| serde_json::from_str::<Value>(raw).ok()) else {
        return Ok(None);
    };
    Ok(verified_axon_admin(&contract, trust, &pin, 0)
        .is_some().then_some((trust, pin, contract)))
}

async fn trusted_axon_enrollment<'a>(
    state: &'a AppState,
    client: &ClientRecord,
    app: &ApplicationRecord,
    binding: &ApplicationClientBindingRecord,
) -> AppResult<Option<(&'a crate::config::AxonAdminTrust, String, crate::db::ApplicationDiscoveryRecord)>> {
    let Some(trust) = state.settings.discovery.axon_admin_trust.as_ref() else {
        return Ok(None);
    };
    let Some(pin) = crate::application_discovery::axon_signer_pin(&trust.signing_public_jwks) else { return Ok(None) };
    if crate::dcr::is_website_client_id(&client.client_id)
        || client.client_id != trust.client_id
        || trust.audience.is_empty() || !trust.origin.starts_with("https://")
        || client.audience != trust.audience
        || client.is_active != 1 || app.is_active != 1 || binding.is_active != 1
        || binding.protocol != "oidc" || binding.client_db_id != client.id
        || binding.application_id != app.id || app.slug != trust.application_id
        || app.organization_id != trust.organization_id
        || client.organization_id.as_deref() != Some(trust.organization_id.as_str())
    {
        return Ok(None);
    }
    if client.grant_types()? != ["authorization_code"] || client.scopes()? != ["openid"] {
        return Ok(None);
    }
    let redirects = client.redirect_uris()?;
    if redirects != [format!("{}/admin/api/auth/signet/callback", trust.origin)] {
        return Ok(None);
    }
    let Some(row) = state.db.find_application_discovery(&app.id).await? else {
        return Ok(None);
    };
    if row.management_mode != crate::application_discovery::MANAGEMENT_MODE_WEBSITE
        || row.operator_disabled != 0
        || crate::application_discovery::website_origin(&row.website_url).ok().as_deref() != Some(trust.origin.as_str())
        || crate::application_discovery::axon_signer_pin(&row.signing_public_jwks).as_deref() != Some(pin.as_str())
    {
        return Ok(None);
    }
    Ok(Some((trust, pin, row)))
}

pub(crate) async fn governed_axon_logout_uri(
    state: &AppState,
    client: &ClientRecord,
) -> AppResult<Option<String>> {
    if !state.settings.discovery.axon_admin_trust.as_ref()
        .is_some_and(|trust| trust.client_id == client.client_id)
    {
        return Ok(None);
    }
    let Some(binding) = state.db.find_application_client_binding_by_public_client_id(&client.client_id).await? else {
        return Ok(None);
    };
    let Some(app) = state.db.find_application_by_id(&binding.application_id).await? else {
        return Ok(None);
    };
    if state.settings.discovery.axon_admin_v2.is_some()
        && let Some((trust, _, _)) = trusted_axon_enrollment(state, client, &app, &binding).await?
    {
        return Ok(Some(format!("{}/admin/api/auth/signet/backchannel-logout", trust.origin)));
    }
    Ok(trusted_axon_client(state, client, &app, &binding).await?.map(|(trust, _, _)|
        format!("{}/admin/api/auth/signet/backchannel-logout", trust.origin)
    ))
}

fn project_verified_axon_session(
    contract: &Value, trust: &crate::config::AxonAdminTrust, pin: &str, is_admin: i32,
    public_session_id: &str, claims: &mut Map<String, Value>,
) {
    if let Some(value) = verified_axon_admin(contract, trust, pin, is_admin) {
        claims.insert("axon_admin".into(), value);
        claims.insert("sid".into(), Value::String(public_session_id.into()));
    }
}

fn verified_axon_admin(
    contract: &Value, trust: &crate::config::AxonAdminTrust, pin: &str, is_admin: i32,
) -> Option<Value> {
    let modules = &contract["modules"];
    let mapping = &modules["axon_admin_mapping"];
    (contract["_signet_axon_verified_signer"].as_str() == Some(pin)
        && contract["application_id"].as_str() == Some(trust.application_id.as_str())
        && mapping == &serde_json::json!({"source":"signet.is_admin","claim":"axon_admin","output":"access_token","client_id":trust.client_id,"audience":trust.audience})
        && modules["clients"].as_array().is_some_and(|clients| clients.iter().any(|declared| {
            declared["client_id"].as_str() == Some(trust.client_id.as_str())
                && declared["protocol"].as_str() == Some("oidc")
                && declared["audiences"] == serde_json::json!([trust.audience])
        }))).then_some(Value::Bool(is_admin == 1))
}

/// Dedicated authorization-code access-token projection candidate.
pub(crate) async fn project_axon_admin_v2(
    state: &AppState,
    snapshot: &AuthorizationSnapshot,
    client: &ClientRecord,
    user: &UserRecord,
    audience: Option<&str>,
    public_session_id: &str,
    scope: &str,
    issuer: &str,
) -> AppResult<Option<Value>> {
    let Some(policy) = state.settings.discovery.axon_admin_v2.as_ref() else {
        return Ok(None);
    };
    let (Some(app), Some(binding)) = (&snapshot.application, &snapshot.binding) else {
        return Ok(None);
    };
    if scope != "openid" || public_session_id.is_empty() || policy.signed_withdrawal
        || client.require_pkce != 1 || client.require_s256_pkce != 1
        || issuer != policy.issuer || policy.introspection_client_id.is_empty()
        || policy.activation_epoch <= 0 || crate::util::now_ts() < policy.activation_epoch
    {
        return Ok(None);
    }
    let Some((trust, pin, _)) = trusted_axon_enrollment(state, client, app, binding).await? else {
        return Ok(None);
    };
    if audience != Some(trust.audience.as_str())
        || policy.enrollment_id.is_empty() || policy.revision <= 0
        || policy.permissions.is_empty()
        || !policy.permissions.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Ok(None);
    }
    let Some(verifier) = state.db.find_client_by_client_id(&policy.introspection_client_id).await?
    else { return Ok(None); };
    if verifier.is_active != 1 || verifier.token_endpoint_auth_method == "none"
        || verifier.client_id == trust.client_id
        || crate::dcr::is_website_client_id(&verifier.client_id)
        || verifier.organization_id.as_deref() != Some(trust.organization_id.as_str())
        || verifier.audience != trust.audience
    {
        return Ok(None);
    }
    let enrollment = crate::db::AxonV2Enrollment {
        application_db_id: app.id.clone(),
        organization_id: trust.organization_id.clone(),
        application_slug: trust.application_id.clone(),
        enrollment_id: policy.enrollment_id.clone(),
        website_origin: trust.origin.clone(),
        signer_pin: pin.clone(),
    };
    let Some(current) = state.db.live_axon_v2_snapshot(
        enrollment, user.id.clone(), policy.revision, policy.digest.clone(),
    ).await? else {
        return Ok(None);
    };
    if !state.db.list_user_sessions(&user.id).await?.iter().any(|session| {
        session.expires_at > crate::util::now_ts()
            && crate::util::session_public_id(&session.id) == public_session_id
    }) {
        return Ok(None);
    }
    project_current_axon_v2(&current, trust, &pin, policy)
}

fn project_current_axon_v2(
    current: &Value, trust: &crate::config::AxonAdminTrust, pin: &str,
    policy: &crate::config::AxonAdminV2Policy,
) -> AppResult<Option<Value>> {
    let mapping = serde_json::json!({
        "version": 2, "source": "signet.is_admin",
        "claim": claim_mapper::AXON_ADMIN_AUTHORITY_CLAIM, "output": "access_token",
        "client_id": trust.client_id, "audience": trust.audience, "permissions": policy.permissions,
    });
    if current["application_id"].as_str() != Some(trust.application_id.as_str())
        || current["_signet_axon_verified_signer"].as_str() != Some(pin)
        || current["revision"].as_i64() != Some(policy.revision)
        || current["modules"]["axon_admin_mapping"] != mapping
    {
        return Ok(None);
    }
    Ok(Some(serde_json::json!({
        "version": 2, "application_id": trust.application_id,
        "revision": policy.revision, "permissions": policy.permissions,
    })))
}

#[cfg(test)]
mod axon_mapping_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn v2_projects_only_the_complete_approved_catalog() {
        let permissions: Vec<String> = serde_json::from_str(include_str!(
            "../tests/fixtures/axon-admin-v2-catalog.json"
        )).unwrap();
        assert_eq!(permissions.len(), 169);
        let trust = crate::config::AxonAdminTrust {
            origin: "https://axon.example".into(), organization_id: "test".into(),
            application_id: "axon".into(), client_id: "operator-browser".into(),
            audience: "https://axon.example/api".into(), signing_public_jwks: String::new(),
        };
        let policy = crate::config::AxonAdminV2Policy {
            enrollment_id: "test".into(), revision: 3, digest: "a".repeat(43), permissions,
            issuer: "https://signet.example".into(), introspection_client_id: "operator-resource".into(),
            activation_epoch: 1,
            signed_withdrawal: false,
        };
        let mut current = json!({
            "application_id": "axon", "revision": 3, "_signet_axon_verified_signer": "test-pin",
            "modules": { "axon_admin_mapping": {
                "version": 2, "source": "signet.is_admin", "claim": "axon_admin_authority",
                "output": "access_token", "client_id": trust.client_id, "audience": trust.audience,
                "permissions": policy.permissions,
            } }
        });
        let claim = project_current_axon_v2(&current, &trust, "test-pin", &policy).unwrap().unwrap();
        assert_eq!(claim, json!({
            "version": 2, "application_id": "axon", "revision": 3, "permissions": policy.permissions,
        }));
        current["modules"]["axon_admin_mapping"]["permissions"].as_array_mut().unwrap().pop();
        assert!(project_current_axon_v2(&current, &trust, "test-pin", &policy).unwrap().is_none());
    }

    #[test]
    fn axon_mapping_requires_exact_signer_and_resource_and_uses_current_admin_bit() {
        let trust = crate::config::AxonAdminTrust {
            origin: "https://axon.test".into(), organization_id: "org".into(),
            application_id: "axon".into(), client_id: "axon-next".into(),
            audience: "https://axon.test/resource".into(), signing_public_jwks: String::new(),
        };
        let mut contract = json!({
            "_signet_axon_verified_signer": "verified",
            "application_id": "axon",
            "modules": {
                "clients": [{"client_id": "axon-next", "protocol": "oidc", "audiences": ["https://axon.test/resource"]}],
                "axon_admin_mapping": {"client_id":"axon-next","audience":"https://axon.test/resource","source":"signet.is_admin","claim":"axon_admin","output":"access_token"}
            }
        });
        assert_eq!(verified_axon_admin(&contract, &trust, "verified", 1), Some(json!(true)));
        assert_eq!(verified_axon_admin(&contract, &trust, "verified", 0), Some(json!(false)));
        assert_eq!(verified_axon_admin(&contract, &trust, "other", 1), None);
        let mut claims = Map::new();
        project_verified_axon_session(&contract, &trust, "other", 1, "session-test", &mut claims);
        assert!(claims.is_empty());
        project_verified_axon_session(&contract, &trust, "verified", 0, "session-test", &mut claims);
        assert_eq!(claims["sid"], json!("session-test"));
        assert_eq!(claims["axon_admin"], json!(false));
        contract["modules"]["axon_admin_mapping"]["audience"] = json!("https://other.test");
        assert_eq!(verified_axon_admin(&contract, &trust, "verified", 1), None);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuthorizationSnapshot {
    pub(crate) policy: authorization::AuthorizationPolicySnapshot,
    pub(crate) application: Option<ApplicationRecord>,
    pub(crate) binding: Option<ApplicationClientBindingRecord>,
    pub(crate) mappers: Vec<ClientClaimMapperRecord>,
    pub(crate) entitlements: Option<authorization::ApplicationEntitlements>,
    reserve_axon_admin: bool,
}

/// Client-connection claims without application/user entitlements.  Login
/// codes issued by the administrator-universal preview and service-adjacent
/// flows must not be turned into ordinary user-application authorization.
#[derive(Debug, Clone)]
pub(crate) struct ClientClaimsSnapshot {
    pub(crate) mappers: Vec<ClientClaimMapperRecord>,
    reserve_axon_admin: bool,
}

impl AuthorizationSnapshot {
    pub(crate) async fn load(
        state: &AppState,
        client: &ClientRecord,
        user: &UserRecord,
    ) -> AppResult<Self> {
        state.db.ensure_application_for_client(client).await?;
        let policy = state
            .db
            .load_client_policy_snapshot_for_protocol(&client.id, &user.id, "oauth2_oidc")
            .await?;
        if !policy.is_authorizable
            || !policy.is_interactive_client_runtime_active()
            || !policy.has_client_application_boundary(&client.id)
        {
            return Err(crate::error::AppError::Forbidden);
        }
        let application = policy.application.clone();
        let binding = policy.binding.clone();
        let entitlements = Some(authorization::resolve_entitlements_from_snapshot(
            &policy, user,
        )?);
        let mappers = policy.claim_mappers.clone();
        Ok(Self {
            policy,
            application,
            binding,
            mappers,
            entitlements,
            reserve_axon_admin: reserve_axon_admin_claim(state, client),
        })
    }

    pub(crate) async fn load_runtime(
        state: &AppState,
        client: &ClientRecord,
    ) -> AppResult<applications::ApplicationRuntimeSnapshot> {
        applications::ApplicationRuntimeSnapshot::load_interactive(state, client, "oauth2_oidc")
            .await
    }

    pub(crate) fn claims_for_user(
        &self,
        client: &ClientRecord,
        user: &UserRecord,
        scope: &str,
        target: ClaimOutputTarget,
    ) -> AppResult<Map<String, Value>> {
        if !self.policy.has_client_application_boundary(&client.id) {
            return Err(crate::error::AppError::Forbidden);
        }
        if !self.policy.has_profile_application_boundary() {
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
        claims.remove(claim_mapper::AXON_ADMIN_AUTHORITY_CLAIM);
        if self.reserve_axon_admin {
            claims.remove("axon_admin");
            claims.remove("sid");
        }
        Ok(claims)
    }
}

impl ClientClaimsSnapshot {
    pub(crate) async fn load(state: &AppState, client: &ClientRecord) -> AppResult<Self> {
        Ok(Self {
            mappers: state.db.list_client_claim_mappers(&client.id).await?,
            reserve_axon_admin: reserve_axon_admin_claim(state, client),
        })
    }

    pub(crate) fn claims_for_user(
        &self,
        client: &ClientRecord,
        user: &UserRecord,
        scope: &str,
        target: ClaimOutputTarget,
    ) -> AppResult<Map<String, Value>> {
        let mut claims = client_claims_for_user(&self.mappers, client, user, scope, target)?;
        if self.reserve_axon_admin {
            claims.remove("axon_admin");
            claims.remove("sid");
        }
        Ok(claims)
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
