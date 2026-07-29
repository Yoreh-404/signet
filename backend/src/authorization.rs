//! Application authorization and entitlement resolution.
//!
//! Authentication answers whether a Signet account may establish a session
//! with a website.  This module answers a different question: what that
//! account may do after the website has accepted the protocol response.  The
//! separation is intentional; an application role must never become an
//! accidental login allowlist.

use crate::{
    AppState, applications,
    db::{ApplicationRecord, UserRecord},
    error::{AppError, AppResult},
    util,
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ApplicationEntitlements {
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub groups: Vec<String>,
    pub organization_role: Option<String>,
    pub policy_version: String,
    pub claims: Map<String, Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApplicationAccessDecision {
    pub allowed: bool,
    pub reason: &'static str,
    pub policy_version: String,
}

/// Performs the live login gate and returns a stable decision object.  No
/// application membership or application-local identity binding is consulted
/// here: those are legacy admission concepts and are not part of a website's
/// Signet login boundary.
pub async fn check_login_access(
    state: &AppState,
    application: &ApplicationRecord,
    user_id: &str,
) -> AppResult<ApplicationAccessDecision> {
    let allowed = state
        .db
        .user_can_access_application(application, user_id)
        .await?;
    let policy_version = application_policy_version(state, application).await?;
    Ok(ApplicationAccessDecision {
        allowed,
        reason: if allowed {
            "active_account"
        } else {
            "inactive_account_or_tenant"
        },
        policy_version,
    })
}

/// Resolves the effective application permissions at request time.
///
/// Existing enterprise roles/groups are used as the compatibility source
/// while the normalized application-role tables are introduced.  Application
/// configuration can add a default role, explicit permissions, permission
/// denials, and deterministic organization/group mappings.  All collections
/// are sorted before being emitted, so the same policy produces stable claims
/// across OAuth/OIDC, JWT, SAML, and CAS adapters.
pub async fn resolve_entitlements(
    state: &AppState,
    application: &ApplicationRecord,
    user: &UserRecord,
) -> AppResult<ApplicationEntitlements> {
    let decision = check_login_access(state, application, &user.id).await?;
    if !decision.allowed {
        return Err(AppError::Forbidden);
    }

    let config = applications::enabled_module_config(state, &application.id, "authorization")
        .await?
        .unwrap_or_default();
    let inherit_enterprise = config
        .get("inherit_enterprise_roles")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let mut roles = BTreeSet::new();
    let mut permissions = BTreeSet::new();
    let mut groups = BTreeSet::new();
    let mut organization_role = None;

    if inherit_enterprise {
        for role in state.db.list_user_roles(&user.id).await? {
            roles.insert(role.name.clone());
            permissions.extend(state.db.list_role_permissions(&role.id).await?);
        }
        for group in state.db.list_user_groups(&user.id).await? {
            groups.insert(group.name.clone());
            for role in state.db.list_group_roles(&group.id).await? {
                roles.insert(role.name.clone());
                permissions.extend(state.db.list_role_permissions(&role.id).await?);
            }
        }
        for membership in state.db.list_user_organizations(&user.id).await? {
            if membership.id == application.organization_id && membership.is_active == 1 {
                organization_role = Some(membership.role.clone());
                roles.insert(format!("enterprise:{}", membership.role));
                break;
            }
        }
    }

    // Normalized application roles take precedence over the compatibility
    // JSON role definitions.  The tables are intentionally read on every
    // decision so an administrator can revoke a grant without waiting for a
    // token/session cache to expire.
    let application_roles = state.db.list_application_roles(&application.id).await?;
    let role_by_id = application_roles
        .iter()
        .filter(|role| role.is_active == 1)
        .map(|role| (role.id.clone(), role))
        .collect::<BTreeMap<_, _>>();
    for role in application_roles
        .iter()
        .filter(|role| role.is_active == 1 && role.is_default == 1)
    {
        add_application_role(role, &mut roles, &mut permissions)?;
    }
    for role_id in state
        .db
        .list_application_user_role_ids(&application.id, &user.id)
        .await?
    {
        if let Some(role) = role_by_id.get(&role_id) {
            add_application_role(role, &mut roles, &mut permissions)?;
        }
    }
    for group in state.db.list_user_groups(&user.id).await? {
        for role_id in state
            .db
            .list_application_group_role_ids(&application.id, &group.id)
            .await?
        {
            if let Some(role) = role_by_id.get(&role_id) {
                add_application_role(role, &mut roles, &mut permissions)?;
            }
        }
    }
    if let Some(org_role) = organization_role.as_deref() {
        for role_id in state
            .db
            .list_application_organization_role_ids(&application.id, org_role)
            .await?
        {
            if let Some(role) = role_by_id.get(&role_id) {
                add_application_role(role, &mut roles, &mut permissions)?;
            }
        }
    }

    if application_roles.is_empty() {
        // Keep the JSON representation as a read-compatible fallback for
        // applications created before the normalized role tables existed.
        // Once an application has real roles, those rows are the authority;
        // otherwise a renamed/deleted role could silently come back from the
        // old config and re-grant access.
        apply_application_role_config(
            &config,
            &mut roles,
            &mut permissions,
            &mut organization_role,
            &groups,
        );
    } else {
        apply_application_explicit_permissions(&config, &mut permissions);
    }

    let mut denied = string_set(&config, "denied_permissions")?;
    for override_record in state
        .db
        .list_application_user_permission_overrides(&application.id, &user.id)
        .await?
    {
        if override_record.effect == "deny" {
            denied.insert(override_record.permission);
        } else if override_record.effect == "allow" {
            permissions.insert(override_record.permission);
        }
    }
    permissions.retain(|permission| !denied.contains(permission));

    let roles_vec = roles.into_iter().collect::<Vec<_>>();
    let permissions_vec = permissions.into_iter().collect::<Vec<_>>();
    let groups_vec = groups.into_iter().collect::<Vec<_>>();
    let policy_version = policy_version(application, &config, &roles_vec, &permissions_vec);
    let claims = build_claims(
        application,
        &roles_vec,
        &permissions_vec,
        &groups_vec,
        organization_role.as_deref(),
        &config,
    );

    Ok(ApplicationEntitlements {
        roles: roles_vec,
        permissions: permissions_vec,
        groups: groups_vec,
        organization_role,
        policy_version,
        claims,
    })
}

fn add_application_role(
    role: &crate::db::ApplicationRoleRecord,
    roles: &mut BTreeSet<String>,
    permissions: &mut BTreeSet<String>,
) -> AppResult<()> {
    roles.insert(role.name.clone());
    permissions.extend(role.permission_keys()?);
    Ok(())
}

async fn application_policy_version(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<String> {
    let config = applications::enabled_module_config(state, &application.id, "authorization")
        .await?
        .unwrap_or_default();
    Ok(util::sha256_base64url(&format!(
        "signet:application-policy:v1:{}:{}:{}",
        application.id,
        application.updated_at,
        serde_json::to_string(&config).unwrap_or_default()
    )))
}

fn apply_application_role_config(
    config: &Map<String, Value>,
    roles: &mut BTreeSet<String>,
    permissions: &mut BTreeSet<String>,
    organization_role: &mut Option<String>,
    groups: &BTreeSet<String>,
) {
    if let Some(default_role) = config
        .get("default_role")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        roles.insert(default_role.to_string());
        permissions.extend(role_permissions(config, default_role));
    }

    if let Some(current_org_role) = organization_role.as_deref() {
        if let Some(mapped_role) = config
            .get("organization_role_mappings")
            .and_then(Value::as_object)
            .and_then(|mappings| mappings.get(current_org_role))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            roles.insert(mapped_role.to_string());
            permissions.extend(role_permissions(config, mapped_role));
        }
    }

    if let Some(mapping_values) = config.get("group_mappings").and_then(Value::as_array) {
        for mapping in mapping_values {
            let Some(mapping) = mapping.as_object() else {
                continue;
            };
            let Some(group_name) = mapping.get("group").and_then(Value::as_str) else {
                continue;
            };
            if !groups.iter().any(|group| group == group_name) {
                continue;
            }
            let Some(role) = mapping.get("role").and_then(Value::as_str) else {
                continue;
            };
            let role = role.trim();
            if role.is_empty() {
                continue;
            }
            roles.insert(role.to_string());
            permissions.extend(role_permissions(config, role));
        }
    }

    if let Ok(explicit) = string_set(config, "permissions") {
        permissions.extend(explicit);
    }
}

fn apply_application_explicit_permissions(
    config: &Map<String, Value>,
    permissions: &mut BTreeSet<String>,
) {
    if let Ok(explicit) = string_set(config, "permissions") {
        permissions.extend(explicit);
    }
}

fn role_permissions(config: &Map<String, Value>, role_name: &str) -> BTreeSet<String> {
    config
        .get("custom_roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .find(|role| {
            role.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name == role_name)
        })
        .and_then(|role| role.get("permissions"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn string_set(config: &Map<String, Value>, key: &str) -> AppResult<BTreeSet<String>> {
    let Some(value) = config.get(key) else {
        return Ok(BTreeSet::new());
    };
    let values = value.as_array().ok_or_else(|| {
        AppError::Configuration(format!("application authorization {key} must be a list"))
    })?;
    if values.iter().any(|value| !value.is_string()) {
        return Err(AppError::Configuration(format!(
            "application authorization {key} must contain strings"
        )));
    }
    Ok(values
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn policy_version(
    application: &ApplicationRecord,
    config: &Map<String, Value>,
    roles: &[String],
    permissions: &[String],
) -> String {
    util::sha256_base64url(&format!(
        "signet:application-entitlements:v1:{}:{}:{}:{}:{}",
        application.id,
        application.updated_at,
        serde_json::to_string(config).unwrap_or_default(),
        serde_json::to_string(roles).unwrap_or_default(),
        serde_json::to_string(permissions).unwrap_or_default(),
    ))
}

fn build_claims(
    application: &ApplicationRecord,
    roles: &[String],
    permissions: &[String],
    groups: &[String],
    organization_role: Option<&str>,
    config: &Map<String, Value>,
) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("roles".to_string(), json_string_array(roles));
    claims.insert("permissions".to_string(), json_string_array(permissions));
    claims.insert("groups".to_string(), json_string_array(groups));
    claims.insert("entitlements".to_string(), json_string_array(permissions));
    claims.insert(
        "application_id".to_string(),
        Value::String(application.id.clone()),
    );
    claims.insert(
        "application_slug".to_string(),
        Value::String(application.slug.clone()),
    );
    if let Some(role) = organization_role.filter(|value| !value.is_empty()) {
        claims.insert(
            "organization_role".to_string(),
            Value::String(role.to_string()),
        );
    }

    if let Some(requested) = config
        .get("claims")
        .and_then(Value::as_array)
        .filter(|requested| !requested.is_empty())
    {
        // `claims` is an application-level allowlist. Identity and policy
        // metadata stay mandatory; all entitlement collections are emitted
        // only when the administrator selected them. This prevents a broad
        // default claim set from becoming an accidental data disclosure.
        let requested = requested
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        claims.retain(|name, _| {
            matches!(name.as_str(), "application_id" | "application_slug")
                || requested.contains(name.as_str())
        });
    }
    claims
}

fn json_string_array(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_role_config_merges_default_group_and_explicit_permissions() {
        let config = serde_json::json!({
            "default_role": "member",
            "permissions": ["reports.read"],
            "custom_roles": [{"name": "member", "permissions": ["app.read"]}],
            "group_mappings": [{"group": "support", "role": "operator"}],
            "organization_role_mappings": {"admin": "owner"}
        });
        let mut roles = BTreeSet::new();
        let mut permissions = BTreeSet::new();
        let mut organization_role = Some("admin".to_string());
        let groups = BTreeSet::from(["support".to_string()]);
        apply_application_role_config(
            config.as_object().unwrap(),
            &mut roles,
            &mut permissions,
            &mut organization_role,
            &groups,
        );
        assert_eq!(
            roles.into_iter().collect::<Vec<_>>(),
            vec!["member", "operator", "owner"]
        );
        assert_eq!(
            permissions.into_iter().collect::<Vec<_>>(),
            vec!["app.read", "reports.read"]
        );
    }

    #[test]
    fn denied_permissions_are_removed_after_resolution() {
        let config = serde_json::json!({"permissions": ["app.read", "app.write"], "denied_permissions": ["app.write"]});
        let mut permissions = string_set(config.as_object().unwrap(), "permissions").unwrap();
        let denied = string_set(config.as_object().unwrap(), "denied_permissions").unwrap();
        permissions.retain(|permission| !denied.contains(permission));
        assert_eq!(
            permissions.into_iter().collect::<Vec<_>>(),
            vec!["app.read"]
        );
    }
}
