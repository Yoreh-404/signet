//! Application authorization and entitlement resolution.
//!
//! Authentication answers whether a Signet account may establish a session
//! with a website.  This module answers a separate question: what that
//! account may do after the protocol response is accepted.  Database reads
//! are confined to the snapshot loaders; the resolver below is deliberately
//! pure in-memory policy evaluation.

use crate::{
    AppState,
    db::{ApplicationProfileRoleRecord, ApplicationRecord, UserRecord},
    error::{AppError, AppResult},
    util,
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub use crate::db::AuthorizationPolicySnapshot;

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

/// Performs the live account/application gate.  Session credentials are not
/// read here: a session authenticates a subject, while this snapshot only
/// describes the subject's current policy inputs.
pub async fn check_login_access(
    state: &AppState,
    application: &ApplicationRecord,
    user_id: &str,
) -> AppResult<ApplicationAccessDecision> {
    let snapshot = state
        .db
        .load_application_access_snapshot(&application.id, user_id)
        .await?;
    if snapshot
        .application
        .as_ref()
        .is_none_or(|loaded| loaded.id != application.id)
    {
        return Err(AppError::Forbidden);
    }
    let loaded_application = snapshot.application.as_ref().ok_or(AppError::Forbidden)?;
    let policy_version = util::sha256_base64url(&format!(
        "signet:application-policy:v2:{}:{}:{}",
        loaded_application.id,
        loaded_application.updated_at,
        serde_json::to_string(&snapshot.authorization_config).unwrap_or_default()
    ));
    Ok(ApplicationAccessDecision {
        allowed: snapshot.is_authorizable,
        reason: if snapshot.is_authorizable {
            "active_account"
        } else {
            "inactive_account_or_tenant"
        },
        policy_version,
    })
}

/// Resolves an application-wide policy from one transactionally materialized
/// subject snapshot.
pub async fn resolve_entitlements(
    state: &AppState,
    application: &ApplicationRecord,
    user: &UserRecord,
) -> AppResult<ApplicationEntitlements> {
    let snapshot = state
        .db
        .load_application_policy_snapshot(&application.id, &user.id)
        .await?;
    validate_application_boundary(&snapshot, application.id.as_str())?;
    resolve_entitlements_from_snapshot(&snapshot, user)
}

pub async fn resolve_entitlements_for_profile(
    state: &AppState,
    application: &ApplicationRecord,
    profile: &crate::db::ApplicationAuthorizationProfileRecord,
    user: &UserRecord,
) -> AppResult<ApplicationEntitlements> {
    let snapshot = state
        .db
        .load_profile_policy_snapshot(&application.id, &profile.id, &user.id)
        .await?;
    validate_profile_boundary(&snapshot, application.id.as_str(), profile.id.as_str())?;
    resolve_entitlements_from_snapshot(&snapshot, user)
}

fn validate_application_boundary(
    snapshot: &AuthorizationPolicySnapshot,
    application_id: &str,
) -> AppResult<()> {
    if snapshot.client_id.is_some()
        || snapshot
            .application
            .as_ref()
            .is_none_or(|application| application.id != application_id)
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validate_profile_boundary(
    snapshot: &AuthorizationPolicySnapshot,
    application_id: &str,
    profile_id: &str,
) -> AppResult<()> {
    validate_application_boundary(snapshot, application_id)?;
    if snapshot.profile.as_ref().map(|profile| profile.id.as_str()) != Some(profile_id) {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Pure entitlement resolution.  This function intentionally has no `AppState`
/// parameter: a code review can therefore verify that it cannot reopen a
/// second connection after the policy snapshot was captured.
pub fn resolve_entitlements_from_snapshot(
    snapshot: &AuthorizationPolicySnapshot,
    user: &UserRecord,
) -> AppResult<ApplicationEntitlements> {
    let application = snapshot.application.as_ref().ok_or(AppError::Forbidden)?;
    if !snapshot.is_authorizable
        || snapshot.user_id != user.id
        || user.is_active != 1
        || user.archived_at.is_some()
    {
        return Err(AppError::Forbidden);
    }

    let config = &snapshot.authorization_config;
    let inherit_enterprise = config
        .get("inherit_enterprise_roles")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let member = snapshot.organization_active
        && snapshot
            .membership
            .as_ref()
            .is_some_and(|membership| membership.is_active == 1);
    let group_ids = snapshot
        .groups
        .iter()
        .map(|group| group.id.clone())
        .collect::<HashSet<_>>();

    let mut roles = BTreeSet::new();
    let mut permissions = BTreeSet::new();
    let mut groups = BTreeSet::new();
    let mut organization_role = None;

    if member && inherit_enterprise {
        apply_enterprise_entitlements(
            snapshot,
            &mut roles,
            &mut permissions,
            &mut groups,
            &mut organization_role,
        )?;
    }

    let profile = snapshot.profile.as_ref().ok_or(AppError::Forbidden)?;
    let active_roles = snapshot
        .profile_roles
        .iter()
        .filter(|role| role.profile_id == profile.id && role.is_active == 1)
        .map(|role| (role.id.as_str(), role))
        .collect::<BTreeMap<_, _>>();
    let default_roles = active_roles
        .values()
        .filter(|role| role.is_default == 1)
        .collect::<Vec<_>>();
    if default_roles.len() > 1 {
        // A profile has one default-role slot. If old data or a failed
        // external write violates that invariant, fail closed instead of
        // silently unioning multiple policy roots.
        return Err(AppError::Forbidden);
    }
    let mut applied_role_ids = BTreeSet::new();
    for role in default_roles {
        if applied_role_ids.insert(role.id.clone()) {
            add_profile_role(role, &mut roles, &mut permissions)?;
        }
    }
    if member {
        for assignment in snapshot
            .profile_user_assignments
            .iter()
            .filter(|assignment| assignment.is_active == 1 && assignment.subject_id == user.id)
        {
            add_profile_assignment_role(
                &active_roles,
                assignment.role_id.as_str(),
                &mut applied_role_ids,
                &mut roles,
                &mut permissions,
            )?;
        }
        for assignment in snapshot
            .profile_group_assignments
            .iter()
            .filter(|assignment| {
                assignment.is_active == 1 && group_ids.contains(assignment.subject_id.as_str())
            })
        {
            add_profile_assignment_role(
                &active_roles,
                assignment.role_id.as_str(),
                &mut applied_role_ids,
                &mut roles,
                &mut permissions,
            )?;
        }
        if let Some(membership_role) = snapshot
            .membership
            .as_ref()
            .map(|membership| membership.role.as_str())
        {
            for assignment in
                snapshot
                    .profile_organization_assignments
                    .iter()
                    .filter(|assignment| {
                        assignment.is_active == 1 && assignment.organization_role == membership_role
                    })
            {
                add_profile_assignment_role(
                    &active_roles,
                    assignment.role_id.as_str(),
                    &mut applied_role_ids,
                    &mut roles,
                    &mut permissions,
                )?;
            }
        }
    }
    apply_base_permissions(config, &mut permissions)?;
    apply_profile_overrides(snapshot, member, &mut permissions, config)?;

    let roles_vec = roles.into_iter().collect::<Vec<_>>();
    let permissions_vec = permissions.into_iter().collect::<Vec<_>>();
    let groups_vec = groups.into_iter().collect::<Vec<_>>();
    let mut claims = build_claims(
        application,
        &roles_vec,
        &permissions_vec,
        &groups_vec,
        organization_role.as_deref(),
        config,
    );
    claims.insert(
        "authorization_profile".to_string(),
        Value::String(profile.profile_key.clone()),
    );
    let policy_version = profile_policy_version(snapshot, profile, &roles_vec, &permissions_vec);
    Ok(ApplicationEntitlements {
        roles: roles_vec,
        permissions: permissions_vec,
        groups: groups_vec,
        organization_role,
        policy_version,
        claims,
    })
}

fn apply_enterprise_entitlements(
    snapshot: &AuthorizationPolicySnapshot,
    roles: &mut BTreeSet<String>,
    permissions: &mut BTreeSet<String>,
    groups: &mut BTreeSet<String>,
    organization_role: &mut Option<String>,
) -> AppResult<()> {
    for role in &snapshot.enterprise_roles {
        roles.insert(role.name.clone());
        permissions.extend(
            snapshot
                .enterprise_role_permissions
                .get(&role.id)
                .into_iter()
                .flatten()
                .cloned(),
        );
    }
    for group in &snapshot.groups {
        groups.insert(group.name.clone());
        if let Some(group_roles) = snapshot.enterprise_group_roles.get(&group.id) {
            for role in group_roles {
                roles.insert(role.name.clone());
                permissions.extend(
                    snapshot
                        .enterprise_role_permissions
                        .get(&role.id)
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
            }
        }
    }
    if let Some(membership) = snapshot.membership.as_ref() {
        organization_role.replace(membership.role.clone());
        roles.insert(format!("enterprise:{}", membership.role));
    }
    Ok(())
}

fn add_profile_assignment_role(
    active_roles: &BTreeMap<&str, &ApplicationProfileRoleRecord>,
    role_id: &str,
    applied_role_ids: &mut BTreeSet<String>,
    roles: &mut BTreeSet<String>,
    permissions: &mut BTreeSet<String>,
) -> AppResult<()> {
    if let Some(role) = active_roles.get(role_id)
        && applied_role_ids.insert(role.id.clone())
    {
        add_profile_role(role, roles, permissions)?;
    }
    Ok(())
}

fn add_profile_role(
    role: &ApplicationProfileRoleRecord,
    roles: &mut BTreeSet<String>,
    permissions: &mut BTreeSet<String>,
) -> AppResult<()> {
    roles.insert(role.role_key.clone());
    permissions.extend(role.permission_keys()?);
    Ok(())
}

fn apply_profile_overrides(
    snapshot: &AuthorizationPolicySnapshot,
    member: bool,
    permissions: &mut BTreeSet<String>,
    config: &Map<String, Value>,
) -> AppResult<()> {
    if !member {
        return Ok(());
    }
    for override_record in &snapshot.profile_permission_overrides {
        match override_record.effect.as_str() {
            "allow" => {
                permissions.insert(override_record.permission.clone());
            }
            "deny" => {
                permissions.remove(&override_record.permission);
            }
            _ => {}
        }
    }
    let denied = string_set(config, "denied_permissions")?;
    permissions.retain(|permission| !denied.contains(permission));
    Ok(())
}

fn apply_base_permissions(
    config: &Map<String, Value>,
    permissions: &mut BTreeSet<String>,
) -> AppResult<()> {
    permissions.extend(string_set(config, "permissions")?);
    Ok(())
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
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn profile_policy_version(
    snapshot: &AuthorizationPolicySnapshot,
    profile: &crate::db::ApplicationAuthorizationProfileRecord,
    roles: &[String],
    permissions: &[String],
) -> String {
    util::sha256_base64url(&format!(
        "signet:application-profile-entitlements:v2:{}:{}:{}:{}:{}:{}",
        snapshot
            .application
            .as_ref()
            .map(|value| value.id.as_str())
            .unwrap_or_default(),
        profile.id,
        profile.updated_at,
        profile.remote_digest.as_deref().unwrap_or_default(),
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
    fn profile_permissions_are_exact_strings() {
        let role = ApplicationProfileRoleRecord {
            id: "role-1".to_string(),
            profile_id: "profile-1".to_string(),
            role_key: "invoice-admin".to_string(),
            name: "Invoice admin".to_string(),
            description: None,
            permissions: serde_json::json!([
                "admin:billing:invoice:read",
                "admin:billing:invoice:approve"
            ])
            .to_string(),
            source: "manual".to_string(),
            is_default: 0,
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        };
        let mut roles = BTreeSet::new();
        let mut permissions = BTreeSet::new();
        add_profile_role(&role, &mut roles, &mut permissions).unwrap();
        assert!(permissions.contains("admin:billing:invoice:read"));
        assert!(permissions.contains("admin:billing:invoice:approve"));
        assert!(!permissions.contains("admin:billing"));
    }

    #[test]
    fn base_permissions_are_independent_from_profile_roles() {
        let config = serde_json::json!({"permissions": ["reports.read", "app.read"]});
        let mut permissions = BTreeSet::new();
        apply_base_permissions(config.as_object().unwrap(), &mut permissions).unwrap();
        assert_eq!(
            permissions.into_iter().collect::<Vec<_>>(),
            vec!["app.read", "reports.read"]
        );
    }
}
