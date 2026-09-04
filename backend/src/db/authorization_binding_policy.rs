use super::{
    AuthorizationBindingPermissionOverride, AuthorizationBindingsUpdate, dedupe_nonempty,
    normalize_application_entitlement_keys,
};
use crate::{
    error::{AppError, AppResult},
    organizations,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const MAX_ROLE_IDS: usize = 900;
const MAX_PERMISSION_OVERRIDES: usize = 900;
const MAX_ORGANIZATION_BINDINGS: usize = 900;

#[derive(Debug, Clone)]
pub(super) struct NormalizedAuthorizationBindingsUpdate {
    pub(super) user_id: Option<String>,
    pub(super) group_id: Option<String>,
    pub(super) user_role_ids: Vec<String>,
    pub(super) user_permission_overrides: Vec<AuthorizationBindingPermissionOverride>,
    pub(super) group_role_ids: Vec<String>,
    pub(super) organization_role_bindings: BTreeMap<String, Vec<String>>,
}

fn normalize_subject_id(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_role_ids(values: Vec<String>, field: &str) -> AppResult<Vec<String>> {
    if values.len() > MAX_ROLE_IDS {
        return Err(AppError::BadRequest(format!(
            "{field} contains too many role ids"
        )));
    }
    Ok(dedupe_nonempty(values))
}

fn normalize_permission_overrides(
    values: Vec<AuthorizationBindingPermissionOverride>,
) -> AppResult<Vec<AuthorizationBindingPermissionOverride>> {
    if values.len() > MAX_PERMISSION_OVERRIDES {
        return Err(AppError::BadRequest(
            "user_permission_overrides contains too many entries".to_string(),
        ));
    }
    let mut positions: HashMap<String, usize> = HashMap::new();
    let mut normalized: Vec<AuthorizationBindingPermissionOverride> = Vec::new();
    for value in values {
        let permission = normalize_application_entitlement_keys(vec![value.permission])?
            .into_iter()
            .next()
            .ok_or_else(|| AppError::BadRequest("permission is required".to_string()))?;
        let effect = value.effect.trim().to_ascii_lowercase();
        if effect != "allow" && effect != "deny" {
            return Err(AppError::BadRequest(
                "permission effect must be allow or deny".to_string(),
            ));
        }
        if let Some(index) = positions.get(&permission).copied() {
            normalized[index].effect = effect;
        } else {
            positions.insert(permission.clone(), normalized.len());
            normalized.push(AuthorizationBindingPermissionOverride { permission, effect });
        }
    }
    Ok(normalized)
}

fn normalize_organization_role_bindings(
    values: BTreeMap<String, Vec<String>>,
) -> AppResult<BTreeMap<String, Vec<String>>> {
    let mut normalized = BTreeMap::new();
    let mut raw_count = 0usize;
    for (organization_role, role_ids) in values {
        let organization_role = organizations::normalize_role(&organization_role)?;
        raw_count = raw_count.saturating_add(role_ids.len());
        if raw_count > MAX_ORGANIZATION_BINDINGS {
            return Err(AppError::BadRequest(
                "organization_role_bindings contains too many entries".to_string(),
            ));
        }
        normalized.insert(organization_role, dedupe_nonempty(role_ids));
    }
    Ok(normalized)
}

pub(super) fn distinct_role_ids(
    user_role_ids: &[String],
    group_role_ids: &[String],
    organization_role_bindings: &BTreeMap<String, Vec<String>>,
) -> BTreeSet<String> {
    let mut role_ids = BTreeSet::new();
    role_ids.extend(user_role_ids.iter().cloned());
    role_ids.extend(group_role_ids.iter().cloned());
    role_ids.extend(
        organization_role_bindings
            .values()
            .flat_map(|role_ids| role_ids.iter().cloned()),
    );
    role_ids
}

pub(super) fn normalize_update(
    update: AuthorizationBindingsUpdate,
) -> AppResult<NormalizedAuthorizationBindingsUpdate> {
    let user_id = normalize_subject_id(update.user_id);
    let group_id = normalize_subject_id(update.group_id);
    let user_role_ids = normalize_role_ids(update.user_role_ids, "user_role_ids")?;
    let group_role_ids = normalize_role_ids(update.group_role_ids, "group_role_ids")?;
    let user_permission_overrides =
        normalize_permission_overrides(update.user_permission_overrides)?;
    let organization_role_bindings =
        normalize_organization_role_bindings(update.organization_role_bindings)?;

    if user_id.is_none() && (!user_role_ids.is_empty() || !user_permission_overrides.is_empty()) {
        return Err(AppError::BadRequest(
            "user_id is required when user bindings are supplied".to_string(),
        ));
    }
    if group_id.is_none() && !group_role_ids.is_empty() {
        return Err(AppError::BadRequest(
            "group_id is required when group bindings are supplied".to_string(),
        ));
    }

    let distinct_role_ids =
        distinct_role_ids(&user_role_ids, &group_role_ids, &organization_role_bindings);
    if distinct_role_ids.len() > MAX_ROLE_IDS {
        return Err(AppError::BadRequest(
            "authorization bindings contain too many distinct role ids".to_string(),
        ));
    }

    Ok(NormalizedAuthorizationBindingsUpdate {
        user_id,
        group_id,
        user_role_ids,
        user_permission_overrides,
        group_role_ids,
        organization_role_bindings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update() -> AuthorizationBindingsUpdate {
        AuthorizationBindingsUpdate {
            user_id: Some(" user-1 ".to_string()),
            group_id: Some(" group-1 ".to_string()),
            user_role_ids: vec!["role-a".to_string(), "role-a".to_string()],
            user_permission_overrides: vec![
                AuthorizationBindingPermissionOverride {
                    permission: " application.read ".to_string(),
                    effect: "allow".to_string(),
                },
                AuthorizationBindingPermissionOverride {
                    permission: "application.read".to_string(),
                    effect: " DENY ".to_string(),
                },
            ],
            group_role_ids: vec!["role-b".to_string()],
            organization_role_bindings: BTreeMap::from([(
                " owner ".to_string(),
                vec!["role-a".to_string(), "role-b".to_string()],
            )]),
        }
    }

    #[test]
    fn normalization_deduplicates_roles_and_last_override_wins() {
        let normalized = normalize_update(update()).expect("valid update");

        assert_eq!(normalized.user_id.as_deref(), Some("user-1"));
        assert_eq!(normalized.group_id.as_deref(), Some("group-1"));
        assert_eq!(normalized.user_role_ids, vec!["role-a"]);
        assert_eq!(normalized.user_permission_overrides.len(), 1);
        assert_eq!(
            normalized.user_permission_overrides[0].permission,
            "application.read"
        );
        assert_eq!(normalized.user_permission_overrides[0].effect, "deny");
        assert_eq!(
            normalized.organization_role_bindings["owner"],
            vec!["role-a", "role-b"]
        );
    }

    #[test]
    fn normalization_rejects_bindings_without_subjects() {
        let mut update = update();
        update.user_id = None;
        assert!(matches!(
            normalize_update(update),
            Err(AppError::BadRequest(message))
                if message == "user_id is required when user bindings are supplied"
        ));
    }

    #[test]
    fn normalization_rejects_unknown_permission_effects() {
        let mut update = update();
        update.user_permission_overrides[0].effect = "maybe".to_string();
        assert!(matches!(
            normalize_update(update),
            Err(AppError::BadRequest(message))
                if message == "permission effect must be allow or deny"
        ));
    }
}
