use crate::{
    db::{OrganizationMemberInput, OrganizationMemberWithUserRecord, UserRecord},
    error::{AppError, AppResult},
};
use std::collections::{BTreeMap, BTreeSet};

pub fn ensure_user_record_editable(user: &UserRecord) -> AppResult<()> {
    if user.archived_at.is_some() {
        return Err(AppError::BadRequest(
            "archived users cannot be edited".to_string(),
        ));
    }
    Ok(())
}

pub fn normalize_user_ids(user_ids: &[String]) -> BTreeSet<String> {
    user_ids
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

pub fn normalize_organization_member_roles(
    members: &[OrganizationMemberInput],
) -> BTreeMap<String, String> {
    let mut normalized = BTreeMap::new();
    for member in members {
        let user_id = member.user_id.trim();
        let role = member.role.trim();
        if !user_id.is_empty() && !role.is_empty() {
            normalized.insert(user_id.to_string(), role.to_string());
        }
    }
    normalized
}

pub fn ensure_archived_group_members_preserved(
    existing_members: &[UserRecord],
    requested_user_ids: &BTreeSet<String>,
) -> AppResult<BTreeSet<String>> {
    let archived_user_ids = existing_members
        .iter()
        .filter(|user| user.archived_at.is_some())
        .map(|user| user.id.clone())
        .collect::<BTreeSet<_>>();
    for user_id in &archived_user_ids {
        if !requested_user_ids.contains(user_id) {
            return Err(AppError::BadRequest(format!(
                "archived group member cannot be removed: {user_id}"
            )));
        }
    }
    Ok(archived_user_ids)
}

pub fn ensure_archived_organization_members_preserved(
    existing_members: &[OrganizationMemberWithUserRecord],
    requested_roles: &BTreeMap<String, String>,
) -> AppResult<BTreeSet<String>> {
    let mut archived_user_ids = BTreeSet::new();
    for member in existing_members
        .iter()
        .filter(|member| member.archived_at.is_some())
    {
        archived_user_ids.insert(member.user_id.clone());
        match requested_roles.get(&member.user_id) {
            Some(role) if role == &member.role => {}
            Some(_) => {
                return Err(AppError::BadRequest(format!(
                    "archived organization member role cannot be changed: {}",
                    member.user_id
                )));
            }
            None => {
                return Err(AppError::BadRequest(format!(
                    "archived organization member cannot be removed: {}",
                    member.user_id
                )));
            }
        }
    }
    Ok(archived_user_ids)
}

pub fn ensure_assignable_user_record(
    user: &UserRecord,
    allowed_archived_user_ids: &BTreeSet<String>,
    target: &str,
) -> AppResult<()> {
    if user.archived_at.is_some() && !allowed_archived_user_ids.contains(&user.id) {
        return Err(AppError::BadRequest(format!(
            "archived users cannot be assigned to {target}: {}",
            user.id
        )));
    }
    Ok(())
}

pub fn ensure_assignable_user_state(
    user_id: &str,
    archived_at: Option<i64>,
    allowed_archived_user_ids: &BTreeSet<String>,
    target: &str,
) -> AppResult<()> {
    if archived_at.is_some() && !allowed_archived_user_ids.contains(user_id) {
        return Err(AppError::BadRequest(format!(
            "archived users cannot be assigned to {target}: {user_id}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str, archived_at: Option<i64>) -> UserRecord {
        UserRecord {
            id: id.to_string(),
            email: format!("{id}@example.com"),
            username: id.to_string(),
            display_name: None,
            phone: None,
            password_hash: "hash".to_string(),
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: 0,
            is_active: 1,
            archived_at,
            registration_source: "local".to_string(),
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn organization_member(
        user_id: &str,
        role: &str,
        archived_at: Option<i64>,
    ) -> OrganizationMemberWithUserRecord {
        OrganizationMemberWithUserRecord {
            organization_id: "org".to_string(),
            user_id: user_id.to_string(),
            role: role.to_string(),
            membership_created_at: 1,
            membership_updated_at: 1,
            email: format!("{user_id}@example.com"),
            username: user_id.to_string(),
            display_name: None,
            is_active: 1,
            archived_at,
        }
    }

    #[test]
    fn archived_users_are_not_editable() {
        assert!(ensure_user_record_editable(&user("active", None)).is_ok());
        assert!(matches!(
            ensure_user_record_editable(&user("archived", Some(100))),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn archived_group_members_must_be_preserved() {
        let existing = vec![user("active", None), user("archived", Some(100))];
        let requested = normalize_user_ids(&["active".to_string(), "archived".to_string()]);
        assert_eq!(
            ensure_archived_group_members_preserved(&existing, &requested).unwrap(),
            BTreeSet::from(["archived".to_string()])
        );

        let requested = normalize_user_ids(&["active".to_string()]);
        assert!(matches!(
            ensure_archived_group_members_preserved(&existing, &requested),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn archived_organization_members_must_keep_role() {
        let existing = vec![
            organization_member("active", "member", None),
            organization_member("archived", "admin", Some(100)),
        ];
        let requested = normalize_organization_member_roles(&[
            OrganizationMemberInput {
                user_id: "active".to_string(),
                role: "owner".to_string(),
            },
            OrganizationMemberInput {
                user_id: "archived".to_string(),
                role: "admin".to_string(),
            },
        ]);
        assert_eq!(
            ensure_archived_organization_members_preserved(&existing, &requested).unwrap(),
            BTreeSet::from(["archived".to_string()])
        );

        let changed_role = normalize_organization_member_roles(&[OrganizationMemberInput {
            user_id: "archived".to_string(),
            role: "member".to_string(),
        }]);
        assert!(matches!(
            ensure_archived_organization_members_preserved(&existing, &changed_role),
            Err(AppError::BadRequest(_))
        ));

        let removed = normalize_organization_member_roles(&[OrganizationMemberInput {
            user_id: "active".to_string(),
            role: "owner".to_string(),
        }]);
        assert!(matches!(
            ensure_archived_organization_members_preserved(&existing, &removed),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn archived_users_can_only_be_reassigned_when_already_preserved() {
        let archived = user("archived", Some(100));
        assert!(ensure_assignable_user_record(&archived, &BTreeSet::new(), "groups").is_err());
        assert!(
            ensure_assignable_user_record(
                &archived,
                &BTreeSet::from(["archived".to_string()]),
                "groups",
            )
            .is_ok()
        );
    }
}
