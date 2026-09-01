use crate::{
    AppState, archived_accounts,
    db::OrganizationMemberInput,
    error::{AppError, AppResult},
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) async fn ensure_user_editable(
    state: &AppState,
    id: &str,
) -> AppResult<crate::db::UserRecord> {
    let user = state
        .db
        .find_user_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;
    archived_accounts::ensure_user_record_editable(&user)?;
    Ok(user)
}

pub(crate) fn ensure_account_metadata_update_allowed(
    current: &crate::db::UserRecord,
    target: &crate::db::UserRecord,
    next_is_admin: bool,
    next_is_active: bool,
) -> AppResult<()> {
    if target.is_active != i32::from(next_is_active) {
        return Err(AppError::BadRequest(
            "use lifecycle actions to change account status".to_string(),
        ));
    }
    if current.id == target.id && target.is_admin != i32::from(next_is_admin) {
        return Err(AppError::BadRequest(
            "administrator cannot change their own administrator role".to_string(),
        ));
    }
    Ok(())
}

pub(crate) async fn ensure_group_members_editable(
    state: &AppState,
    group_id: &str,
    requested_user_ids: &[String],
) -> AppResult<()> {
    let existing_members = state.db.list_group_members(group_id).await?;
    let requested_user_ids = archived_accounts::normalize_user_ids(requested_user_ids);
    let allowed_archived_user_ids = archived_accounts::ensure_archived_group_members_preserved(
        &existing_members,
        &requested_user_ids,
    )?;
    ensure_assignable_user_ids(
        state,
        &requested_user_ids,
        &allowed_archived_user_ids,
        "groups",
    )
    .await
}

pub(crate) async fn ensure_organization_members_editable(
    state: &AppState,
    organization_id: &str,
    requested_members: &[OrganizationMemberInput],
) -> AppResult<()> {
    let existing_members = state.db.list_organization_members(organization_id).await?;
    let requested_roles = archived_accounts::normalize_organization_member_roles(requested_members);
    let allowed_archived_user_ids =
        archived_accounts::ensure_archived_organization_members_preserved(
            &existing_members,
            &requested_roles,
        )?;
    let requested_user_ids = requested_roles.into_keys().collect::<BTreeSet<_>>();
    ensure_assignable_user_ids(
        state,
        &requested_user_ids,
        &allowed_archived_user_ids,
        "organizations",
    )
    .await
}

pub(crate) async fn ensure_assignable_user_ids(
    state: &AppState,
    requested_user_ids: &BTreeSet<String>,
    allowed_archived_user_ids: &BTreeSet<String>,
    target: &str,
) -> AppResult<()> {
    let requested = requested_user_ids.iter().cloned().collect::<Vec<_>>();
    let states = state.db.find_user_assignment_states(&requested).await?;
    let states = states
        .into_iter()
        .map(|state| (state.id, state.archived_at))
        .collect::<BTreeMap<_, _>>();
    for user_id in requested_user_ids {
        let archived_at = states
            .get(user_id)
            .copied()
            .ok_or_else(|| AppError::BadRequest(format!("unknown user: {user_id}")))?;
        archived_accounts::ensure_assignable_user_state(
            user_id,
            archived_at,
            allowed_archived_user_ids,
            target,
        )?;
    }
    Ok(())
}
