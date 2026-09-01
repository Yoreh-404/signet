use crate::{
    AppState,
    db::UserRecord,
    error::{AppError, AppResult},
    util,
};

async fn load_user_record(state: &AppState, user_id: &str) -> AppResult<UserRecord> {
    state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or(AppError::Unauthorized)
}

async fn trial_enrollment_is_active(state: &AppState, user: &UserRecord) -> AppResult<bool> {
    Ok(state
        .db
        .find_trial_enrollment_for_user(&user.id)
        .await?
        .is_none_or(|enrollment| enrollment.is_active_at(util::now_ts())))
}

pub(super) async fn load_active_user(state: &AppState, user_id: &str) -> AppResult<UserRecord> {
    let user = load_user_record(state, user_id).await?;
    if user.is_active == 1
        && user.archived_at.is_none()
        && trial_enrollment_is_active(state, &user).await?
    {
        Ok(user)
    } else {
        Err(AppError::Unauthorized)
    }
}

pub(super) async fn load_oidc_user(state: &AppState, user_id: &str) -> AppResult<UserRecord> {
    let user = load_user_record(state, user_id).await?;
    if user.is_active != 1 || !trial_enrollment_is_active(state, &user).await? {
        return Err(AppError::Unauthorized);
    }
    if user.archived_at.is_none() {
        return Ok(user);
    }
    let looks_temporary = user.email.ends_with("@temporary.local")
        && state.db.user_has_invitation_redemption(&user.id).await?;
    if looks_temporary {
        Ok(user)
    } else {
        Err(AppError::Unauthorized)
    }
}
