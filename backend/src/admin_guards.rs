use crate::{
    AppState,
    access::{Authorizer, Permission},
    auth::{self, AccountCapabilities},
    error::{AppError, AppResult},
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn require_permission(
    state: &AppState,
    jar: &CookieJar,
    permission: Permission,
) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    if !current.can_mutate_account() {
        return Err(AppError::Forbidden);
    }
    state
        .db
        .require_permission(&current.user, permission)
        .await?;
    Ok(current)
}

pub(super) async fn require_any_permission(
    state: &AppState,
    jar: &CookieJar,
    permissions: &[Permission],
) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    if !current.can_mutate_account() {
        return Err(AppError::Forbidden);
    }
    state
        .db
        .require_any_permission(&current.user, permissions)
        .await?;
    Ok(current)
}
