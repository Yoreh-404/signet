use crate::{
    AppState,
    access::{Authorizer, Permission},
    auth,
    error::AppResult,
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn require_permission(
    state: &AppState,
    jar: &CookieJar,
    permission: Permission,
) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    auth::ensure_current_account_mutable(&current)?;
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
    auth::ensure_current_account_mutable(&current)?;
    state
        .db
        .require_any_permission(&current.user, permissions)
        .await?;
    Ok(current)
}
