use crate::{
    AppState,
    access::{Authorizer, Permission},
    auth,
    error::AppResult,
};
use axum_extra::extract::cookie::CookieJar;

pub(crate) const ADMIN_READ_PERMISSIONS: &[Permission] = &[
    Permission::AdminRead,
    Permission::SettingsManage,
    Permission::UsersRead,
    Permission::UsersManage,
    Permission::ClientsRead,
    Permission::ClientsManage,
    Permission::IapRead,
    Permission::IapManage,
    Permission::OrganizationsRead,
    Permission::OrganizationsManage,
    Permission::AuthorizationCodesManage,
    Permission::ProvidersManage,
    Permission::AuditRead,
    Permission::SecurityManage,
];

pub(crate) const USER_READ_PERMISSIONS: &[Permission] = &[
    Permission::UsersRead,
    Permission::UsersManage,
    Permission::SecurityManage,
];
pub(crate) const CLIENT_READ_PERMISSIONS: &[Permission] =
    &[Permission::ClientsRead, Permission::ClientsManage];
pub(crate) const IAP_READ_PERMISSIONS: &[Permission] =
    &[Permission::IapRead, Permission::IapManage];
pub(crate) const ORGANIZATION_READ_PERMISSIONS: &[Permission] = &[
    Permission::OrganizationsRead,
    Permission::OrganizationsManage,
];
pub(crate) const ORGANIZATION_OPTION_PERMISSIONS: &[Permission] = &[
    Permission::OrganizationsRead,
    Permission::OrganizationsManage,
    Permission::UsersRead,
    Permission::UsersManage,
    Permission::AuthorizationCodesManage,
    Permission::ClientsManage,
    Permission::IapRead,
    Permission::IapManage,
    Permission::ProvidersManage,
];

pub(crate) async fn require_permission(
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

pub(crate) async fn require_any_permission(
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

pub(crate) async fn require_admin_reader(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, ADMIN_READ_PERMISSIONS).await
}

pub(crate) async fn require_settings_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::SettingsManage).await
}

pub(crate) async fn require_user_reader(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, USER_READ_PERMISSIONS).await
}

pub(crate) async fn require_user_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::UsersManage).await
}

pub(crate) async fn require_iap_reader(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, IAP_READ_PERMISSIONS).await
}

pub(crate) async fn require_authorization_code_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::AuthorizationCodesManage).await
}

pub(crate) async fn require_security_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::SecurityManage).await
}

pub(crate) async fn require_organization_reader(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, ORGANIZATION_READ_PERMISSIONS).await
}

pub(crate) async fn require_organization_option_reader(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, ORGANIZATION_OPTION_PERMISSIONS).await
}

pub(crate) async fn require_organization_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::OrganizationsManage).await
}
