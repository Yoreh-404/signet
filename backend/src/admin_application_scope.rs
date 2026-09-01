use crate::{
    AppState,
    access::{Authorizer, Permission},
    application_discovery, auth,
    db::ApplicationRecord,
    error::{AppError, AppResult},
    organizations,
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn managed_application(
    state: &AppState,
    jar: &CookieJar,
    id: &str,
) -> AppResult<(auth::CurrentUser, ApplicationRecord)> {
    let current = auth::require_current_user(state, jar).await?;
    let application = state
        .db
        .find_application_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(state, &current, &application.organization_id).await?;
    Ok((current, application))
}

pub(super) async fn require_organization_manager_for(
    state: &AppState,
    current: &auth::CurrentUser,
    organization_id: &str,
) -> AppResult<()> {
    auth::ensure_current_account_mutable(current)?;
    let organization = state
        .db
        .find_organization_by_id(organization_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if organization.kind == organizations::ORGANIZATION_KIND_SYSTEM {
        state
            .db
            .require_permission(&current.user, Permission::OrganizationsManage)
            .await?;
        return Ok(());
    }
    if state
        .db
        .has_permission(&current.user, Permission::OrganizationsManage)
        .await?
    {
        return Ok(());
    }
    let memberships = state.db.list_user_organizations(&current.user.id).await?;
    let membership = memberships
        .into_iter()
        .find(|organization| organization.id == organization_id && organization.is_active == 1);
    match membership
        .as_ref()
        .map(|membership| membership.role.as_str())
    {
        Some(organizations::ROLE_OWNER | organizations::ROLE_ADMIN) => Ok(()),
        _ => Err(AppError::Forbidden),
    }
}

pub(super) async fn ensure_website_application_modules_editable(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<()> {
    if application_is_website_managed(state, application).await? {
        return Err(AppError::BadRequest(
            "website-managed application modules are read-only; update the website manifest"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn application_is_website_managed(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<bool> {
    Ok(state
        .db
        .find_application_discovery(&application.id)
        .await?
        .is_some_and(|record| {
            record.management_mode == application_discovery::MANAGEMENT_MODE_WEBSITE
        }))
}
