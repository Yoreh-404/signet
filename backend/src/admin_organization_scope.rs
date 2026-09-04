use crate::{
    AppState,
    access::{Authorizer, Permission},
    auth,
    db::{OrganizationRecord, UserOrganizationRecord},
    error::{AppError, AppResult},
    organizations,
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn current_organization_context(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<(auth::CurrentUser, UserOrganizationRecord)> {
    let current = auth::require_current_user(state, jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .active_user_organization(&current.user.id)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(
                "join or create an organization before using the management console".to_string(),
            )
        })?;
    Ok((current, organization))
}

pub(super) async fn require_current_organization_manager(
    state: &AppState,
    current: &auth::CurrentUser,
    organization: &UserOrganizationRecord,
) -> AppResult<()> {
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
    match organization.role.as_str() {
        organizations::ROLE_OWNER | organizations::ROLE_ADMIN => Ok(()),
        _ => Err(AppError::Forbidden),
    }
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
    require_organization_manager(state, current, &organization).await
}

pub(super) async fn managed_organization_for(
    state: &AppState,
    jar: &CookieJar,
    organization_id: &str,
) -> AppResult<(auth::CurrentUser, OrganizationRecord)> {
    let current = auth::require_current_user(state, jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .find_organization_by_id(organization_id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager(state, &current, &organization).await?;
    Ok((current, organization))
}

async fn require_organization_manager(
    state: &AppState,
    current: &auth::CurrentUser,
    organization: &OrganizationRecord,
) -> AppResult<()> {
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
    let membership = state
        .db
        .find_active_organization_membership(&current.user.id, &organization.id)
        .await?;
    match membership
        .as_ref()
        .map(|membership| membership.role.as_str())
    {
        Some(organizations::ROLE_OWNER | organizations::ROLE_ADMIN) => Ok(()),
        _ => Err(AppError::Forbidden),
    }
}

pub(super) fn client_organization_from_context(
    submitted_organization_id: Option<String>,
    organization: &UserOrganizationRecord,
) -> AppResult<Option<String>> {
    if let Some(submitted) = submitted_organization_id {
        let submitted = submitted.trim();
        if !submitted.is_empty() && submitted != organization.id {
            return Err(AppError::Forbidden);
        }
    }
    Ok(Some(organization.id.clone()))
}
