use crate::{
    AppState,
    access::{Authorizer, Permission},
    auth,
    db::UserOrganizationRecord,
    error::{AppError, AppResult},
};
use axum_extra::extract::cookie::CookieJar;

use super::{
    admin_guards::CLIENT_READ_PERMISSIONS,
    admin_organization_scope::{
        current_organization_context, require_current_organization_manager,
    },
};

pub(crate) async fn current_organization_client_manager(
    state: &AppState,
    jar: &CookieJar,
    manage: bool,
) -> AppResult<(auth::CurrentUser, UserOrganizationRecord)> {
    let (current, organization) = current_organization_context(state, jar).await?;
    let global_permission = if manage {
        Permission::ClientsManage
    } else {
        Permission::ClientsRead
    };
    let has_global_permission = if manage {
        state
            .db
            .has_permission(&current.user, global_permission)
            .await?
    } else {
        state
            .db
            .has_any_permission(&current.user, CLIENT_READ_PERMISSIONS)
            .await?
    };
    if has_global_permission {
        return Ok((current, organization));
    }
    require_current_organization_manager(state, &current, &organization).await?;
    Ok((current, organization))
}

pub(crate) async fn current_organization_provider_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<(auth::CurrentUser, UserOrganizationRecord, bool)> {
    let (current, organization) = current_organization_context(state, jar).await?;
    let platform_manager = state
        .db
        .has_permission(&current.user, Permission::ProvidersManage)
        .await?;
    if !platform_manager {
        require_current_organization_manager(state, &current, &organization).await?;
    }
    Ok((current, organization, platform_manager))
}

pub(crate) async fn normalize_client_organization_id(
    state: &AppState,
    organization_id: Option<String>,
) -> AppResult<Option<String>> {
    let Some(organization_id) = organization_id.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if organization_id.is_empty() {
        return Ok(None);
    }
    if state
        .db
        .find_organization_by_id(&organization_id)
        .await?
        .is_none()
    {
        return Err(AppError::BadRequest(
            "organization_id does not reference an existing organization".to_string(),
        ));
    }
    Ok(Some(organization_id))
}
