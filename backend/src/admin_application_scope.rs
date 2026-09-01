use super::admin_organization_scope::require_organization_manager_for;
use crate::{
    AppState, application_discovery, auth,
    db::ApplicationRecord,
    error::{AppError, AppResult},
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
