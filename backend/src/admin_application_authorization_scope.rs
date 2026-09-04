use super::admin_application_scope::{application_is_website_managed, managed_application};
use crate::{
    AppState, auth,
    db::{ApplicationAuthorizationProfileRecord, ApplicationRecord, UserRecord},
    error::{AppError, AppResult},
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn ensure_local_profile_catalog_editable(
    state: &AppState,
    application: &ApplicationRecord,
    _profile: &ApplicationAuthorizationProfileRecord,
) -> AppResult<()> {
    if application_is_website_managed(state, application).await? {
        return Err(AppError::BadRequest(
            "website-managed role catalogs are read-only; update the website manifest".to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn managed_authorization_profile(
    state: &AppState,
    jar: &CookieJar,
    application_id: &str,
    profile_id: &str,
) -> AppResult<(
    auth::CurrentUser,
    ApplicationRecord,
    ApplicationAuthorizationProfileRecord,
)> {
    let (current, application) = managed_application(state, jar, application_id).await?;
    let profile = state
        .db
        .find_application_authorization_profile_by_id(profile_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if profile.application_id != application.id {
        return Err(AppError::NotFound);
    }
    Ok((current, application, profile))
}

pub(super) async fn application_authorization_user(
    state: &AppState,
    application: &ApplicationRecord,
    user_id: &str,
) -> AppResult<UserRecord> {
    let user = state
        .db
        .find_application_authorization_user(&application.id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(user)
}
