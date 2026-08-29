use crate::{
    AppState,
    auth::{self, AccountCapabilities},
    db::UserOrganizationRecord,
    error::{AppError, AppResult},
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn current_organization_context(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<(auth::CurrentUser, UserOrganizationRecord)> {
    let current = auth::require_current_user(state, jar).await?;
    if !current.can_mutate_account() {
        return Err(AppError::Forbidden);
    }
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
