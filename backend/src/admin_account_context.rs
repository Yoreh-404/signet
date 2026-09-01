use super::*;

pub(crate) async fn me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Option<auth::CurrentUserResponse>>> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let Some(current) = current else {
        return Ok(Json(None));
    };
    Ok(Json(Some(
        auth::current_user_response_for_session(&state, current).await?,
    )))
}

pub(crate) async fn my_organizations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<UserOrganizationRecord>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    Ok(Json(
        state.db.list_user_organizations(&current.user.id).await?,
    ))
}

#[derive(Debug, Deserialize)]
pub(crate) struct OrganizationContextInput {
    pub(crate) organization_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct OrganizationContextResponse {
    pub(crate) organization: Option<UserOrganizationRecord>,
}

pub(crate) async fn my_organization_context(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<OrganizationContextResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    Ok(Json(OrganizationContextResponse {
        organization: state.db.active_user_organization(&current.user.id).await?,
    }))
}

pub(crate) async fn set_my_organization_context(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<OrganizationContextInput>,
) -> AppResult<Json<OrganizationContextResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .set_active_user_organization(&current.user.id, payload.organization_id.trim())
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.context.select",
            "organization",
            Some(organization.id.clone()),
            serde_json::json!({ "slug": organization.slug }),
        ))
        .await?;
    Ok(Json(OrganizationContextResponse {
        organization: Some(organization),
    }))
}
