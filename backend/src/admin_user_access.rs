use super::{
    admin_access_types::{RoleIdsInput, UserAccessResponse},
    admin_assignment_policy::ensure_user_editable,
    admin_guards::require_security_manager,
};
use crate::{
    AppState,
    audit::{self, AuditSink},
    error::{AppError, AppResult},
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;

pub(crate) async fn user_access(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<UserAccessResponse>> {
    require_security_manager(&state, &jar).await?;
    state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(load_user_access_response(&state, &id).await?))
}

async fn load_user_access_response(
    state: &AppState,
    user_id: &str,
) -> AppResult<UserAccessResponse> {
    let (direct_roles, groups, effective_permissions) = tokio::try_join!(
        state.db.list_user_roles(user_id),
        state.db.list_user_groups(user_id),
        state.db.list_effective_permissions(user_id),
    )?;
    Ok(UserAccessResponse {
        direct_roles,
        groups,
        effective_permissions,
    })
}

pub(crate) async fn update_user_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<RoleIdsInput>,
) -> AppResult<Json<UserAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    ensure_user_editable(&state, &id).await?;
    state
        .db
        .replace_user_roles(&id, payload.role_ids.clone())
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "user.roles.update",
            "user",
            Some(id.clone()),
            serde_json::json!({ "role_ids": payload.role_ids }),
        ))
        .await?;
    Ok(Json(load_user_access_response(&state, &id).await?))
}
