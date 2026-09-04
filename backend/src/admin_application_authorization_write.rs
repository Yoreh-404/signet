use super::{
    admin_application_authorization_scope::{
        ensure_local_profile_catalog_editable, managed_authorization_profile,
    },
    admin_defaults::default_true,
};
use crate::{
    AppState, application_discovery,
    audit::{self, AuditSink},
    db::{
        ApplicationProfileRoleRecord, AuthorizationBindingPermissionOverride,
        AuthorizationBindingsSnapshot, AuthorizationBindingsUpdate, NewApplicationProfileRole,
    },
    error::{AppError, AppResult},
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub(super) struct ApplicationProfileRoleResponse {
    id: String,
    profile_id: String,
    role_key: String,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    source: String,
    is_default: bool,
    is_active: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplicationProfileRoleInput {
    role_key: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default = "default_true")]
    is_active: bool,
    #[serde(default)]
    is_default: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplicationAuthorizationBindingsInput {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    user_role_ids: Vec<String>,
    #[serde(default)]
    user_permission_overrides: Vec<ApplicationPermissionOverrideInput>,
    #[serde(default)]
    group_role_ids: Vec<String>,
    #[serde(default)]
    organization_role_bindings: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ApplicationPermissionOverrideInput {
    permission: String,
    effect: String,
}

fn role_response(role: ApplicationProfileRoleRecord) -> AppResult<ApplicationProfileRoleResponse> {
    Ok(ApplicationProfileRoleResponse {
        permissions: role.permission_keys()?,
        id: role.id,
        profile_id: role.profile_id,
        role_key: role.role_key,
        name: role.name,
        description: role.description,
        source: role.source,
        is_default: role.is_default == 1,
        is_active: role.is_active == 1,
        created_at: role.created_at,
        updated_at: role.updated_at,
    })
}

pub(super) async fn get_bindings(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<AuthorizationBindingsSnapshot>> {
    let (_, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    Ok(Json(
        state
            .db
            .read_application_authorization_bindings(&application.id, &profile.id)
            .await?,
    ))
}

pub(super) async fn update_bindings(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationAuthorizationBindingsInput>,
) -> AppResult<Json<AuthorizationBindingsSnapshot>> {
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let user_id = payload.user_id.clone();
    let group_id = payload.group_id.clone();
    let user_role_ids = payload.user_role_ids.clone();
    let group_role_ids = payload.group_role_ids.clone();
    let organization_role_bindings = payload.organization_role_bindings.clone();
    let snapshot = state
        .db
        .replace_application_authorization_bindings_with_audit(
            &application.id,
            &profile.id,
            AuthorizationBindingsUpdate {
                user_id: payload.user_id,
                group_id: payload.group_id,
                user_role_ids: payload.user_role_ids,
                user_permission_overrides: payload
                    .user_permission_overrides
                    .into_iter()
                    .map(|value| AuthorizationBindingPermissionOverride {
                        permission: value.permission,
                        effect: value.effect,
                    })
                    .collect(),
                group_role_ids: payload.group_role_ids,
                organization_role_bindings: payload.organization_role_bindings,
            },
            audit::management_event(
                current.user.id,
                "application.authorization_profile.bindings.update",
                "application_authorization_profile",
                Some(profile.id.clone()),
                serde_json::json!({
                    "application_id": application.id,
                    "profile_id": profile.id,
                    "user_id": user_id,
                    "group_id": group_id,
                    "user_role_ids": user_role_ids,
                    "group_role_ids": group_role_ids,
                    "organization_role_bindings": organization_role_bindings,
                }),
            ),
        )
        .await?;
    Ok(Json(snapshot))
}

pub(super) async fn list_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ApplicationProfileRoleResponse>>> {
    managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    Ok(Json(
        state
            .db
            .list_application_profile_roles(&profile_id)
            .await?
            .into_iter()
            .map(role_response)
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

pub(super) async fn create_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationProfileRoleInput>,
) -> AppResult<Json<ApplicationProfileRoleResponse>> {
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    ensure_local_profile_catalog_editable(&state, &application, &profile).await?;
    let role = state
        .db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile_id.clone(),
            role_key: payload.role_key,
            name: payload.name,
            description: payload.description,
            permissions: payload.permissions,
            source: application_discovery::SOURCE_MANUAL.to_string(),
            is_default: payload.is_default,
            is_active: payload.is_active,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile_role.create",
            "application_profile_role",
            Some(role.id.clone()),
            serde_json::json!({ "application_id": application.id, "profile_id": profile_id }),
        ))
        .await?;
    Ok(Json(role_response(role)?))
}

pub(super) async fn update_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, role_id)): Path<(String, String, String)>,
    Json(payload): Json<ApplicationProfileRoleInput>,
) -> AppResult<Json<ApplicationProfileRoleResponse>> {
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    ensure_local_profile_catalog_editable(&state, &application, &profile).await?;
    let current_role = state
        .db
        .find_application_profile_role(&profile_id, &role_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if current_role.source == application_discovery::SOURCE_WEBSITE
        && payload.role_key != current_role.role_key
    {
        return Err(AppError::BadRequest(
            "manifest role keys cannot be renamed locally".to_string(),
        ));
    }
    let role = state
        .db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: Some(role_id),
            profile_id: profile_id.clone(),
            role_key: current_role.role_key,
            name: payload.name,
            description: payload.description,
            permissions: payload.permissions,
            source: current_role.source,
            is_default: payload.is_default,
            is_active: payload.is_active,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile_role.update",
            "application_profile_role",
            Some(role.id.clone()),
            serde_json::json!({ "application_id": application.id, "profile_id": profile_id }),
        ))
        .await?;
    Ok(Json(role_response(role)?))
}

pub(super) async fn delete_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, role_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    ensure_local_profile_catalog_editable(&state, &application, &profile).await?;
    state
        .db
        .delete_application_profile_role(&profile_id, &role_id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile_role.delete",
            "application_profile_role",
            Some(role_id.clone()),
            serde_json::json!({ "application_id": application.id, "profile_id": profile_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
