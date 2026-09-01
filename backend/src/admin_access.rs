use super::*;

pub(crate) async fn role_response(
    state: &AppState,
    role: RoleRecord,
) -> AppResult<RoleAccessResponse> {
    let permissions = state.db.list_role_permissions(&role.id).await?;
    Ok(RoleAccessResponse {
        id: role.id,
        name: role.name,
        description: role.description,
        is_system: role.is_system,
        permissions,
        created_at: role.created_at,
        updated_at: role.updated_at,
    })
}

pub(crate) async fn group_response(
    state: &AppState,
    group: GroupRecord,
) -> AppResult<GroupAccessResponse> {
    let roles = state.db.list_group_roles(&group.id).await?;
    let members = state
        .db
        .list_group_members(&group.id)
        .await?
        .into_iter()
        .map(|user| user.public())
        .collect();
    Ok(GroupAccessResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        roles,
        members,
        created_at: group.created_at,
        updated_at: group.updated_at,
    })
}

pub(crate) async fn list_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PermissionInfo>>> {
    require_security_manager(&state, &jar).await?;
    Ok(Json(permission_catalog()))
}

pub(crate) async fn list_roles(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<RoleAccessResponse>>> {
    require_security_manager(&state, &jar).await?;
    let (roles, permissions_by_role) = tokio::try_join!(
        state.db.list_roles(),
        state.db.list_role_permissions_by_role(),
    )?;
    let mut response = Vec::with_capacity(roles.len());
    for role in roles {
        response.push(RoleAccessResponse {
            permissions: permissions_by_role
                .get(&role.id)
                .cloned()
                .unwrap_or_default(),
            id: role.id,
            name: role.name,
            description: role.description,
            is_system: role.is_system,
            created_at: role.created_at,
            updated_at: role.updated_at,
        });
    }
    Ok(Json(response))
}

pub(crate) async fn create_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RoleInput>,
) -> AppResult<Json<RoleAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let role = state
        .db
        .insert_role(NewRole {
            name: payload.name,
            description: payload.description,
            is_system: false,
            permissions: payload.permissions,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "role.create",
            "role",
            Some(role.id.clone()),
            serde_json::json!({ "name": role.name.clone() }),
        ))
        .await?;
    Ok(Json(role_response(&state, role).await?))
}

pub(crate) async fn update_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<RoleInput>,
) -> AppResult<Json<RoleAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let role = state
        .db
        .update_role(
            &id,
            NewRole {
                name: payload.name,
                description: payload.description,
                is_system: false,
                permissions: payload.permissions,
            },
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "role.update",
            "role",
            Some(role.id.clone()),
            serde_json::json!({ "name": role.name.clone() }),
        ))
        .await?;
    Ok(Json(role_response(&state, role).await?))
}

pub(crate) async fn delete_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_security_manager(&state, &jar).await?;
    let role = state
        .db
        .find_role_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_role(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "role.delete",
            "role",
            Some(id),
            serde_json::json!({ "name": role.name }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub(crate) async fn list_groups(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<GroupAccessResponse>>> {
    require_security_manager(&state, &jar).await?;
    let (groups, roles_by_group, members_by_group) = tokio::try_join!(
        state.db.list_groups(),
        state.db.list_group_roles_by_group(),
        state.db.list_group_members_public_by_group(),
    )?;
    let mut response = Vec::with_capacity(groups.len());
    for group in groups {
        response.push(GroupAccessResponse {
            roles: roles_by_group.get(&group.id).cloned().unwrap_or_default(),
            members: members_by_group.get(&group.id).cloned().unwrap_or_default(),
            id: group.id,
            name: group.name,
            description: group.description,
            created_at: group.created_at,
            updated_at: group.updated_at,
        });
    }
    Ok(Json(response))
}

pub(crate) async fn create_group(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<GroupInput>,
) -> AppResult<Json<GroupAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let group = state
        .db
        .insert_group_with_audit(
            NewGroup {
                name: payload.name,
                description: payload.description,
            },
            audit::management_event(
                current.user.id,
                "group.create",
                "group",
                None,
                serde_json::json!({}),
            ),
        )
        .await?;
    Ok(Json(group_response(&state, group).await?))
}

pub(crate) async fn update_group(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<GroupInput>,
) -> AppResult<Json<GroupAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let group = state
        .db
        .update_group_with_audit(
            &id,
            NewGroup {
                name: payload.name,
                description: payload.description,
            },
            audit::management_event(
                current.user.id,
                "group.update",
                "group",
                Some(id.clone()),
                serde_json::json!({}),
            ),
        )
        .await?;
    Ok(Json(group_response(&state, group).await?))
}

pub(crate) async fn delete_group(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_security_manager(&state, &jar).await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .delete_group_with_audit(
            &id,
            audit::management_event(
                current.user.id,
                "group.delete",
                "group",
                Some(id.clone()),
                serde_json::json!({ "name": group.name }),
            ),
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub(crate) async fn update_group_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<RoleIdsInput>,
) -> AppResult<Json<GroupAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    state
        .db
        .replace_group_roles_with_audit(
            &id,
            payload.role_ids.clone(),
            audit::management_event(
                current.user.id,
                "group.roles.update",
                "group",
                Some(id.clone()),
                serde_json::json!({ "role_ids": payload.role_ids }),
            ),
        )
        .await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(group_response(&state, group).await?))
}

pub(crate) async fn update_group_members(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<UserIdsInput>,
) -> AppResult<Json<GroupAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_group_members_editable(&state, &id, &payload.user_ids).await?;
    state
        .db
        .replace_group_members_with_audit(
            &id,
            payload.user_ids.clone(),
            audit::management_event(
                current.user.id,
                "group.members.update",
                "group",
                Some(id.clone()),
                serde_json::json!({ "user_ids": payload.user_ids }),
            ),
        )
        .await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(group_response(&state, group).await?))
}
