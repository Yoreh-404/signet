use super::{
    admin_account_security,
    admin_assignment_policy::{ensure_account_metadata_update_allowed, ensure_user_editable},
    admin_guards::require_user_manager,
    admin_user_import::normalize_user_input,
    admin_user_types::{UserInput, UserLifecycleBatchInput, lifecycle_mutation_for_user},
};
use crate::{
    AppState,
    audit::{self, AuditSink},
    db::{NewUser, PublicUser, UserUpdate},
    error::{AppError, AppResult},
    security_policy, util,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

pub(crate) async fn create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<UserInput>,
) -> AppResult<Json<PublicUser>> {
    let current = require_user_manager(&state, &jar).await?;
    let payload = normalize_user_input(payload)?;
    let password = payload
        .password
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("password is required".to_string()))?;
    security_policy::validate_password_for_subject(
        &state,
        password,
        &payload.email,
        &payload.username,
    )
    .await?;
    let user = state
        .db
        .insert_user(NewUser {
            email: payload.email,
            username: payload.username,
            display_name: payload.display_name,
            phone: payload.phone,
            password_hash: util::hash_password(password)?,
            email_verified_at: Some(util::now_ts()),
            phone_verified_at: None,
            is_admin: payload.is_admin,
            is_active: payload.is_active,
            archived_at: None,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "user.create",
            "user",
            Some(user.id.clone()),
            serde_json::json!({ "email": user.email.clone() }),
        ))
        .await?;
    Ok(Json(user.public()))
}

pub(crate) async fn update_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<UserInput>,
) -> AppResult<Json<PublicUser>> {
    let current = require_user_manager(&state, &jar).await?;
    let target = ensure_user_editable(&state, &id).await?;
    let payload = normalize_user_input(payload)?;
    ensure_account_metadata_update_allowed(
        &current.user,
        &target,
        payload.is_admin,
        payload.is_active,
    )?;
    if let Some(password) = payload.password.as_deref() {
        security_policy::validate_password_for_subject(
            &state,
            password,
            &payload.email,
            &payload.username,
        )
        .await?;
    }
    let password_hash = payload
        .password
        .as_deref()
        .map(util::hash_password)
        .transpose()?;
    let user_update = UserUpdate {
        id: &id,
        email: payload.email,
        username: payload.username,
        display_name: payload.display_name,
        phone: payload.phone,
        is_admin: payload.is_admin,
        is_active: payload.is_active,
    };
    let updated_email = user_update.email.clone();
    let user = if let Some(password_hash) = password_hash {
        state
            .db
            .update_user_with_password_and_audit(
                user_update,
                password_hash,
                audit::management_event(
                    current.user.id.clone(),
                    "user.update",
                    "user",
                    Some(id.clone()),
                    serde_json::json!({ "email": updated_email }),
                ),
            )
            .await?
    } else {
        let user = state.db.update_user(user_update).await?;
        state
            .db
            .record_audit_event(audit::management_event(
                current.user.id,
                "user.update",
                "user",
                Some(id),
                serde_json::json!({ "email": user.email.clone() }),
            ))
            .await?;
        user
    };
    Ok(Json(user.public()))
}

pub(crate) async fn delete_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_user_manager(&state, &jar).await?;
    if current.user.id == id {
        return Err(AppError::BadRequest(
            "administrator cannot change their own account lifecycle".to_string(),
        ));
    }
    let target = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mutation = lifecycle_mutation_for_user(target.archived_at, target.is_active);
    match mutation {
        super::admin_user_types::UserLifecycleMutation::PermanentlyDelete => {
            state.db.permanently_delete_user(&id).await?;
        }
        super::admin_user_types::UserLifecycleMutation::Disable => {
            state.db.disable_user(&id).await?;
        }
        super::admin_user_types::UserLifecycleMutation::Archive => {
            state.db.archive_user(&id).await?;
        }
    }
    let action = mutation.action();
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            format!("user.{action}"),
            "user",
            Some(id),
            serde_json::json!({ "email": target.email }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true, "action": action })))
}

pub(crate) async fn enable_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<PublicUser>> {
    let current = require_user_manager(&state, &jar).await?;
    state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.enable_user(&id).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "user.enable",
            "user",
            Some(id),
            serde_json::json!({ "email": user.email.clone() }),
        ))
        .await?;
    Ok(Json(user.public()))
}

pub(crate) async fn bulk_user_lifecycle(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<UserLifecycleBatchInput>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_user_manager(&state, &jar).await?;
    let action = crate::db::UserLifecycleBatchAction::parse(&payload.action)?;
    let count = state
        .db
        .apply_user_lifecycle_batch(&current.user.id, payload.user_ids, action)
        .await?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "action": action.as_str(),
        "count": count,
    })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct PasswordInput {
    password: String,
}

pub(crate) async fn set_user_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<PasswordInput>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_user_manager(&state, &jar).await?;
    let user = ensure_user_editable(&state, &id).await?;
    security_policy::validate_password_for_subject(
        &state,
        &payload.password,
        &user.email,
        &user.username,
    )
    .await?;
    state
        .db
        .replace_user_password_with_audit(
            &id,
            util::hash_password(&payload.password)?,
            audit::management_event(
                current.user.id,
                "user.password.set",
                "user",
                Some(id.clone()),
                serde_json::json!({}),
            ),
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub(crate) async fn reset_user_mfa(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<admin_account_security::MfaStatusResponse>> {
    let current = require_user_manager(&state, &jar).await?;
    ensure_user_editable(&state, &id).await?;
    state
        .db
        .delete_mfa_for_user_with_audit(
            &id,
            audit::management_event(
                current.user.id,
                "mfa.admin_reset",
                "user",
                Some(id.clone()),
                serde_json::json!({}),
            ),
        )
        .await?;
    Ok(Json(
        admin_account_security::mfa_status_for_user(&state, &id).await?,
    ))
}
