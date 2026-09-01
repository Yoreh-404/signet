use crate::{
    AppState,
    access::{Authorizer, Permission},
    audit::{self, AuditSink},
    auth,
    db::{AuditEventRecord, PublicAuditWebhook},
    error::{AppError, AppResult},
    webhooks,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;

pub(crate) async fn list_audit_events(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<AuditEventRecord>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::AuditRead)
        .await?;
    Ok(Json(state.db.list_audit_events(200).await?))
}

pub(crate) async fn list_audit_webhooks(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicAuditWebhook>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_any_permission(
            &current.user,
            &[Permission::AuditRead, Permission::SecurityManage],
        )
        .await?;
    let webhooks = state
        .db
        .list_audit_webhooks()
        .await?
        .into_iter()
        .map(|record| record.public())
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(webhooks))
}

pub(crate) async fn create_audit_webhook(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<webhooks::AuditWebhookInput>,
) -> AppResult<Json<PublicAuditWebhook>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    let webhook = state
        .db
        .insert_audit_webhook(webhooks::new_webhook(payload)?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "audit_webhook.create",
            "audit_webhook",
            Some(webhook.id.clone()),
            serde_json::json!({ "name": webhook.name.clone(), "url": webhook.url.clone() }),
        ))
        .await?;
    Ok(Json(webhook.public()?))
}

pub(crate) async fn update_audit_webhook(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<webhooks::AuditWebhookInput>,
) -> AppResult<Json<PublicAuditWebhook>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    let webhook = state
        .db
        .update_audit_webhook(&id, webhooks::update_webhook(payload)?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "audit_webhook.update",
            "audit_webhook",
            Some(webhook.id.clone()),
            serde_json::json!({ "name": webhook.name.clone(), "url": webhook.url.clone() }),
        ))
        .await?;
    Ok(Json(webhook.public()?))
}

pub(crate) async fn delete_audit_webhook(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    let webhook = state
        .db
        .find_audit_webhook(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_audit_webhook(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "audit_webhook.delete",
            "audit_webhook",
            Some(id),
            serde_json::json!({ "name": webhook.name, "url": webhook.url }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
