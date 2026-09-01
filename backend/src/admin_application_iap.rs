use super::{
    admin_application_scope::{ensure_website_application_modules_editable, managed_application},
    admin_guards::require_iap_reader,
    iap_application_input_to_new,
};
use crate::{
    AppState,
    audit::{self, AuditSink},
    db::PublicIapApplication,
    error::{AppError, AppResult},
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct IapApplicationInput {
    pub(super) slug: String,
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) external_host: String,
    pub(super) path_prefix: String,
    #[serde(default)]
    pub(super) required_organization_id: Option<String>,
    #[serde(default)]
    pub(super) required_organization_roles: Vec<String>,
    #[serde(default)]
    pub(super) required_permissions: Vec<String>,
    pub(super) is_active: bool,
}

pub(super) async fn list_iap_applications(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicIapApplication>>> {
    require_iap_reader(&state, &jar).await?;
    Ok(Json(
        state
            .db
            .list_iap_applications()
            .await?
            .into_iter()
            .map(|app| app.public())
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

pub(super) async fn list_application_iap_rules(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicIapApplication>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    Ok(Json(
        state
            .db
            .list_iap_applications_for_application(&id)
            .await?
            .into_iter()
            .map(|rule| rule.public())
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

pub(super) async fn create_application_iap_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<IapApplicationInput>,
) -> AppResult<Json<PublicIapApplication>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    let rule = state
        .db
        .insert_iap_application(iap_application_input_to_new(&state, &application, payload).await?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.iap_rule.create",
            "application",
            Some(id),
            serde_json::json!({
                "rule_id": rule.id,
                "slug": rule.slug,
                "external_host": rule.external_host,
                "path_prefix": rule.path_prefix,
            }),
        ))
        .await?;
    Ok(Json(rule.public()?))
}

pub(super) async fn update_application_iap_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, rule_id)): Path<(String, String)>,
    Json(payload): Json<IapApplicationInput>,
) -> AppResult<Json<PublicIapApplication>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    let existing = state
        .db
        .find_iap_application_by_id(&rule_id)
        .await?
        .filter(|rule| rule.application_id.as_deref() == Some(id.as_str()))
        .ok_or(AppError::NotFound)?;
    let rule = state
        .db
        .update_iap_application(
            &existing.id,
            iap_application_input_to_new(&state, &application, payload).await?,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.iap_rule.update",
            "application",
            Some(id),
            serde_json::json!({
                "rule_id": rule.id,
                "slug": rule.slug,
                "is_active": rule.is_active == 1,
            }),
        ))
        .await?;
    Ok(Json(rule.public()?))
}

pub(super) async fn delete_application_iap_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, rule_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, _application) = managed_application(&state, &jar, &id).await?;
    let existing = state
        .db
        .find_iap_application_by_id(&rule_id)
        .await?
        .filter(|rule| rule.application_id.as_deref() == Some(id.as_str()))
        .ok_or(AppError::NotFound)?;
    state.db.delete_iap_application(&existing.id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.iap_rule.delete",
            "application",
            Some(id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
