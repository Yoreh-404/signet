use super::{
    AppError, AppResult, AppState, ApplicationModuleInput, ApplicationModuleResponse, Json, Path,
    State, application_module_response, applications, audit,
    ensure_website_application_modules_editable, managed_application,
};
use crate::audit::AuditSink;
use axum_extra::extract::cookie::CookieJar;

const APPLICATION_MODULE_KEYS: &[&str] = &[
    "protocols",
    "login_adapters",
    "directory_sync",
    "authorization",
];

fn normalize_application_module_key(value: &str) -> AppResult<String> {
    let key = value.trim();
    if APPLICATION_MODULE_KEYS.contains(&key) {
        return Ok(key.to_string());
    }
    Err(AppError::BadRequest(format!(
        "unsupported application module: {key}"
    )))
}

pub(super) async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationModuleResponse>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let modules = state
        .db
        .list_application_modules(&id)
        .await?
        .into_iter()
        .map(application_module_response)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(modules))
}

pub(super) async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, module_key)): Path<(String, String)>,
    Json(payload): Json<ApplicationModuleInput>,
) -> AppResult<Json<ApplicationModuleResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    let module_key = normalize_application_module_key(&module_key)?;
    let config = applications::normalize_module_config(&module_key, payload.config)?;
    applications::validate_module_bindings(
        &state,
        &application,
        &module_key,
        config.as_object().ok_or_else(|| {
            AppError::BadRequest("application module config must be an object".to_string())
        })?,
    )
    .await?;
    let config_json = serde_json::to_string(&config).map_err(|err| {
        AppError::BadRequest(format!("application module config is invalid: {err}"))
    })?;
    if config_json.len() > 512 * 1024 {
        return Err(AppError::BadRequest(
            "application module config is too large".to_string(),
        ));
    }
    let module = state
        .db
        .upsert_application_module_with_audit(
            &id,
            &module_key,
            &config_json,
            payload.is_enabled,
            audit::management_event(
                current.user.id.clone(),
                "application.module.update",
                "application",
                Some(id.clone()),
                serde_json::json!({
                    "organization_id": application.organization_id,
                    "module": module_key.clone(),
                    "is_enabled": payload.is_enabled,
                }),
            ),
        )
        .await?;
    Ok(Json(application_module_response(module)?))
}

pub(super) async fn delete(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, module_key)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    let module_key = normalize_application_module_key(&module_key)?;
    state.db.delete_application_module(&id, &module_key).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.module.delete",
            "application",
            Some(id),
            serde_json::json!({
                "organization_id": application.organization_id,
                "module": module_key,
            }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
