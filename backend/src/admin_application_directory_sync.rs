use super::admin_application_scope::managed_application;
use crate::{
    AppState,
    audit::{self, AuditSink},
    directory_sync,
    error::AppResult,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn list_runs(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<crate::db::DirectorySyncRunRecord>>> {
    let (_, application) = managed_application(&state, &jar, &id).await?;
    Ok(Json(
        directory_sync::list_application_ldap_sync_runs(&state, &application.id).await?,
    ))
}

pub(super) async fn run(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, provider_id)): Path<(String, String)>,
) -> AppResult<Json<crate::db::DirectorySyncRunRecord>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let result =
        directory_sync::run_application_ldap_sync(&state, &application.id, &provider_id).await;
    match result {
        Ok(run) => {
            state
                .db
                .record_audit_event(audit::management_event(
                    current.user.id,
                    "application.directory_sync.run",
                    "application",
                    Some(application.id),
                    serde_json::json!({
                        "organization_id": application.organization_id,
                        "provider_id": provider_id,
                        "status": run.status,
                        "run_id": run.id,
                    }),
                ))
                .await?;
            Ok(Json(run))
        }
        Err(error) => {
            let _ = state
                .db
                .record_audit_event(audit::management_event(
                    current.user.id,
                    "application.directory_sync.run",
                    "application",
                    Some(application.id),
                    serde_json::json!({
                        "organization_id": application.organization_id,
                        "provider_id": provider_id,
                        "status": "failed",
                    }),
                ))
                .await;
            Err(error)
        }
    }
}
