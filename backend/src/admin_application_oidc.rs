use super::{
    MissingApplicationClientPolicy, admin_application_scope::managed_application,
    admin_client_types::ClientInput, application_client_binding_responses_from_graph,
    client_input_to_claim_mappers, client_input_to_new,
    ensure_website_application_modules_editable, public_client_with_claim_mappers,
    validate_client_input,
};
use crate::{
    AppState,
    audit::{self, AuditSink},
    db::PublicClient,
    error::{AppError, AppResult},
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicClient>>> {
    managed_application(&state, &jar, &id).await?;
    let graph = state.db.read_application_client_binding_graph(&id).await?;
    let clients = application_client_binding_responses_from_graph(
        &graph,
        Some("oidc"),
        MissingApplicationClientPolicy::NotFound,
    )?
    .into_iter()
    .map(|binding| binding.client)
    .collect();
    Ok(Json(clients))
}

pub(super) async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ClientInput>,
) -> AppResult<Json<PublicClient>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    validate_client_input(&payload)?;
    if payload
        .organization_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|organization_id| {
            !organization_id.is_empty() && organization_id != application.organization_id
        })
    {
        return Err(AppError::Forbidden);
    }
    let claim_mappers = client_input_to_claim_mappers(&payload)?;
    let client = state
        .db
        .create_application_oidc_client_graph(
            &application.id,
            client_input_to_new(
                payload,
                None,
                Some(application.organization_id.clone()),
                None,
            )?,
            claim_mappers,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.oidc_client.create",
            "application",
            Some(application.id),
            serde_json::json!({ "client_id": client.client_id }),
        ))
        .await?;
    Ok(Json(
        public_client_with_claim_mappers(&state, client).await?,
    ))
}

pub(super) async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, client_db_id)): Path<(String, String)>,
    Json(payload): Json<ClientInput>,
) -> AppResult<Json<PublicClient>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    validate_client_input(&payload)?;
    if payload
        .organization_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|organization_id| {
            !organization_id.is_empty() && organization_id != application.organization_id
        })
    {
        return Err(AppError::Forbidden);
    }
    let existing = state
        .db
        .find_application_oidc_client(&application.id, &client_db_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let claim_mappers = client_input_to_claim_mappers(&payload)?;
    let client = state
        .db
        .update_application_oidc_client_graph(
            &application.id,
            &existing.client_db_id,
            client_input_to_new(
                payload,
                existing.client_secret_hash.clone(),
                Some(application.organization_id.clone()),
                Some(existing.audience.clone()),
            )?,
            claim_mappers,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.oidc_client.update",
            "application",
            Some(application.id),
            serde_json::json!({ "client_id": client.client_id }),
        ))
        .await?;
    Ok(Json(
        public_client_with_claim_mappers(&state, client).await?,
    ))
}

pub(super) async fn delete(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, client_db_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    let client = state
        .db
        .delete_application_oidc_client_graph(&application.id, &client_db_id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.oidc_client.delete",
            "application",
            Some(application.id),
            serde_json::json!({ "client_id": client.client_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
