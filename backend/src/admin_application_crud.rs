use super::{
    admin_application_response::{
        ApplicationClientBindingResponse, ApplicationResponse, MissingApplicationClientPolicy,
        application_client_binding_responses_from_graph, application_response,
        application_response_from_graph,
    },
    admin_application_scope::managed_application,
    admin_organization_scope::{
        current_organization_context, require_current_organization_manager,
    },
    admin_settings::normalize_optional_text,
};
use crate::{
    AppState, applications, audit,
    db::NewApplication,
    error::{AppError, AppResult},
    util,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct ApplicationInput {
    slug: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    account_selection_mode: String,
    #[serde(default)]
    unique_identity_factors: Vec<String>,
    is_active: bool,
    #[serde(default)]
    website_url: Option<String>,
}

fn application_protocols_config(website_url: Option<&str>) -> AppResult<String> {
    let config = applications::normalize_module_config(
        "protocols",
        serde_json::json!({ "website_url": website_url.unwrap_or_default() }),
    )?;
    util::to_json(&config)
}

fn application_input_to_new(
    organization_id: String,
    input: ApplicationInput,
) -> AppResult<NewApplication> {
    Ok(NewApplication {
        organization_id,
        slug: applications::normalize_application_slug(&input.slug)?,
        name: applications::normalize_application_name(&input.name)?,
        description: normalize_optional_text(input.description),
        access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
        registration_mode: applications::REGISTRATION_DISABLED.to_string(),
        account_selection_mode: applications::normalize_account_selection_mode(
            &input.account_selection_mode,
        )?,
        unique_identity_factors: applications::normalize_unique_identity_factors(
            input.unique_identity_factors,
        )?,
        is_active: input.is_active,
    })
}

pub(super) async fn list_applications(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<ApplicationResponse>>> {
    let (current, organization) = current_organization_context(&state, &jar).await?;
    require_current_organization_manager(&state, &current, &organization).await?;
    let applications = state.db.list_applications(Some(&organization.id)).await?;
    let application_ids = applications
        .iter()
        .map(|application| application.id.clone())
        .collect::<Vec<_>>();
    let mut graphs = state
        .db
        .read_application_graph_batch(&application_ids)
        .await?;
    let result = applications
        .into_iter()
        .map(|application| {
            let graph = graphs.remove(&application.id).ok_or_else(|| {
                AppError::Internal(format!(
                    "application graph is missing for {}",
                    application.id
                ))
            })?;
            application_response_from_graph(application, graph)
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(result))
}

pub(super) async fn create_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ApplicationInput>,
) -> AppResult<Json<ApplicationResponse>> {
    let (current, organization) = current_organization_context(&state, &jar).await?;
    require_current_organization_manager(&state, &current, &organization).await?;
    let protocols_config = application_protocols_config(payload.website_url.as_deref())?;
    let application_input = application_input_to_new(organization.id.clone(), payload)?;
    let slug = application_input.slug.clone();
    let application = state
        .db
        .insert_application_with_module_with_audit(
            application_input,
            "protocols",
            &protocols_config,
            false,
            audit::management_event(
                current.user.id.clone(),
                "application.create",
                "application",
                None,
                serde_json::json!({
                    "organization_id": organization.id,
                    "slug": slug,
                }),
            ),
        )
        .await?;
    Ok(Json(application_response(&state, application).await?))
}

pub(super) async fn update_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationInput>,
) -> AppResult<Json<ApplicationResponse>> {
    let (current, existing) = managed_application(&state, &jar, &id).await?;
    let organization_id = existing.organization_id.clone();
    let protocols_config = application_protocols_config(payload.website_url.as_deref())?;
    let application = state
        .db
        .update_application_with_module_with_audit(
            &id,
            application_input_to_new(existing.organization_id.clone(), payload)?,
            "protocols",
            &protocols_config,
            false,
            audit::management_event(
                current.user.id.clone(),
                "application.update",
                "application",
                Some(id.clone()),
                serde_json::json!({ "organization_id": organization_id }),
            ),
        )
        .await?;
    Ok(Json(application_response(&state, application).await?))
}

pub(super) async fn delete_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, existing) = managed_application(&state, &jar, &id).await?;
    state
        .db
        .delete_application_with_expected_organization_and_audit(
            &id,
            &existing.organization_id,
            audit::management_event(
                current.user.id,
                "application.delete",
                "application",
                Some(id.clone()),
                serde_json::json!({ "organization_id": existing.organization_id }),
            ),
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub(super) async fn list_application_client_bindings(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationClientBindingResponse>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let graph = state.db.read_application_client_binding_graph(&id).await?;
    Ok(Json(application_client_binding_responses_from_graph(
        &graph,
        None,
        MissingApplicationClientPolicy::Skip,
    )?))
}
