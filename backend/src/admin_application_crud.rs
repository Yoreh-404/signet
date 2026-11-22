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
    AppState, applications, audit::{self, AuditSink},
    db::NewApplication,
    error::{AppError, AppResult},
    util,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AnonymousSubIdentityPolicy {
    allow_auto_create: bool,
}

pub(super) async fn anonymous_sub_identity_policy(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<AnonymousSubIdentityPolicy>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    Ok(Json(AnonymousSubIdentityPolicy {
        allow_auto_create: state.db.anonymous_sub_identity_creation_setting(&application.id).await?,
    }))
}

pub(super) async fn update_anonymous_sub_identity_policy(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<AnonymousSubIdentityPolicy>,
) -> AppResult<Json<AnonymousSubIdentityPolicy>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    state.db.set_anonymous_sub_identity_creation_allowed(
        &application.id,
        payload.allow_auto_create,
    ).await?;
    state.db.record_audit_event(audit::management_event(
        current.user.id,
        "application.anonymous_sub_identity_policy.update",
        "application",
        Some(application.id),
        serde_json::json!({ "allow_auto_create": payload.allow_auto_create }),
    )).await?;
    Ok(Json(payload))
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplicationInput {
    slug: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    /// Per-application registration rule. On update omitted means retain the
    /// existing rule; on creation the default is disabled.
    #[serde(default)]
    registration_mode: Option<String>,
    account_selection_mode: String,
    #[serde(default)]
    unique_identity_factors: Vec<String>,
    is_active: bool,
    #[serde(default)]
    website_url: Option<String>,
    #[serde(default)]
    login_validity_days: Option<i64>,
}

fn application_protocols_config(website_url: Option<&str>, login_validity_days: Option<i64>) -> AppResult<String> {
    let config = applications::normalize_module_config(
        "protocols",
        serde_json::json!({ "website_url": website_url.unwrap_or_default(), "login_validity_days": login_validity_days.unwrap_or(30) }),
    )?;
    util::to_json(&config)
}

fn application_input_to_new(
    organization_id: String,
    input: ApplicationInput,
    existing: Option<&crate::db::ApplicationRecord>,
) -> AppResult<NewApplication> {
    Ok(NewApplication {
        organization_id,
        slug: applications::normalize_application_slug(&input.slug)?,
        name: applications::normalize_application_name(&input.name)?,
        description: normalize_optional_text(input.description),
        access_mode: existing.map(|app| app.access_mode.clone())
            .unwrap_or_else(|| applications::ACCESS_ALL_SIGNET_USERS.to_string()),
        registration_mode: match input.registration_mode.as_deref() {
            Some(value) => applications::normalize_registration_mode(value, false)?,
            None => existing.map(|app| app.registration_mode.clone())
                .unwrap_or_else(|| applications::REGISTRATION_DISABLED.to_owned()),
        },
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
    let protocols_config = application_protocols_config(payload.website_url.as_deref(), payload.login_validity_days)?;
    let application_input = application_input_to_new(organization.id.clone(), payload, None)?;
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
    let managed_by_site = super::admin_application_scope::application_is_website_managed(&state, &existing).await?;
    if managed_by_site {
        if payload.registration_mode.as_deref().is_some_and(|mode| mode != existing.registration_mode)
            || payload.slug != existing.slug
        {
            return Err(AppError::BadRequest(
                "website-managed application identity and registration policy must be changed in the signed website manifest".into(),
            ));
        }
    }
    let current_protocols = state.db.find_application_module(&id, "protocols").await?;
    let login_days = payload.login_validity_days;
    let old_url = applications::application_website_url(&state, &id).await?.unwrap_or_default();
    let requested_url = payload.website_url.as_deref().map(str::trim)
        .unwrap_or(old_url.as_str()).to_owned();
    if managed_by_site && requested_url != old_url {
        return Err(AppError::BadRequest(
            "website-managed application URL must be changed in the signed website manifest".into(),
        ));
    }
    let application_input = application_input_to_new(existing.organization_id.clone(), payload, Some(&existing))?;
    let event = audit::management_event(
        current.user.id, "application.update", "application", Some(id.clone()),
        serde_json::json!({ "organization_id": organization_id }),
    );
    let existing_days = current_protocols.as_ref().and_then(|module|
        serde_json::from_str::<serde_json::Value>(&module.config_json).ok()
    ).and_then(|config| config.get("login_validity_days").and_then(|value| value.as_i64()))
        .unwrap_or(30);
    let requested_days = login_days.unwrap_or(existing_days);
    let application = if requested_url != old_url || requested_days != existing_days {
        // Preserve every existing protocol and its enabled state when only
        // editing the site's public URL. The previous handler rebuilt a new
        // disabled module and could silently break working SSO clients.
        let mut config = current_protocols.as_ref().and_then(|module| {
            serde_json::from_str::<serde_json::Value>(&module.config_json).ok()
        }).unwrap_or_else(|| serde_json::json!({}));
        let values = config.as_object_mut().ok_or_else(||
            AppError::Internal("existing application protocol config must be an object".into()))?;
        values.insert("website_url".into(), serde_json::Value::String(requested_url));
        values.insert("login_validity_days".into(), serde_json::json!(requested_days));
        let config = applications::normalize_module_config("protocols", config)?;
        state.db.update_application_with_module_with_audit(
            &id, application_input, "protocols", &util::to_json(&config)?,
            current_protocols.as_ref().is_some_and(|module| module.is_enabled == 1), event,
        ).await?
    } else {
        state.db.update_application_with_audit(&id, application_input, event).await?
    };
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
        &state,
        &graph,
        None,
        MissingApplicationClientPolicy::Skip,
    ).await?))
}
