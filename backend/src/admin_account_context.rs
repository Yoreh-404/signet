use super::admin_organization_types::OrganizationResponse;
use super::admin_organizations;
use super::admin_settings::normalize_optional_text;
use crate::{
    AppState,
    audit::{self, AuditSink},
    auth,
    db::{NewOrganization, UserOrganizationRecord},
    error::AppResult,
    organizations, security_policy,
};
use axum::{Json, extract::State};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

pub(crate) async fn me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Option<auth::CurrentUserResponse>>> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let Some(current) = current else {
        return Ok(Json(None));
    };
    Ok(Json(Some(
        auth::current_user_response_for_session(&state, current).await?,
    )))
}

pub(crate) async fn my_organizations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<UserOrganizationRecord>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    Ok(Json(
        state.db.list_user_organizations(&current.user.id).await?,
    ))
}

#[derive(Debug, Deserialize)]
pub(super) struct MyOrganizationInput {
    slug: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    allowed_email_domains: Vec<String>,
}

pub(crate) async fn create_my_organization(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<MyOrganizationInput>,
) -> AppResult<Json<OrganizationResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization_input = NewOrganization {
        slug: organizations::normalize_slug(&payload.slug)?,
        name: organizations::normalize_name(&payload.name)?,
        kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
        description: normalize_optional_text(payload.description),
        allowed_email_domains: security_policy::normalize_email_domain_rules(
            payload.allowed_email_domains,
        )?,
        is_active: true,
    };
    let organization = state
        .db
        .create_organization_with_owner_and_audit(
            organization_input.clone(),
            &current.user.id,
            audit::management_event(
                current.user.id.clone(),
                "organization.self_service_create",
                "organization",
                None,
                serde_json::json!({ "slug": organization_input.slug, "name": organization_input.name }),
            ),
        )
        .await?;
    Ok(Json(
        admin_organizations::organization_response(&state, organization).await?,
    ))
}

#[derive(Debug, Deserialize)]
pub(crate) struct OrganizationContextInput {
    pub(crate) organization_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct OrganizationContextResponse {
    pub(crate) organization: Option<UserOrganizationRecord>,
}

pub(crate) async fn my_organization_context(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<OrganizationContextResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    Ok(Json(OrganizationContextResponse {
        organization: state.db.active_user_organization(&current.user.id).await?,
    }))
}

pub(crate) async fn set_my_organization_context(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<OrganizationContextInput>,
) -> AppResult<Json<OrganizationContextResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .set_active_user_organization(&current.user.id, payload.organization_id.trim())
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.context.select",
            "organization",
            Some(organization.id.clone()),
            serde_json::json!({ "slug": organization.slug }),
        ))
        .await?;
    Ok(Json(OrganizationContextResponse {
        organization: Some(organization),
    }))
}
