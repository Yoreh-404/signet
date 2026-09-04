use super::{
    admin_application_authorization_scope::managed_authorization_profile,
    admin_application_scope::managed_application,
    admin_organization_types::OrganizationMemberResponse,
};
use crate::{
    AppState,
    access::permission_catalog,
    application_discovery,
    db::{ApplicationAuthorizationProfileRecord, ApplicationPermissionDefinitionRecord},
    error::AppResult,
    organizations,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct ApplicationAuthorizationProfileResponse {
    pub(super) id: String,
    pub(super) profile_key: String,
    pub(super) connection_kind: String,
    pub(super) connection_id: Option<String>,
    pub(super) source_mode: String,
    pub(super) remote_version: Option<String>,
    pub(super) remote_digest: Option<String>,
    pub(super) sync_status: String,
    pub(super) last_synced_at: Option<i64>,
    pub(super) last_error: Option<String>,
    pub(super) permission_count: usize,
    pub(super) role_count: usize,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct ApplicationPermissionDefinitionResponse {
    key: String,
    label: String,
    description: Option<String>,
    source: String,
    is_active: bool,
}

#[derive(Debug, Serialize)]
struct ApplicationAuthorizationGroupResponse {
    id: String,
    name: String,
    description: Option<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct ApplicationAuthorizationSubjectsResponse {
    users: Vec<OrganizationMemberResponse>,
    groups: Vec<ApplicationAuthorizationGroupResponse>,
    organization_roles: Vec<String>,
}

fn permission_definition_response(
    definition: ApplicationPermissionDefinitionRecord,
) -> ApplicationPermissionDefinitionResponse {
    ApplicationPermissionDefinitionResponse {
        key: definition.permission_key,
        label: definition.label,
        description: definition.description,
        source: definition.source,
        is_active: definition.is_active == 1,
    }
}

fn profile_response_with_counts(
    profile: ApplicationAuthorizationProfileRecord,
    permission_count: usize,
    role_count: usize,
) -> ApplicationAuthorizationProfileResponse {
    ApplicationAuthorizationProfileResponse {
        id: profile.id,
        profile_key: profile.profile_key,
        connection_kind: profile.connection_kind,
        connection_id: profile.connection_id,
        source_mode: profile.source_mode,
        remote_version: profile.remote_version,
        remote_digest: profile.remote_digest,
        sync_status: profile.sync_status,
        last_synced_at: profile.last_synced_at,
        last_error: profile.last_error,
        permission_count,
        role_count,
        created_at: profile.created_at,
        updated_at: profile.updated_at,
    }
}

async fn profile_response(
    state: &AppState,
    profile: ApplicationAuthorizationProfileRecord,
) -> AppResult<ApplicationAuthorizationProfileResponse> {
    let counts = state
        .db
        .list_application_authorization_profile_counts(std::slice::from_ref(&profile.id))
        .await?;
    let (permission_count, role_count) = counts.get(&profile.id).copied().unwrap_or((0, 0));
    Ok(profile_response_with_counts(
        profile,
        permission_count.max(0) as usize,
        role_count.max(0) as usize,
    ))
}

pub(super) async fn catalog(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<crate::access::PermissionInfo>>> {
    managed_application(&state, &jar, &id).await?;
    Ok(Json(permission_catalog()))
}

pub(super) async fn subjects(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<ApplicationAuthorizationSubjectsResponse>> {
    let (_, application) = managed_application(&state, &jar, &id).await?;
    let (users_result, groups_result) = tokio::join!(
        state
            .db
            .list_active_organization_members(&application.organization_id),
        state
            .db
            .list_application_authorization_groups(&application.organization_id),
    );
    let users = users_result?
        .into_iter()
        .map(|member| OrganizationMemberResponse {
            organization_id: member.organization_id,
            user_id: member.user_id,
            role: member.role,
            email: member.email,
            username: member.username,
            display_name: member.display_name,
            is_active: true,
            archived_at: None,
            created_at: member.membership_created_at,
            updated_at: member.membership_updated_at,
        })
        .collect();
    let groups = groups_result?
        .into_iter()
        .map(|group| ApplicationAuthorizationGroupResponse {
            id: group.id,
            name: group.name,
            description: group.description,
            created_at: group.created_at,
            updated_at: group.updated_at,
        })
        .collect();
    Ok(Json(ApplicationAuthorizationSubjectsResponse {
        users,
        groups,
        organization_roles: vec![
            organizations::ROLE_OWNER.to_string(),
            organizations::ROLE_ADMIN.to_string(),
            organizations::ROLE_MEMBER.to_string(),
        ],
    }))
}

pub(super) async fn list_profiles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationAuthorizationProfileResponse>>> {
    let (_, application) = managed_application(&state, &jar, &id).await?;
    let profiles = state
        .db
        .list_application_authorization_profiles(&application.id)
        .await?;
    let profile_ids = profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<Vec<_>>();
    let counts = state
        .db
        .list_application_authorization_profile_counts(&profile_ids)
        .await?;
    let response = profiles
        .into_iter()
        .map(|profile| {
            let (permission_count, role_count) = counts.get(&profile.id).copied().unwrap_or((0, 0));
            profile_response_with_counts(
                profile,
                permission_count.max(0) as usize,
                role_count.max(0) as usize,
            )
        })
        .collect();
    Ok(Json(response))
}

pub(super) async fn get_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<ApplicationAuthorizationProfileResponse>> {
    let (_, _, profile) = managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    Ok(Json(profile_response(&state, profile).await?))
}

pub(super) async fn profile_catalog(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ApplicationPermissionDefinitionResponse>>> {
    let (_, _, profile) = managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let mut definitions = Vec::new();
    if profile.source_mode == application_discovery::SOURCE_MODE_MANUAL {
        definitions.extend(permission_catalog().into_iter().map(|item| {
            ApplicationPermissionDefinitionResponse {
                key: item.key.to_string(),
                label: item.label.to_string(),
                description: Some(item.category.to_string()),
                source: "signet_compat".to_string(),
                is_active: true,
            }
        }));
    }
    definitions.extend(
        state
            .db
            .list_application_permission_definitions(&profile.id)
            .await?
            .into_iter()
            .map(permission_definition_response),
    );
    definitions.sort_by(|left, right| left.key.cmp(&right.key));
    definitions.dedup_by(|left, right| left.key == right.key);
    Ok(Json(definitions))
}
