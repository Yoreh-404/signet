use crate::{
    AppState,
    access::{Authorizer, Permission},
    applications, archived_accounts,
    audit::{self, AuditSink},
    db::{
        ApplicationRecord, GroupRecord, NewBulkProvisionedUser, NewGroup, NewUser, UserListScope,
        UserRecord, UserUpdate,
    },
    error::AppError,
    security_policy::{self, PasswordPolicy, PasswordSubject},
    service_accounts::ServiceAccountProfile,
    util,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_READ_SCOPE: &str = "scim.read";
const SCIM_WRITE_SCOPE: &str = "scim.write";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/Schemas", get(schemas))
        .route("/scim/v2/ResourceTypes", get(resource_types))
        .route("/scim/v2/Users", get(list_users).post(create_user))
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route(
            "/scim/v2/Users/{id}",
            get(get_user)
                .put(replace_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(get_group)
                .put(replace_group)
                .patch(patch_group)
                .delete(delete_group),
        )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimUser {
    schemas: Vec<&'static str>,
    id: String,
    user_name: String,
    active: bool,
    name: ScimName,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    emails: Vec<ScimEmail>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    phone_numbers: Vec<ScimPhone>,
    meta: ScimMeta,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroup {
    schemas: Vec<&'static str>,
    id: String,
    display_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    members: Vec<ScimMember>,
    meta: ScimMeta,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScimMember {
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display: Option<String>,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    ref_: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    formatted: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScimEmail {
    value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    primary: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScimPhone {
    value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    primary: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimMeta {
    resource_type: &'static str,
    created: String,
    last_modified: String,
    location: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListResponse<T> {
    schemas: Vec<&'static str>,
    total_results: usize,
    start_index: usize,
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    start_index: Option<usize>,
    count: Option<usize>,
    filter: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimUserInput {
    user_name: String,
    active: Option<bool>,
    name: Option<ScimName>,
    display_name: Option<String>,
    emails: Option<Vec<ScimEmail>>,
    phone_numbers: Option<Vec<ScimPhone>>,
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupInput {
    display_name: String,
    members: Option<Vec<ScimMember>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchRequest {
    #[serde(rename = "Operations")]
    operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
struct PatchOperation {
    op: String,
    path: Option<String>,
    value: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceProviderConfig {
    schemas: Vec<&'static str>,
    patch: FeatureFlag,
    bulk: FeatureFlag,
    filter: FilterConfig,
    change_password: FeatureFlag,
    sort: FeatureFlag,
    etag: FeatureFlag,
    authentication_schemes: Vec<AuthScheme>,
}

#[derive(Debug, Serialize)]
struct FeatureFlag {
    supported: bool,
}

#[derive(Debug, Serialize)]
struct FilterConfig {
    supported: bool,
    #[serde(rename = "maxResults")]
    max_results: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthScheme {
    name: &'static str,
    description: &'static str,
    spec_uri: &'static str,
    documentation_uri: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    primary: bool,
}

#[derive(Debug)]
struct ScimPrincipal {
    user: Option<UserRecord>,
    client_id: Option<String>,
    application: Option<ApplicationRecord>,
    token_id: Option<String>,
    groups_enabled: bool,
    organization_id: Option<String>,
}

#[derive(Debug)]
struct ScimError {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
    www_authenticate: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScimAccess {
    Read,
    Write,
}

impl ScimAccess {
    fn scope(self) -> &'static str {
        match self {
            Self::Read => SCIM_READ_SCOPE,
            Self::Write => SCIM_WRITE_SCOPE,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimErrorBody {
    schemas: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scim_type: Option<&'static str>,
    detail: String,
    status: String,
}

trait ScimUserMapper {
    fn to_scim_user(&self, state: &AppState, headers: &HeaderMap) -> ScimUser;
}

impl ScimUserMapper for UserRecord {
    fn to_scim_user(&self, state: &AppState, headers: &HeaderMap) -> ScimUser {
        let location = format!(
            "{}/scim/v2/Users/{}",
            scim_base_url(state, headers),
            self.id
        );
        ScimUser {
            schemas: vec![USER_SCHEMA],
            id: self.id.clone(),
            user_name: self.username.clone(),
            active: self.is_active == 1 && self.archived_at.is_none(),
            name: ScimName {
                formatted: self.display_name.clone(),
            },
            display_name: self.display_name.clone(),
            emails: vec![ScimEmail {
                value: self.email.clone(),
                kind: Some("work".to_string()),
                primary: true,
            }],
            phone_numbers: self
                .phone
                .clone()
                .map(|phone| {
                    vec![ScimPhone {
                        value: phone,
                        kind: Some("work".to_string()),
                        primary: true,
                    }]
                })
                .unwrap_or_default(),
            meta: ScimMeta {
                resource_type: "User",
                created: iso_ts(self.created_at),
                last_modified: iso_ts(self.updated_at),
                location,
            },
        }
    }
}

async fn group_to_scim(
    state: &AppState,
    headers: &HeaderMap,
    group: &GroupRecord,
    principal: &ScimPrincipal,
) -> Result<ScimGroup, ScimError> {
    let location = format!(
        "{}/scim/v2/Groups/{}",
        scim_base_url(state, headers),
        group.id
    );
    let members = list_scim_group_members(state, principal, &group.id)
        .await?
        .into_iter()
        .map(|user| ScimMember {
            ref_: Some(format!(
                "{}/scim/v2/Users/{}",
                scim_base_url(state, headers),
                user.id
            )),
            display: user.display_name.clone().or(Some(user.username.clone())),
            value: user.id,
        })
        .collect();
    Ok(ScimGroup {
        schemas: vec![GROUP_SCHEMA],
        id: group.id.clone(),
        display_name: group.name.clone(),
        members,
        meta: ScimMeta {
            resource_type: "Group",
            created: iso_ts(group.created_at),
            last_modified: iso_ts(group.updated_at),
            location,
        },
    })
}

trait UserFilter {
    fn matches(&self, user: &UserRecord) -> bool;

    fn list_scope(&self) -> UserListScope {
        UserListScope::Live
    }
}

trait GroupFilter {
    fn matches(&self, group: &GroupRecord) -> bool;
}

enum ScimUserFilter {
    All,
    UserName(String),
    Email(String),
    Id(String),
    Active(bool),
}

enum ScimGroupFilter {
    All,
    Id(String),
    DisplayName(String),
}

impl UserFilter for ScimUserFilter {
    fn list_scope(&self) -> UserListScope {
        match self {
            ScimUserFilter::Active(true) => UserListScope::Active,
            ScimUserFilter::Active(false) => UserListScope::Disabled,
            ScimUserFilter::All
            | ScimUserFilter::UserName(_)
            | ScimUserFilter::Email(_)
            | ScimUserFilter::Id(_) => UserListScope::Live,
        }
    }

    fn matches(&self, user: &UserRecord) -> bool {
        match self {
            ScimUserFilter::All => true,
            ScimUserFilter::UserName(value) => user.username.eq_ignore_ascii_case(value),
            ScimUserFilter::Email(value) => user.email.eq_ignore_ascii_case(value),
            ScimUserFilter::Id(value) => user.id == *value,
            ScimUserFilter::Active(value) => {
                (user.is_active == 1 && user.archived_at.is_none()) == *value
            }
        }
    }
}

impl GroupFilter for ScimGroupFilter {
    fn matches(&self, group: &GroupRecord) -> bool {
        match self {
            ScimGroupFilter::All => true,
            ScimGroupFilter::Id(value) => group.id == *value,
            ScimGroupFilter::DisplayName(value) => group.name.eq_ignore_ascii_case(value),
        }
    }
}

async fn service_provider_config() -> impl IntoResponse {
    scim_json(ServiceProviderConfig {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        patch: FeatureFlag { supported: true },
        bulk: FeatureFlag { supported: false },
        filter: FilterConfig {
            supported: true,
            max_results: 200,
        },
        change_password: FeatureFlag { supported: true },
        sort: FeatureFlag { supported: false },
        etag: FeatureFlag { supported: false },
        authentication_schemes: vec![AuthScheme {
            name: "OAuth Bearer Token",
            description: "Use a Signet access token for an administrator or a user with SCIM permissions.",
            spec_uri: "https://www.rfc-editor.org/rfc/rfc6750",
            documentation_uri: "",
            kind: "oauthbearertoken",
            primary: true,
        }],
    })
}

async fn schemas() -> impl IntoResponse {
    scim_json(serde_json::json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": 2,
        "startIndex": 1,
        "itemsPerPage": 2,
        "Resources": [
            {
                "id": USER_SCHEMA,
                "name": "User",
                "description": "Core User",
                "attributes": [
                    { "name": "userName", "type": "string", "required": true, "mutability": "readWrite" },
                    { "name": "active", "type": "boolean", "required": false, "mutability": "readWrite" },
                    { "name": "emails", "type": "complex", "multiValued": true, "required": true, "mutability": "readWrite" },
                    { "name": "displayName", "type": "string", "required": false, "mutability": "readWrite" }
                ]
            },
            {
                "id": GROUP_SCHEMA,
                "name": "Group",
                "description": "Core Group",
                "attributes": [
                    { "name": "displayName", "type": "string", "required": true, "mutability": "readWrite" },
                    { "name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite" }
                ]
            }
        ]
    }))
}

async fn resource_types() -> impl IntoResponse {
    scim_json(serde_json::json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": 2,
        "startIndex": 1,
        "itemsPerPage": 2,
        "Resources": [
            {
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": USER_SCHEMA
            },
            {
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": GROUP_SCHEMA
            }
        ]
    }))
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response, ScimError> {
    let principal =
        require_scim_permission(&state, &headers, Permission::UsersRead, ScimAccess::Read).await?;
    let filter = parse_user_filter(query.filter.as_deref())?;
    let users = scoped_scim_users(&state, &principal, filter.list_scope())
        .await?
        .into_iter()
        .filter(|user| filter.matches(user))
        .collect::<Vec<_>>();
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100).min(200);
    let resources = users
        .iter()
        .skip(start_index - 1)
        .take(count)
        .map(|user| user.to_scim_user(&state, &headers))
        .collect::<Vec<_>>();
    Ok(scim_json(ListResponse {
        schemas: vec![LIST_SCHEMA],
        total_results: users.len(),
        start_index,
        items_per_page: resources.len(),
        resources,
    }))
}

async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let principal =
        require_scim_permission(&state, &headers, Permission::UsersRead, ScimAccess::Read).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or_else(|| ScimError::not_found("user not found"))?;
    ensure_scim_user_scope(&state, &principal, &user).await?;
    Ok(scim_json(user.to_scim_user(&state, &headers)))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserInput>,
) -> Result<Response, ScimError> {
    let principal =
        require_scim_permission(&state, &headers, Permission::UsersManage, ScimAccess::Write)
            .await?;
    let email = primary_email(&payload)?;
    let username = normalize_required(&payload.user_name, "userName")?;
    let display_name = payload.display_name.clone().or_else(|| {
        payload
            .name
            .as_ref()
            .and_then(|name| name.formatted.clone())
    });
    let phone = primary_phone(&payload);
    let password = payload
        .password
        .clone()
        .unwrap_or_else(generated_scim_password);
    validate_password_for_subject(&state, &password, &email, &username).await?;
    let new_user = NewUser {
        email: security_policy::normalize_login_subject(&email),
        username,
        display_name,
        phone,
        password_hash: util::hash_password(&password)?,
        email_verified_at: Some(util::now_ts()),
        phone_verified_at: None,
        is_admin: false,
        is_active: payload.active.unwrap_or(true),
        archived_at: None,
    };
    let user = if let Some(organization_id) = principal.organization_id.as_deref() {
        state
            .db
            .insert_bulk_provisioned_users(vec![NewBulkProvisionedUser {
                user: new_user,
                organization_id: Some(organization_id.to_string()),
                organization_role: Some(crate::organizations::ROLE_MEMBER.to_string()),
            }])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                ScimError::from(AppError::Internal("SCIM user was not created".to_string()))
            })?
    } else {
        state.db.insert_user(new_user).await?
    };
    audit_scim(
        &state,
        &principal,
        "scim.user.create",
        Some(user.id.clone()),
        serde_json::json!({ "email": user.email.clone() }),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        scim_json(user.to_scim_user(&state, &headers)),
    )
        .into_response())
}

async fn replace_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<ScimUserInput>,
) -> Result<Response, ScimError> {
    let principal =
        require_scim_permission(&state, &headers, Permission::UsersManage, ScimAccess::Write)
            .await?;
    let current = editable_user(&state, &id).await?;
    ensure_scim_user_scope(&state, &principal, &current).await?;
    let email = primary_email(&payload)?;
    let username = normalize_required(&payload.user_name, "userName")?;
    let display_name = payload.display_name.clone().or_else(|| {
        payload
            .name
            .as_ref()
            .and_then(|name| name.formatted.clone())
    });
    let phone = primary_phone(&payload);
    let user = state
        .db
        .update_user(UserUpdate {
            id: &id,
            email: security_policy::normalize_login_subject(&email),
            username,
            display_name,
            phone,
            is_admin: current.is_admin == 1,
            is_active: current.is_active == 1,
        })
        .await?;
    if let Some(password) = payload
        .password
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        validate_password_for_subject(&state, password, &user.email, &user.username).await?;
        state
            .db
            .set_user_password(&id, util::hash_password(password)?)
            .await?;
    }
    apply_active(&state, &id, payload.active).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or_else(|| ScimError::not_found("user not found"))?;
    ensure_scim_user_scope(&state, &principal, &user).await?;
    audit_scim(
        &state,
        &principal,
        "scim.user.replace",
        Some(id),
        serde_json::json!({ "email": user.email.clone() }),
    )
    .await?;
    Ok(scim_json(user.to_scim_user(&state, &headers)))
}

async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<PatchRequest>,
) -> Result<Response, ScimError> {
    let principal =
        require_scim_permission(&state, &headers, Permission::UsersManage, ScimAccess::Write)
            .await?;
    let mut user = editable_user(&state, &id).await?;
    ensure_scim_user_scope(&state, &principal, &user).await?;
    for operation in payload.operations {
        let op = operation.op.to_ascii_lowercase();
        if op != "replace" && op != "add" {
            return Err(ScimError::bad_request(
                "mutability",
                "only add/replace are supported",
            ));
        }
        apply_patch_operation(&state, &id, &mut user, operation).await?;
        user = state
            .db
            .find_user_by_id(&id)
            .await?
            .ok_or_else(|| ScimError::not_found("user not found"))?;
    }
    audit_scim(
        &state,
        &principal,
        "scim.user.patch",
        Some(id.clone()),
        serde_json::json!({ "email": user.email.clone() }),
    )
    .await?;
    Ok(scim_json(user.to_scim_user(&state, &headers)))
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let principal =
        require_scim_permission(&state, &headers, Permission::UsersManage, ScimAccess::Write)
            .await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or_else(|| ScimError::not_found("user not found"))?;
    ensure_scim_user_scope(&state, &principal, &user).await?;
    if user.archived_at.is_some() {
        return Err(ScimError::bad_request(
            "mutability",
            "archived users cannot be changed through SCIM",
        ));
    }
    state.db.disable_user(&id).await?;
    audit_scim(
        &state,
        &principal,
        "scim.user.disable",
        Some(id),
        serde_json::json!({ "email": user.email }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(
        &state,
        &headers,
        Permission::SecurityManage,
        ScimAccess::Read,
    )
    .await?;
    ensure_scim_groups_enabled(&principal)?;
    let filter = parse_group_filter(query.filter.as_deref())?;
    let groups = scoped_scim_groups(&state, &principal)
        .await?
        .into_iter()
        .filter(|group| filter.matches(group))
        .collect::<Vec<_>>();
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100).min(200);
    let mut resources = Vec::new();
    for group in groups.iter().skip(start_index - 1).take(count) {
        resources.push(group_to_scim(&state, &headers, group, &principal).await?);
    }
    Ok(scim_json(ListResponse {
        schemas: vec![LIST_SCHEMA],
        total_results: groups.len(),
        start_index,
        items_per_page: resources.len(),
        resources,
    }))
}

async fn get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(
        &state,
        &headers,
        Permission::SecurityManage,
        ScimAccess::Read,
    )
    .await?;
    ensure_scim_groups_enabled(&principal)?;
    let group = find_scim_group(&state, &principal, &id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    Ok(scim_json(
        group_to_scim(&state, &headers, &group, &principal).await?,
    ))
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScimGroupInput>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(
        &state,
        &headers,
        Permission::SecurityManage,
        ScimAccess::Write,
    )
    .await?;
    ensure_scim_groups_enabled(&principal)?;
    let requested_members = payload.members.map(member_ids).unwrap_or_default();
    let new_group = NewGroup {
        name: normalize_required(&payload.display_name, "displayName")?,
        description: None,
    };
    let group = if let Some(application) = principal.application.as_ref() {
        state
            .db
            .insert_application_scim_group(&application.id, new_group)
            .await?
    } else {
        state.db.insert_group(new_group).await?
    };
    if !requested_members.is_empty() {
        if let Err(error) =
            replace_scim_group_members(&state, &principal, &group.id, requested_members).await
        {
            if let Some(application) = principal.application.as_ref() {
                let _ = state
                    .db
                    .delete_application_scim_group(&application.id, &group.id)
                    .await;
            } else {
                let _ = state.db.delete_group(&group.id).await;
            }
            return Err(error);
        }
    }
    let group = find_scim_group(&state, &principal, &group.id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    audit_scim(
        &state,
        &principal,
        "scim.group.create",
        Some(group.id.clone()),
        serde_json::json!({ "name": group.name.clone() }),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        scim_json(group_to_scim(&state, &headers, &group, &principal).await?),
    )
        .into_response())
}

async fn replace_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<ScimGroupInput>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(
        &state,
        &headers,
        Permission::SecurityManage,
        ScimAccess::Write,
    )
    .await?;
    ensure_scim_groups_enabled(&principal)?;
    let existing = find_scim_group(&state, &principal, &id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    let group = state
        .db
        .update_group(
            &id,
            NewGroup {
                name: normalize_required(&payload.display_name, "displayName")?,
                description: existing.description.clone(),
            },
        )
        .await?;
    if let Some(members) = payload.members {
        let member_ids = member_ids(members);
        replace_scim_group_members(&state, &principal, &id, member_ids).await?;
    }
    let group = find_scim_group(&state, &principal, &group.id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    audit_scim(
        &state,
        &principal,
        "scim.group.replace",
        Some(id),
        serde_json::json!({ "name": group.name.clone() }),
    )
    .await?;
    Ok(scim_json(
        group_to_scim(&state, &headers, &group, &principal).await?,
    ))
}

async fn patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<PatchRequest>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(
        &state,
        &headers,
        Permission::SecurityManage,
        ScimAccess::Write,
    )
    .await?;
    ensure_scim_groups_enabled(&principal)?;
    let mut group = find_scim_group(&state, &principal, &id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    for operation in payload.operations {
        apply_group_patch_operation(&state, &principal, &id, &mut group, operation).await?;
        group = find_scim_group(&state, &principal, &id)
            .await?
            .ok_or_else(|| ScimError::not_found("group not found"))?;
    }
    audit_scim(
        &state,
        &principal,
        "scim.group.patch",
        Some(id.clone()),
        serde_json::json!({ "name": group.name.clone() }),
    )
    .await?;
    Ok(scim_json(
        group_to_scim(&state, &headers, &group, &principal).await?,
    ))
}

async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(
        &state,
        &headers,
        Permission::SecurityManage,
        ScimAccess::Write,
    )
    .await?;
    ensure_scim_groups_enabled(&principal)?;
    let group = find_scim_group(&state, &principal, &id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    if let Some(application) = principal.application.as_ref() {
        state
            .db
            .delete_application_scim_group(&application.id, &id)
            .await?;
    } else {
        state.db.delete_group(&id).await?;
    }
    audit_scim(
        &state,
        &principal,
        "scim.group.delete",
        Some(id),
        serde_json::json!({ "name": group.name }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn apply_patch_operation(
    state: &AppState,
    id: &str,
    user: &mut UserRecord,
    operation: PatchOperation,
) -> Result<(), ScimError> {
    match operation.path.as_deref().map(normalize_path) {
        Some(path) if path == "active" => {
            let active = operation
                .value
                .as_bool()
                .ok_or_else(|| ScimError::bad_request("invalidValue", "active must be boolean"))?;
            apply_active(state, id, Some(active)).await
        }
        Some(path) if path == "username" => {
            let username = json_string(&operation.value, "userName")?;
            replace_user_fields(state, id, user, Some(username), None, None, None).await
        }
        Some(path) if path == "displayname" || path == "name.formatted" => {
            let display_name = json_string(&operation.value, "displayName")?;
            replace_user_fields(state, id, user, None, None, Some(display_name), None).await
        }
        Some(path) if path == "emails" || path == "emails.value" => {
            let email = patch_email_value(&operation.value)?;
            replace_user_fields(state, id, user, None, Some(email), None, None).await
        }
        Some(path) if path == "phonenumbers" || path == "phonenumbers.value" => {
            let phone = patch_phone_value(&operation.value);
            replace_user_fields(state, id, user, None, None, None, Some(phone)).await
        }
        Some(path) => Err(ScimError::bad_request(
            "invalidPath",
            format!("unsupported path: {path}"),
        )),
        None => apply_patch_object(state, id, user, operation.value).await,
    }
}

async fn apply_patch_object(
    state: &AppState,
    id: &str,
    user: &mut UserRecord,
    value: Value,
) -> Result<(), ScimError> {
    let object = value
        .as_object()
        .ok_or_else(|| ScimError::bad_request("invalidValue", "patch value must be an object"))?;
    if let Some(active) = object.get("active").and_then(Value::as_bool) {
        apply_active(state, id, Some(active)).await?;
    }
    let username = object
        .get("userName")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let email = object.get("emails").map(patch_email_value).transpose()?;
    let display_name = object
        .get("displayName")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            object
                .get("name")
                .and_then(|value| value.get("formatted"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let phone = object.get("phoneNumbers").map(patch_phone_value);
    if username.is_some() || email.is_some() || display_name.is_some() || phone.is_some() {
        replace_user_fields(state, id, user, username, email, display_name, phone).await?;
    }
    Ok(())
}

async fn replace_user_fields(
    state: &AppState,
    id: &str,
    user: &UserRecord,
    username: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
    phone: Option<Option<String>>,
) -> Result<(), ScimError> {
    let next_email = email
        .map(|value| security_policy::normalize_login_subject(&value))
        .unwrap_or_else(|| user.email.clone());
    let next_username = username.unwrap_or_else(|| user.username.clone());
    state
        .db
        .update_user(UserUpdate {
            id,
            email: next_email,
            username: next_username,
            display_name: display_name.or_else(|| user.display_name.clone()),
            phone: phone.unwrap_or_else(|| user.phone.clone()),
            is_admin: user.is_admin == 1,
            is_active: user.is_active == 1,
        })
        .await?;
    Ok(())
}

async fn apply_active(state: &AppState, id: &str, active: Option<bool>) -> Result<(), ScimError> {
    match active {
        Some(true) => state.db.enable_user(id).await?,
        Some(false) => state.db.disable_user(id).await?,
        None => {}
    }
    Ok(())
}

async fn apply_group_patch_operation(
    state: &AppState,
    principal: &ScimPrincipal,
    id: &str,
    group: &mut GroupRecord,
    operation: PatchOperation,
) -> Result<(), ScimError> {
    let op = operation.op.to_ascii_lowercase();
    match operation.path.as_deref().map(normalize_path) {
        Some(path) if path == "displayname" => {
            if op != "replace" && op != "add" {
                return Err(ScimError::bad_request(
                    "mutability",
                    "displayName only supports add/replace",
                ));
            }
            let display_name = json_string(&operation.value, "displayName")?;
            state
                .db
                .update_group(
                    id,
                    NewGroup {
                        name: display_name,
                        description: group.description.clone(),
                    },
                )
                .await?;
            Ok(())
        }
        Some(path) if path == "members" => {
            let next = match op.as_str() {
                "replace" => member_ids(patch_members_value(&operation.value)?),
                "add" => {
                    let mut ids = list_scim_group_members(state, principal, id)
                        .await?
                        .into_iter()
                        .map(|user| user.id)
                        .collect::<Vec<_>>();
                    ids.extend(member_ids(patch_members_value(&operation.value)?));
                    ids
                }
                "remove" => {
                    let remove = member_ids(patch_members_value(&operation.value)?);
                    list_scim_group_members(state, principal, id)
                        .await?
                        .into_iter()
                        .map(|user| user.id)
                        .filter(|user_id| !remove.iter().any(|item| item == user_id))
                        .collect()
                }
                _ => {
                    return Err(ScimError::bad_request(
                        "mutability",
                        "members supports add/replace/remove",
                    ));
                }
            };
            replace_scim_group_members(state, principal, id, next).await?;
            Ok(())
        }
        Some(path) => Err(ScimError::bad_request(
            "invalidPath",
            format!("unsupported path: {path}"),
        )),
        None => {
            let object = operation.value.as_object().ok_or_else(|| {
                ScimError::bad_request("invalidValue", "patch value must be an object")
            })?;
            if let Some(value) = object.get("displayName") {
                let display_name = json_string(value, "displayName")?;
                state
                    .db
                    .update_group(
                        id,
                        NewGroup {
                            name: display_name,
                            description: group.description.clone(),
                        },
                    )
                    .await?;
            }
            if let Some(value) = object.get("members") {
                let member_ids = member_ids(patch_members_value(value)?);
                replace_scim_group_members(state, principal, id, member_ids).await?;
            }
            Ok(())
        }
    }
}

async fn require_scim_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
    access: ScimAccess,
) -> Result<ScimPrincipal, ScimError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
        .ok_or_else(|| ScimError::bearer_invalid("missing bearer token"))?;
    // `scim_v1_` credentials are opaque application credentials. Never send
    // an expired/revoked one through the JWT fallback: that fallback would
    // make an invalid opaque token depend on runtime JWT settings and could
    // turn a normal authentication failure into a 404/500 response.
    let is_application_token = token.starts_with("scim_v1_");
    if let Some(principal) = application_scim_token_principal(state, token, access).await? {
        return Ok(principal);
    }
    if is_application_token {
        return Err(ScimError::bearer_invalid("invalid application SCIM token"));
    }
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    // A service-account token may target the application's configured SCIM
    // audience rather than the platform `/scim/v2` audience. Verify the
    // signature and issuer first only to discover that application binding;
    // both branches below perform a second, audience-enforcing verification
    // before authorizing the request.
    let bootstrap_claims = state
        .jwt
        .verify_access_token_for_generic_bearer(token, &issuer_refs)
        .map_err(|_| ScimError::bearer_invalid("invalid bearer token"))?;
    if bootstrap_claims.cnf.is_some() {
        return Err(ScimError::bearer_invalid(
            "DPoP-bound tokens require a DPoP-capable resource endpoint",
        ));
    }
    if let Some(principal) =
        application_scim_principal(state, token, &issuer_refs, &bootstrap_claims, access).await?
    {
        return Ok(principal);
    }
    let runtime = state.db.runtime_settings().await?;
    let expected_audience = format!("{}/scim/v2", runtime.public_base_url.trim_end_matches('/'));
    let audiences = [expected_audience.clone()];
    let claims = state
        .jwt
        .verify_access_token_with_issuers_and_audiences(token, &issuer_refs, &audiences)
        .map_err(|_| ScimError::bearer_invalid("token audience is not valid for SCIM"))?;
    validate_scim_claims(&claims, &expected_audience, access)?;
    let user = state
        .db
        .find_user_by_id(&claims.sub)
        .await?
        .ok_or_else(|| ScimError::bearer_invalid("subject user not found"))?;
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(ScimError::bearer_invalid("subject user is not active"));
    }
    if state
        .db
        .find_trial_enrollment_for_user(&user.id)
        .await?
        .is_some()
    {
        return Err(ScimError::bearer_invalid(
            "trial enrollment accounts cannot access SCIM",
        ));
    }
    state.db.require_permission(&user, permission).await?;
    Ok(ScimPrincipal {
        user: Some(user),
        client_id: None,
        application: None,
        token_id: None,
        groups_enabled: true,
        organization_id: None,
    })
}

/// An application SCIM token is deliberately opaque and has no user subject.
/// It is looked up before JWT verification so a website can provision users
/// without creating a global Signet user token or OAuth client credential.
async fn application_scim_token_principal(
    state: &AppState,
    raw_token: &str,
    access: ScimAccess,
) -> Result<Option<ScimPrincipal>, ScimError> {
    let token_hash = util::token_hash(raw_token);
    let Some(token) = state
        .db
        .find_active_application_scim_token(&token_hash)
        .await?
    else {
        return Ok(None);
    };
    let application = state
        .db
        .find_application_by_id(&token.application_id)
        .await?
        .ok_or_else(|| ScimError::bearer_invalid("SCIM application no longer exists"))?;
    let config = ensure_application_scim_enabled(state, &application).await?;
    let scopes: Vec<String> = util::from_json(&token.scopes).map_err(ScimError::from)?;
    if !scopes.iter().any(|scope| scope == access.scope()) {
        return Err(ScimError::insufficient_scope(access.scope()));
    }
    state.db.touch_application_scim_token(&token_hash).await?;
    let organization_id = application.organization_id.clone();
    Ok(Some(ScimPrincipal {
        user: None,
        client_id: Some(format!("scim-token:{}", token.id)),
        application: Some(application),
        token_id: Some(token.id),
        groups_enabled: config
            .get("sync_groups")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        organization_id: Some(organization_id),
    }))
}

/// Application SCIM is authenticated with an OAuth client-credentials token,
/// never with a browser session or a client credential that merely happens to
/// have a `users.*` permission. The OIDC client must be attached to the
/// application and the application must explicitly enable SCIM with the
/// exact configured audience. This keeps a website's directory source from
/// becoming an ambient global management token.
async fn application_scim_principal(
    state: &AppState,
    raw_token: &str,
    issuers: &[&str],
    claims: &crate::jwt::TokenClaims,
    access: ScimAccess,
) -> Result<Option<ScimPrincipal>, ScimError> {
    let expected_subject = format!("service-account:{}", claims.client_id);
    if claims.sub != expected_subject {
        return Ok(None);
    }
    let client = state
        .db
        .find_client_by_client_id(&claims.client_id)
        .await?
        .ok_or_else(|| ScimError::bearer_invalid("SCIM client is not registered"))?;
    if client.is_active != 1 || !client.service_account_enabled() {
        return Err(ScimError::bearer_invalid(
            "SCIM service account is disabled",
        ));
    }
    if !claims
        .scope
        .split_ascii_whitespace()
        .any(|scope| scope == access.scope())
    {
        return Err(ScimError::insufficient_scope(access.scope()));
    }
    let Some(application) = state.db.find_application_for_client(&client.id).await? else {
        return Err(ScimError::bearer_invalid(
            "SCIM client is not attached to an application",
        ));
    };
    let config = ensure_application_scim_enabled(state, &application).await?;
    let expected_audience = config
        .get("scim_audience")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|audience| !audience.is_empty())
        .ok_or_else(|| ScimError::bearer_invalid("application SCIM audience is not configured"))?
        .to_string();
    let audiences = [expected_audience];
    // The application and its directory module are resolved before this
    // check, so a website cannot borrow another website's configured
    // audience. The JWT layer performs the actual `aud` validation.
    let claims = state
        .jwt
        .verify_access_token_with_issuers_and_audiences(raw_token, issuers, &audiences)
        .map_err(|_| {
            ScimError::bearer_invalid(
                "token audience is not valid for this application SCIM source",
            )
        })?;
    if claims.sub != format!("service-account:{}", claims.client_id) {
        return Err(ScimError::bearer_invalid(
            "SCIM service account subject is invalid",
        ));
    }
    let required_permission = match access {
        ScimAccess::Read => Permission::UsersRead,
        ScimAccess::Write => Permission::UsersManage,
    };
    if !client
        .service_account_permissions()?
        .iter()
        .any(|permission| permission == required_permission.as_str())
    {
        return Err(ScimError::insufficient_scope(required_permission.as_str()));
    }
    let organization_id = application.organization_id.clone();
    Ok(Some(ScimPrincipal {
        user: None,
        client_id: Some(client.client_id),
        application: Some(application),
        token_id: None,
        groups_enabled: config
            .get("sync_groups")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        organization_id: Some(organization_id),
    }))
}

fn ensure_scim_groups_enabled(principal: &ScimPrincipal) -> Result<(), ScimError> {
    if principal.groups_enabled {
        Ok(())
    } else {
        Err(ScimError::new(
            StatusCode::FORBIDDEN,
            Some("mutability"),
            "group synchronization is disabled for this application",
        ))
    }
}

async fn ensure_application_scim_enabled(
    state: &AppState,
    application: &ApplicationRecord,
) -> Result<serde_json::Map<String, Value>, ScimError> {
    applications::ensure_application_runtime_active(state, application)
        .await
        .map_err(|error| match error {
            AppError::Forbidden => ScimError::bearer_invalid("SCIM application is disabled"),
            other => ScimError::from(other),
        })?;
    let Some(config) =
        applications::enabled_module_config(state, &application.id, "directory_sync").await?
    else {
        return Err(ScimError::bearer_invalid(
            "SCIM is not enabled for application",
        ));
    };
    if config.get("scim_enabled").and_then(Value::as_bool) != Some(true) {
        return Err(ScimError::bearer_invalid(
            "SCIM is not enabled for application",
        ));
    }
    Ok(config)
}

fn validate_scim_claims(
    claims: &crate::jwt::TokenClaims,
    expected_audience: &str,
    access: ScimAccess,
) -> Result<(), ScimError> {
    if claims.gpt_sso_login_code_level.is_some() {
        return Err(ScimError::bearer_invalid(
            "authorization-code login tokens cannot access SCIM",
        ));
    }
    if claims.aud != expected_audience {
        return Err(ScimError::bearer_invalid(
            "token audience is not valid for SCIM",
        ));
    }
    if claims.sub == claims.client_id || claims.sub.starts_with("service-account:") {
        return Err(ScimError::bearer_invalid(
            "client credential subjects are not supported by SCIM",
        ));
    }
    let required_scope = access.scope();
    if !claims
        .scope
        .split_ascii_whitespace()
        .any(|scope| scope == required_scope)
    {
        return Err(ScimError::insufficient_scope(required_scope));
    }
    Ok(())
}

async fn editable_user(state: &AppState, id: &str) -> Result<UserRecord, ScimError> {
    let user = state
        .db
        .find_user_by_id(id)
        .await?
        .ok_or_else(|| ScimError::not_found("user not found"))?;
    if user.archived_at.is_some() {
        Err(ScimError::bad_request(
            "mutability",
            "archived users cannot be changed through SCIM",
        ))
    } else {
        Ok(user)
    }
}

async fn scoped_scim_users(
    state: &AppState,
    principal: &ScimPrincipal,
    scope: UserListScope,
) -> Result<Vec<UserRecord>, ScimError> {
    match principal.organization_id.as_deref() {
        Some(organization_id) => state
            .db
            .list_users_for_organization(organization_id, scope)
            .await
            .map_err(ScimError::from),
        None => state.db.list_users(scope).await.map_err(ScimError::from),
    }
}

async fn ensure_scim_user_scope(
    state: &AppState,
    principal: &ScimPrincipal,
    user: &UserRecord,
) -> Result<(), ScimError> {
    let Some(organization_id) = principal.organization_id.as_deref() else {
        return Ok(());
    };
    if state
        .db
        .user_belongs_to_organization(organization_id, &user.id)
        .await?
    {
        Ok(())
    } else {
        Err(ScimError::not_found("user not found"))
    }
}

async fn scoped_scim_groups(
    state: &AppState,
    principal: &ScimPrincipal,
) -> Result<Vec<GroupRecord>, ScimError> {
    match principal.application.as_ref() {
        Some(application) => state
            .db
            .list_application_scim_groups(&application.id)
            .await
            .map_err(ScimError::from),
        None => state.db.list_groups().await.map_err(ScimError::from),
    }
}

async fn find_scim_group(
    state: &AppState,
    principal: &ScimPrincipal,
    group_id: &str,
) -> Result<Option<GroupRecord>, ScimError> {
    match principal.application.as_ref() {
        Some(application) => state
            .db
            .find_application_scim_group(&application.id, group_id)
            .await
            .map_err(ScimError::from),
        None => state
            .db
            .find_group_by_id(group_id)
            .await
            .map_err(ScimError::from),
    }
}

async fn list_scim_group_members(
    state: &AppState,
    principal: &ScimPrincipal,
    group_id: &str,
) -> Result<Vec<UserRecord>, ScimError> {
    match principal.application.as_ref() {
        Some(application) => state
            .db
            .list_application_scim_group_members(&application.id, group_id)
            .await
            .map_err(ScimError::from),
        None => state
            .db
            .list_group_members(group_id)
            .await
            .map_err(ScimError::from),
    }
}

async fn replace_scim_group_members(
    state: &AppState,
    principal: &ScimPrincipal,
    group_id: &str,
    requested_user_ids: Vec<String>,
) -> Result<(), ScimError> {
    ensure_group_members_syncable(state, principal, group_id, &requested_user_ids).await?;
    if let Some(application) = principal.application.as_ref() {
        state
            .db
            .replace_application_scim_group_members(&application.id, group_id, requested_user_ids)
            .await
            .map_err(ScimError::from)
    } else {
        state
            .db
            .replace_group_members(group_id, requested_user_ids)
            .await
            .map_err(ScimError::from)
    }
}

async fn ensure_group_members_syncable(
    state: &AppState,
    principal: &ScimPrincipal,
    group_id: &str,
    requested_user_ids: &[String],
) -> Result<(), ScimError> {
    let existing_members = list_scim_group_members(state, principal, group_id).await?;
    let requested_user_ids = archived_accounts::normalize_user_ids(requested_user_ids);
    let allowed_archived_user_ids = archived_accounts::ensure_archived_group_members_preserved(
        &existing_members,
        &requested_user_ids,
    )?;
    ensure_assignable_group_user_ids(
        state,
        principal,
        &requested_user_ids,
        &allowed_archived_user_ids,
    )
    .await
}

async fn ensure_assignable_group_user_ids(
    state: &AppState,
    principal: &ScimPrincipal,
    requested_user_ids: &BTreeSet<String>,
    allowed_archived_user_ids: &BTreeSet<String>,
) -> Result<(), ScimError> {
    for user_id in requested_user_ids {
        let user = state
            .db
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::BadRequest(format!("unknown user: {user_id}")))?;
        archived_accounts::ensure_assignable_user_record(
            &user,
            allowed_archived_user_ids,
            "SCIM groups",
        )?;
        ensure_scim_user_scope(state, principal, &user).await?;
    }
    Ok(())
}

async fn validate_password_for_subject(
    state: &AppState,
    password: &str,
    email: &str,
    username: &str,
) -> Result<(), ScimError> {
    state
        .db
        .security_policy()
        .await?
        .validate_password(password, PasswordSubject { email, username })
        .map_err(ScimError::from)
}

async fn audit_scim(
    state: &AppState,
    principal: &ScimPrincipal,
    action: &str,
    target_id: Option<String>,
    metadata: Value,
) -> Result<(), ScimError> {
    let mut event = if let Some(user) = principal.user.as_ref() {
        audit::management_event(
            user.id.clone(),
            action,
            "scim_user",
            target_id.clone(),
            metadata,
        )
    } else {
        audit::oauth_event(
            principal.client_id.clone().unwrap_or_default(),
            action,
            audit::AuditOutcome::Success,
            metadata,
        )
    };
    if principal.user.is_none() {
        event.target_kind = "scim_application".to_string();
        event.target_id = target_id;
        event.details = serde_json::json!({
            "application": principal.application.as_ref().map(|application| {
                serde_json::json!({
                    "id": application.id,
                    "slug": application.slug,
                })
            }),
            "credential": principal.token_id.as_ref().map(|token_id| {
                serde_json::json!({
                    "kind": "opaque_scim_token",
                    "id": token_id,
                })
            }),
            "operation": event.details,
        });
    }
    state.db.record_audit_event(event).await?;
    Ok(())
}

fn parse_user_filter(value: Option<&str>) -> Result<ScimUserFilter, ScimError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(ScimUserFilter::All);
    };
    let Some((field, raw_value)) = value.split_once(" eq ") else {
        return Err(ScimError::bad_request(
            "invalidFilter",
            "only eq filters are supported",
        ));
    };
    let field = normalize_path(field);
    let raw_value = raw_value.trim().trim_matches('"');
    match field.as_str() {
        "username" => Ok(ScimUserFilter::UserName(raw_value.to_string())),
        "emails.value" => Ok(ScimUserFilter::Email(raw_value.to_string())),
        "id" => Ok(ScimUserFilter::Id(raw_value.to_string())),
        "active" => match raw_value {
            "true" => Ok(ScimUserFilter::Active(true)),
            "false" => Ok(ScimUserFilter::Active(false)),
            _ => Err(ScimError::bad_request(
                "invalidFilter",
                "active filter must be true or false",
            )),
        },
        _ => Err(ScimError::bad_request(
            "invalidFilter",
            format!("unsupported filter field: {field}"),
        )),
    }
}

fn parse_group_filter(value: Option<&str>) -> Result<ScimGroupFilter, ScimError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(ScimGroupFilter::All);
    };
    let Some((field, raw_value)) = value.split_once(" eq ") else {
        return Err(ScimError::bad_request(
            "invalidFilter",
            "only eq filters are supported",
        ));
    };
    let field = normalize_path(field);
    let raw_value = raw_value.trim().trim_matches('"');
    match field.as_str() {
        "displayname" => Ok(ScimGroupFilter::DisplayName(raw_value.to_string())),
        "id" => Ok(ScimGroupFilter::Id(raw_value.to_string())),
        _ => Err(ScimError::bad_request(
            "invalidFilter",
            format!("unsupported filter field: {field}"),
        )),
    }
}

fn primary_email(payload: &ScimUserInput) -> Result<String, ScimError> {
    payload
        .emails
        .as_ref()
        .and_then(|emails| {
            emails
                .iter()
                .find(|email| email.primary)
                .or_else(|| emails.first())
        })
        .map(|email| email.value.trim().to_string())
        .filter(|email| !email.is_empty())
        .ok_or_else(|| ScimError::bad_request("invalidValue", "primary email is required"))
}

fn primary_phone(payload: &ScimUserInput) -> Option<String> {
    payload.phone_numbers.as_ref().and_then(|phones| {
        phones
            .iter()
            .find(|phone| phone.primary)
            .or_else(|| phones.first())
            .map(|phone| phone.value.trim().to_string())
            .filter(|phone| !phone.is_empty())
    })
}

fn patch_email_value(value: &Value) -> Result<String, ScimError> {
    if let Some(value) = value.as_str() {
        return Ok(value.to_string());
    }
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .find(|item| {
                item.get("primary")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .or_else(|| array.first())
            .and_then(|item| item.get("value").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .ok_or_else(|| ScimError::bad_request("invalidValue", "email value is required"));
    }
    value
        .get("value")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ScimError::bad_request("invalidValue", "email value is required"))
}

fn patch_phone_value(value: &Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return Some(value.to_string());
    }
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .find(|item| {
                item.get("primary")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .or_else(|| array.first())
            .and_then(|item| item.get("value").and_then(Value::as_str))
            .map(ToOwned::to_owned);
    }
    value
        .get("value")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn patch_members_value(value: &Value) -> Result<Vec<ScimMember>, ScimError> {
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .map(|item| {
                let value = item.get("value").and_then(Value::as_str).ok_or_else(|| {
                    ScimError::bad_request("invalidValue", "member value is required")
                })?;
                Ok(ScimMember {
                    value: value.to_string(),
                    display: item
                        .get("display")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    ref_: item
                        .get("$ref")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                })
            })
            .collect();
    }
    let value = value
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| ScimError::bad_request("invalidValue", "member value is required"))?;
    Ok(vec![ScimMember {
        value: value.to_string(),
        display: None,
        ref_: None,
    }])
}

fn member_ids(members: Vec<ScimMember>) -> Vec<String> {
    members
        .into_iter()
        .map(|member| member.value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn json_string(value: &Value, field: &str) -> Result<String, ScimError> {
    value
        .as_str()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ScimError::bad_request("invalidValue", format!("{field} must be string")))
}

fn normalize_required(value: &str, field: &str) -> Result<String, ScimError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(ScimError::bad_request(
            "invalidValue",
            format!("{field} is required"),
        ))
    } else {
        Ok(value)
    }
}

fn generated_scim_password() -> String {
    format!("Scim-{}9!", util::random_token(24))
}

fn normalize_path(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .split('[')
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase()
}

fn bearer_token(value: &str) -> Option<&str> {
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") || parts.next().is_some() {
        return None;
    }
    Some(token)
}

fn scim_base_url(state: &AppState, headers: &HeaderMap) -> String {
    util::external_base_url(
        &state.settings,
        headers,
        &state.settings.server.public_base_url,
    )
}

fn iso_ts(value: i64) -> String {
    DateTime::<Utc>::from_timestamp(value, 0)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339()
}

fn scim_json<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    response
}

impl ScimError {
    fn new(status: StatusCode, scim_type: Option<&'static str>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
            www_authenticate: None,
        }
    }

    fn bearer_invalid(detail: impl Into<String>) -> Self {
        let mut error = Self::new(StatusCode::UNAUTHORIZED, None, detail);
        error.www_authenticate = Some("Bearer realm=\"scim\", error=\"invalid_token\"".to_string());
        error
    }

    fn insufficient_scope(scope: &'static str) -> Self {
        let mut error = Self::new(
            StatusCode::FORBIDDEN,
            None,
            format!("required OAuth scope is missing: {scope}"),
        );
        error.www_authenticate = Some(format!(
            "Bearer realm=\"scim\", error=\"insufficient_scope\", scope=\"{scope}\""
        ));
        error
    }

    fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, None, detail)
    }

    fn bad_request(scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(scim_type), detail)
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let body = ScimErrorBody {
            schemas: vec![ERROR_SCHEMA],
            scim_type: self.scim_type,
            detail: self.detail,
            status: self.status.as_u16().to_string(),
        };
        let mut response = (self.status, scim_json(body)).into_response();
        if let Some(value) = self.www_authenticate.and_then(|value| value.parse().ok()) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

impl From<AppError> for ScimError {
    fn from(value: AppError) -> Self {
        let status = value.status();
        let is_internal = matches!(
            &value,
            AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_)
        );
        if is_internal {
            tracing::error!(error = %value, "SCIM request failed with an internal error");
        }
        let scim_type = match &value {
            AppError::BadRequest(_) | AppError::Oidc(_) => Some("invalidValue"),
            _ => None,
        };
        let detail = if is_internal {
            "internal server error".to_string()
        } else {
            value.to_string()
        };
        Self::new(status, scim_type, detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn token_claims(audience: &str, scope: &str) -> crate::jwt::TokenClaims {
        crate::jwt::TokenClaims {
            iss: "https://sso.example".to_string(),
            sub: "user-id".to_string(),
            aud: audience.to_string(),
            exp: util::now_ts() + 300,
            iat: util::now_ts(),
            jti: Some("test-jti".to_string()),
            token_use: "access_token".to_string(),
            client_id: "scim-client".to_string(),
            application_id: None,
            authorization_profile_id: None,
            scope: scope.to_string(),
            email: "admin@example.com".to_string(),
            email_verified: true,
            name: Some("Admin".to_string()),
            preferred_username: "admin".to_string(),
            nonce: None,
            auth_time: None,
            sid: None,
            cnf: None,
            authorization_details: None,
            act: None,
            grant_id: None,
            gpt_sso_login_code_level: None,
        }
    }

    #[test]
    fn user_filters_choose_live_scopes_for_scim_lists() {
        let filter = parse_user_filter(None).unwrap();
        assert!(matches!(filter.list_scope(), UserListScope::Live));

        let filter = parse_user_filter(Some(r#"userName eq "alice""#)).unwrap();
        assert!(matches!(filter.list_scope(), UserListScope::Live));

        let filter = parse_user_filter(Some("active eq true")).unwrap();
        assert!(matches!(filter.list_scope(), UserListScope::Active));

        let filter = parse_user_filter(Some("active eq false")).unwrap();
        assert!(matches!(filter.list_scope(), UserListScope::Disabled));
    }

    #[test]
    fn scim_claims_require_exact_audience_and_operation_scope() {
        let expected = "https://sso.example/scim/v2";
        let read = token_claims(expected, "openid scim.read");
        assert!(validate_scim_claims(&read, expected, ScimAccess::Read).is_ok());
        assert!(matches!(
            validate_scim_claims(&read, expected, ScimAccess::Write),
            Err(ScimError {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));

        let wrong_audience = token_claims("https://api.example", "scim.read");
        assert!(matches!(
            validate_scim_claims(&wrong_audience, expected, ScimAccess::Read),
            Err(ScimError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));
        let prefixed_scope = token_claims(expected, "scim.reader");
        assert!(validate_scim_claims(&prefixed_scope, expected, ScimAccess::Read).is_err());
    }

    #[test]
    fn scim_claims_reject_client_credential_subjects() {
        let expected = "https://sso.example/scim/v2";
        let mut claims = token_claims(expected, "scim.read");
        claims.sub = claims.client_id.clone();
        assert!(matches!(
            validate_scim_claims(&claims, expected, ScimAccess::Read),
            Err(ScimError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));

        claims.sub = "service-account:scim-client".to_string();
        assert!(validate_scim_claims(&claims, expected, ScimAccess::Read).is_err());
    }

    #[test]
    fn scim_claims_reject_login_code_tokens() {
        let expected = "https://sso.example/scim/v2";
        for level in [
            "account_recovery",
            "admin_universal",
            "trial_enrollment",
            "future_level",
        ] {
            let mut claims = token_claims(expected, "scim.read scim.write");
            claims.gpt_sso_login_code_level = Some(level.to_string());
            assert!(matches!(
                validate_scim_claims(&claims, expected, ScimAccess::Read),
                Err(ScimError {
                    status: StatusCode::UNAUTHORIZED,
                    ..
                })
            ));
        }
    }

    #[test]
    fn scim_internal_errors_are_sanitized() {
        let error = ScimError::from(AppError::Database("private SQL detail".to_string()));
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.detail, "internal server error");
        assert!(!error.detail.contains("SQL"));
    }

    #[test]
    fn scim_scope_errors_include_rfc6750_challenge() {
        let response = ScimError::insufficient_scope(SCIM_WRITE_SCOPE).into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"scim\", error=\"insufficient_scope\", scope=\"scim.write\"")
        );
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_and_requires_one_credential() {
        assert_eq!(bearer_token("bearer opaque-token"), Some("opaque-token"));
        assert_eq!(bearer_token("BEARER opaque-token"), Some("opaque-token"));
        assert_eq!(bearer_token("Basic opaque-token"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer first second"), None);
    }

    #[cfg(feature = "sqlite")]
    async fn http_test_state() -> (AppState, std::path::PathBuf) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-scim-http-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        (AppState { settings, db, jwt }, path)
    }

    #[cfg(feature = "sqlite")]
    async fn scim_http_request(
        app: &mut axum::Router,
        method: axum::http::Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::ACCEPT, "application/scim+json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = if let Some(body) = body {
            builder
                .header(header::CONTENT_TYPE, "application/scim+json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        app.oneshot(request).await.unwrap()
    }

    #[cfg(feature = "sqlite")]
    async fn response_json(response: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[cfg(feature = "sqlite")]
    async fn insert_scim_service_client(
        state: &AppState,
        organization_id: &str,
        client_id: &str,
        secret: &str,
    ) -> (crate::db::ClientRecord, crate::db::NewClient) {
        let input = crate::db::NewClient {
            client_id: client_id.to_string(),
            client_secret_hash: Some(util::hash_password(secret).unwrap()),
            client_name: client_id.to_string(),
            logo_uri: String::new(),
            organization_id: Some(organization_id.to_string()),
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            scopes: vec![SCIM_READ_SCOPE.to_string(), SCIM_WRITE_SCOPE.to_string()],
            audience: String::new(),
            grant_types: vec!["client_credentials".to_string()],
            response_types: Vec::new(),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            require_pkce: false,
            require_mfa: false,
            require_pushed_authorization_requests: false,
            require_s256_pkce: false,
            require_confidential_client: false,
            require_dpop: false,
            require_account_selection: false,
            trust_email_verified: false,
            authorization_details_types: Vec::new(),
            subject_type: crate::subject::SUBJECT_TYPE_PUBLIC.to_string(),
            sector_identifier_uri: String::new(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: false,
            service_account_enabled: true,
            service_account_permissions: vec![
                crate::access::Permission::UsersRead.as_str().to_string(),
                crate::access::Permission::UsersManage.as_str().to_string(),
            ],
            is_active: true,
        };
        let client = state.db.insert_client(input.clone()).await.unwrap();
        (client, input)
    }

    #[cfg(feature = "sqlite")]
    async fn issue_service_account_token(
        app: &axum::Router,
        client_id: &str,
        secret: &str,
        scope: &str,
        resource: Option<&str>,
    ) -> String {
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", secret),
            ("scope", scope),
        ];
        if let Some(resource) = resource {
            form.push(("resource", resource));
        }
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/oauth2/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(serde_urlencoded::to_string(form).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        if response.status() != StatusCode::OK {
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            panic!(
                "OAuth token endpoint returned {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        response_json(response).await["access_token"]
            .as_str()
            .expect("OAuth token response must contain access_token")
            .to_string()
    }

    #[cfg(feature = "sqlite")]
    fn http_test_organization(slug: &str) -> crate::db::NewOrganization {
        crate::db::NewOrganization {
            slug: slug.to_string(),
            name: slug.to_string(),
            kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn http_test_application(organization_id: &str, slug: &str) -> crate::db::NewApplication {
        crate::db::NewApplication {
            organization_id: organization_id.to_string(),
            slug: slug.to_string(),
            name: slug.to_string(),
            description: None,
            access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    async fn add_scim_module(state: &AppState, application_id: &str) {
        state
            .db
            .upsert_application_module(
                application_id,
                "directory_sync",
                &serde_json::json!({
                    "enabled": true,
                    "scim_enabled": true,
                    "sync_groups": true,
                    "scim_audience": "https://signet.example/scim/v2"
                })
                .to_string(),
                true,
            )
            .await
            .unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn scim_http_enforces_application_token_scope_and_resource_boundaries() {
        let (state, path) = http_test_state().await;
        let organization = state
            .db
            .insert_organization(http_test_organization("scim-http-org"))
            .await
            .unwrap();
        let application = state
            .db
            .insert_application(http_test_application(&organization.id, "scim-http-app"))
            .await
            .unwrap();
        let other_application = state
            .db
            .insert_application(http_test_application(&organization.id, "scim-http-other"))
            .await
            .unwrap();
        add_scim_module(&state, &application.id).await;
        add_scim_module(&state, &other_application.id).await;

        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "scim-http@example.com".to_string(),
                username: "scim-http".to_string(),
                display_name: Some("SCIM HTTP".to_string()),
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        state
            .db
            .upsert_organization_member(
                &organization.id,
                &user.id,
                crate::organizations::ROLE_MEMBER,
            )
            .await
            .unwrap();

        let raw_token = "scim_v1_http_test_token";
        state
            .db
            .insert_application_scim_token(crate::db::NewApplicationScimToken {
                id: "scim-http-token".to_string(),
                application_id: application.id.clone(),
                token_prefix: raw_token.chars().take(16).collect(),
                token_hash: util::token_hash(raw_token),
                scopes: vec![SCIM_READ_SCOPE.to_string(), SCIM_WRITE_SCOPE.to_string()],
                expires_at: None,
            })
            .await
            .unwrap();
        let read_only_token = "scim_v1_http_read_only";
        state
            .db
            .insert_application_scim_token(crate::db::NewApplicationScimToken {
                id: "scim-http-read-only".to_string(),
                application_id: application.id.clone(),
                token_prefix: read_only_token.chars().take(16).collect(),
                token_hash: util::token_hash(read_only_token),
                scopes: vec![SCIM_READ_SCOPE.to_string()],
                expires_at: None,
            })
            .await
            .unwrap();

        let other_group = state
            .db
            .insert_application_scim_group(
                &other_application.id,
                crate::db::NewGroup {
                    name: "Other application group".to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        let mut app = routes().with_state(state.clone());
        let response = scim_http_request(
            &mut app,
            axum::http::Method::GET,
            "/scim/v2/Users?startIndex=1&count=1",
            Some(raw_token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/scim+json")
        );
        let users = response_json(response).await;
        assert_eq!(users["totalResults"], 1);
        assert_eq!(users["Resources"][0]["id"], user.id.clone());

        let group_response = scim_http_request(
            &mut app,
            axum::http::Method::GET,
            "/scim/v2/Groups",
            Some(raw_token),
            None,
        )
        .await;
        assert_eq!(group_response.status(), StatusCode::OK);
        let groups = response_json(group_response).await;
        assert_eq!(groups["totalResults"], 0);
        assert_eq!(other_group.name, "Other application group");

        let response = scim_http_request(
            &mut app,
            axum::http::Method::POST,
            "/scim/v2/Users",
            Some(read_only_token),
            Some(serde_json::json!({
                "userName": "read-only-write",
                "emails": [{"value": "read-only-write@example.com", "primary": true}]
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"scim\", error=\"insufficient_scope\", scope=\"scim.write\"")
        );

        let patch = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "path": "active", "value": false}]
        });
        for _ in 0..2 {
            let response = scim_http_request(
                &mut app,
                axum::http::Method::PATCH,
                &format!("/scim/v2/Users/{}", user.id),
                Some(raw_token),
                Some(patch.clone()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        assert_eq!(
            state
                .db
                .find_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .is_active,
            0
        );

        let expired = "scim_v1_expired_http_token";
        state
            .db
            .insert_application_scim_token(crate::db::NewApplicationScimToken {
                id: "scim-http-expired".to_string(),
                application_id: application.id.clone(),
                token_prefix: expired.chars().take(16).collect(),
                token_hash: util::token_hash(expired),
                scopes: vec![SCIM_READ_SCOPE.to_string()],
                expires_at: Some(util::now_ts() - 1),
            })
            .await
            .unwrap();
        let response = scim_http_request(
            &mut app,
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(expired),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        state
            .db
            .revoke_application_scim_token(&application.id, "scim-http-token")
            .await
            .unwrap();
        let response = scim_http_request(
            &mut app,
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(raw_token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn scim_http_enforces_service_account_jwt_binding_and_lifecycle() {
        let (state, path) = http_test_state().await;
        let organization = state
            .db
            .insert_organization(http_test_organization("scim-jwt-org"))
            .await
            .unwrap();
        let (client, client_input) =
            insert_scim_service_client(&state, &organization.id, "scim-jwt-client", "jwt-secret")
                .await;
        let application = state
            .db
            .find_application_for_client(&client.id)
            .await
            .unwrap()
            .expect("OAuth client must have an application aggregate");
        add_scim_module(&state, &application.id).await;

        // Use the real OAuth client-credentials endpoint. The application
        // aggregate created for the client is the resource boundary used by
        // the SCIM verifier below.
        let app = crate::oidc::routes()
            .merge(routes())
            .with_state(state.clone());
        let audience = "https://signet.example/scim/v2";
        let full_token = issue_service_account_token(
            &app,
            &client.client_id,
            "jwt-secret",
            "scim.read scim.write",
            Some(audience),
        )
        .await;
        let claims = state
            .jwt
            .verify_access_token_with_issuers_and_audiences(
                &full_token,
                &[state.settings.oidc.issuer.as_str()],
                &[audience.to_string()],
            )
            .unwrap();
        assert_eq!(claims.sub, "service-account:scim-jwt-client");
        assert_eq!(claims.aud, audience);
        assert_eq!(claims.scope, "scim.read scim.write");

        let response = scim_http_request(
            &mut app.clone(),
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(&full_token),
            None,
        )
        .await;
        if response.status() != StatusCode::OK {
            let status = response.status();
            let body = response_json(response).await;
            panic!("SCIM service-account request returned {status}: {body}");
        }

        let read_token = issue_service_account_token(
            &app,
            &client.client_id,
            "jwt-secret",
            SCIM_READ_SCOPE,
            Some(audience),
        )
        .await;
        let response = scim_http_request(
            &mut app.clone(),
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(&read_token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = scim_http_request(
            &mut app.clone(),
            axum::http::Method::POST,
            "/scim/v2/Users",
            Some(&read_token),
            Some(serde_json::json!({
                "userName": "scim-read-only",
                "emails": [{"value": "scim-read-only@example.com", "primary": true}]
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"scim\", error=\"insufficient_scope\", scope=\"scim.write\"")
        );

        let wrong_audience = issue_service_account_token(
            &app,
            &client.client_id,
            "jwt-secret",
            SCIM_READ_SCOPE,
            Some("https://another.example/scim/v2"),
        )
        .await;
        let response = scim_http_request(
            &mut app.clone(),
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(&wrong_audience),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // An OAuth-issued JWT with an already expired exp is rejected at the
        // resource boundary even though its signature and client are valid.
        let mut expired_settings = state.settings.clone();
        expired_settings.oidc.access_token_ttl_seconds = -1;
        let expired_state = AppState {
            settings: expired_settings,
            db: state.db.clone(),
            jwt: state.jwt.clone(),
        };
        let expired_app = crate::oidc::routes()
            .merge(routes())
            .with_state(expired_state);
        let expired_token = issue_service_account_token(
            &expired_app,
            &client.client_id,
            "jwt-secret",
            SCIM_READ_SCOPE,
            Some(audience),
        )
        .await;
        let response = scim_http_request(
            &mut app.clone(),
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(&expired_token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Existing tokens are invalidated immediately when the website is
        // disabled, even before their short JWT TTL elapses.
        state
            .db
            .update_application(
                &application.id,
                crate::db::NewApplication {
                    organization_id: application.organization_id.clone(),
                    slug: application.slug.clone(),
                    name: application.name.clone(),
                    description: application.description.clone(),
                    access_mode: application.access_mode.clone(),
                    registration_mode: application.registration_mode.clone(),
                    account_selection_mode: application.account_selection_mode.clone(),
                    unique_identity_factors: application.unique_identity_factors().unwrap(),
                    is_active: false,
                },
            )
            .await
            .unwrap();
        let response = scim_http_request(
            &mut app.clone(),
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(&full_token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        state
            .db
            .update_application(
                &application.id,
                crate::db::NewApplication {
                    organization_id: application.organization_id.clone(),
                    slug: application.slug.clone(),
                    name: application.name.clone(),
                    description: application.description.clone(),
                    access_mode: application.access_mode.clone(),
                    registration_mode: application.registration_mode.clone(),
                    account_selection_mode: application.account_selection_mode.clone(),
                    unique_identity_factors: application.unique_identity_factors().unwrap(),
                    is_active: true,
                },
            )
            .await
            .unwrap();

        // The enterprise is an equally strict boundary for an application
        // service account. Restore it before testing client revocation.
        state
            .db
            .update_organization(
                &organization.id,
                crate::db::NewOrganization {
                    slug: organization.slug.clone(),
                    name: organization.name.clone(),
                    kind: organization.kind.clone(),
                    description: organization.description.clone(),
                    allowed_email_domains: util::from_json(&organization.allowed_email_domains)
                        .unwrap(),
                    is_active: false,
                },
            )
            .await
            .unwrap();
        let response = scim_http_request(
            &mut app.clone(),
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(&full_token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        state
            .db
            .update_organization(
                &organization.id,
                crate::db::NewOrganization {
                    slug: organization.slug.clone(),
                    name: organization.name.clone(),
                    kind: organization.kind.clone(),
                    description: organization.description.clone(),
                    allowed_email_domains: util::from_json(&organization.allowed_email_domains)
                        .unwrap(),
                    is_active: true,
                },
            )
            .await
            .unwrap();

        let mut revoked_client = client_input;
        revoked_client.service_account_enabled = false;
        state
            .db
            .update_client(&client.id, revoked_client)
            .await
            .unwrap();
        let response = scim_http_request(
            &mut app.clone(),
            axum::http::Method::GET,
            "/scim/v2/Users",
            Some(&full_token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        drop(app);
        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn scim_http_returns_rfc6750_errors_for_missing_and_insufficient_credentials() {
        let (state, path) = http_test_state().await;
        let mut app = routes().with_state(state);
        let response = scim_http_request(
            &mut app,
            axum::http::Method::GET,
            "/scim/v2/Users",
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"scim\", error=\"invalid_token\"")
        );

        drop(app);
        let _ = std::fs::remove_file(path);
    }
}
