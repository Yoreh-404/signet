use crate::{
    AppState,
    access::{Authorizer, Permission},
    archived_accounts,
    audit::{self, AuditSink},
    db::{GroupRecord, NewGroup, NewUser, UserListScope, UserRecord},
    error::AppError,
    security_policy::{self, PasswordPolicy, PasswordSubject},
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
    user: UserRecord,
}

#[derive(Debug)]
struct ScimError {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
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
) -> Result<ScimGroup, ScimError> {
    let location = format!(
        "{}/scim/v2/Groups/{}",
        scim_base_url(state, headers),
        group.id
    );
    let members = state
        .db
        .list_group_members(&group.id)
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
            description: "Use a GPT SSO access token for an administrator or a user with SCIM permissions.",
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
    require_scim_permission(&state, &headers, Permission::UsersRead).await?;
    let filter = parse_user_filter(query.filter.as_deref())?;
    let users = state
        .db
        .list_users(filter.list_scope())
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
    require_scim_permission(&state, &headers, Permission::UsersRead).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or_else(|| ScimError::not_found("user not found"))?;
    Ok(scim_json(user.to_scim_user(&state, &headers)))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserInput>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(&state, &headers, Permission::UsersManage).await?;
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
    let user = state
        .db
        .insert_user(NewUser {
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
        })
        .await?;
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
    let principal = require_scim_permission(&state, &headers, Permission::UsersManage).await?;
    let current = editable_user(&state, &id).await?;
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
        .update_user(
            &id,
            security_policy::normalize_login_subject(&email),
            username,
            display_name,
            phone,
            current.is_admin == 1,
            current.is_active == 1,
        )
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
    let principal = require_scim_permission(&state, &headers, Permission::UsersManage).await?;
    let mut user = editable_user(&state, &id).await?;
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
    let principal = require_scim_permission(&state, &headers, Permission::UsersManage).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or_else(|| ScimError::not_found("user not found"))?;
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
    require_scim_permission(&state, &headers, Permission::SecurityManage).await?;
    let filter = parse_group_filter(query.filter.as_deref())?;
    let groups = state
        .db
        .list_groups()
        .await?
        .into_iter()
        .filter(|group| filter.matches(group))
        .collect::<Vec<_>>();
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100).min(200);
    let mut resources = Vec::new();
    for group in groups.iter().skip(start_index - 1).take(count) {
        resources.push(group_to_scim(&state, &headers, group).await?);
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
    require_scim_permission(&state, &headers, Permission::SecurityManage).await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    Ok(scim_json(group_to_scim(&state, &headers, &group).await?))
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScimGroupInput>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(&state, &headers, Permission::SecurityManage).await?;
    let group = state
        .db
        .insert_group(NewGroup {
            name: normalize_required(&payload.display_name, "displayName")?,
            description: None,
        })
        .await?;
    if let Some(members) = payload.members {
        let member_ids = member_ids(members);
        ensure_group_members_syncable(&state, &group.id, &member_ids).await?;
        state
            .db
            .replace_group_members(&group.id, member_ids)
            .await?;
    }
    let group = state
        .db
        .find_group_by_id(&group.id)
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
        scim_json(group_to_scim(&state, &headers, &group).await?),
    )
        .into_response())
}

async fn replace_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<ScimGroupInput>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(&state, &headers, Permission::SecurityManage).await?;
    let group = state
        .db
        .update_group(
            &id,
            NewGroup {
                name: normalize_required(&payload.display_name, "displayName")?,
                description: None,
            },
        )
        .await?;
    if let Some(members) = payload.members {
        let member_ids = member_ids(members);
        ensure_group_members_syncable(&state, &id, &member_ids).await?;
        state.db.replace_group_members(&id, member_ids).await?;
    }
    let group = state
        .db
        .find_group_by_id(&group.id)
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
    Ok(scim_json(group_to_scim(&state, &headers, &group).await?))
}

async fn patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<PatchRequest>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(&state, &headers, Permission::SecurityManage).await?;
    let mut group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    for operation in payload.operations {
        apply_group_patch_operation(&state, &id, &mut group, operation).await?;
        group = state
            .db
            .find_group_by_id(&id)
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
    Ok(scim_json(group_to_scim(&state, &headers, &group).await?))
}

async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let principal = require_scim_permission(&state, &headers, Permission::SecurityManage).await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or_else(|| ScimError::not_found("group not found"))?;
    state.db.delete_group(&id).await?;
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
            &format!("unsupported path: {path}"),
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
        .update_user(
            id,
            next_email,
            next_username,
            display_name.or_else(|| user.display_name.clone()),
            phone.unwrap_or_else(|| user.phone.clone()),
            user.is_admin == 1,
            user.is_active == 1,
        )
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
                    let mut ids = state
                        .db
                        .list_group_members(id)
                        .await?
                        .into_iter()
                        .map(|user| user.id)
                        .collect::<Vec<_>>();
                    ids.extend(member_ids(patch_members_value(&operation.value)?));
                    ids
                }
                "remove" => {
                    let remove = member_ids(patch_members_value(&operation.value)?);
                    state
                        .db
                        .list_group_members(id)
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
            ensure_group_members_syncable(state, id, &next).await?;
            state.db.replace_group_members(id, next).await?;
            Ok(())
        }
        Some(path) => Err(ScimError::bad_request(
            "invalidPath",
            &format!("unsupported path: {path}"),
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
                ensure_group_members_syncable(state, id, &member_ids).await?;
                state.db.replace_group_members(id, member_ids).await?;
            }
            Ok(())
        }
    }
}

async fn require_scim_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<ScimPrincipal, ScimError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ScimError::new(StatusCode::UNAUTHORIZED, None, "missing bearer token"))?;
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let claims = state
        .jwt
        .verify_access_token_with_issuers(token, &issuer_refs)
        .map_err(|_| ScimError::new(StatusCode::UNAUTHORIZED, None, "invalid bearer token"))?;
    if claims.cnf.is_some() {
        return Err(ScimError::new(
            StatusCode::UNAUTHORIZED,
            None,
            "DPoP-bound tokens require a DPoP-capable resource endpoint",
        ));
    }
    let user = state
        .db
        .find_user_by_id(&claims.sub)
        .await?
        .ok_or_else(|| ScimError::new(StatusCode::UNAUTHORIZED, None, "subject user not found"))?;
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(ScimError::new(
            StatusCode::UNAUTHORIZED,
            None,
            "subject user is not active",
        ));
    }
    state.db.require_permission(&user, permission).await?;
    Ok(ScimPrincipal { user })
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

async fn ensure_group_members_syncable(
    state: &AppState,
    group_id: &str,
    requested_user_ids: &[String],
) -> Result<(), ScimError> {
    let existing_members = state.db.list_group_members(group_id).await?;
    let requested_user_ids = archived_accounts::normalize_user_ids(requested_user_ids);
    let allowed_archived_user_ids = archived_accounts::ensure_archived_group_members_preserved(
        &existing_members,
        &requested_user_ids,
    )?;
    ensure_assignable_group_user_ids(state, &requested_user_ids, &allowed_archived_user_ids).await
}

async fn ensure_assignable_group_user_ids(
    state: &AppState,
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
    state
        .db
        .record_audit_event(audit::management_event(
            principal.user.id.clone(),
            action,
            "scim_user",
            target_id,
            metadata,
        ))
        .await?;
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
            &format!("unsupported filter field: {field}"),
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
            &format!("unsupported filter field: {field}"),
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
        .ok_or_else(|| ScimError::bad_request("invalidValue", &format!("{field} must be string")))
}

fn normalize_required(value: &str, field: &str) -> Result<String, ScimError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(ScimError::bad_request(
            "invalidValue",
            &format!("{field} is required"),
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
        }
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
        (self.status, scim_json(body)).into_response()
    }
}

impl From<AppError> for ScimError {
    fn from(value: AppError) -> Self {
        let status = value.status();
        let scim_type = match value {
            AppError::BadRequest(_) | AppError::Oidc(_) => Some("invalidValue"),
            AppError::Forbidden => Some("mutability"),
            _ => None,
        };
        Self::new(status, scim_type, value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
