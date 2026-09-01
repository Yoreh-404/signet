use crate::db::{GroupRecord, PublicUser, RoleRecord};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(super) struct RoleAccessResponse {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) is_system: i32,
    pub(super) permissions: Vec<String>,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct GroupAccessResponse {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) roles: Vec<RoleRecord>,
    pub(super) members: Vec<PublicUser>,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct UserAccessResponse {
    pub(super) direct_roles: Vec<RoleRecord>,
    pub(super) groups: Vec<GroupRecord>,
    pub(super) effective_permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RoleInput {
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct GroupInput {
    pub(super) name: String,
    pub(super) description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RoleIdsInput {
    pub(super) role_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct UserIdsInput {
    pub(super) user_ids: Vec<String>,
}
