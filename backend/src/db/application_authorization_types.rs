use crate::util;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

use super::{
    ApplicationClientBindingRecord, ClientClaimMapperRecord, ClientRecord, OrganizationRecord,
};

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationModuleRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub module_key: String,
    #[diesel(sql_type = Text)]
    pub config_json: String,
    #[diesel(sql_type = Integer)]
    pub is_enabled: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationAuthorizationProfileRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub profile_key: String,
    #[diesel(sql_type = Text)]
    pub connection_kind: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub connection_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub source_mode: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub remote_version: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub remote_digest: Option<String>,
    #[diesel(sql_type = Text)]
    pub sync_status: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_synced_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_error: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationAuthorizationProfile {
    pub id: String,
    pub application_id: String,
    pub profile_key: String,
    pub connection_kind: String,
    pub connection_id: Option<String>,
    pub source_mode: String,
    pub remote_version: Option<String>,
    pub remote_digest: Option<String>,
    pub sync_status: String,
    pub last_synced_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationPermissionDefinitionRecord {
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = Text)]
    pub permission_key: String,
    #[diesel(sql_type = Text)]
    pub label: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub source: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationPermissionDefinition {
    pub profile_id: String,
    pub permission_key: String,
    pub label: String,
    pub description: Option<String>,
    pub source: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationProfileRoleRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = Text)]
    pub role_key: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub permissions: String,
    #[diesel(sql_type = Text)]
    pub source: String,
    #[diesel(sql_type = Integer)]
    pub is_default: i32,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct ApplicationGraphRecordSet {
    pub bindings: Vec<ApplicationClientBindingRecord>,
    pub clients: Vec<ClientRecord>,
    pub claim_mappers: Vec<ClientClaimMapperRecord>,
    pub organizations: Vec<OrganizationRecord>,
    pub modules: Vec<ApplicationModuleRecord>,
    pub profiles: Vec<ApplicationAuthorizationProfileRecord>,
    pub permission_definitions: Vec<ApplicationPermissionDefinitionRecord>,
    pub profile_roles: Vec<ApplicationProfileRoleRecord>,
}

impl ApplicationProfileRoleRecord {
    pub fn permission_keys(&self) -> crate::error::AppResult<Vec<String>> {
        util::from_json(&self.permissions)
    }
}

#[derive(Debug, Clone)]
pub struct NewApplicationProfileRole {
    pub id: Option<String>,
    pub profile_id: String,
    pub role_key: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub source: String,
    pub is_default: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationProfilePermissionOverrideRecord {
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub permission: String,
    #[diesel(sql_type = Text)]
    pub effect: String,
}
