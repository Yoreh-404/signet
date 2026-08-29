use super::PublicUser;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct RoleRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Integer)]
    pub is_system: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewRole {
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct GroupRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
    #[diesel(sql_type = BigInt)]
    pub version: i64,
}

#[derive(Debug, Clone)]
pub struct NewGroup {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct GroupMemberPublicRow {
    #[diesel(sql_type = Text)]
    pub group_id: String,
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub email: String,
    #[diesel(sql_type = Text)]
    pub username: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub display_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub phone: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub email_verified_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub phone_verified_at: Option<i64>,
    #[diesel(sql_type = Integer)]
    pub is_admin: i32,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub archived_at: Option<i64>,
    #[diesel(sql_type = Text)]
    pub registration_source: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_login_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_login_ip: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_oidc_client_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_login_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct GroupRoleJoinRow {
    #[diesel(sql_type = Text)]
    pub group_id: String,
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Integer)]
    pub is_system: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct RoleIdRow {
    #[diesel(sql_type = Text)]
    pub id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct RolePermissionJoinRow {
    #[diesel(sql_type = Text)]
    pub role_id: String,
    #[diesel(sql_type = Text)]
    pub permission: String,
}

impl GroupRoleJoinRow {
    pub(super) fn role(self) -> RoleRecord {
        RoleRecord {
            id: self.id,
            name: self.name,
            description: self.description,
            is_system: self.is_system,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl GroupMemberPublicRow {
    pub(super) fn public(self) -> PublicUser {
        PublicUser {
            id: self.id,
            email: self.email,
            username: self.username,
            display_name: self.display_name,
            phone: self.phone,
            email_verified_at: self.email_verified_at,
            phone_verified_at: self.phone_verified_at,
            is_admin: self.is_admin == 1,
            is_active: self.is_active == 1,
            archived_at: self.archived_at,
            registration_source: self.registration_source,
            last_login_at: self.last_login_at,
            last_login_ip: self.last_login_ip,
            last_oidc_client_id: self.last_oidc_client_id,
            last_login_method: self.last_login_method,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}
