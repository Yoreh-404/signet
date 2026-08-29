use crate::util;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct UserRecord {
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
    #[diesel(sql_type = Text)]
    pub password_hash: String,
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

impl UserRecord {
    pub fn scim_concurrency_version(&self) -> String {
        util::sha256_base64url(&serde_json::to_string(self).unwrap_or_default())
    }

    pub fn public(self) -> PublicUser {
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

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct UserOptionRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub email: String,
    #[diesel(sql_type = Text)]
    pub username: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct UserAssignmentStateRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub archived_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub id: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub email_verified_at: Option<i64>,
    pub phone_verified_at: Option<i64>,
    pub is_admin: bool,
    pub is_active: bool,
    pub archived_at: Option<i64>,
    pub registration_source: String,
    pub last_login_at: Option<i64>,
    pub last_login_ip: Option<String>,
    pub last_oidc_client_id: Option<String>,
    pub last_login_method: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserRegistrationSource {
    Local,
    AuthorizationCode,
}

impl UserRegistrationSource {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::AuthorizationCode => "authorization_code",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserListScope {
    Live,
    Active,
    Disabled,
    Archived,
    AuthorizationCode,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserListLinkedIdentityFilter {
    #[default]
    All,
    Linked,
    Unlinked,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UserListRoleFilter {
    #[default]
    Any,
    Admin,
    User,
    Named(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserListLoginRegion {
    #[default]
    All,
    Domestic,
    Overseas,
}

#[derive(Debug, Clone, Default)]
pub struct UserListFilters {
    pub organization_id: Option<String>,
    pub linked_identity: UserListLinkedIdentityFilter,
    pub search: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub role: UserListRoleFilter,
    pub created_from: Option<i64>,
    pub created_to: Option<i64>,
    pub last_login_from: Option<i64>,
    pub last_login_to: Option<i64>,
    pub login_region: UserListLoginRegion,
}

#[derive(Debug, Clone)]
pub struct UserListPage {
    pub total: i64,
    pub offset: usize,
    pub limit: usize,
    pub users: Vec<UserRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDirectoryCursor {
    pub archived: bool,
    pub archived_at: Option<i64>,
    pub is_active: i32,
    pub created_at: i64,
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct UserDirectoryCursorPage {
    pub limit: usize,
    pub users: Vec<UserRecord>,
    pub next_cursor: Option<UserDirectoryCursor>,
}

#[derive(Debug, Clone)]
pub enum UserListFilter {
    UserName(String),
    Email(String),
    Id(String),
    Active(bool),
}

#[derive(Debug, Clone)]
pub enum GroupListFilter {
    Id(String),
    DisplayName(String),
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub password_hash: String,
    pub email_verified_at: Option<i64>,
    pub phone_verified_at: Option<i64>,
    pub is_admin: bool,
    pub is_active: bool,
    pub archived_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewBulkProvisionedUser {
    pub user: NewUser,
    pub organization_id: Option<String>,
    pub organization_role: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserUpdate<'a> {
    pub id: &'a str,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub is_admin: bool,
    pub is_active: bool,
}
