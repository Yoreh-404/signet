use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub organization_id: String,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub access_mode: String,
    #[diesel(sql_type = Text)]
    pub registration_mode: String,
    #[diesel(sql_type = Text)]
    pub account_selection_mode: String,
    #[diesel(sql_type = Text)]
    pub unique_identity_factors: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationAuthDomainRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub assurance_policy: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationClientBindingRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub client_db_id: String,
    #[diesel(sql_type = Text)]
    pub protocol: String,
    #[diesel(sql_type = Text)]
    pub authorization_profile_id: String,
    #[diesel(sql_type = Text)]
    pub auth_domain_id: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplication {
    pub organization_id: String,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub access_mode: String,
    pub registration_mode: String,
    pub account_selection_mode: String,
    pub unique_identity_factors: Vec<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct NewApplicationMember {
    pub user_id: String,
    pub role: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationIdentityBindingRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub factor_type: String,
    #[diesel(sql_type = Text)]
    pub factor_digest: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationMemberRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub role: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationMemberWithUserRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub role: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
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
}
