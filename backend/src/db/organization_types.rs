use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct OrganizationRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Text)]
    pub kind: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub allowed_email_domains: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewOrganization {
    pub slug: String,
    pub name: String,
    pub kind: String,
    pub description: Option<String>,
    pub allowed_email_domains: Vec<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct OrganizationMemberInput {
    pub user_id: String,
    pub role: String,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct OrganizationMemberRecord {
    #[diesel(sql_type = Text)]
    pub organization_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub role: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct OrganizationMemberCountRecord {
    #[diesel(sql_type = Text)]
    pub organization_id: String,
    #[diesel(sql_type = BigInt)]
    pub member_count: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct OrganizationMemberWithUserRecord {
    #[diesel(sql_type = Text)]
    pub organization_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub role: String,
    #[diesel(sql_type = BigInt)]
    pub membership_created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub membership_updated_at: i64,
    #[diesel(sql_type = Text)]
    pub email: String,
    #[diesel(sql_type = Text)]
    pub username: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub display_name: Option<String>,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub archived_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct UserOrganizationRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Text)]
    pub kind: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Text)]
    pub role: String,
    #[diesel(sql_type = BigInt)]
    pub membership_created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub membership_updated_at: i64,
}
