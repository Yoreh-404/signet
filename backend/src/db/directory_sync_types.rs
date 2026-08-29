use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

pub struct DirectorySyncRunUpdate<'a> {
    pub run_id: &'a str,
    pub status: &'a str,
    pub total_seen: i64,
    pub created_count: i64,
    pub updated_count: i64,
    pub disabled_count: i64,
    pub error: Option<String>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct DirectorySyncRunRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub provider_id: String,
    #[diesel(sql_type = Text)]
    pub status: String,
    #[diesel(sql_type = BigInt)]
    pub total_seen: i64,
    #[diesel(sql_type = BigInt)]
    pub created_count: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_count: i64,
    #[diesel(sql_type = BigInt)]
    pub disabled_count: i64,
    #[diesel(sql_type = Nullable<Text>)]
    pub error: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub cursor: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub started_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub finished_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct DirectorySyncCheckpointRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub provider_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub cursor: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub last_success_at: i64,
    #[diesel(sql_type = Integer)]
    pub consecutive_failures: i32,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct DirectorySyncMembershipRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub provider_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Integer)]
    pub managed: i32,
    #[diesel(sql_type = BigInt)]
    pub last_seen_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct DirectorySyncGroupRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub provider_id: String,
    #[diesel(sql_type = Text)]
    pub external_id: String,
    #[diesel(sql_type = Text)]
    pub group_id: String,
    #[diesel(sql_type = BigInt)]
    pub last_seen_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}
