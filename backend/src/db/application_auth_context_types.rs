use diesel::sql_types::{BigInt, Nullable, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationAuthContextRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub auth_domain_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub acr: String,
    #[diesel(sql_type = Text)]
    pub amr: String,
    #[diesel(sql_type = BigInt)]
    pub authenticated_at: i64,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationAuthContext {
    pub id: String,
    pub auth_domain_id: String,
    pub user_id: String,
    pub acr: String,
    pub amr: Vec<String>,
    pub authenticated_at: i64,
    pub expires_at: i64,
}
