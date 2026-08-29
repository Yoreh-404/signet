use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationJwtCodeRecord {
    #[diesel(sql_type = Text)]
    pub code_hash: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub redirect_uri: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub nonce: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub code_challenge: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub code_challenge_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationJwtCode {
    pub code_hash: String,
    pub application_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationSamlInteractionRecord {
    #[diesel(sql_type = Text)]
    pub handle_hash: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub request_id: String,
    #[diesel(sql_type = Text)]
    pub sp_entity_id: String,
    #[diesel(sql_type = Text)]
    pub acs_url: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub relay_state: Option<String>,
    #[diesel(sql_type = Text)]
    pub response_binding: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationSamlInteraction {
    pub handle_hash: String,
    pub application_id: String,
    pub request_id: String,
    pub sp_entity_id: String,
    pub acs_url: String,
    pub relay_state: Option<String>,
    pub response_binding: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationSamlSessionRecord {
    #[diesel(sql_type = Text)]
    pub session_index_hash: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub signet_session_id: String,
    #[diesel(sql_type = Text)]
    pub name_id_hash: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationSamlSession {
    pub session_index_hash: String,
    pub application_id: String,
    pub user_id: String,
    pub signet_session_id: String,
    pub name_id_hash: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationCasTicketRecord {
    #[diesel(sql_type = Text)]
    pub ticket_hash: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub ticket_type: String,
    #[diesel(sql_type = Text)]
    pub service: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub parent_ticket_hash: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub pgt_iou: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationCasTicket {
    pub ticket_hash: String,
    pub application_id: String,
    pub ticket_type: String,
    pub service: String,
    pub user_id: String,
    pub parent_ticket_hash: Option<String>,
    pub pgt_iou: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationScimTokenRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub token_prefix: String,
    #[diesel(sql_type = Text)]
    pub token_hash: String,
    #[diesel(sql_type = Text)]
    pub scopes: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_used_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationScimToken {
    pub id: String,
    pub application_id: String,
    pub token_prefix: String,
    pub token_hash: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationJwtClientRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub client_type: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationJwtClientSecretRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub jwt_client_id: String,
    #[diesel(sql_type = Text)]
    pub secret_hash: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewApplicationJwtClient {
    pub client_id: String,
    pub client_type: String,
    pub is_active: bool,
}
