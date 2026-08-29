use diesel::sql_types::{BigInt, Nullable, Text};
use serde::Serialize;

use super::UserRecord;

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct AuthorizationCodeRecord {
    #[diesel(sql_type = Text)]
    pub code: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub application_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorization_profile_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub auth_context_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub session_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub redirect_uri: String,
    #[diesel(sql_type = Text)]
    pub scope: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub resource: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorization_details: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub nonce: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub code_challenge: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub code_challenge_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub auth_time: i64,
    #[diesel(sql_type = Text)]
    pub acr: String,
    #[diesel(sql_type = Text)]
    pub amr: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub application_id: Option<String>,
    pub authorization_profile_id: Option<String>,
    pub auth_context_id: Option<String>,
    pub session_id: Option<String>,
    pub redirect_uri: String,
    pub scope: String,
    pub resource: Option<String>,
    pub authorization_details: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub auth_time: i64,
    pub acr: String,
    pub amr: Vec<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct OidcLoginGrantRecord {
    #[diesel(sql_type = Text)]
    pub credential_hash: String,
    #[diesel(sql_type = Text)]
    pub invitation_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub interaction_request_hash: String,
    #[diesel(sql_type = BigInt)]
    pub auth_time: i64,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct OidcLoginGrantRedemption {
    pub invitation_id: String,
    pub user: UserRecord,
    pub grant: OidcLoginGrantRecord,
}

pub(crate) struct AdminLoginCodeRedemptionInput<'a> {
    pub code: &'a str,
    pub user_id: &'a str,
    pub email: &'a str,
    pub trusted_client_id: &'a str,
    pub interaction_request_hash: &'a str,
    pub credential_hash: &'a str,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct RefreshTokenRecord {
    #[diesel(sql_type = Text)]
    pub token_hash: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub application_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorization_profile_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub auth_context_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub scope: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub resource: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorization_details: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub dpop_jkt: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenInput {
    pub token_hash: String,
    pub user_id: String,
    pub scope: String,
    pub resource: Option<String>,
    pub authorization_details: Option<String>,
    pub dpop_jkt: Option<String>,
    pub auth_context_id: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ClientGrantRecord {
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub granted_scopes: String,
    #[diesel(sql_type = BigInt)]
    pub granted_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ClientGrantWithClientRecord {
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub client_name: Option<String>,
    #[diesel(sql_type = Text)]
    pub granted_scopes: String,
    #[diesel(sql_type = BigInt)]
    pub granted_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
}
