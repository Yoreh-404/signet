use crate::error::AppResult;
use crate::util;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct LoginEventRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = BigInt)]
    pub login_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    pub ip_address: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_agent: Option<String>,
    #[diesel(sql_type = Text)]
    pub method: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub oidc_client_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub external_provider: Option<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct AuditEventRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub actor_user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub actor_client_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub action: String,
    #[diesel(sql_type = Text)]
    pub target_kind: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub target_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub outcome: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub ip_address: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_agent: Option<String>,
    #[diesel(sql_type = Text)]
    pub details: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
#[allow(dead_code)]
pub(crate) struct AuditWebhookOutboxRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub event_id: String,
    #[diesel(sql_type = Text)]
    pub state: String,
    #[diesel(sql_type = Integer)]
    pub attempts: i32,
    #[diesel(sql_type = BigInt)]
    pub next_attempt_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    pub lease_owner: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub lease_expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_error: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct AuditWebhookRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Text)]
    pub url: String,
    #[diesel(sql_type = Text)]
    pub secret: String,
    #[diesel(sql_type = Text)]
    pub actions: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Integer)]
    pub timeout_seconds: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_delivered_at: Option<i64>,
    #[diesel(sql_type = Nullable<Integer>)]
    pub last_status_code: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_error: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicAuditWebhook {
    pub id: String,
    pub name: String,
    pub url: String,
    pub has_secret: bool,
    pub actions: Vec<String>,
    pub is_active: bool,
    pub timeout_seconds: i32,
    pub last_delivered_at: Option<i64>,
    pub last_status_code: Option<i32>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl AuditWebhookRecord {
    pub fn public(self) -> AppResult<PublicAuditWebhook> {
        Ok(PublicAuditWebhook {
            id: self.id,
            name: self.name,
            url: self.url,
            has_secret: !self.secret.is_empty(),
            actions: util::from_json(&self.actions)?,
            is_active: self.is_active == 1,
            timeout_seconds: self.timeout_seconds,
            last_delivered_at: self.last_delivered_at,
            last_status_code: self.last_status_code,
            last_error: self.last_error,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    pub fn actions(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.actions)
    }
}

#[derive(Debug, Clone)]
pub struct NewAuditWebhook {
    pub name: String,
    pub url: String,
    pub secret: String,
    pub actions: Vec<String>,
    pub is_active: bool,
    pub timeout_seconds: i32,
}

#[derive(Debug, Clone)]
pub struct UpdateAuditWebhook {
    pub name: String,
    pub url: String,
    pub secret: Option<String>,
    pub actions: Vec<String>,
    pub is_active: bool,
    pub timeout_seconds: i32,
}
