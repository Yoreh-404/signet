use super::{TrialEnrollmentRecord, UserRecord};
use diesel::sql_types::{BigInt, Nullable, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct SessionRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub csrf_token: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub ip_address: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_agent: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub login_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct UserSessionSummary {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub ip_address: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_agent: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub login_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SessionMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub login_method: Option<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct BrowserContextRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub csrf_token: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct BrowserContextAccountRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub browser_context_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub session_id: String,
    #[diesel(sql_type = BigInt)]
    pub added_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_selected_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct BrowserContextAccountOption {
    pub account: BrowserContextAccountRecord,
    pub user: UserRecord,
    pub session: SessionRecord,
    pub trial_enrollment: Option<TrialEnrollmentRecord>,
    pub has_authorization_code_redemption: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct AccountLoginFlowRecord {
    #[diesel(sql_type = Text)]
    pub id_hash: String,
    #[diesel(sql_type = Text)]
    pub browser_context_id: String,
    #[diesel(sql_type = Text)]
    pub return_to: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub expected_user_id: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct MfaTotpMethodRecord {
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub secret: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_used_step: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub enabled_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct MfaTotpSetupRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub secret: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct MfaChallengeRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub purpose: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub return_to: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct MfaRecoveryCodeRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    #[serde(skip)]
    pub code_hash: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub used_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct PasskeyRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub credential_id: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Text)]
    pub passkey_json: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_used_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicPasskey {
    pub id: String,
    pub name: String,
    pub credential_id: String,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl PasskeyRecord {
    pub fn public(self) -> PublicPasskey {
        PublicPasskey {
            id: self.id,
            name: self.name,
            credential_id: self.credential_id,
            last_used_at: self.last_used_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct WebauthnChallengeRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub purpose: String,
    #[diesel(sql_type = Text)]
    pub state_json: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}
