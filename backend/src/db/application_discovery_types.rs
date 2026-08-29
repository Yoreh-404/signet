use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationDiscoveryRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub management_mode: String,
    #[diesel(sql_type = Text)]
    pub website_url: String,
    #[diesel(sql_type = Text)]
    pub fetch_secret_ciphertext: String,
    #[diesel(sql_type = Text)]
    pub signing_public_jwks: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_verified_revision: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_verified_version: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_verified_digest: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_verified_expires_at: Option<i64>,
    #[diesel(sql_type = Text)]
    pub sync_status: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_fetched_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_success_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_error: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub snapshot_json: Option<String>,
    #[diesel(sql_type = Integer)]
    pub operator_disabled: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    pub lease_owner: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub lease_expires_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub lease_generation: i64,
}

/// Joined read model used by the discovery reconciler.  Discovery records are
/// always consumed together with their application, so loading the two rows
/// one application at a time creates an avoidable 1+2D query pattern.
#[derive(Debug, diesel::QueryableByName)]
pub(crate) struct ApplicationDiscoveryJoinRecord {
    #[diesel(sql_type = Text)]
    pub(crate) id: String,
    #[diesel(sql_type = Text)]
    pub(crate) organization_id: String,
    #[diesel(sql_type = Text)]
    pub(crate) slug: String,
    #[diesel(sql_type = Text)]
    pub(crate) name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub(crate) description: Option<String>,
    #[diesel(sql_type = Text)]
    pub(crate) access_mode: String,
    #[diesel(sql_type = Text)]
    pub(crate) registration_mode: String,
    #[diesel(sql_type = Text)]
    pub(crate) account_selection_mode: String,
    #[diesel(sql_type = Text)]
    pub(crate) unique_identity_factors: String,
    #[diesel(sql_type = Integer)]
    pub(crate) is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub(crate) created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub(crate) updated_at: i64,
    #[diesel(sql_type = Text)]
    pub(crate) discovery_management_mode: String,
    #[diesel(sql_type = Text)]
    pub(crate) discovery_website_url: String,
    #[diesel(sql_type = Text)]
    pub(crate) fetch_secret_ciphertext: String,
    #[diesel(sql_type = Text)]
    pub(crate) signing_public_jwks: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub(crate) last_verified_revision: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub(crate) last_verified_version: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub(crate) last_verified_digest: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub(crate) last_verified_expires_at: Option<i64>,
    #[diesel(sql_type = Text)]
    pub(crate) discovery_sync_status: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub(crate) last_fetched_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub(crate) last_success_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub(crate) discovery_last_error: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub(crate) snapshot_json: Option<String>,
    #[diesel(sql_type = Integer)]
    pub(crate) operator_disabled: i32,
    #[diesel(sql_type = BigInt)]
    pub(crate) discovery_created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub(crate) discovery_updated_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    pub(crate) discovery_lease_owner: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub(crate) discovery_lease_expires_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub(crate) discovery_lease_generation: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationDiscovery {
    pub application_id: String,
    pub management_mode: String,
    pub website_url: String,
    pub fetch_secret_ciphertext: String,
    pub signing_public_jwks: String,
    pub last_verified_revision: Option<i64>,
    pub last_verified_version: Option<String>,
    pub last_verified_digest: Option<String>,
    pub last_verified_expires_at: Option<i64>,
    pub sync_status: String,
    pub last_fetched_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
    pub snapshot_json: Option<String>,
    pub operator_disabled: bool,
}

/// Durable cross-process lease returned to the discovery reconciler.  The
/// generation is incremented on every reclaim and must accompany every
/// renew/release/commit call; the owner token alone is intentionally not
/// treated as a reusable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationDiscoveryLease {
    pub application_id: String,
    pub owner_token: String,
    pub lease_expires_at: i64,
    pub lease_generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationDiscoveryIdempotencyClaim {
    Claimed { claim_token: String },
    Completed { application_id: String },
    InProgress,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct ApplicationDiscoveryIdempotencyRecord {
    #[diesel(sql_type = Text)]
    pub(crate) request_hash: String,
    #[diesel(sql_type = Text)]
    pub(crate) origin: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub(crate) application_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub(crate) status: String,
    #[diesel(sql_type = BigInt)]
    pub(crate) updated_at: i64,
}
