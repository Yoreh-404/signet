#[cfg(test)]
use crate::organizations::ORGANIZATION_KIND_TENANT;
use crate::{
    access::Permission,
    config::{BootstrapApplication, BootstrapClient, DatabaseKind, DatabaseSettings, Settings},
    error::{AppError, AppResult},
    organizations::{
        ORGANIZATION_KIND_SYSTEM, OrganizationEmailPolicy, SIGNET_ORGANIZATION_ID,
        SIGNET_ORGANIZATION_SLUG,
    },
    util,
};
use axum::http::StatusCode;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl,
    connection::SimpleConnection,
    r2d2::{ConnectionManager, Pool},
    sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};
use tracing::warn;

const DIRECTORY_SYNC_LEASE_TTL_SECONDS: i64 = 60 * 60;
const APPLICATION_DISCOVERY_LEASE_TTL_SECONDS: i64 = 15 * 60;
const AUDIT_WEBHOOK_OUTBOX_LEASE_TTL_SECONDS: i64 = 60;
const SCIM_TOKEN_USAGE_TOUCH_INTERVAL_SECONDS: i64 = 60;

fn optimistic_concurrency_conflict(detail: impl Into<String>) -> AppError {
    AppError::OAuth {
        error: "resource_conflict".to_string(),
        description: detail.into(),
        status: StatusCode::CONFLICT,
    }
}

#[cfg(feature = "mysql")]
use diesel::MysqlConnection;
#[cfg(feature = "postgres")]
use diesel::PgConnection;
#[cfg(feature = "sqlite")]
use diesel::SqliteConnection;

#[cfg(feature = "sqlite")]
type SqlitePool = Pool<ConnectionManager<SqliteConnection>>;
#[cfg(feature = "postgres")]
type PgPool = Pool<ConnectionManager<PgConnection>>;
#[cfg(feature = "mysql")]
type MysqlPool = Pool<ConnectionManager<MysqlConnection>>;

#[cfg(feature = "sqlite")]
#[derive(Debug)]
struct SqliteConnectionCustomizer;

#[cfg(feature = "sqlite")]
impl diesel::r2d2::CustomizeConnection<SqliteConnection, diesel::r2d2::Error>
    for SqliteConnectionCustomizer
{
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        conn.batch_execute("PRAGMA busy_timeout = 5000;")
            .map_err(Into::into)
    }
}

#[derive(Clone)]
pub enum Db {
    #[cfg(feature = "sqlite")]
    Sqlite(SqlitePool),
    #[cfg(feature = "postgres")]
    Postgres(PgPool),
    #[cfg(feature = "mysql")]
    Mysql(MysqlPool),
}

macro_rules! with_conn {
    ($db:expr, |$conn:ident, $kind:ident| $body:block) => {{
        let db = $db.clone();
        blocking(move || match db {
            #[cfg(feature = "sqlite")]
            Db::Sqlite(pool) => {
                let mut $conn = pool
                    .get()
                    .map_err(|err| AppError::Database(err.to_string()))?;
                let $kind = DatabaseKind::Sqlite;
                $body
            }
            #[cfg(feature = "postgres")]
            Db::Postgres(pool) => {
                let mut $conn = pool
                    .get()
                    .map_err(|err| AppError::Database(err.to_string()))?;
                let $kind = DatabaseKind::Postgres;
                $body
            }
            #[cfg(feature = "mysql")]
            Db::Mysql(pool) => {
                let mut $conn = pool
                    .get()
                    .map_err(|err| AppError::Database(err.to_string()))?;
                let $kind = DatabaseKind::Mysql;
                $body
            }
        })
        .await
    }};
}

/// Inserts an audit record on the connection owned by the caller.
///
/// Audit writes that belong to a business mutation must use this macro from
/// inside the same `Connection::transaction` closure as the mutation. The
/// outbox row is committed with the audit row, so a webhook worker can never
/// observe an event that was rolled back. Post-commit call sites only provide
/// a best-effort wake-up hint; the durable outbox remains authoritative.
macro_rules! insert_audit_event_on_conn {
    ($conn:expr, $kind:expr, $event:expr $(,)?) => {{
        let conn = &mut *$conn;
        let event = $event;
        let record = AuditEventRecord {
            id: uuid::Uuid::new_v4().to_string(),
            actor_user_id: event.actor_user_id,
            actor_client_id: event.actor_client_id,
            action: event.action,
            target_kind: event.target_kind,
            target_id: event.target_id,
            outcome: event.outcome.as_str().to_string(),
            ip_address: event.ip_address,
            user_agent: event.user_agent,
            details: util::to_json(&event.details)?,
            created_at: util::now_ts(),
        };
        let sql = format!(
            "INSERT INTO audit_events (id, actor_user_id, actor_client_id, action, target_kind, target_id, outcome, ip_address, user_agent, details, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph($kind, 1), ph($kind, 2), ph($kind, 3), ph($kind, 4), ph($kind, 5),
            ph($kind, 6), ph($kind, 7), ph($kind, 8), ph($kind, 9), ph($kind, 10), ph($kind, 11)
        );
        sql_query(sql)
            .bind::<Text, _>(&record.id)
            .bind::<Nullable<Text>, _>(&record.actor_user_id)
            .bind::<Nullable<Text>, _>(&record.actor_client_id)
            .bind::<Text, _>(&record.action)
            .bind::<Text, _>(&record.target_kind)
            .bind::<Nullable<Text>, _>(&record.target_id)
            .bind::<Text, _>(&record.outcome)
            .bind::<Nullable<Text>, _>(&record.ip_address)
            .bind::<Nullable<Text>, _>(&record.user_agent)
            .bind::<Text, _>(&record.details)
            .bind::<BigInt, _>(record.created_at)
            .execute(conn)
            .map_err(AppError::from)?;
        let outbox_sql = format!(
            "INSERT INTO audit_webhook_outbox (id, event_id, state, attempts, next_attempt_at, lease_owner, lease_expires_at, last_error, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph($kind, 1), ph($kind, 2), ph($kind, 3), ph($kind, 4), ph($kind, 5),
            ph($kind, 6), ph($kind, 7), ph($kind, 8), ph($kind, 9), ph($kind, 10),
        );
        sql_query(outbox_sql)
            .bind::<Text, _>(&record.id)
            .bind::<Text, _>(&record.id)
            .bind::<Text, _>("pending")
            .bind::<Integer, _>(0)
            .bind::<BigInt, _>(record.created_at)
            .bind::<Nullable<Text>, _>(None::<String>)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .bind::<Nullable<Text>, _>(None::<String>)
            .bind::<BigInt, _>(record.created_at)
            .bind::<BigInt, _>(record.created_at)
            .execute(conn)
            .map_err(AppError::from)?;
        Ok::<AuditEventRecord, AppError>(record)
    }};
}

pub(crate) use auth_challenges::VerificationCodeVerifier;
pub use auth_challenges::{
    CaptchaChallengeRecord, LoginFailureSummary, NewVerificationCode, VerificationCodeClaim,
    VerificationCodeRecord,
};
use auth_challenges::{
    VerificationCodeDecision, consume_verification_code_sql, ensure_verification_resend_allowed,
    select_latest_verification_code_sql, select_verification_code_by_id_sql,
};
use sql::{bind_text_list, blocking, ph};
use user_cleanup::{USER_AUTH_STATE_TABLES, USER_PERMANENT_DEPENDENT_TABLES};

pub use billing::{
    ApplicationBillingSettingsRecord, NewApplicationBillingSettings, NewPaymentOrder,
    NewWalletOperation, PaymentOrderLease, PaymentOrderRecord, PaymentRefundRecord,
    WalletAccountRecord, WalletHoldRecord, WalletTransactionRecord,
};

pub use authorization::{
    ApplicationOrganizationRoleAssignmentRecord,
    ApplicationProfileOrganizationRoleAssignmentRecord, ApplicationProfileRoleAssignmentRecord,
    AuthorizationPolicySnapshot,
};
pub use authorization_transients::{
    DeviceAuthorizationRecord, DeviceAuthorizationStatus, DeviceAuthorizationTransition,
    NewDeviceAuthorization, NewPushedAuthorizationRequest, PushedAuthorizationRequestRecord,
};

pub use directory_sync::{
    DirectorySyncApplyContext, DirectorySyncApplyStats, DirectorySyncGroupPlan,
    DirectorySyncSnapshotPlan, DirectorySyncUserPlan,
};

pub use scim::{
    ScimApplicationContext, ScimApplicationTokenContext, ScimDiscoveryState,
    ScimServiceAccountContext, ScimUserMutationScope,
};

pub use mutation_receipts::MutationReceiptRecord;

pub use authorization_bindings::{
    AuthorizationBindingPermissionOverride, AuthorizationBindingPermissionOverrideSnapshot,
    AuthorizationBindingsSnapshot, AuthorizationBindingsUpdate, AuthorizationUserBindingSnapshot,
};
pub use user_lifecycle::UserLifecycleBatchAction;

macro_rules! ensure_user_identity_available {
    ($conn:expr, $kind:expr, $candidate:expr, $message:expr) => {{
        let candidate = &$candidate;
        let count = sql_query(count_user_identity_conflicts_sql($kind))
            .bind::<Text, _>(&candidate.email)
            .bind::<Text, _>(&candidate.username)
            .bind::<Nullable<Text>, _>(candidate.exclude_user_id.clone())
            .bind::<Nullable<Text>, _>(candidate.exclude_user_id.clone())
            .get_result::<CountRow>($conn)
            .map_err(AppError::from)?
            .count;
        if count > 0 {
            Err(AppError::BadRequest($message.to_string()))
        } else {
            Ok(())
        }
    }};
}

macro_rules! ensure_first_user_registration_still_first {
    ($conn:expr, $expected_first_user:expr) => {{
        if $expected_first_user {
            let count = sql_query(count_all_users_sql())
                .get_result::<CountRow>($conn)
                .map_err(AppError::from)?
                .count;
            ensure_first_user_registration_state($expected_first_user, count)
        } else {
            Ok(())
        }
    }};
}

/// Application identity bindings are leases over a user's currently verified
/// contacts, not historical account attributes.  A contact change releases
/// only that contact's leases; deactivation releases them all.
macro_rules! clear_user_application_identity_bindings_for_conn {
    ($conn:expr, $kind:expr, $user_id:expr) => {{
        let sql = format!(
            "DELETE FROM application_identity_bindings WHERE user_id = {}",
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>($user_id)
            .execute($conn)
            .map(|_| ())
            .map_err(AppError::from)
    }};
}

macro_rules! clear_user_application_identity_factor_bindings_for_conn {
    ($conn:expr, $kind:expr, $user_id:expr, $factor_type:expr) => {{
        let sql = format!(
            "DELETE FROM application_identity_bindings WHERE user_id = {} AND factor_type = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        sql_query(sql)
            .bind::<Text, _>($user_id)
            .bind::<Text, _>($factor_type)
            .execute($conn)
            .map(|_| ())
            .map_err(AppError::from)
    }};
}

macro_rules! clear_application_identity_bindings_for_user_for_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $user_id:expr) => {{
        let sql = format!(
            "DELETE FROM application_identity_bindings WHERE application_id = {} AND user_id = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        sql_query(sql)
            .bind::<Text, _>($application_id)
            .bind::<Text, _>($user_id)
            .execute($conn)
            .map(|_| ())
            .map_err(AppError::from)
    }};
}

macro_rules! latest_verification_code {
    ($conn:expr, $kind:expr, $claim:expr) => {{
        let claim = $claim;
        sql_query(crate::db::auth_challenges::select_latest_verification_code_sql($kind))
            .bind::<Text, _>(&claim.channel)
            .bind::<Text, _>(&claim.target)
            .bind::<Text, _>(&claim.purpose)
            .get_result::<VerificationCodeRecord>($conn)
            .optional()
            .map_err(AppError::from)?
    }};
}

macro_rules! increment_verification_attempts {
    ($conn:expr, $kind:expr, $id:expr) => {{
        sql_query(crate::db::auth_challenges::increment_verification_attempts_sql($kind))
            .bind::<Text, _>($id)
            .execute($conn)
            .map_err(AppError::from)?
    }};
}

macro_rules! mark_verification_code_consumed {
    ($conn:expr, $kind:expr, $now:expr, $id:expr) => {{
        sql_query(crate::db::auth_challenges::consume_verification_code_sql(
            $kind,
        ))
        .bind::<BigInt, _>($now)
        .bind::<Text, _>($id)
        .execute($conn)
        .map_err(AppError::from)?
    }};
}

macro_rules! clear_user_auth_state_for_conn {
    ($conn:expr, $kind:expr, $user_id:expr) => {{
        for table in ["session_credentials", "browser_context_accounts"] {
            let sql = format!(
                "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id = {})",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($user_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        for (table, column) in USER_AUTH_STATE_TABLES {
            let sql = format!("DELETE FROM {table} WHERE {column} = {}", ph($kind, 1));
            sql_query(sql)
                .bind::<Text, _>($user_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! revoke_trial_enrollment_auth_state_for_invitation {
    ($conn:expr, $kind:expr, $invitation_id:expr) => {{
        for table in ["session_credentials", "browser_context_accounts"] {
            let sql = format!(
                "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN (SELECT user_id FROM trial_enrollments WHERE invitation_id = {}))",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($invitation_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        for (table, column) in [
            ("authorization_codes", "user_id"),
            ("oidc_login_grants", "user_id"),
            ("refresh_tokens", "user_id"),
            ("device_authorizations", "authorized_user_id"),
        ] {
            let sql = format!(
                "DELETE FROM {table} WHERE {column} IN (SELECT user_id FROM trial_enrollments WHERE invitation_id = {})",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($invitation_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        let sql = format!(
            "DELETE FROM sessions WHERE user_id IN (SELECT user_id FROM trial_enrollments WHERE invitation_id = {})",
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>($invitation_id)
            .execute($conn)
            .map_err(AppError::from)?;
    }};
}

macro_rules! revoke_trial_enrollment_auth_state_for_organization {
    ($conn:expr, $kind:expr, $organization_id:expr) => {{
        for table in ["session_credentials", "browser_context_accounts"] {
            let sql = format!(
                "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN (SELECT user_id FROM trial_enrollments WHERE organization_id = {}))",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($organization_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        for (table, column) in [
            ("authorization_codes", "user_id"),
            ("oidc_login_grants", "user_id"),
            ("refresh_tokens", "user_id"),
            ("device_authorizations", "authorized_user_id"),
        ] {
            let sql = format!(
                "DELETE FROM {table} WHERE {column} IN (SELECT user_id FROM trial_enrollments WHERE organization_id = {})",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($organization_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        let sql = format!(
            "DELETE FROM sessions WHERE user_id IN (SELECT user_id FROM trial_enrollments WHERE organization_id = {})",
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>($organization_id)
            .execute($conn)
            .map_err(AppError::from)?;
    }};
}

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
    /// Returns an opaque digest of the complete row snapshot used by SCIM
    /// optimistic concurrency.  The password hash is included only as input
    /// to the digest; it is never returned to a caller.  Hashing the full row
    /// also catches changes to login/authentication state that do not change
    /// the SCIM-visible representation.
    pub fn scim_concurrency_version(&self) -> String {
        util::sha256_base64url(&serde_json::to_string(self).unwrap_or_default())
    }
}

/// Minimal projection used by administrative selectors.  Keep this separate
/// from `UserRecord`: selector reads must never hydrate password hashes,
/// login metadata, or other fields that are not needed to identify an account.
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

/// Minimal lifecycle projection used when validating bulk assignments.  It
/// intentionally excludes credentials and login metadata while retaining the
/// one state bit needed by archived-account invariants.
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

impl UserRecord {
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

/// How an account was first created.  The value is intentionally immutable:
/// redeeming a login-only authorization code must never change an existing
/// account into an authorization-code-created account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserRegistrationSource {
    Local,
    AuthorizationCode,
}

impl UserRegistrationSource {
    const fn as_str(self) -> &'static str {
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

/// SQL-backed filters for the administrative user directory.  All fields are
/// optional so the same predicate can be used for both COUNT and page reads.
/// The organization and linked-identity fields are deliberately represented
/// here instead of being applied to a loaded Rust vector.
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

/// Stable keyset position for the administrative user directory.  The cursor
/// is typed rather than interpolated into SQL; a transport may serialize it
/// as an opaque token, but the data layer always binds each component.
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

/// Exact-match filters used by bounded directory reads.  Keeping this small
/// value object in the data layer lets callers push filtering into SQL without
/// exposing SQL fragments or making the SCIM transport depend on a query
/// builder.
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

/// A new local account and, optionally, its first organization membership.
///
/// This is deliberately an insert-only shape.  Enterprise provisioning must
/// never turn a CSV upload into an implicit update of an existing identity.
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

#[derive(Debug, Clone)]
struct UserIdentityCandidate {
    email: String,
    username: String,
    exclude_user_id: Option<String>,
}

impl UserIdentityCandidate {
    fn insert(user: &NewUser) -> Self {
        Self {
            email: user.email.clone(),
            username: user.username.clone(),
            exclude_user_id: None,
        }
    }
    fn update(id: &str, email: String, username: String) -> Self {
        Self {
            email,
            username,
            exclude_user_id: Some(id.to_string()),
        }
    }
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ClientRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub client_secret_hash: Option<String>,
    #[diesel(sql_type = Text)]
    pub client_name: String,
    #[diesel(sql_type = Text)]
    pub logo_uri: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub redirect_uris: String,
    #[diesel(sql_type = Text)]
    pub post_logout_redirect_uris: String,
    #[diesel(sql_type = Text)]
    pub scopes: String,
    #[diesel(sql_type = Text)]
    pub audience: String,
    #[diesel(sql_type = Text)]
    pub grant_types: String,
    #[diesel(sql_type = Text)]
    pub response_types: String,
    #[diesel(sql_type = Text)]
    pub token_endpoint_auth_method: String,
    #[diesel(sql_type = Integer)]
    pub require_pkce: i32,
    #[diesel(sql_type = Integer)]
    pub require_mfa: i32,
    #[diesel(sql_type = Integer)]
    pub require_pushed_authorization_requests: i32,
    #[diesel(sql_type = Integer)]
    pub require_s256_pkce: i32,
    #[diesel(sql_type = Integer)]
    pub require_confidential_client: i32,
    #[diesel(sql_type = Integer)]
    pub require_dpop: i32,
    #[diesel(sql_type = Integer)]
    pub require_account_selection: i32,
    #[diesel(sql_type = Integer)]
    pub trust_email_verified: i32,
    #[diesel(sql_type = Text)]
    pub authorization_details_types: String,
    #[diesel(sql_type = Text)]
    pub subject_type: String,
    #[diesel(sql_type = Text)]
    pub sector_identifier_uri: String,
    #[diesel(sql_type = Text)]
    pub jwks_uri: String,
    #[diesel(sql_type = Text)]
    pub jwks: String,
    #[diesel(sql_type = Text)]
    pub backchannel_logout_uri: String,
    #[diesel(sql_type = Integer)]
    pub backchannel_logout_session_required: i32,
    #[diesel(sql_type = Text)]
    pub frontchannel_logout_uri: String,
    #[diesel(sql_type = Integer)]
    pub frontchannel_logout_session_required: i32,
    #[diesel(sql_type = Integer)]
    pub service_account_enabled: i32,
    #[diesel(sql_type = Text)]
    pub service_account_permissions: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ClientRegistrationRecord {
    #[diesel(sql_type = Text)]
    pub client_db_id: String,
    #[diesel(sql_type = Text)]
    pub registration_access_token_hash: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ClientClaimMapperRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub client_db_id: String,
    #[diesel(sql_type = Text)]
    pub claim_name: String,
    #[diesel(sql_type = Text)]
    pub source: String,
    #[diesel(sql_type = Text)]
    pub source_value: String,
    #[diesel(sql_type = Text)]
    pub value_type: String,
    #[diesel(sql_type = Integer)]
    pub include_in_id_token: i32,
    #[diesel(sql_type = Integer)]
    pub include_in_access_token: i32,
    #[diesel(sql_type = Integer)]
    pub include_in_userinfo: i32,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Integer)]
    pub sort_order: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct SigningKeyRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub kid: String,
    #[diesel(sql_type = Text)]
    pub private_key_pem: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub activated_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub retired_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewSigningKey {
    pub kid: String,
    pub private_key_pem: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicClient {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub logo_uri: String,
    pub organization_id: Option<String>,
    pub organization_slug: Option<String>,
    pub organization_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub audience: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub require_mfa: bool,
    pub require_pushed_authorization_requests: bool,
    pub require_s256_pkce: bool,
    pub require_confidential_client: bool,
    pub require_dpop: bool,
    pub require_account_selection: bool,
    pub trust_email_verified: bool,
    pub authorization_details_types: Vec<String>,
    pub subject_type: String,
    pub sector_identifier_uri: String,
    pub jwks_uri: String,
    pub jwks: String,
    pub backchannel_logout_uri: String,
    pub backchannel_logout_session_required: bool,
    pub frontchannel_logout_uri: String,
    pub frontchannel_logout_session_required: bool,
    pub service_account_enabled: bool,
    pub service_account_permissions: Vec<String>,
    pub is_active: bool,
    pub claim_mappers: Vec<PublicClientClaimMapper>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicClientClaimMapper {
    pub id: String,
    pub claim_name: String,
    pub source: String,
    pub source_value: String,
    pub value_type: String,
    pub include_in_id_token: bool,
    pub include_in_access_token: bool,
    pub include_in_userinfo: bool,
    pub is_active: bool,
    pub sort_order: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ClientRecord {
    pub fn public(self) -> AppResult<PublicClient> {
        Ok(PublicClient {
            id: self.id,
            client_id: self.client_id,
            client_name: self.client_name,
            logo_uri: self.logo_uri,
            organization_id: self.organization_id,
            organization_slug: None,
            organization_name: None,
            redirect_uris: util::from_json(&self.redirect_uris)?,
            post_logout_redirect_uris: util::from_json(&self.post_logout_redirect_uris)?,
            scopes: util::from_json(&self.scopes)?,
            audience: self.audience,
            grant_types: util::from_json(&self.grant_types)?,
            response_types: util::from_json(&self.response_types)?,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            require_pkce: self.require_pkce == 1,
            require_mfa: self.require_mfa == 1,
            require_pushed_authorization_requests: self.require_pushed_authorization_requests == 1,
            require_s256_pkce: self.require_s256_pkce == 1,
            require_confidential_client: self.require_confidential_client == 1,
            require_dpop: self.require_dpop == 1,
            require_account_selection: self.require_account_selection == 1,
            trust_email_verified: self.trust_email_verified == 1,
            authorization_details_types: util::from_json(&self.authorization_details_types)?,
            subject_type: self.subject_type,
            sector_identifier_uri: self.sector_identifier_uri,
            jwks_uri: self.jwks_uri,
            jwks: self.jwks,
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: self.backchannel_logout_session_required == 1,
            frontchannel_logout_uri: self.frontchannel_logout_uri,
            frontchannel_logout_session_required: self.frontchannel_logout_session_required == 1,
            service_account_enabled: self.service_account_enabled == 1,
            service_account_permissions: util::from_json(&self.service_account_permissions)?,
            is_active: self.is_active == 1,
            claim_mappers: Vec::new(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    pub fn redirect_uris(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.redirect_uris)
    }

    pub fn post_logout_redirect_uris(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.post_logout_redirect_uris)
    }

    pub fn scopes(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.scopes)
    }

    pub fn grant_types(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.grant_types)
    }

    pub fn response_types(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.response_types)
    }

    pub fn authorization_details_types(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.authorization_details_types)
    }
}

impl ClientClaimMapperRecord {
    pub fn public(self) -> PublicClientClaimMapper {
        PublicClientClaimMapper {
            id: self.id,
            claim_name: self.claim_name,
            source: self.source,
            source_value: self.source_value,
            value_type: self.value_type,
            include_in_id_token: self.include_in_id_token == 1,
            include_in_access_token: self.include_in_access_token == 1,
            include_in_userinfo: self.include_in_userinfo == 1,
            is_active: self.is_active == 1,
            sort_order: self.sort_order,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewClient {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub client_name: String,
    pub logo_uri: String,
    pub organization_id: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub audience: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub require_mfa: bool,
    pub require_pushed_authorization_requests: bool,
    pub require_s256_pkce: bool,
    pub require_confidential_client: bool,
    pub require_dpop: bool,
    pub require_account_selection: bool,
    pub trust_email_verified: bool,
    pub authorization_details_types: Vec<String>,
    pub subject_type: String,
    pub sector_identifier_uri: String,
    pub jwks_uri: String,
    pub jwks: String,
    pub backchannel_logout_uri: String,
    pub backchannel_logout_session_required: bool,
    pub frontchannel_logout_uri: String,
    pub frontchannel_logout_session_required: bool,
    pub service_account_enabled: bool,
    pub service_account_permissions: Vec<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct NewClientClaimMapper {
    pub claim_name: String,
    pub source: String,
    pub source_value: String,
    pub value_type: String,
    pub include_in_id_token: bool,
    pub include_in_access_token: bool,
    pub include_in_userinfo: bool,
    pub is_active: bool,
    pub sort_order: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct IapApplicationRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub application_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub external_host: String,
    #[diesel(sql_type = Text)]
    pub path_prefix: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub required_organization_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub required_organization_roles: String,
    #[diesel(sql_type = Text)]
    pub required_permissions: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIapApplication {
    pub id: String,
    pub application_id: Option<String>,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub external_host: String,
    pub path_prefix: String,
    pub required_organization_id: Option<String>,
    pub required_organization_roles: Vec<String>,
    pub required_permissions: Vec<String>,
    pub is_active: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl IapApplicationRecord {
    pub fn public(self) -> AppResult<PublicIapApplication> {
        Ok(PublicIapApplication {
            id: self.id,
            application_id: self.application_id,
            slug: self.slug,
            name: self.name,
            description: self.description,
            external_host: self.external_host,
            path_prefix: self.path_prefix,
            required_organization_id: self.required_organization_id,
            required_organization_roles: util::from_json(&self.required_organization_roles)?,
            required_permissions: util::from_json(&self.required_permissions)?,
            is_active: self.is_active == 1,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    pub fn required_organization_roles(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.required_organization_roles)
    }

    pub fn required_permissions(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.required_permissions)
    }
}

#[derive(Debug, Clone)]
pub struct NewIapApplication {
    pub application_id: String,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub external_host: String,
    pub path_prefix: String,
    pub required_organization_id: Option<String>,
    pub required_organization_roles: Vec<String>,
    pub required_permissions: Vec<String>,
    pub is_active: bool,
}

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

/// Set-based chooser read model. Browser account selection needs the account,
/// live session, trial provenance, and recovery-code capability together; a
/// caller should not resolve those relations once per remembered account.
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

#[derive(Debug, Clone, diesel::QueryableByName, Serialize, Deserialize)]
pub struct RegistrationSettingsRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Integer)]
    pub allow_password_registration: i32,
    #[diesel(sql_type = Integer)]
    pub require_email_verification: i32,
    #[diesel(sql_type = Integer)]
    pub require_phone_verification: i32,
    #[diesel(sql_type = Integer)]
    pub allow_external_oidc_registration: i32,
    #[diesel(sql_type = Integer)]
    pub require_invitation: i32,
    #[diesel(sql_type = Integer)]
    pub first_user_direct_admin: i32,
    #[diesel(sql_type = Integer)]
    pub default_user_active: i32,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicRegistrationSettings {
    pub allow_password_registration: bool,
    pub require_email_verification: bool,
    pub require_phone_verification: bool,
    pub allow_external_oidc_registration: bool,
    pub require_invitation: bool,
    pub first_user_direct_admin: bool,
    pub default_user_active: bool,
}

pub const FIRST_REGISTERED_USER_IS_ADMIN: bool = true;

pub fn registered_user_is_admin(first_user: bool) -> bool {
    first_user && FIRST_REGISTERED_USER_IS_ADMIN
}

impl RegistrationSettingsRecord {
    pub fn public(&self) -> PublicRegistrationSettings {
        PublicRegistrationSettings {
            allow_password_registration: self.allow_password_registration == 1,
            require_email_verification: self.require_email_verification == 1,
            require_phone_verification: self.require_phone_verification == 1,
            allow_external_oidc_registration: self.allow_external_oidc_registration == 1,
            require_invitation: self.require_invitation == 1,
            first_user_direct_admin: FIRST_REGISTERED_USER_IS_ADMIN,
            default_user_active: self.default_user_active == 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewRegistrationSettings {
    pub allow_password_registration: bool,
    pub require_email_verification: bool,
    pub require_phone_verification: bool,
    pub allow_external_oidc_registration: bool,
    pub require_invitation: bool,
    pub first_user_direct_admin: bool,
    pub default_user_active: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct SecurityPolicyRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Integer)]
    pub password_min_length: i32,
    #[diesel(sql_type = Integer)]
    pub password_require_uppercase: i32,
    #[diesel(sql_type = Integer)]
    pub password_require_lowercase: i32,
    #[diesel(sql_type = Integer)]
    pub password_require_digit: i32,
    #[diesel(sql_type = Integer)]
    pub password_require_symbol: i32,
    #[diesel(sql_type = Integer)]
    pub password_reject_user_info: i32,
    #[diesel(sql_type = Integer)]
    pub login_lockout_enabled: i32,
    #[diesel(sql_type = Integer)]
    pub max_failed_login_attempts: i32,
    #[diesel(sql_type = BigInt)]
    pub failure_window_seconds: i64,
    #[diesel(sql_type = BigInt)]
    pub lockout_seconds: i64,
    #[diesel(sql_type = Text)]
    pub trusted_ip_cidrs: String,
    #[diesel(sql_type = Integer)]
    pub require_mfa_outside_trusted_networks: i32,
    #[diesel(sql_type = Text)]
    pub allowed_ip_cidrs: String,
    #[diesel(sql_type = Text)]
    pub blocked_ip_cidrs: String,
    #[diesel(sql_type = Text)]
    pub allowed_email_domains: String,
    #[diesel(sql_type = Text)]
    pub blocked_email_domains: String,
    #[diesel(sql_type = Integer)]
    pub captcha_enabled: i32,
    #[diesel(sql_type = Integer)]
    pub captcha_after_failed_attempts: i32,
    #[diesel(sql_type = BigInt)]
    pub captcha_ttl_seconds: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewSecurityPolicy {
    pub password_min_length: i32,
    pub password_require_uppercase: bool,
    pub password_require_lowercase: bool,
    pub password_require_digit: bool,
    pub password_require_symbol: bool,
    pub password_reject_user_info: bool,
    pub login_lockout_enabled: bool,
    pub max_failed_login_attempts: i32,
    pub failure_window_seconds: i64,
    pub lockout_seconds: i64,
    pub trusted_ip_cidrs: Vec<String>,
    pub require_mfa_outside_trusted_networks: bool,
    pub allowed_ip_cidrs: Vec<String>,
    pub blocked_ip_cidrs: Vec<String>,
    pub allowed_email_domains: Vec<String>,
    pub blocked_email_domains: Vec<String>,
    pub captcha_enabled: bool,
    pub captcha_after_failed_attempts: i32,
    pub captcha_ttl_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicSecurityPolicy {
    pub id: String,
    pub password_min_length: i32,
    pub password_require_uppercase: i32,
    pub password_require_lowercase: i32,
    pub password_require_digit: i32,
    pub password_require_symbol: i32,
    pub password_reject_user_info: i32,
    pub login_lockout_enabled: i32,
    pub max_failed_login_attempts: i32,
    pub failure_window_seconds: i64,
    pub lockout_seconds: i64,
    pub trusted_ip_cidrs: Vec<String>,
    pub require_mfa_outside_trusted_networks: bool,
    pub allowed_ip_cidrs: Vec<String>,
    pub blocked_ip_cidrs: Vec<String>,
    pub allowed_email_domains: Vec<String>,
    pub blocked_email_domains: Vec<String>,
    pub captcha_enabled: bool,
    pub captcha_after_failed_attempts: i32,
    pub captcha_ttl_seconds: i64,
    pub updated_at: i64,
}

impl SecurityPolicyRecord {
    pub fn public(&self) -> AppResult<PublicSecurityPolicy> {
        Ok(PublicSecurityPolicy {
            id: self.id.clone(),
            password_min_length: self.password_min_length,
            password_require_uppercase: self.password_require_uppercase,
            password_require_lowercase: self.password_require_lowercase,
            password_require_digit: self.password_require_digit,
            password_require_symbol: self.password_require_symbol,
            password_reject_user_info: self.password_reject_user_info,
            login_lockout_enabled: self.login_lockout_enabled,
            max_failed_login_attempts: self.max_failed_login_attempts,
            failure_window_seconds: self.failure_window_seconds,
            lockout_seconds: self.lockout_seconds,
            trusted_ip_cidrs: util::from_json(&self.trusted_ip_cidrs)?,
            require_mfa_outside_trusted_networks: self.require_mfa_outside_trusted_networks == 1,
            allowed_ip_cidrs: util::from_json(&self.allowed_ip_cidrs)?,
            blocked_ip_cidrs: util::from_json(&self.blocked_ip_cidrs)?,
            allowed_email_domains: util::from_json(&self.allowed_email_domains)?,
            blocked_email_domains: util::from_json(&self.blocked_email_domains)?,
            captcha_enabled: self.captcha_enabled == 1,
            captcha_after_failed_attempts: self.captcha_after_failed_attempts,
            captcha_ttl_seconds: self.captcha_ttl_seconds,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct InvitationRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    #[serde(skip)]
    pub code_hash: String,
    #[diesel(sql_type = Text)]
    pub code_prefix: String,
    #[diesel(sql_type = Nullable<Text>)]
    #[serde(skip)]
    pub code_reveal_key_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    #[serde(skip)]
    pub code_reveal_ciphertext: Option<String>,
    #[diesel(sql_type = Text)]
    pub code_type: String,
    #[diesel(sql_type = Text)]
    pub login_code_level: String,
    #[diesel(sql_type = Text)]
    pub allowed_client_ids: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_role: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorized_email: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorized_username: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    #[serde(skip)]
    pub authorized_user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorized_display_name: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<Integer>)]
    pub max_uses: Option<i32>,
    #[diesel(sql_type = Integer)]
    pub uses_count: i32,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Nullable<Text>)]
    pub created_by: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicInvitationRedemption {
    pub id: String,
    pub user_id: String,
    pub user_email: Option<String>,
    pub user_username: Option<String>,
    pub redeemed_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct InvitationRedemptionRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub invitation_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_email: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_username: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub redeemed_at: i64,
}

impl InvitationRedemptionRecord {
    pub fn public(self) -> PublicInvitationRedemption {
        PublicInvitationRedemption {
            id: self.id,
            user_id: self.user_id,
            user_email: self.user_email,
            user_username: self.user_username,
            redeemed_at: self.redeemed_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicInvitation {
    pub id: String,
    pub code_prefix: String,
    /// Whether this code was created with protected reveal material.  The
    /// management client uses this server-authoritative flag instead of trying
    /// to infer recoverability from a prefix or creation date.
    pub can_reveal: bool,
    pub code_type: AuthorizationCodeType,
    pub login_code_level: LoginCodeLevel,
    pub allowed_client_ids: Vec<String>,
    pub organization_id: Option<String>,
    pub organization_role: Option<String>,
    pub description: Option<String>,
    pub authorized_email: Option<String>,
    pub authorized_username: Option<String>,
    pub authorized_display_name: Option<String>,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
    pub uses_count: i32,
    pub is_active: bool,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl InvitationRecord {
    pub fn authorization_code_type(&self) -> AppResult<AuthorizationCodeType> {
        AuthorizationCodeType::parse(&self.code_type)
    }

    pub fn login_code_level(&self) -> AppResult<LoginCodeLevel> {
        LoginCodeLevel::parse(&self.login_code_level)
    }

    pub fn allowed_client_ids(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.allowed_client_ids).map_err(|err| {
            AppError::Configuration(format!(
                "authorization code client allowlist is invalid: {err}"
            ))
        })
    }

    pub fn public(self) -> AppResult<PublicInvitation> {
        let code_type = self.authorization_code_type()?;
        let login_code_level = self.login_code_level()?;
        let allowed_client_ids = self.allowed_client_ids()?;
        let can_reveal = self.code_reveal_key_id.is_some() && self.code_reveal_ciphertext.is_some();
        Ok(PublicInvitation {
            id: self.id,
            code_prefix: self.code_prefix,
            can_reveal,
            code_type,
            login_code_level,
            allowed_client_ids,
            organization_id: self.organization_id,
            organization_role: self.organization_role,
            description: self.description,
            authorized_email: self.authorized_email,
            authorized_username: self.authorized_username,
            authorized_display_name: self.authorized_display_name,
            expires_at: self.expires_at,
            max_uses: self.max_uses,
            uses_count: self.uses_count,
            is_active: self.is_active == 1,
            created_by: self.created_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationCodeType {
    Registration,
    Login,
}

impl AuthorizationCodeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Login => "login",
        }
    }

    pub fn parse(value: &str) -> AppResult<Self> {
        match value {
            "registration" => Ok(Self::Registration),
            "login" => Ok(Self::Login),
            _ => Err(AppError::Configuration(format!(
                "unknown authorization code type: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginCodeLevel {
    AccountRecovery,
    AdminUniversal,
    TrialEnrollment,
}

impl LoginCodeLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountRecovery => "account_recovery",
            Self::AdminUniversal => "admin_universal",
            Self::TrialEnrollment => "trial_enrollment",
        }
    }

    pub fn parse(value: &str) -> AppResult<Self> {
        match value {
            "account_recovery" => Ok(Self::AccountRecovery),
            "admin_universal" => Ok(Self::AdminUniversal),
            "trial_enrollment" => Ok(Self::TrialEnrollment),
            _ => Err(AppError::Configuration(format!(
                "unknown login authorization code type: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewInvitation {
    pub code_type: AuthorizationCodeType,
    pub login_code_level: LoginCodeLevel,
    pub allowed_client_ids: Vec<String>,
    pub organization_id: Option<String>,
    pub organization_role: Option<String>,
    pub description: Option<String>,
    pub authorized_email: Option<String>,
    pub authorized_username: Option<String>,
    pub authorized_user_id: Option<String>,
    pub authorized_display_name: Option<String>,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
    pub is_active: bool,
    pub created_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InvitationUpdate<'a> {
    pub id: &'a str,
    pub description: Option<String>,
    pub authorized_email: Option<String>,
    pub authorized_username: Option<String>,
    pub authorized_display_name: Option<String>,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct AccountRecoveryCodeRedemption {
    pub invitation_id: String,
    pub user: UserRecord,
    pub code_expires_at: Option<i64>,
}

/// The immutable enrollment provenance for a trial account. It deliberately
/// snapshots the client allowlist at redemption time: disabling or deleting a
/// code revokes these records, while an administrator can never accidentally
/// turn a former trial session into a normal SSO session by editing a code.
#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct TrialEnrollmentRecord {
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub invitation_id: String,
    #[diesel(sql_type = Text)]
    pub organization_id: String,
    #[diesel(sql_type = Text)]
    pub organization_role: String,
    #[diesel(sql_type = Text)]
    pub allowed_client_ids: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

impl TrialEnrollmentRecord {
    pub fn allowed_client_ids(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.allowed_client_ids).map_err(|err| {
            AppError::Configuration(format!(
                "trial enrollment client allowlist is invalid: {err}"
            ))
        })
    }

    pub fn allows_client(&self, client_id: &str) -> AppResult<bool> {
        Ok(self
            .allowed_client_ids()?
            .iter()
            .any(|allowed| allowed == client_id))
    }

    pub fn is_active_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expires_at| expires_at >= now)
    }
}

#[derive(Debug, Clone)]
pub struct NewTrialEnrollmentUser {
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct TrialEnrollmentCodeRedemption {
    pub invitation_id: String,
    pub user: UserRecord,
    pub code_expires_at: Option<i64>,
    pub organization_id: String,
}

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

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct RoleRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Integer)]
    pub is_system: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewRole {
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct GroupRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
    /// Monotonic resource version used by SCIM compare-and-swap updates.
    #[diesel(sql_type = BigInt)]
    pub version: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct GroupMemberPublicRow {
    #[diesel(sql_type = Text)]
    group_id: String,
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    email: String,
    #[diesel(sql_type = Text)]
    username: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    phone: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    email_verified_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    phone_verified_at: Option<i64>,
    #[diesel(sql_type = Integer)]
    is_admin: i32,
    #[diesel(sql_type = Integer)]
    is_active: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    archived_at: Option<i64>,
    #[diesel(sql_type = Text)]
    registration_source: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_login_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    last_login_ip: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_oidc_client_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_login_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct GroupRoleJoinRow {
    #[diesel(sql_type = Text)]
    group_id: String,
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Nullable<Text>)]
    description: Option<String>,
    #[diesel(sql_type = Integer)]
    is_system: i32,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct RoleIdRow {
    #[diesel(sql_type = Text)]
    id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct RolePermissionJoinRow {
    #[diesel(sql_type = Text)]
    role_id: String,
    #[diesel(sql_type = Text)]
    permission: String,
}

impl GroupRoleJoinRow {
    fn role(self) -> RoleRecord {
        RoleRecord {
            id: self.id,
            name: self.name,
            description: self.description,
            is_system: self.is_system,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl GroupMemberPublicRow {
    fn public(self) -> PublicUser {
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

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ScimGroupMemberRecord {
    #[diesel(sql_type = Text)]
    pub group_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub username: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub display_name: Option<String>,
}

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
    /// Only platform migrations may create a system organization. Public
    /// organization creation always supplies `tenant`.
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

/// A tenant-owned product surface.  Authentication protocols are connections
/// beneath an application, so the application is the place where account
/// eligibility and anti-duplication policy lives.
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
    /// `all_users`, `assigned_accounts`, `organization_members`, or the
    /// migration-only compatibility mode `legacy_all_users`.
    #[diesel(sql_type = Text)]
    pub access_mode: String,
    /// `disabled`, `invitation`, `organization_members`, or `legacy`.
    #[diesel(sql_type = Text)]
    pub registration_mode: String,
    /// `optional` or `required`.
    #[diesel(sql_type = Text)]
    pub account_selection_mode: String,
    /// JSON list of verified factors (`email`, `phone`) uniquely reserved by
    /// each account in this application.
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

/// A separately managed capability of a website application.  The module
/// payload is intentionally JSON so protocol-specific settings can evolve
/// without changing the core application row or forcing unrelated modules
/// to share a schema.
#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationModuleRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub module_key: String,
    #[diesel(sql_type = Text)]
    pub config_json: String,
    #[diesel(sql_type = Integer)]
    pub is_enabled: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

/// An application authorization profile is the policy boundary for one
/// protocol connection.  OIDC clients attached to the same website may
/// therefore expose different permission vocabularies without sharing role
/// assignments accidentally.
#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationAuthorizationProfileRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub profile_key: String,
    #[diesel(sql_type = Text)]
    pub connection_kind: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub connection_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub source_mode: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub remote_version: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub remote_digest: Option<String>,
    #[diesel(sql_type = Text)]
    pub sync_status: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_synced_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_error: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationAuthorizationProfile {
    pub id: String,
    pub application_id: String,
    pub profile_key: String,
    pub connection_kind: String,
    pub connection_id: Option<String>,
    pub source_mode: String,
    pub remote_version: Option<String>,
    pub remote_digest: Option<String>,
    pub sync_status: String,
    pub last_synced_at: Option<i64>,
    pub last_error: Option<String>,
}

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
struct ApplicationDiscoveryJoinRecord {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    organization_id: String,
    #[diesel(sql_type = Text)]
    slug: String,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Nullable<Text>)]
    description: Option<String>,
    #[diesel(sql_type = Text)]
    access_mode: String,
    #[diesel(sql_type = Text)]
    registration_mode: String,
    #[diesel(sql_type = Text)]
    account_selection_mode: String,
    #[diesel(sql_type = Text)]
    unique_identity_factors: String,
    #[diesel(sql_type = Integer)]
    is_active: i32,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
    #[diesel(sql_type = Text)]
    discovery_management_mode: String,
    #[diesel(sql_type = Text)]
    discovery_website_url: String,
    #[diesel(sql_type = Text)]
    fetch_secret_ciphertext: String,
    #[diesel(sql_type = Text)]
    signing_public_jwks: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_verified_revision: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    last_verified_version: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_verified_digest: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_verified_expires_at: Option<i64>,
    #[diesel(sql_type = Text)]
    discovery_sync_status: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_fetched_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_success_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    discovery_last_error: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    snapshot_json: Option<String>,
    #[diesel(sql_type = Integer)]
    operator_disabled: i32,
    #[diesel(sql_type = BigInt)]
    discovery_created_at: i64,
    #[diesel(sql_type = BigInt)]
    discovery_updated_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    discovery_lease_owner: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    discovery_lease_expires_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    discovery_lease_generation: i64,
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
struct ApplicationDiscoveryIdempotencyRecord {
    #[diesel(sql_type = Text)]
    request_hash: String,
    #[diesel(sql_type = Text)]
    origin: String,
    #[diesel(sql_type = Nullable<Text>)]
    application_id: Option<String>,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationPermissionDefinitionRecord {
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = Text)]
    pub permission_key: String,
    #[diesel(sql_type = Text)]
    pub label: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub source: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationPermissionDefinition {
    pub profile_id: String,
    pub permission_key: String,
    pub label: String,
    pub description: Option<String>,
    pub source: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationProfileRoleRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = Text)]
    pub role_key: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub permissions: String,
    #[diesel(sql_type = Text)]
    pub source: String,
    #[diesel(sql_type = Integer)]
    pub is_default: i32,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

/// The read side of an application aggregate.  Each collection is loaded in
/// one bounded query on one connection; callers can assemble the graph in
/// memory without opening a new connection for every client or profile.
#[derive(Debug, Clone)]
pub struct ApplicationGraphRecordSet {
    pub bindings: Vec<ApplicationClientBindingRecord>,
    pub clients: Vec<ClientRecord>,
    pub claim_mappers: Vec<ClientClaimMapperRecord>,
    pub organizations: Vec<OrganizationRecord>,
    pub modules: Vec<ApplicationModuleRecord>,
    pub profiles: Vec<ApplicationAuthorizationProfileRecord>,
    pub permission_definitions: Vec<ApplicationPermissionDefinitionRecord>,
    pub profile_roles: Vec<ApplicationProfileRoleRecord>,
}

impl ApplicationProfileRoleRecord {
    pub fn permission_keys(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.permissions)
    }
}

#[derive(Debug, Clone)]
pub struct NewApplicationProfileRole {
    pub id: Option<String>,
    pub profile_id: String,
    pub role_key: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub source: String,
    pub is_default: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationProfilePermissionOverrideRecord {
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub permission: String,
    #[diesel(sql_type = Text)]
    pub effect: String,
}

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

/// A short-lived browser handoff for an already validated SAML AuthnRequest.
/// The raw XML is deliberately not persisted; the trusted request identity and
/// exact ACS/RelayState are enough to resume response issuance after login.
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

/// A short-lived binding between a SAML assertion session and the Signet
/// browser session that produced it.  The SAML SessionIndex and NameID are
/// stored only as domain-separated hashes so a database read does not expose
/// protocol identifiers or user identifiers in clear text.
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

/// A short-lived, application-scoped CAS ticket.  The raw bearer value is
/// never persisted; `ticket_hash` is the only lookup material.  Service and
/// proxy-granting tickets share a table so revocation and application
/// deletion have one transactionally complete cleanup path.
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

/// An application-scoped SCIM bearer credential. The raw token is returned
/// only at creation time; all subsequent authentication uses `token_hash`.
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

/// A JWT protocol client belongs to one website application.  It is kept
/// separate from the generic module JSON because authentication material and
/// its lifecycle must never be returned as part of a configuration read.
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

#[derive(Debug, Clone)]
pub struct NewGroup {
    pub name: String,
    pub description: Option<String>,
}

/// Final state of a SCIM group mutation.  SCIM parses and folds the protocol
/// operations into this value; the database applies the group metadata and
/// membership set together so a later invalid member cannot leave an earlier
/// operation committed.
#[derive(Debug, Clone)]
pub struct GroupPatchPlan {
    pub application_id: Option<String>,
    pub group_id: String,
    pub name: String,
    pub description: Option<String>,
    pub member_ids: Vec<String>,
    /// Creates the group and its optional application binding inside the same
    /// transaction as membership validation and replacement. This is used by
    /// SCIM create so a rejected member list cannot leave an empty group.
    pub create: bool,
    /// When present, the aggregate mutation is compare-and-swap guarded by
    /// this version.  Non-SCIM callers may omit it for legacy unconditional
    /// updates; SCIM always supplies the version read at request start.
    pub expected_version: Option<i64>,
}

/// Fully folded SCIM user state.  The protocol layer is responsible for
/// parsing and validating operations; the database applies this aggregate in
/// one transaction so a later password/active transition cannot leave an
/// earlier profile update committed.
#[derive(Debug, Clone)]
pub struct ScimUserMutationPlan {
    pub id: String,
    /// Digest of the UserRecord observed before the request was folded.  The
    /// database checks it again inside the write transaction so a delayed
    /// PATCH cannot overwrite a newer identity, credential, or lifecycle
    /// change.
    pub expected_version: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub is_admin: bool,
    pub is_active: bool,
    pub password_hash: Option<String>,
    pub scope: Option<ScimUserMutationScope>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct PermissionRow {
    #[diesel(sql_type = Text)]
    permission: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct GroupMemberLifecycleRow {
    #[diesel(sql_type = Text)]
    user_id: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    archived_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct GroupMemberIdRow {
    #[diesel(sql_type = Text)]
    user_id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct UserEmailIdRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    email: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct UserIdentityConflictRow {
    #[diesel(sql_type = Text)]
    email: String,
    #[diesel(sql_type = Text)]
    username: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct BrowserContextAccountOptionRow {
    #[diesel(sql_type = Text)]
    account_id: String,
    #[diesel(sql_type = Text)]
    account_browser_context_id: String,
    #[diesel(sql_type = Text)]
    account_user_id: String,
    #[diesel(sql_type = Text)]
    account_session_id: String,
    #[diesel(sql_type = BigInt)]
    account_added_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    account_last_selected_at: Option<i64>,
    #[diesel(sql_type = Text)]
    user_id: String,
    #[diesel(sql_type = Text)]
    user_email: String,
    #[diesel(sql_type = Text)]
    user_username: String,
    #[diesel(sql_type = Nullable<Text>)]
    user_display_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    user_phone: Option<String>,
    #[diesel(sql_type = Text)]
    user_password_hash: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    user_email_verified_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    user_phone_verified_at: Option<i64>,
    #[diesel(sql_type = Integer)]
    user_is_admin: i32,
    #[diesel(sql_type = Integer)]
    user_is_active: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    user_archived_at: Option<i64>,
    #[diesel(sql_type = Text)]
    user_registration_source: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    user_last_login_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    user_last_login_ip: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    user_last_oidc_client_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    user_last_login_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    user_created_at: i64,
    #[diesel(sql_type = BigInt)]
    user_updated_at: i64,
    #[diesel(sql_type = Text)]
    session_id: String,
    #[diesel(sql_type = Text)]
    session_user_id: String,
    #[diesel(sql_type = Text)]
    session_csrf_token: String,
    #[diesel(sql_type = Nullable<Text>)]
    session_ip_address: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    session_user_agent: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    session_login_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    session_expires_at: i64,
    #[diesel(sql_type = BigInt)]
    session_created_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    trial_user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    trial_invitation_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    trial_organization_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    trial_organization_role: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    trial_allowed_client_ids: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    trial_expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    trial_revoked_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    trial_created_at: Option<i64>,
    #[diesel(sql_type = Integer)]
    has_authorization_code_redemption: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ApplicationAuthorizationProfileCountRow {
    #[diesel(sql_type = Text)]
    profile_id: String,
    #[diesel(sql_type = BigInt)]
    permission_count: i64,
    #[diesel(sql_type = BigInt)]
    role_count: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct UpdatedAtRow {
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct LinkedIdentityRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub provider_slug: String,
    #[diesel(sql_type = Text)]
    pub external_subject: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub external_email: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ExternalOidcProviderRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub display_name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub issuer: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub client_secret: String,
    #[diesel(sql_type = Text)]
    pub authorization_endpoint: String,
    #[diesel(sql_type = Text)]
    pub token_endpoint: String,
    #[diesel(sql_type = Text)]
    pub userinfo_endpoint: String,
    #[diesel(sql_type = Text)]
    pub redirect_path: String,
    #[diesel(sql_type = Text)]
    pub scopes: String,
    #[diesel(sql_type = Text)]
    pub email_domains: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Integer)]
    pub allow_login: i32,
    #[diesel(sql_type = Integer)]
    pub allow_registration: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicExternalOidcProvider {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub organization_id: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub redirect_path: String,
    pub scopes: Vec<String>,
    pub email_domains: Vec<String>,
    pub is_active: bool,
    pub allow_login: bool,
    pub allow_registration: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct LdapProviderRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub display_name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub url: String,
    #[diesel(sql_type = Integer)]
    pub starttls: i32,
    #[diesel(sql_type = Text)]
    pub bind_dn: String,
    #[diesel(sql_type = Text)]
    pub bind_password: String,
    #[diesel(sql_type = Text)]
    pub base_dn: String,
    #[diesel(sql_type = Text)]
    pub user_filter: String,
    #[diesel(sql_type = Text)]
    pub user_id_attribute: String,
    #[diesel(sql_type = Text)]
    pub email_attribute: String,
    #[diesel(sql_type = Text)]
    pub username_attribute: String,
    #[diesel(sql_type = Text)]
    pub display_name_attribute: String,
    #[diesel(sql_type = Text)]
    pub phone_attribute: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Integer)]
    pub allow_login: i32,
    #[diesel(sql_type = Integer)]
    pub allow_registration: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicLdapProvider {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub organization_id: Option<String>,
    pub url: String,
    pub starttls: bool,
    pub bind_dn: String,
    pub has_bind_password: bool,
    pub base_dn: String,
    pub user_filter: String,
    pub user_id_attribute: String,
    pub email_attribute: String,
    pub username_attribute: String,
    pub display_name_attribute: String,
    pub phone_attribute: String,
    pub is_active: bool,
    pub allow_login: bool,
    pub allow_registration: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl LdapProviderRecord {
    pub fn provider_key(&self) -> String {
        ldap_provider_key(&self.slug)
    }

    pub fn public(self) -> PublicLdapProvider {
        PublicLdapProvider {
            id: self.id,
            slug: self.slug,
            display_name: self.display_name,
            organization_id: self.organization_id,
            url: self.url,
            starttls: self.starttls == 1,
            bind_dn: self.bind_dn,
            has_bind_password: !self.bind_password.is_empty(),
            base_dn: self.base_dn,
            user_filter: self.user_filter,
            user_id_attribute: self.user_id_attribute,
            email_attribute: self.email_attribute,
            username_attribute: self.username_attribute,
            display_name_attribute: self.display_name_attribute,
            phone_attribute: self.phone_attribute,
            is_active: self.is_active == 1,
            allow_login: self.allow_login == 1,
            allow_registration: self.allow_registration == 1,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
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

pub fn ldap_provider_key(slug: &str) -> String {
    format!("ldap:{slug}")
}

impl ExternalOidcProviderRecord {
    pub fn public(self) -> AppResult<PublicExternalOidcProvider> {
        Ok(PublicExternalOidcProvider {
            id: self.id,
            slug: self.slug,
            display_name: self.display_name,
            organization_id: self.organization_id,
            issuer: self.issuer,
            client_id: self.client_id,
            authorization_endpoint: self.authorization_endpoint,
            token_endpoint: self.token_endpoint,
            userinfo_endpoint: self.userinfo_endpoint,
            redirect_path: self.redirect_path,
            scopes: util::from_json(&self.scopes)?,
            email_domains: util::from_json(&self.email_domains)?,
            is_active: self.is_active == 1,
            allow_login: self.allow_login == 1,
            allow_registration: self.allow_registration == 1,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewExternalOidcProvider {
    pub slug: String,
    pub display_name: String,
    pub organization_id: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub redirect_path: String,
    pub scopes: Vec<String>,
    pub email_domains: Vec<String>,
    pub is_active: bool,
    pub allow_login: bool,
    pub allow_registration: bool,
}

#[derive(Debug, Clone)]
pub struct NewLdapProvider {
    pub slug: String,
    pub display_name: String,
    pub organization_id: Option<String>,
    pub url: String,
    pub starttls: bool,
    pub bind_dn: String,
    pub bind_password: Option<String>,
    pub base_dn: String,
    pub user_filter: String,
    pub user_id_attribute: String,
    pub email_attribute: String,
    pub username_attribute: String,
    pub display_name_attribute: String,
    pub phone_attribute: String,
    pub is_active: bool,
    pub allow_login: bool,
    pub allow_registration: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ExternalOidcStateRecord {
    #[diesel(sql_type = Text)]
    pub state: String,
    #[diesel(sql_type = Text)]
    pub provider_slug: String,
    #[diesel(sql_type = Text)]
    pub nonce: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub return_to: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

fn select_user_sql() -> &'static str {
    "SELECT users.id, users.email, users.username, users.display_name, users.phone, users.password_hash, users.email_verified_at, users.phone_verified_at, users.is_admin, users.is_active, users.archived_at, users.registration_source, users.last_login_at, users.last_login_ip, users.last_oidc_client_id, users.last_login_method, users.created_at, users.updated_at FROM users"
}

fn authorization_code_registration_source_backfill_sql(kind: DatabaseKind) -> String {
    format!(
        "UPDATE users SET registration_source = {} WHERE registration_source = {} AND id IN (SELECT invitation_redemptions.user_id FROM invitation_redemptions INNER JOIN invitations ON invitations.id = invitation_redemptions.invitation_id WHERE invitations.code_type = {} OR (invitations.code_type = {} AND invitations.login_code_level = {}))",
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3),
        ph(kind, 4),
        ph(kind, 5),
    )
}

fn count_all_users_sql() -> &'static str {
    "SELECT COUNT(*) AS count FROM users"
}

fn ensure_first_user_registration_state(
    expected_first_user: bool,
    current_user_count: i64,
) -> AppResult<()> {
    if expected_first_user && current_user_count > 0 {
        Err(AppError::BadRequest(
            "first user registration already completed; retry registration".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn count_user_identity_conflicts_sql(kind: DatabaseKind) -> String {
    format!(
        "SELECT COUNT(*) AS count FROM users WHERE (email = {} OR username = {}) AND ({} IS NULL OR id <> {})",
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3),
        ph(kind, 4)
    )
}

fn insert_user_sql(kind: DatabaseKind, registration_source: UserRegistrationSource) -> String {
    let source = registration_source.as_str();
    format!(
        "INSERT INTO users (id, email, username, display_name, phone, password_hash, email_verified_at, phone_verified_at, is_admin, is_active, archived_at, registration_source, last_login_at, last_login_ip, last_oidc_client_id, last_login_method, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, '{source}', {}, {}, {}, {}, {}, {})",
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3),
        ph(kind, 4),
        ph(kind, 5),
        ph(kind, 6),
        ph(kind, 7),
        ph(kind, 8),
        ph(kind, 9),
        ph(kind, 10),
        ph(kind, 11),
        ph(kind, 12),
        ph(kind, 13),
        ph(kind, 14),
        ph(kind, 15),
        ph(kind, 16),
        ph(kind, 17),
    )
}

fn select_client_sql() -> &'static str {
    "SELECT id, client_id, client_secret_hash, client_name, COALESCE(logo_uri, '') AS logo_uri, organization_id, redirect_uris, post_logout_redirect_uris, scopes, COALESCE(audience, '') AS audience, grant_types, response_types, token_endpoint_auth_method, require_pkce, COALESCE(require_mfa, 0) AS require_mfa, COALESCE(require_pushed_authorization_requests, 0) AS require_pushed_authorization_requests, COALESCE(require_s256_pkce, 0) AS require_s256_pkce, COALESCE(require_confidential_client, 0) AS require_confidential_client, COALESCE(require_dpop, 0) AS require_dpop, COALESCE(require_account_selection, 0) AS require_account_selection, COALESCE(trust_email_verified, 0) AS trust_email_verified, COALESCE(authorization_details_types, '[]') AS authorization_details_types, subject_type, sector_identifier_uri, COALESCE(jwks_uri, '') AS jwks_uri, COALESCE(jwks, '') AS jwks, COALESCE(backchannel_logout_uri, '') AS backchannel_logout_uri, COALESCE(backchannel_logout_session_required, 0) AS backchannel_logout_session_required, COALESCE(frontchannel_logout_uri, '') AS frontchannel_logout_uri, COALESCE(frontchannel_logout_session_required, 0) AS frontchannel_logout_session_required, COALESCE(service_account_enabled, 0) AS service_account_enabled, COALESCE(service_account_permissions, '[]') AS service_account_permissions, is_active, created_at, updated_at FROM clients"
}

fn select_client_claim_mapper_sql() -> &'static str {
    "SELECT id, client_db_id, claim_name, source, source_value, value_type, include_in_id_token, include_in_access_token, include_in_userinfo, is_active, sort_order, created_at, updated_at FROM client_claim_mappers"
}

macro_rules! insert_client_on_conn {
    ($conn:expr, $kind:expr, $id:expr, $client:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let id = $id;
        let client = $client;
        let now = $now;
    let redirect_uris = util::to_json(&client.redirect_uris)?;
    let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
    let scopes = util::to_json(&client.scopes)?;
    let audience = client.audience.trim().to_string();
    let grant_types = util::to_json(&client.grant_types)?;
    let response_types = util::to_json(&client.response_types)?;
    let authorization_details_types = util::to_json(&client.authorization_details_types)?;
    let service_account_permissions = util::to_json(&client.service_account_permissions)?;
    let sql = format!(
        "INSERT INTO clients (id, client_id, client_secret_hash, client_name, logo_uri, organization_id, redirect_uris, post_logout_redirect_uris, scopes, audience, grant_types, response_types, token_endpoint_auth_method, require_pkce, require_mfa, require_pushed_authorization_requests, require_s256_pkce, require_confidential_client, require_dpop, require_account_selection, trust_email_verified, authorization_details_types, subject_type, sector_identifier_uri, jwks_uri, jwks, backchannel_logout_uri, backchannel_logout_session_required, frontchannel_logout_uri, frontchannel_logout_session_required, service_account_enabled, service_account_permissions, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3),
        ph(kind, 4),
        ph(kind, 5),
        ph(kind, 6),
        ph(kind, 7),
        ph(kind, 8),
        ph(kind, 9),
        ph(kind, 10),
        ph(kind, 11),
        ph(kind, 12),
        ph(kind, 13),
        ph(kind, 14),
        ph(kind, 15),
        ph(kind, 16),
        ph(kind, 17),
        ph(kind, 18),
        ph(kind, 19),
        ph(kind, 20),
        ph(kind, 21),
        ph(kind, 22),
        ph(kind, 23),
        ph(kind, 24),
        ph(kind, 25),
        ph(kind, 26),
        ph(kind, 27),
        ph(kind, 28),
        ph(kind, 29),
        ph(kind, 30),
        ph(kind, 31),
        ph(kind, 32),
        ph(kind, 33),
        ph(kind, 34),
        ph(kind, 35)
    );
    sql_query(sql)
        .bind::<Text, _>(id.to_string())
        .bind::<Text, _>(client.client_id)
        .bind::<Nullable<Text>, _>(client.client_secret_hash)
        .bind::<Text, _>(client.client_name)
        .bind::<Text, _>(client.logo_uri)
        .bind::<Nullable<Text>, _>(client.organization_id)
        .bind::<Text, _>(redirect_uris)
        .bind::<Text, _>(post_logout_redirect_uris)
        .bind::<Text, _>(scopes)
        .bind::<Text, _>(audience)
        .bind::<Text, _>(grant_types)
        .bind::<Text, _>(response_types)
        .bind::<Text, _>(client.token_endpoint_auth_method)
        .bind::<Integer, _>(i32::from(client.require_pkce))
        .bind::<Integer, _>(i32::from(client.require_mfa))
        .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
        .bind::<Integer, _>(i32::from(client.require_s256_pkce))
        .bind::<Integer, _>(i32::from(client.require_confidential_client))
        .bind::<Integer, _>(i32::from(client.require_dpop))
        .bind::<Integer, _>(i32::from(client.require_account_selection))
        .bind::<Integer, _>(i32::from(client.trust_email_verified))
        .bind::<Text, _>(authorization_details_types)
        .bind::<Text, _>(client.subject_type)
        .bind::<Text, _>(client.sector_identifier_uri)
        .bind::<Text, _>(client.jwks_uri)
        .bind::<Text, _>(client.jwks)
        .bind::<Text, _>(client.backchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
        .bind::<Text, _>(client.frontchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
        .bind::<Integer, _>(i32::from(client.service_account_enabled))
        .bind::<Text, _>(service_account_permissions)
        .bind::<Integer, _>(i32::from(client.is_active))
        .bind::<BigInt, _>(now)
        .bind::<BigInt, _>(now)
        .execute(conn)
        .map_err(AppError::from)?;

    let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
    sql_query(sql)
        .bind::<Text, _>(id.to_string())
        .get_result::<ClientRecord>(conn)
        .map_err(AppError::from)
    }};
}

macro_rules! update_client_on_conn {
    ($conn:expr, $kind:expr, $id:expr, $client:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let id = $id;
        let client = $client;
        let now = $now;
    let redirect_uris = util::to_json(&client.redirect_uris)?;
    let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
    let scopes = util::to_json(&client.scopes)?;
    let audience = client.audience.trim().to_string();
    let grant_types = util::to_json(&client.grant_types)?;
    let response_types = util::to_json(&client.response_types)?;
    let authorization_details_types = util::to_json(&client.authorization_details_types)?;
    let service_account_permissions = util::to_json(&client.service_account_permissions)?;
    let sql = format!(
        "UPDATE clients SET client_id = {}, client_secret_hash = {}, client_name = {}, logo_uri = {}, organization_id = {}, redirect_uris = {}, post_logout_redirect_uris = {}, scopes = {}, audience = {}, grant_types = {}, response_types = {}, token_endpoint_auth_method = {}, require_pkce = {}, require_mfa = {}, require_pushed_authorization_requests = {}, require_s256_pkce = {}, require_confidential_client = {}, require_dpop = {}, require_account_selection = {}, trust_email_verified = {}, authorization_details_types = {}, subject_type = {}, sector_identifier_uri = {}, jwks_uri = {}, jwks = {}, backchannel_logout_uri = {}, backchannel_logout_session_required = {}, frontchannel_logout_uri = {}, frontchannel_logout_session_required = {}, service_account_enabled = {}, service_account_permissions = {}, is_active = {}, updated_at = {} WHERE id = {}",
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3),
        ph(kind, 4),
        ph(kind, 5),
        ph(kind, 6),
        ph(kind, 7),
        ph(kind, 8),
        ph(kind, 9),
        ph(kind, 10),
        ph(kind, 11),
        ph(kind, 12),
        ph(kind, 13),
        ph(kind, 14),
        ph(kind, 15),
        ph(kind, 16),
        ph(kind, 17),
        ph(kind, 18),
        ph(kind, 19),
        ph(kind, 20),
        ph(kind, 21),
        ph(kind, 22),
        ph(kind, 23),
        ph(kind, 24),
        ph(kind, 25),
        ph(kind, 26),
        ph(kind, 27),
        ph(kind, 28),
        ph(kind, 29),
        ph(kind, 30),
        ph(kind, 31),
        ph(kind, 32),
        ph(kind, 33),
        ph(kind, 34)
    );
    let affected = sql_query(sql)
        .bind::<Text, _>(client.client_id)
        .bind::<Nullable<Text>, _>(client.client_secret_hash)
        .bind::<Text, _>(client.client_name)
        .bind::<Text, _>(client.logo_uri)
        .bind::<Nullable<Text>, _>(client.organization_id)
        .bind::<Text, _>(redirect_uris)
        .bind::<Text, _>(post_logout_redirect_uris)
        .bind::<Text, _>(scopes)
        .bind::<Text, _>(audience)
        .bind::<Text, _>(grant_types)
        .bind::<Text, _>(response_types)
        .bind::<Text, _>(client.token_endpoint_auth_method)
        .bind::<Integer, _>(i32::from(client.require_pkce))
        .bind::<Integer, _>(i32::from(client.require_mfa))
        .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
        .bind::<Integer, _>(i32::from(client.require_s256_pkce))
        .bind::<Integer, _>(i32::from(client.require_confidential_client))
        .bind::<Integer, _>(i32::from(client.require_dpop))
        .bind::<Integer, _>(i32::from(client.require_account_selection))
        .bind::<Integer, _>(i32::from(client.trust_email_verified))
        .bind::<Text, _>(authorization_details_types)
        .bind::<Text, _>(client.subject_type)
        .bind::<Text, _>(client.sector_identifier_uri)
        .bind::<Text, _>(client.jwks_uri)
        .bind::<Text, _>(client.jwks)
        .bind::<Text, _>(client.backchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
        .bind::<Text, _>(client.frontchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
        .bind::<Integer, _>(i32::from(client.service_account_enabled))
        .bind::<Text, _>(service_account_permissions)
        .bind::<Integer, _>(i32::from(client.is_active))
        .bind::<BigInt, _>(now)
        .bind::<Text, _>(id.to_string())
        .execute(conn)
        .map_err(AppError::from)?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
    sql_query(sql)
        .bind::<Text, _>(id.to_string())
        .get_result::<ClientRecord>(conn)
        .map_err(AppError::from)
    }};
}

macro_rules! replace_client_claim_mappers_on_conn {
    ($conn:expr, $kind:expr, $client_db_id:expr, $mappers:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let client_db_id = $client_db_id;
        let mappers = $mappers;
        let now = $now;
    let sql = format!(
        "DELETE FROM client_claim_mappers WHERE client_db_id = {}",
        ph(kind, 1)
    );
    sql_query(sql)
        .bind::<Text, _>(client_db_id.to_string())
        .execute(&mut *conn)
        .map_err(AppError::from)?;
    for mapper in mappers {
        let sql = format!(
            "INSERT INTO client_claim_mappers (id, client_db_id, claim_name, source, source_value, value_type, include_in_id_token, include_in_access_token, include_in_userinfo, is_active, sort_order, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6),
            ph(kind, 7),
            ph(kind, 8),
            ph(kind, 9),
            ph(kind, 10),
            ph(kind, 11),
            ph(kind, 12),
            ph(kind, 13)
        );
        sql_query(sql)
            .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
            .bind::<Text, _>(client_db_id.to_string())
            .bind::<Text, _>(mapper.claim_name)
            .bind::<Text, _>(mapper.source)
            .bind::<Text, _>(mapper.source_value)
            .bind::<Text, _>(mapper.value_type)
            .bind::<Integer, _>(i32::from(mapper.include_in_id_token))
            .bind::<Integer, _>(i32::from(mapper.include_in_access_token))
            .bind::<Integer, _>(i32::from(mapper.include_in_userinfo))
            .bind::<Integer, _>(i32::from(mapper.is_active))
            .bind::<Integer, _>(mapper.sort_order)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    let sql = format!(
        "{} WHERE client_db_id = {} ORDER BY sort_order ASC, created_at ASC",
        select_client_claim_mapper_sql(),
        ph(kind, 1)
    );
    sql_query(sql)
        .bind::<Text, _>(client_db_id.to_string())
        .load::<ClientClaimMapperRecord>(conn)
        .map_err(AppError::from)
    }};
}

macro_rules! write_application_profile_on_conn {
    ($conn:expr, $kind:expr, $profile:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let profile = $profile;
        let now = $now;
    let profile_key = profile.profile_key.trim().to_string();
    if profile_key.is_empty()
        || profile_key.len() > 255
        || profile_key.chars().any(|ch| ch.is_control())
    {
        return Err(AppError::BadRequest(
            "authorization profile key is invalid".to_string(),
        ));
    }
    let existing_by_id_sql = format!(
        "{} WHERE id = {} AND application_id = {}",
        select_application_authorization_profile_sql(),
        ph(kind, 1),
        ph(kind, 2)
    );
    let existing_by_id = sql_query(existing_by_id_sql)
        .bind::<Text, _>(profile.id.clone())
        .bind::<Text, _>(profile.application_id.clone())
        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
        .optional()
        .map_err(AppError::from)?;
    let existing_by_key_sql = format!(
        "{} WHERE application_id = {} AND profile_key = {}",
        select_application_authorization_profile_sql(),
        ph(kind, 1),
        ph(kind, 2)
    );
    if let Some(existing_by_key) = sql_query(existing_by_key_sql)
        .bind::<Text, _>(profile.application_id.clone())
        .bind::<Text, _>(profile_key.clone())
        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
        .optional()
        .map_err(AppError::from)?
    {
        if existing_by_key.id != profile.id {
            return Err(AppError::BadRequest(
                "authorization profile key is already used by another connection".to_string(),
            ));
        }
    }

    if existing_by_id.is_some() {
        let sql = format!(
            "UPDATE application_authorization_profiles SET profile_key = {}, connection_kind = {}, connection_id = {}, source_mode = {}, remote_version = {}, remote_digest = {}, sync_status = {}, last_synced_at = {}, last_error = {}, updated_at = {} WHERE id = {} AND application_id = {}",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6),
            ph(kind, 7),
            ph(kind, 8),
            ph(kind, 9),
            ph(kind, 10),
            ph(kind, 11),
            ph(kind, 12)
        );
        sql_query(sql)
            .bind::<Text, _>(profile_key)
            .bind::<Text, _>(profile.connection_kind)
            .bind::<Nullable<Text>, _>(profile.connection_id)
            .bind::<Text, _>(profile.source_mode)
            .bind::<Nullable<Text>, _>(profile.remote_version)
            .bind::<Nullable<Text>, _>(profile.remote_digest)
            .bind::<Text, _>(profile.sync_status)
            .bind::<Nullable<BigInt>, _>(profile.last_synced_at)
            .bind::<Nullable<Text>, _>(profile.last_error)
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(profile.id.clone())
            .bind::<Text, _>(profile.application_id.clone())
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    } else {
        let sql = format!(
            "INSERT INTO application_authorization_profiles (id, application_id, profile_key, connection_kind, connection_id, source_mode, remote_version, remote_digest, sync_status, last_synced_at, last_error, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6),
            ph(kind, 7),
            ph(kind, 8),
            ph(kind, 9),
            ph(kind, 10),
            ph(kind, 11),
            ph(kind, 12),
            ph(kind, 13)
        );
        sql_query(sql)
            .bind::<Text, _>(profile.id.clone())
            .bind::<Text, _>(profile.application_id.clone())
            .bind::<Text, _>(profile_key)
            .bind::<Text, _>(profile.connection_kind)
            .bind::<Nullable<Text>, _>(profile.connection_id)
            .bind::<Text, _>(profile.source_mode)
            .bind::<Nullable<Text>, _>(profile.remote_version)
            .bind::<Nullable<Text>, _>(profile.remote_digest)
            .bind::<Text, _>(profile.sync_status)
            .bind::<Nullable<BigInt>, _>(profile.last_synced_at)
            .bind::<Nullable<Text>, _>(profile.last_error)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    let sql = format!(
        "{} WHERE id = {} AND application_id = {}",
        select_application_authorization_profile_sql(),
        ph(kind, 1),
        ph(kind, 2)
    );
    sql_query(sql)
        .bind::<Text, _>(profile.id)
        .bind::<Text, _>(profile.application_id)
        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
        .map_err(AppError::from)
    }};
}

/// Makes the application-level authorization boundary explicit. Every
/// application has one physical `default` profile, including applications
/// that do not yet expose a client-bound protocol. Runtime adapters resolve
/// this row instead of falling back to a second application-wide role graph.
macro_rules! ensure_application_default_profile_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let application_id = $application_id;
        let existing_sql = format!(
            "{} WHERE application_id = {} AND profile_key = {}",
            select_application_authorization_profile_sql(),
            ph(kind, 1),
            ph(kind, 2)
        );
        if let Some(existing) = sql_query(existing_sql)
            .bind::<Text, _>(application_id.to_string())
            .bind::<Text, _>("default")
            .get_result::<ApplicationAuthorizationProfileRecord>(conn)
            .optional()
            .map_err(AppError::from)?
        {
            existing
        } else {
            write_application_profile_on_conn!(
                conn,
                kind,
                NewApplicationAuthorizationProfile {
                    id: format!("application-default-profile:{application_id}"),
                    application_id: application_id.to_string(),
                    profile_key: "default".to_string(),
                    connection_kind: "application".to_string(),
                    connection_id: None,
                    source_mode: crate::application_discovery::SOURCE_MODE_MANUAL.to_string(),
                    remote_version: None,
                    remote_digest: None,
                    sync_status: crate::application_discovery::SYNC_STATUS_MANUAL.to_string(),
                    last_synced_at: None,
                    last_error: None,
                },
                $now,
            )?
        }
    }};
}

macro_rules! ensure_application_client_binding_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $client_db_id:expr, $protocol:expr, $authorization_profile_id:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let application_id = $application_id;
        let client_db_id = $client_db_id;
        let protocol = $protocol;
        let authorization_profile_id = $authorization_profile_id;
        let now = $now;
    let application_count_sql = format!(
        "SELECT COUNT(*) AS count FROM applications WHERE id = {}",
        ph(kind, 1)
    );
    if sql_query(application_count_sql)
        .bind::<Text, _>(application_id.to_string())
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        == 0
    {
        return Err(AppError::NotFound);
    }
    let profile_count_sql = format!(
        "SELECT COUNT(*) AS count FROM application_authorization_profiles WHERE id = {} AND application_id = {}",
        ph(kind, 1),
        ph(kind, 2)
    );
    if sql_query(profile_count_sql)
        .bind::<Text, _>(authorization_profile_id.to_string())
        .bind::<Text, _>(application_id.to_string())
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        == 0
    {
        return Err(AppError::BadRequest(
            "authorization profile must belong to the application".to_string(),
        ));
    }
    let same_organization_sql = format!(
        "SELECT COUNT(*) AS count FROM applications INNER JOIN clients ON clients.id = {} WHERE applications.id = {} AND clients.organization_id = applications.organization_id",
        ph(kind, 1),
        ph(kind, 2)
    );
    if sql_query(same_organization_sql)
        .bind::<Text, _>(client_db_id.to_string())
        .bind::<Text, _>(application_id.to_string())
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        == 0
    {
        return Err(AppError::BadRequest(
            "OIDC client must belong to the application's organization".to_string(),
        ));
    }
    let existing_binding_sql = format!(
        "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE client_db_id = {}",
        ph(kind, 1)
    );
    let existing_binding = sql_query(existing_binding_sql)
        .bind::<Text, _>(client_db_id.to_string())
        .get_result::<ApplicationClientBindingRecord>(conn)
        .optional()
        .map_err(AppError::from)?;
    if let Some(existing_binding) = existing_binding.as_ref()
        && existing_binding.application_id != *application_id
    {
        return Err(AppError::BadRequest(
            "OIDC client already belongs to another application".to_string(),
        ));
    }
    let auth_domain_id = format!("auth-domain:{application_id}");
    let auth_domain_count_sql = format!(
        "SELECT COUNT(*) AS count FROM application_auth_domains WHERE application_id = {}",
        ph(kind, 1)
    );
    if sql_query(auth_domain_count_sql)
        .bind::<Text, _>(application_id.to_string())
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        == 0
    {
        let auth_domain_sql = format!(
            "INSERT INTO application_auth_domains (id, application_id, assurance_policy, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6)
        );
        sql_query(auth_domain_sql)
            .bind::<Text, _>(auth_domain_id.clone())
            .bind::<Text, _>(application_id.to_string())
            .bind::<Text, _>("default")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    if existing_binding.is_some() {
        let update_binding_sql = format!(
            "UPDATE application_client_bindings SET protocol = {}, authorization_profile_id = {}, auth_domain_id = {}, is_active = {}, updated_at = {} WHERE application_id = {} AND client_db_id = {}",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6),
            ph(kind, 7)
        );
        sql_query(update_binding_sql)
            .bind::<Text, _>(protocol.to_string())
            .bind::<Text, _>(authorization_profile_id.to_string())
            .bind::<Text, _>(auth_domain_id)
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(application_id.to_string())
            .bind::<Text, _>(client_db_id.to_string())
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    } else {
        let binding_sql = format!(
            "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6),
            ph(kind, 7),
            ph(kind, 8)
        );
        sql_query(binding_sql)
            .bind::<Text, _>(application_id.to_string())
            .bind::<Text, _>(client_db_id.to_string())
            .bind::<Text, _>(protocol.to_string())
            .bind::<Text, _>(authorization_profile_id.to_string())
            .bind::<Text, _>(auth_domain_id)
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    Ok::<(), AppError>(())
    }};
}

macro_rules! delete_client_on_conn {
    ($conn:expr, $kind:expr, $id:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let id = $id;
    let client_sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
    let client = sql_query(client_sql)
        .bind::<Text, _>(id.to_string())
        .get_result::<ClientRecord>(conn)
        .optional()
        .map_err(AppError::from)?
        .ok_or(AppError::NotFound)?;
    for (table, column) in [
        ("authorization_codes", "client_id"),
        ("refresh_tokens", "client_id"),
        ("client_grants", "client_id"),
        ("device_authorizations", "client_id"),
        ("pushed_authorization_requests", "client_id"),
        ("oidc_login_grants", "client_id"),
        ("client_assertion_jtis", "client_id"),
    ] {
        let sql = format!(
            "DELETE FROM {table} WHERE {column} IN (SELECT client_id FROM clients WHERE id = {})",
            ph(kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>(id.to_string())
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    for table in ["client_registrations", "client_claim_mappers"] {
        let sql = format!(
            "DELETE FROM {table} WHERE client_db_id = {}",
            ph(kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>(id.to_string())
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    let binding_sql = format!(
        "DELETE FROM application_client_bindings WHERE client_db_id = {}",
        ph(kind, 1)
    );
    sql_query(binding_sql)
        .bind::<Text, _>(id.to_string())
        .execute(&mut *conn)
        .map_err(AppError::from)?;
    let sql = format!("DELETE FROM clients WHERE id = {}", ph(kind, 1));
    let affected = sql_query(sql)
        .bind::<Text, _>(id.to_string())
        .execute(&mut *conn)
        .map_err(AppError::from)?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(client)
    }};
}

fn select_iap_application_sql() -> &'static str {
    "SELECT id, application_id, slug, name, description, external_host, path_prefix, required_organization_id, required_organization_roles, required_permissions, is_active, created_at, updated_at FROM iap_applications"
}

fn select_oidc_login_grant_sql() -> &'static str {
    "SELECT credential_hash, invitation_id, user_id, client_id, interaction_request_hash, auth_time, expires_at, consumed_at, created_at FROM oidc_login_grants"
}

fn select_invitation_sql() -> &'static str {
    "SELECT id, code_hash, code_prefix, code_reveal_key_id, code_reveal_ciphertext, code_type, login_code_level, COALESCE(allowed_client_ids, '[]') AS allowed_client_ids, organization_id, organization_role, description, authorized_email, authorized_username, authorized_user_id, authorized_display_name, expires_at, max_uses, uses_count, is_active, created_by, created_at, updated_at FROM invitations"
}

fn select_trial_enrollment_sql() -> &'static str {
    "SELECT user_id, invitation_id, organization_id, organization_role, allowed_client_ids, expires_at, revoked_at, created_at FROM trial_enrollments"
}

fn redeem_invitation_update_sql(kind: DatabaseKind) -> String {
    format!(
        "UPDATE invitations SET uses_count = uses_count + 1, updated_at = {} WHERE id = {} AND code_type = {} AND is_active = 1 AND (expires_at IS NULL OR expires_at >= {}) AND (max_uses IS NULL OR uses_count < max_uses)",
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3),
        ph(kind, 4)
    )
}

fn redeem_account_recovery_invitation_update_sql(kind: DatabaseKind) -> String {
    format!(
        "UPDATE invitations SET uses_count = uses_count + 1, authorized_user_id = COALESCE(authorized_user_id, {}), updated_at = {} WHERE id = {} AND code_type = {} AND login_code_level = {} AND (authorized_user_id IS NULL OR authorized_user_id = {}) AND is_active = 1 AND (expires_at IS NULL OR expires_at >= {}) AND (max_uses IS NULL OR uses_count < max_uses)",
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3),
        ph(kind, 4),
        ph(kind, 5),
        ph(kind, 6),
        ph(kind, 7)
    )
}

fn redeem_trial_enrollment_invitation_update_sql(kind: DatabaseKind) -> String {
    format!(
        "UPDATE invitations SET uses_count = uses_count + 1, updated_at = {} WHERE id = {} AND code_type = {} AND login_code_level = {} AND is_active = 1 AND (expires_at IS NULL OR expires_at >= {}) AND (max_uses IS NULL OR uses_count < max_uses)",
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3),
        ph(kind, 4),
        ph(kind, 5)
    )
}

fn ensure_invitation_redeemable(invitation: &InvitationRecord, now: i64) -> AppResult<()> {
    if invitation.is_active != 1 {
        return Err(AppError::BadRequest(
            "authorization code is disabled".to_string(),
        ));
    }
    if invitation
        .expires_at
        .is_some_and(|expires_at| expires_at < now)
    {
        return Err(AppError::BadRequest(
            "authorization code expired".to_string(),
        ));
    }
    if invitation
        .max_uses
        .is_some_and(|max_uses| invitation.uses_count >= max_uses)
    {
        return Err(AppError::BadRequest(
            "authorization code is exhausted".to_string(),
        ));
    }
    Ok(())
}

fn select_organization_sql() -> &'static str {
    "SELECT id, slug, name, COALESCE(kind, 'tenant') AS kind, description, COALESCE(allowed_email_domains, '[]') AS allowed_email_domains, is_active, created_at, updated_at FROM organizations"
}

fn select_application_sql() -> &'static str {
    "SELECT id, organization_id, slug, name, description, access_mode, registration_mode, account_selection_mode, COALESCE(unique_identity_factors, '[]') AS unique_identity_factors, is_active, created_at, updated_at FROM applications"
}

fn select_group_sql() -> &'static str {
    "SELECT id, name, description, created_at, updated_at, version FROM access_groups"
}

fn select_application_member_sql() -> &'static str {
    "SELECT application_id, user_id, role, is_active, created_at, updated_at FROM application_members"
}

fn select_application_identity_binding_sql() -> &'static str {
    "SELECT application_id, factor_type, factor_digest, user_id, created_at, updated_at FROM application_identity_bindings"
}

fn select_application_module_sql() -> &'static str {
    "SELECT application_id, module_key, config_json, is_enabled, created_at, updated_at FROM application_modules"
}

fn select_application_authorization_profile_sql() -> &'static str {
    "SELECT id, application_id, profile_key, connection_kind, connection_id, source_mode, remote_version, remote_digest, sync_status, last_synced_at, last_error, created_at, updated_at FROM application_authorization_profiles"
}

fn select_application_discovery_sql() -> &'static str {
    "SELECT application_id, management_mode, website_url, fetch_secret_ciphertext, signing_public_jwks, last_verified_revision, last_verified_version, last_verified_digest, last_verified_expires_at, sync_status, last_fetched_at, last_success_at, last_error, snapshot_json, operator_disabled, created_at, updated_at, lease_owner, lease_expires_at, lease_generation FROM application_discovery"
}

fn select_application_permission_definition_sql() -> &'static str {
    "SELECT profile_id, permission_key, label, description, source, is_active, created_at, updated_at FROM application_permission_definitions"
}

fn select_application_profile_role_sql() -> &'static str {
    "SELECT id, profile_id, role_key, name, description, permissions, source, is_default, is_active, created_at, updated_at FROM application_profile_roles"
}

fn select_application_profile_permission_override_sql() -> &'static str {
    "SELECT profile_id, user_id, permission, effect FROM application_profile_permission_overrides"
}

fn select_application_jwt_client_sql() -> &'static str {
    "SELECT id, application_id, client_id, client_type, is_active, created_at, updated_at FROM application_jwt_clients"
}

fn select_application_jwt_secret_sql() -> &'static str {
    "SELECT id, jwt_client_id, secret_hash, created_at, expires_at, revoked_at FROM application_jwt_client_secrets"
}

fn select_application_saml_interaction_sql() -> &'static str {
    "SELECT handle_hash, application_id, request_id, sp_entity_id, acs_url, relay_state, response_binding, expires_at, created_at FROM application_saml_interactions"
}

fn select_application_saml_session_sql() -> &'static str {
    "SELECT session_index_hash, application_id, user_id, signet_session_id, name_id_hash, expires_at, created_at FROM application_saml_sessions"
}

fn select_application_cas_ticket_sql() -> &'static str {
    "SELECT ticket_hash, application_id, ticket_type, service, user_id, parent_ticket_hash, pgt_iou, expires_at, consumed_at, revoked_at, created_at FROM application_cas_tickets"
}

fn select_application_scim_token_sql() -> &'static str {
    "SELECT id, application_id, token_prefix, token_hash, scopes, expires_at, revoked_at, last_used_at, created_at FROM application_scim_tokens"
}

/// The application aggregate write primitives below intentionally accept an
/// existing connection.  The public one-operation methods use them directly,
/// while audited mutation methods compose them with the audit insert inside
/// one transaction.
macro_rules! allocate_application_slug_on_conn {
    ($conn:expr, $kind:expr, $organization_id:expr, $client_id:expr $(,)?) => {{
        let base_slug = application_slug_base($client_id);
        let base_sql = format!(
            "SELECT COUNT(*) AS count FROM applications WHERE organization_id = {} AND slug = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        let base_taken = sql_query(base_sql)
            .bind::<Text, _>($organization_id)
            .bind::<Text, _>(&base_slug)
            .get_result::<CountRow>($conn)
            .map_err(AppError::from)?
            .count
            > 0;
        if !base_taken {
            base_slug
        } else {
            let candidate = application_slug_collision_candidate(&base_slug, $client_id);
            let candidate_sql = format!(
                "SELECT COUNT(*) AS count FROM applications WHERE organization_id = {} AND slug = {}",
                ph($kind, 1),
                ph($kind, 2)
            );
            let candidate_taken = sql_query(candidate_sql)
                .bind::<Text, _>($organization_id)
                .bind::<Text, _>(&candidate)
                .get_result::<CountRow>($conn)
                .map_err(AppError::from)?
                .count
                > 0;
            if !candidate_taken {
                candidate
            } else {
                // A digest collision is extraordinarily unlikely, but the
                // database unique key remains the final concurrency guard.
                let mut prefix = base_slug;
                prefix.truncate(31);
                format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
            }
        }
    }};
}

macro_rules! insert_application_on_conn {
    ($conn:expr, $kind:expr, $id:expr, $application:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let application = $application;
        let unique_identity_factors = util::to_json(&application.unique_identity_factors)?;
        let sql = format!(
            "INSERT INTO applications (id, organization_id, slug, name, description, access_mode, registration_mode, account_selection_mode, unique_identity_factors, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3),
            ph($kind, 4),
            ph($kind, 5),
            ph($kind, 6),
            ph($kind, 7),
            ph($kind, 8),
            ph($kind, 9),
            ph($kind, 10),
            ph($kind, 11),
            ph($kind, 12)
        );
        sql_query(sql)
            .bind::<Text, _>($id)
            .bind::<Text, _>(&application.organization_id)
            .bind::<Text, _>(&application.slug)
            .bind::<Text, _>(&application.name)
            .bind::<Nullable<Text>, _>(&application.description)
            .bind::<Text, _>(&application.access_mode)
            .bind::<Text, _>(&application.registration_mode)
            .bind::<Text, _>(&application.account_selection_mode)
            .bind::<Text, _>(unique_identity_factors)
            .bind::<Integer, _>(i32::from(application.is_active))
            .bind::<BigInt, _>($now)
            .bind::<BigInt, _>($now)
            .execute(conn)
            .map_err(AppError::from)?;
        let _ = ensure_application_default_profile_on_conn!(conn, $kind, $id, $now);
        let sql = format!("{} WHERE id = {}", select_application_sql(), ph($kind, 1));
        sql_query(sql)
            .bind::<Text, _>($id)
            .get_result::<ApplicationRecord>(conn)
            .map_err(AppError::from)
    }};
}

macro_rules! update_application_on_conn {
    ($conn:expr, $kind:expr, $id:expr, $application:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let application = $application;
        let unique_identity_factors = util::to_json(&application.unique_identity_factors)?;
        let sql = format!(
            "UPDATE applications SET organization_id = {}, slug = {}, name = {}, description = {}, access_mode = {}, registration_mode = {}, account_selection_mode = {}, unique_identity_factors = {}, is_active = {}, updated_at = {} WHERE id = {}",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3),
            ph($kind, 4),
            ph($kind, 5),
            ph($kind, 6),
            ph($kind, 7),
            ph($kind, 8),
            ph($kind, 9),
            ph($kind, 10),
            ph($kind, 11)
        );
        let affected = sql_query(sql)
            .bind::<Text, _>(&application.organization_id)
            .bind::<Text, _>(&application.slug)
            .bind::<Text, _>(&application.name)
            .bind::<Nullable<Text>, _>(&application.description)
            .bind::<Text, _>(&application.access_mode)
            .bind::<Text, _>(&application.registration_mode)
            .bind::<Text, _>(&application.account_selection_mode)
            .bind::<Text, _>(unique_identity_factors)
            .bind::<Integer, _>(i32::from(application.is_active))
            .bind::<BigInt, _>($now)
            .bind::<Text, _>($id)
            .execute(conn)
            .map_err(AppError::from)?;
        if affected == 0 {
            return Err(AppError::NotFound);
        }
        let sql = format!("{} WHERE id = {}", select_application_sql(), ph($kind, 1));
        sql_query(sql)
            .bind::<Text, _>($id)
            .get_result::<ApplicationRecord>(conn)
            .map_err(AppError::from)
    }};
}

macro_rules! upsert_application_module_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $module_key:expr, $config_json:expr, $is_enabled:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let application_id = $application_id;
        let module_key = $module_key;
        let config_json = $config_json;
        let is_enabled = $is_enabled;
        let lock_sql = format!(
            "UPDATE applications SET updated_at = updated_at WHERE id = {}",
            ph($kind, 1)
        );
        if sql_query(lock_sql)
            .bind::<Text, _>(application_id)
            .execute(conn)
            .map_err(AppError::from)?
            == 0
        {
            return Err(AppError::NotFound);
        }
        let exists_sql = format!(
            "SELECT COUNT(*) AS count FROM application_modules WHERE application_id = {} AND module_key = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        let exists = sql_query(exists_sql)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(module_key)
            .get_result::<CountRow>(conn)
            .map_err(AppError::from)?
            .count
            > 0;
        if exists {
            let update_sql = format!(
                "UPDATE application_modules SET config_json = {}, is_enabled = {}, updated_at = {} WHERE application_id = {} AND module_key = {}",
                ph($kind, 1),
                ph($kind, 2),
                ph($kind, 3),
                ph($kind, 4),
                ph($kind, 5)
            );
            sql_query(update_sql)
                .bind::<Text, _>(config_json)
                .bind::<Integer, _>(i32::from(is_enabled))
                .bind::<BigInt, _>($now)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(module_key)
                .execute(conn)
                .map_err(AppError::from)?;
        } else {
            let insert_sql = format!(
                "INSERT INTO application_modules (application_id, module_key, config_json, is_enabled, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                ph($kind, 1),
                ph($kind, 2),
                ph($kind, 3),
                ph($kind, 4),
                ph($kind, 5),
                ph($kind, 6)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(module_key)
                .bind::<Text, _>(config_json)
                .bind::<Integer, _>(i32::from(is_enabled))
                .bind::<BigInt, _>($now)
                .bind::<BigInt, _>($now)
                .execute(conn)
                .map_err(AppError::from)?;
        }
        let select_sql = format!(
            "{} WHERE application_id = {} AND module_key = {}",
            select_application_module_sql(),
            ph($kind, 1),
            ph($kind, 2)
        );
        sql_query(select_sql)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(module_key)
            .get_result::<ApplicationModuleRecord>(conn)
            .map_err(AppError::from)
    }};
}

macro_rules! insert_application_scim_token_on_conn {
    ($conn:expr, $kind:expr, $token:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let token = $token;
        let scopes = util::to_json(&token.scopes)?;
        let sql = format!(
            "INSERT INTO application_scim_tokens (id, application_id, token_prefix, token_hash, scopes, expires_at, revoked_at, last_used_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3),
            ph($kind, 4),
            ph($kind, 5),
            ph($kind, 6),
            ph($kind, 7),
            ph($kind, 8),
            ph($kind, 9)
        );
        sql_query(sql)
            .bind::<Text, _>(&token.id)
            .bind::<Text, _>(&token.application_id)
            .bind::<Text, _>(&token.token_prefix)
            .bind::<Text, _>(&token.token_hash)
            .bind::<Text, _>(scopes)
            .bind::<Nullable<BigInt>, _>(token.expires_at)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .bind::<BigInt, _>($now)
            .execute(conn)
            .map_err(AppError::from)?;
        let sql = format!(
            "{} WHERE id = {}",
            select_application_scim_token_sql(),
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>(&token.id)
            .get_result::<ApplicationScimTokenRecord>(conn)
            .map_err(AppError::from)
    }};
}

macro_rules! rotate_application_jwt_secret_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $client_id:expr, $secret_hash:expr, $grace_seconds:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let client_sql = format!(
            "{} WHERE application_id = {} AND client_id = {}",
            select_application_jwt_client_sql(),
            ph($kind, 1),
            ph($kind, 2)
        );
        let client = sql_query(client_sql)
            .bind::<Text, _>($application_id)
            .bind::<Text, _>($client_id)
            .get_result::<ApplicationJwtClientRecord>(conn)
            .optional()
            .map_err(AppError::from)?
            .ok_or(AppError::NotFound)?;
        if client.client_type != "confidential" || client.is_active != 1 {
            return Err(AppError::BadRequest(
                "JWT secrets require an active confidential client".to_string(),
            ));
        }
        let secret_hash = $secret_hash;
        if secret_hash.trim().is_empty() || secret_hash.len() > 512 {
            return Err(AppError::BadRequest(
                "application JWT secret hash is invalid".to_string(),
            ));
        }
        let expires_at = $now.saturating_add($grace_seconds.clamp(0, 86_400));
        let update_sql = format!(
            "UPDATE application_jwt_client_secrets SET expires_at = CASE WHEN expires_at IS NULL OR expires_at > {} THEN {} ELSE expires_at END WHERE jwt_client_id = {} AND revoked_at IS NULL",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3)
        );
        sql_query(update_sql)
            .bind::<BigInt, _>(expires_at)
            .bind::<BigInt, _>(expires_at)
            .bind::<Text, _>(&client.id)
            .execute(conn)
            .map_err(AppError::from)?;
        let secret_id = uuid::Uuid::new_v4().to_string();
        let insert_sql = format!(
            "INSERT INTO application_jwt_client_secrets (id, jwt_client_id, secret_hash, created_at, expires_at, revoked_at) VALUES ({}, {}, {}, {}, {}, {})",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3),
            ph($kind, 4),
            ph($kind, 5),
            ph($kind, 6)
        );
        sql_query(insert_sql)
            .bind::<Text, _>(&secret_id)
            .bind::<Text, _>(&client.id)
            .bind::<Text, _>(secret_hash)
            .bind::<BigInt, _>($now)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .execute(conn)
            .map_err(AppError::from)?;
        let select_sql = format!(
            "{} WHERE id = {}",
            select_application_jwt_secret_sql(),
            ph($kind, 1)
        );
        sql_query(select_sql)
            .bind::<Text, _>(secret_id)
            .get_result::<ApplicationJwtClientSecretRecord>(conn)
            .map_err(AppError::from)
    }};
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize, Deserialize)]
pub struct RuntimeSettingsRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub public_base_url: String,
    #[diesel(sql_type = Text)]
    pub issuer: String,
    #[diesel(sql_type = Integer)]
    pub trust_proxy_headers: i32,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicRuntimeSettings {
    pub public_base_url: String,
    pub issuer: String,
    pub trust_proxy_headers: bool,
    pub updated_at: i64,
}

impl RuntimeSettingsRecord {
    pub fn public(&self) -> PublicRuntimeSettings {
        PublicRuntimeSettings {
            public_base_url: self.public_base_url.clone(),
            issuer: self.issuer.clone(),
            trust_proxy_headers: self.trust_proxy_headers == 1,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewRuntimeSettings {
    pub public_base_url: String,
    pub issuer: String,
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickLink {
    pub id: String,
    pub label: String,
    pub url: String,
    #[serde(default)]
    pub icon: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize, Deserialize)]
pub struct LoginSettingsRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub brand_logo_url: String,
    #[diesel(sql_type = Text)]
    pub email_domains: String,
    #[diesel(sql_type = Text)]
    pub quick_links: String,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicLoginSettings {
    pub brand_logo_url: String,
    pub email_domains: Vec<String>,
    pub quick_links: Vec<QuickLink>,
    pub updated_at: i64,
}

impl LoginSettingsRecord {
    pub fn public(&self) -> AppResult<PublicLoginSettings> {
        Ok(PublicLoginSettings {
            brand_logo_url: self.brand_logo_url.clone(),
            email_domains: util::from_json(&self.email_domains)?,
            quick_links: util::from_json(&self.quick_links)?,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewLoginSettings {
    pub brand_logo_url: String,
    pub email_domains: Vec<String>,
    pub quick_links: Vec<QuickLink>,
}

fn default_openai_quick_link() -> QuickLink {
    QuickLink {
        id: "openai".to_string(),
        label: "OpenAI".to_string(),
        url: "https://chatgpt.com/auth/login?sso=true&connection=conn_01KTR8HRA3ZQR9S3EGT32TY3WT"
            .to_string(),
        // Retained in stored data for backward-compatible deserialization;
        // the login page now derives icons from each destination URL.
        icon: String::new(),
        is_active: true,
    }
}

fn merge_missing_quick_links(
    existing: &LoginSettingsRecord,
    defaults: &[QuickLink],
) -> AppResult<Option<String>> {
    let mut links = util::from_json::<Vec<QuickLink>>(&existing.quick_links)?;
    let mut changed = false;
    for default in defaults {
        let exists = links
            .iter()
            .any(|link| link.id == default.id || link.url == default.url);
        if !exists {
            links.push(default.clone());
            changed = true;
        }
    }
    changed.then(|| util::to_json(&links)).transpose()
}

fn select_security_policy_sql() -> &'static str {
    "SELECT id, password_min_length, password_require_uppercase, password_require_lowercase, password_require_digit, password_require_symbol, password_reject_user_info, login_lockout_enabled, max_failed_login_attempts, failure_window_seconds, lockout_seconds, COALESCE(trusted_ip_cidrs, '[]') AS trusted_ip_cidrs, COALESCE(require_mfa_outside_trusted_networks, 0) AS require_mfa_outside_trusted_networks, COALESCE(allowed_ip_cidrs, '[]') AS allowed_ip_cidrs, COALESCE(blocked_ip_cidrs, '[]') AS blocked_ip_cidrs, COALESCE(allowed_email_domains, '[]') AS allowed_email_domains, COALESCE(blocked_email_domains, '[]') AS blocked_email_domains, COALESCE(captcha_enabled, 0) AS captcha_enabled, COALESCE(captcha_after_failed_attempts, 3) AS captcha_after_failed_attempts, COALESCE(captcha_ttl_seconds, 300) AS captcha_ttl_seconds, updated_at FROM security_policy"
}

fn dedupe_nonempty(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn dedupe_organization_members(
    members: Vec<OrganizationMemberInput>,
) -> Vec<OrganizationMemberInput> {
    members
        .into_iter()
        .map(|member| OrganizationMemberInput {
            user_id: member.user_id.trim().to_string(),
            role: member.role.trim().to_string(),
        })
        .filter(|member| !member.user_id.is_empty() && !member.role.is_empty())
        .map(|member| (member.user_id.clone(), member))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn normalize_permission_keys(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut keys = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        keys.insert(Permission::try_from(trimmed)?.as_str().to_string());
    }
    Ok(keys.into_iter().collect())
}

fn normalize_application_entitlement_keys(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut keys = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if value.len() > 256
            || value
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
            || value.split(':').any(str::is_empty)
        {
            return Err(AppError::BadRequest(
                "application permission key is invalid".to_string(),
            ));
        }
        keys.insert(value.to_string());
    }
    Ok(keys.into_iter().collect())
}

fn application_slug_base(client_id: &str) -> String {
    let mut base = client_id
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    while base.contains("--") {
        base = base.replace("--", "-");
    }
    base = base.trim_matches('-').to_string();
    if base.len() < 2 {
        base = format!(
            "app-{}",
            util::sha256_base64url(client_id)
                .chars()
                .take(10)
                .collect::<String>()
        );
    }
    base.truncate(54);
    if client_id.trim() != base {
        return application_slug_collision_candidate(&base, client_id);
    }
    base
}

/// Produces a deterministic, valid suffix for a sanitized client-id
/// collision. The previous allocator scanned every numeric suffix up to
/// 10,000; a short digest keeps the URL readable while making allocation
/// independent of the number of sibling applications.
fn application_slug_collision_candidate(base_slug: &str, client_id: &str) -> String {
    let suffix = util::sha256_base64url(client_id)
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(10)
        .collect::<String>();
    let mut prefix = base_slug.to_string();
    prefix.truncate(52);
    format!("{prefix}-{suffix}")
}

#[cfg(feature = "sqlite")]
fn migrate_sqlite_phone_uniqueness(conn: &mut SqliteConnection) -> AppResult<()> {
    #[derive(diesel::QueryableByName)]
    struct SchemaRow {
        #[diesel(sql_type = Text)]
        sql: String,
    }

    #[derive(diesel::QueryableByName)]
    struct IndexRow {
        #[diesel(sql_type = Text)]
        name: String,
        #[diesel(sql_type = Nullable<Text>)]
        sql: Option<String>,
    }

    let schema = sql_query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'")
        .get_result::<SchemaRow>(conn)
        .optional()
        .map_err(AppError::from)?;
    let Some(schema) = schema else {
        return Ok(());
    };

    // A column/table UNIQUE constraint requires a table rebuild in SQLite,
    // while a deployment-created index can be removed in place. Inspect both:
    // the former has no SQL entry in sqlite_master, the latter does.
    let indexes = sql_query(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'users' AND sql IS NOT NULL",
    )
    .load::<IndexRow>(conn)
    .map_err(AppError::from)?;
    let explicit_phone_unique_indexes = indexes
        .iter()
        .filter(|index| index.sql.as_deref().is_some_and(sqlite_phone_unique_index))
        .map(|index| index.name.clone())
        .collect::<Vec<_>>();
    let has_inline_phone_unique = sqlite_table_has_phone_unique_constraint(&schema.sql);

    if !has_inline_phone_unique {
        if explicit_phone_unique_indexes.is_empty() {
            return Ok(());
        }
        return conn.transaction::<(), AppError, _>(|conn| {
            for index in &explicit_phone_unique_indexes {
                let escaped = index.replace('"', "\"\"");
                conn.batch_execute(&format!("DROP INDEX \"{escaped}\""))
                    .map_err(|err| AppError::Database(err.to_string()))?;
            }
            Ok(())
        });
    }

    // Explicit deployment indexes survive the table rebuild. Recreate every
    // one except the single-column phone UNIQUE indexes being retired.
    let indexes = indexes
        .into_iter()
        .filter_map(|index| index.sql.filter(|sql| !sqlite_phone_unique_index(sql)))
        .collect::<Vec<_>>();

    conn.transaction::<(), AppError, _>(|conn| {
        conn.batch_execute(
            "CREATE TABLE users__shared_phone_migration (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT,
                phone TEXT,
                password_hash TEXT NOT NULL,
                email_verified_at INTEGER,
                phone_verified_at INTEGER,
                is_admin INTEGER NOT NULL,
                is_active INTEGER NOT NULL,
                archived_at INTEGER,
                registration_source TEXT NOT NULL DEFAULT 'local',
                last_login_at INTEGER,
                last_login_ip TEXT,
                last_oidc_client_id TEXT,
                last_login_method TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            INSERT INTO users__shared_phone_migration (
                id, email, username, display_name, phone, password_hash,
                email_verified_at, phone_verified_at, is_admin, is_active,
                archived_at, registration_source, last_login_at, last_login_ip,
                last_oidc_client_id, last_login_method, created_at, updated_at
            )
            SELECT
                id, email, username, display_name, phone, password_hash,
                email_verified_at, phone_verified_at, is_admin, is_active,
                archived_at, registration_source, last_login_at, last_login_ip,
                last_oidc_client_id, last_login_method, created_at, updated_at
            FROM users;
            DROP TABLE users;
            ALTER TABLE users__shared_phone_migration RENAME TO users;",
        )
        .map_err(|err| AppError::Database(err.to_string()))?;
        for index in &indexes {
            conn.batch_execute(index)
                .map_err(|err| AppError::Database(err.to_string()))?;
        }
        Ok(())
    })
}

#[cfg(feature = "sqlite")]
fn sqlite_table_has_phone_unique_constraint(sql: &str) -> bool {
    let normalized = sqlite_normalized_sql(sql);
    normalized.contains("unique(phone)")
        || normalized.split(',').any(|definition| {
            definition.starts_with("phone")
                && !definition.starts_with("phone_")
                && definition.contains("unique")
        })
}

#[cfg(feature = "sqlite")]
fn sqlite_phone_unique_index(sql: &str) -> bool {
    let normalized = sqlite_normalized_sql(sql);
    let Some(after_create) = normalized.strip_prefix("createuniqueindex") else {
        return false;
    };
    let after_create = after_create
        .strip_prefix("ifnotexists")
        .unwrap_or(after_create);
    let Some((_, indexed_columns)) = after_create.split_once("onusers(") else {
        return false;
    };
    let Some((column, _)) = indexed_columns.split_once(')') else {
        return false;
    };

    matches!(column, "phone" | "phoneasc" | "phonedesc") || column.starts_with("phonecollate")
}

#[cfg(feature = "sqlite")]
fn sqlite_normalized_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && !matches!(character, '`' | '"' | '[' | ']')
        })
        .collect::<String>()
        .to_ascii_lowercase()
}

#[cfg(feature = "postgres")]
fn migrate_postgres_phone_uniqueness(conn: &mut PgConnection) -> AppResult<()> {
    #[derive(diesel::QueryableByName)]
    struct ConstraintRow {
        #[diesel(sql_type = Text)]
        name: String,
    }

    let constraints = sql_query(
        "SELECT key_column_usage.constraint_name AS name
         FROM information_schema.key_column_usage
         INNER JOIN information_schema.table_constraints
           ON table_constraints.constraint_schema = key_column_usage.constraint_schema
          AND table_constraints.constraint_name = key_column_usage.constraint_name
          AND table_constraints.table_name = key_column_usage.table_name
         WHERE key_column_usage.table_schema = current_schema()
           AND key_column_usage.table_name = 'users'
           AND table_constraints.constraint_type = 'UNIQUE'
         GROUP BY key_column_usage.constraint_name
         HAVING COUNT(*) = 1 AND MAX(key_column_usage.column_name) = 'phone'",
    )
    .load::<ConstraintRow>(conn)
    .map_err(AppError::from)?;
    for constraint in constraints {
        let escaped = constraint.name.replace('"', "\"\"");
        conn.batch_execute(&format!("ALTER TABLE users DROP CONSTRAINT \"{escaped}\""))
            .map_err(|err| AppError::Database(err.to_string()))?;
    }
    Ok(())
}

#[cfg(feature = "mysql")]
fn migrate_mysql_phone_uniqueness(conn: &mut MysqlConnection) -> AppResult<()> {
    #[derive(diesel::QueryableByName)]
    struct IndexRow {
        #[diesel(sql_type = Text)]
        name: String,
    }

    let indexes = sql_query(
        "SELECT index_name AS name
         FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'users'
           AND non_unique = 0
         GROUP BY index_name
         HAVING COUNT(*) = 1 AND MAX(column_name) = 'phone'",
    )
    .load::<IndexRow>(conn)
    .map_err(AppError::from)?;
    for index in indexes {
        let escaped = index.name.replace('`', "``");
        conn.batch_execute(&format!("ALTER TABLE users DROP INDEX `{escaped}`"))
            .map_err(|err| AppError::Database(err.to_string()))?;
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
fn connect_sqlite(settings: &DatabaseSettings) -> AppResult<Db> {
    if let Some(parent) = Path::new(&settings.url).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| AppError::Database(format!("failed to create sqlite dir: {err}")))?;
    }
    let manager = ConnectionManager::<SqliteConnection>::new(settings.url.clone());
    let pool = Pool::builder()
        .max_size(settings.pool_size)
        .connection_customizer(Box::new(SqliteConnectionCustomizer))
        .build(manager)
        .map_err(|err| AppError::Database(err.to_string()))?;
    Ok(Db::Sqlite(pool))
}

#[cfg(not(feature = "sqlite"))]
fn connect_sqlite(_settings: &DatabaseSettings) -> AppResult<Db> {
    Err(AppError::Configuration(
        "database.kind=sqlite requires cargo feature `sqlite`".to_string(),
    ))
}

#[cfg(feature = "postgres")]
fn connect_postgres(settings: &DatabaseSettings) -> AppResult<Db> {
    let manager = ConnectionManager::<PgConnection>::new(settings.url.clone());
    let pool = Pool::builder()
        .max_size(settings.pool_size)
        .build(manager)
        .map_err(|err| AppError::Database(err.to_string()))?;
    Ok(Db::Postgres(pool))
}

#[cfg(not(feature = "postgres"))]
fn connect_postgres(_settings: &DatabaseSettings) -> AppResult<Db> {
    Err(AppError::Configuration(
        "database.kind=postgres requires cargo feature `postgres`".to_string(),
    ))
}

#[cfg(feature = "mysql")]
fn connect_mysql(settings: &DatabaseSettings) -> AppResult<Db> {
    let manager = ConnectionManager::<MysqlConnection>::new(settings.url.clone());
    let pool = Pool::builder()
        .max_size(settings.pool_size)
        .build(manager)
        .map_err(|err| AppError::Database(err.to_string()))?;
    Ok(Db::Mysql(pool))
}

#[cfg(not(feature = "mysql"))]
fn connect_mysql(_settings: &DatabaseSettings) -> AppResult<Db> {
    Err(AppError::Configuration(
        "database.kind=mysql requires cargo feature `mysql`".to_string(),
    ))
}

// Keep the large backend-neutral test suite before the per-database migration
// tables so the production SQL remains grouped by engine at the end of file.
#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit;

    #[test]
    fn default_quick_link_is_merged_without_overwriting_existing_links() {
        let existing_link = QuickLink {
            id: "help".to_string(),
            label: "Help".to_string(),
            url: "https://help.example".to_string(),
            icon: "help".to_string(),
            is_active: true,
        };
        let record = LoginSettingsRecord {
            id: "default".to_string(),
            brand_logo_url: String::new(),
            email_domains: "[]".to_string(),
            quick_links: util::to_json(&vec![existing_link.clone()]).unwrap(),
            updated_at: 1,
        };

        let merged = merge_missing_quick_links(&record, &[default_openai_quick_link()])
            .unwrap()
            .unwrap();
        let links = util::from_json::<Vec<QuickLink>>(&merged).unwrap();

        assert_eq!(links.len(), 2);
        assert!(links.iter().any(|link| link.id == existing_link.id));
        assert!(links.iter().any(|link| link.id == "openai"));
    }

    #[test]
    fn default_quick_link_merge_is_idempotent() {
        let openai = default_openai_quick_link();
        let record = LoginSettingsRecord {
            id: "default".to_string(),
            brand_logo_url: String::new(),
            email_domains: "[]".to_string(),
            quick_links: util::to_json(&vec![openai.clone()]).unwrap(),
            updated_at: 1,
        };

        assert!(
            merge_missing_quick_links(&record, &[openai])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn invitation_public_response_excludes_reveal_material() {
        let invitation = InvitationRecord {
            id: "invitation-id".to_string(),
            code_hash: "hash".to_string(),
            code_prefix: "AUTH-abc".to_string(),
            code_reveal_key_id: Some("signing-key-1".to_string()),
            code_reveal_ciphertext: Some("ciphertext".to_string()),
            code_type: "login".to_string(),
            login_code_level: "account_recovery".to_string(),
            allowed_client_ids: "[]".to_string(),
            organization_id: None,
            organization_role: None,
            description: Some("temporary access".to_string()),
            authorized_email: Some("visitor@example.com".to_string()),
            authorized_username: Some("visitor".to_string()),
            authorized_user_id: Some("user-id".to_string()),
            authorized_display_name: Some("Visitor".to_string()),
            expires_at: Some(1000),
            max_uses: Some(1),
            uses_count: 1,
            is_active: 1,
            created_by: Some("admin-id".to_string()),
            created_at: 1,
            updated_at: 2,
        };
        let public = invitation.public().unwrap();
        let serialized = serde_json::to_string(&public).unwrap();

        assert!(public.can_reveal);
        assert!(!serialized.contains("hash"));
        assert!(!serialized.contains("ciphertext"));
        assert!(!serialized.contains("signing-key-1"));
    }

    #[test]
    fn invitation_redemption_update_is_guarded_by_state_and_use_limit() {
        for kind in [
            DatabaseKind::Sqlite,
            DatabaseKind::Postgres,
            DatabaseKind::Mysql,
        ] {
            let sql = redeem_invitation_update_sql(kind);
            assert!(sql.contains("is_active = 1"));
            assert!(sql.contains("expires_at IS NULL OR expires_at >="));
            assert!(sql.contains("max_uses IS NULL OR uses_count < max_uses"));
        }
    }

    #[test]
    fn migration_duplicate_errors_are_ignored_only_for_idempotent_shapes() {
        assert!(is_ignorable_migration_error(
            "ALTER TABLE users ADD COLUMN archived_at BIGINT NULL",
            "Duplicate column name 'archived_at'",
        ));
        assert!(is_ignorable_migration_error(
            "CREATE INDEX idx_login_events_user_id ON login_events(user_id, login_at)",
            "Duplicate key name 'idx_login_events_user_id'",
        ));
        assert!(is_ignorable_migration_error(
            "CREATE INDEX idx_login_events_user_id ON login_events(user_id, login_at)",
            "relation \"idx_login_events_user_id\" already exists",
        ));
        assert!(is_ignorable_migration_error(
            "CREATE UNIQUE INDEX idx_users_email ON users(email)",
            "Duplicate key name 'idx_users_email'",
        ));
        assert!(!is_ignorable_migration_error(
            "CREATE TABLE users (id TEXT PRIMARY KEY)",
            "syntax error near users",
        ));
        assert!(!is_ignorable_migration_error(
            "UPDATE users SET email = 'duplicate'",
            "duplicate key value violates unique constraint",
        ));
    }

    #[test]
    fn mysql_migrations_do_not_use_text_defaults() {
        for statement in MYSQL_MIGRATIONS {
            assert!(
                !statement.contains("TEXT NOT NULL DEFAULT")
                    && !statement.contains("TEXT NULL DEFAULT"),
                "MySQL migration uses an incompatible default column type: {statement}"
            );
            assert!(
                !statement
                    .trim_start()
                    .to_ascii_uppercase()
                    .starts_with("UPDATE ")
                    && !statement
                        .trim_start()
                        .to_ascii_uppercase()
                        .contains(" MODIFY COLUMN "),
                "MySQL startup migration must not rewrite existing tables: {statement}"
            );
        }

        for statement in [
            "ALTER TABLE clients ADD COLUMN authorization_details_types TEXT NULL",
            "ALTER TABLE clients ADD COLUMN service_account_permissions TEXT NULL",
            "ALTER TABLE authorization_codes ADD COLUMN amr TEXT NULL",
            "ALTER TABLE security_policy ADD COLUMN trusted_ip_cidrs TEXT NULL",
            "ALTER TABLE security_policy ADD COLUMN allowed_ip_cidrs TEXT NULL",
            "ALTER TABLE security_policy ADD COLUMN blocked_ip_cidrs TEXT NULL",
            "ALTER TABLE security_policy ADD COLUMN allowed_email_domains TEXT NULL",
            "ALTER TABLE security_policy ADD COLUMN blocked_email_domains TEXT NULL",
            "ALTER TABLE organizations ADD COLUMN allowed_email_domains TEXT NULL",
            "ALTER TABLE external_oidc_providers ADD COLUMN email_domains TEXT NULL",
        ] {
            assert!(
                MYSQL_MIGRATIONS.contains(&statement),
                "missing nullable legacy JSON migration: {statement}"
            );
        }
    }

    #[test]
    fn login_settings_brand_logo_url_migrations_cover_all_database_engines() {
        assert!(SQLITE_MIGRATIONS.contains(
            &"ALTER TABLE login_settings ADD COLUMN brand_logo_url TEXT NOT NULL DEFAULT ''"
        ));
        assert!(POSTGRES_MIGRATIONS.contains(
            &"ALTER TABLE login_settings ADD COLUMN IF NOT EXISTS brand_logo_url TEXT NOT NULL DEFAULT ''"
        ));
        assert!(MYSQL_MIGRATIONS.contains(
            &"ALTER TABLE login_settings ADD COLUMN brand_logo_url VARCHAR(2048) NOT NULL DEFAULT ''"
        ));
    }

    #[test]
    fn client_audience_migrations_cover_all_database_engines() {
        assert!(
            SQLITE_MIGRATIONS
                .contains(&"ALTER TABLE clients ADD COLUMN audience TEXT NOT NULL DEFAULT ''")
        );
        assert!(POSTGRES_MIGRATIONS.contains(
            &"ALTER TABLE clients ADD COLUMN IF NOT EXISTS audience TEXT NOT NULL DEFAULT ''"
        ));
        assert!(MYSQL_MIGRATIONS.contains(
            &"ALTER TABLE clients ADD COLUMN audience VARCHAR(2048) NOT NULL DEFAULT ''"
        ));
    }

    #[test]
    fn application_authorization_profile_migrations_cover_all_database_engines() {
        let required_tables = [
            "application_authorization_profiles",
            "application_authorization_migration_state",
            "application_permission_definitions",
            "application_profile_roles",
            "application_profile_user_roles",
            "application_profile_group_roles",
            "application_profile_organization_roles",
            "application_profile_permission_overrides",
        ];
        for (kind, migrations) in [
            (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
            (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
            (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
        ] {
            for table in required_tables {
                assert!(
                    migrations.iter().any(|statement| {
                        statement.contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
                    }),
                    "{kind:?} is missing {table}"
                );
            }
        }
    }

    #[test]
    fn application_discovery_idempotency_migrations_cover_all_database_engines() {
        for (kind, migrations) in [
            (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
            (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
            (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
        ] {
            assert!(
                migrations.iter().any(|statement| {
                    statement
                        .contains("CREATE TABLE IF NOT EXISTS application_discovery_idempotency")
                        && statement.contains("claim_token")
                        && statement.contains("request_hash")
                }),
                "{kind:?} is missing application discovery idempotency storage"
            );
        }
    }

    #[test]
    fn billing_migrations_cover_wallet_orders_refunds_and_all_database_engines() {
        let required_tables = [
            "application_billing_settings",
            "wallet_accounts",
            "wallet_transactions",
            "wallet_entries",
            "wallet_holds",
            "payment_orders",
            "payment_refunds",
        ];
        for (kind, migrations) in [
            (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
            (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
            (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
        ] {
            for table in required_tables {
                assert!(
                    migrations.iter().any(|statement| {
                        statement.contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
                    }),
                    "{kind:?} is missing {table}"
                );
            }
            assert!(
                migrations.iter().any(|statement| {
                    statement.contains("idempotency_key") && statement.contains("payment_refunds")
                }),
                "{kind:?} is missing payment refund idempotency compatibility"
            );
            assert!(
                migrations.iter().any(|statement| {
                    statement.contains("payment_orders")
                        && statement.contains("idempotency_key")
                        && statement.contains("UNIQUE")
                }),
                "{kind:?} is missing payment order idempotency uniqueness"
            );
        }
    }

    #[test]
    fn application_jwt_migrations_cover_clients_secrets_and_bound_codes() {
        for (kind, migrations) in [
            (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
            (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
            (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
        ] {
            let has_code_table = migrations.iter().any(|statement| {
                statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_codes")
            });
            let has_client_table = migrations.iter().any(|statement| {
                statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_clients")
            });
            let has_secret_table = migrations.iter().any(|statement| {
                statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_client_secrets")
            });
            assert!(has_code_table, "{kind:?} is missing application JWT codes");
            assert!(
                has_client_table,
                "{kind:?} is missing application JWT clients"
            );
            assert!(
                has_secret_table,
                "{kind:?} is missing application JWT secrets"
            );

            let code_schema = migrations
                .iter()
                .find(|statement| {
                    statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_codes")
                })
                .expect("application JWT code table must have a create statement");
            assert!(
                code_schema.contains("client_id")
                    && code_schema.contains("application_id")
                    && code_schema.contains("code_challenge"),
                "{kind:?} application JWT codes must bind client and PKCE"
            );

            let secret_schema = migrations
                .iter()
                .find(|statement| {
                    statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_client_secrets")
                })
                .expect("application JWT secret table must have a create statement");
            assert!(secret_schema.contains("jwt_client_id"));
            assert!(secret_schema.contains("secret_hash"));
            assert!(secret_schema.contains("expires_at"));
            assert!(secret_schema.contains("revoked_at"));
        }
    }

    #[test]
    fn application_scim_token_migrations_cover_all_database_engines() {
        for (kind, migrations) in [
            (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
            (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
            (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
        ] {
            let schema = migrations
                .iter()
                .find(|statement| {
                    statement.contains("CREATE TABLE IF NOT EXISTS application_scim_tokens")
                })
                .expect("application SCIM token table must have a create statement");
            for column in [
                "application_id",
                "token_prefix",
                "token_hash",
                "scopes",
                "expires_at",
                "revoked_at",
                "last_used_at",
            ] {
                assert!(
                    schema.contains(column),
                    "{kind:?} SCIM token schema missing {column}"
                );
            }
            assert!(
                migrations.iter().any(|statement| {
                    statement.contains("idx_application_scim_tokens_application")
                }),
                "{kind:?} is missing the application SCIM token index"
            );
        }
    }

    #[test]
    fn directory_sync_migrations_cover_runs_checkpoints_memberships_and_groups() {
        for (kind, migrations) in [
            (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
            (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
            (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
        ] {
            for table in [
                "directory_sync_runs",
                "directory_sync_leases",
                "directory_sync_checkpoints",
                "directory_sync_memberships",
                "directory_sync_groups",
            ] {
                assert!(
                    migrations.iter().any(|statement| {
                        statement.contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
                    }),
                    "{kind:?} is missing directory sync table {table}"
                );
            }
            let run_schema = migrations
                .iter()
                .find(|statement| {
                    statement.contains("CREATE TABLE IF NOT EXISTS directory_sync_runs")
                })
                .expect("directory sync run table must have a create statement");
            for column in [
                "application_id",
                "provider_id",
                "status",
                "total_seen",
                "created_count",
                "updated_count",
                "disabled_count",
                "cursor",
            ] {
                assert!(
                    run_schema.contains(column),
                    "{kind:?} directory sync run schema missing {column}"
                );
            }
            assert!(
                migrations
                    .iter()
                    .any(|statement| { statement.contains("idx_directory_sync_runs_application") }),
                "{kind:?} is missing the directory sync run index"
            );
            assert!(
                migrations
                    .iter()
                    .any(|statement| { statement.contains("idx_directory_sync_leases_expiry") }),
                "{kind:?} is missing the directory sync lease expiry index"
            );
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn directory_sync_leases_serialize_runs_and_reclaim_expired_workers() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        let left = db.clone();
        let right = db.clone();
        let (left, right) = tokio::join!(
            left.start_directory_sync_run("lease-app", "lease-provider"),
            right.start_directory_sync_run("lease-app", "lease-provider")
        );
        assert!(left.is_ok() ^ right.is_ok());
        let run = left.or(right).unwrap();
        assert!(
            db.renew_directory_sync_lease("lease-app", "lease-provider", &run.id)
                .await
                .is_ok()
        );

        let expired_at = util::now_ts() - 1;
        with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "UPDATE directory_sync_leases SET expires_at = {} WHERE application_id = {} AND provider_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<BigInt, _>(expired_at)
                .bind::<Text, _>("lease-app")
                .bind::<Text, _>("lease-provider")
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

        let reclaimed = db
            .start_directory_sync_run("lease-app", "lease-provider")
            .await
            .unwrap();
        assert_ne!(reclaimed.id, run.id);
        assert_eq!(
            db.list_directory_sync_runs("lease-app", 20)
                .await
                .unwrap()
                .into_iter()
                .find(|candidate| candidate.id == run.id)
                .unwrap()
                .status,
            "failed"
        );
        assert!(
            db.renew_directory_sync_lease("lease-app", "lease-provider", &run.id)
                .await
                .is_err()
        );
        db.finish_directory_sync_run(&reclaimed.id, "succeeded", 0, 0, 0, 0, None, None)
            .await
            .unwrap();
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ldap_provider_organization_migrations_cover_all_database_engines() {
        for (kind, migrations, organization_definition) in [
            (
                DatabaseKind::Sqlite,
                SQLITE_MIGRATIONS,
                "organization_id TEXT",
            ),
            (
                DatabaseKind::Postgres,
                POSTGRES_MIGRATIONS,
                "organization_id TEXT",
            ),
            (
                DatabaseKind::Mysql,
                MYSQL_MIGRATIONS,
                "organization_id VARCHAR(64) NULL",
            ),
        ] {
            let schema = migrations
                .iter()
                .find(|statement| statement.contains("CREATE TABLE IF NOT EXISTS ldap_providers"))
                .expect("LDAP provider table must have a create statement");
            assert!(
                schema.contains(organization_definition),
                "{kind:?} LDAP provider schema must include organization ownership"
            );
            assert!(
                migrations.iter().any(|statement| {
                    statement.contains("ALTER TABLE ldap_providers ADD COLUMN")
                        && statement.contains("organization_id")
                }),
                "{kind:?} must migrate existing LDAP provider tables"
            );
            assert!(
                migrations
                    .iter()
                    .any(|statement| { statement.contains("idx_ldap_providers_organization") }),
                "{kind:?} is missing the LDAP provider organization index"
            );
        }
        assert!(external_identities::select_ldap_provider_sql().contains("organization_id"));
    }

    #[test]
    fn user_identity_conflicts_cover_email_username_and_current_user_exclusion() {
        for kind in [
            DatabaseKind::Sqlite,
            DatabaseKind::Postgres,
            DatabaseKind::Mysql,
        ] {
            let sql = count_user_identity_conflicts_sql(kind);
            assert!(sql.contains("email ="));
            assert!(sql.contains("username ="));
            assert!(!sql.contains("phone"));
            assert!(sql.contains("id <>"));
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn scim_user_mutation_rolls_back_profile_password_and_active_state_together() {
        let (db, path) = sqlite_test_db().await;
        let first = db
            .insert_user(test_user("scim-first@example.test", "scim-first"))
            .await
            .unwrap();
        let second = db
            .insert_user(test_user("scim-second@example.test", "scim-second"))
            .await
            .unwrap();

        assert!(
            db.apply_scim_user_mutation(ScimUserMutationPlan {
                id: first.id.clone(),
                expected_version: first.scim_concurrency_version(),
                email: second.email.clone(),
                username: "scim-first-renamed".to_string(),
                display_name: Some("would roll back".to_string()),
                phone: None,
                is_admin: false,
                is_active: false,
                password_hash: Some("would-also-roll-back".to_string()),
                scope: None,
            })
            .await
            .is_err()
        );
        let unchanged = db.find_user_by_id(&first.id).await.unwrap().unwrap();
        assert_eq!(unchanged.email, "scim-first@example.test");
        assert_eq!(unchanged.username, "scim-first");
        assert_eq!(unchanged.display_name, None);
        assert!(unchanged.is_active == 1);
        assert_eq!(unchanged.password_hash, "test-hash");
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn password_replacement_revokes_sessions_and_audits_atomically() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user(
                "credential-rotation@example.test",
                "credential-rotation",
            ))
            .await
            .unwrap();
        let (session, _) = db
            .insert_session(&user.id, 600, SessionMetadata::default())
            .await
            .unwrap();

        let updated = db
            .replace_user_password_with_audit(
                &user.id,
                "rotated-password-hash".to_string(),
                crate::audit::management_event(
                    "credential-actor",
                    "user.password.set",
                    "user",
                    Some(user.id.clone()),
                    serde_json::json!({}),
                ),
            )
            .await
            .unwrap();

        assert_eq!(updated.password_hash, "rotated-password-hash");
        assert!(db.find_session(&session.id).await.unwrap().is_none());
        assert!(
            db.list_audit_events(20)
                .await
                .unwrap()
                .iter()
                .any(|event| event.action == "user.password.set")
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn mfa_enable_rolls_back_setup_and_recovery_codes_when_audit_fails() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("mfa-atomic@example.test", "mfa-atomic"))
            .await
            .unwrap();
        let setup = db
            .create_mfa_totp_setup(&user.id, "encrypted-totp-secret".to_string(), 300)
            .await
            .unwrap();
        with_conn!(db.clone(), |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_mfa_audit_outbox BEFORE INSERT ON audit_webhook_outbox BEGIN SELECT RAISE(ABORT, 'forced mfa audit failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();

        let result = db
            .confirm_totp_setup_with_audit(
                &user.id,
                &setup.id,
                vec!["recovery-hash".to_string()],
                crate::audit::management_event(
                    user.id.clone(),
                    "mfa.totp.enable",
                    "user",
                    Some(user.id.clone()),
                    serde_json::json!({ "method": "totp" }),
                ),
            )
            .await;
        assert!(
            matches!(result, Err(AppError::Database(message)) if message.contains("forced mfa audit failure"))
        );

        with_conn!(db.clone(), |conn, _kind| {
            conn.batch_execute("DROP TRIGGER fail_mfa_audit_outbox")
                .map_err(AppError::from)
        })
        .unwrap();
        assert!(db.find_mfa_totp_setup(&setup.id).await.unwrap().is_some());
        assert!(db.find_totp_method(&user.id).await.unwrap().is_none());
        assert!(db.list_recovery_codes(&user.id).await.unwrap().is_empty());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn organization_creation_rolls_back_owner_and_context_when_audit_fails() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user(
                "organization-atomic@example.test",
                "organization-atomic",
            ))
            .await
            .unwrap();
        with_conn!(db.clone(), |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_organization_audit_outbox BEFORE INSERT ON audit_webhook_outbox BEGIN SELECT RAISE(ABORT, 'forced organization audit failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();
        let result = db
            .create_organization_with_owner_and_audit(
                NewOrganization {
                    slug: "organization-atomic".to_string(),
                    name: "Organization Atomic".to_string(),
                    kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                    description: None,
                    allowed_email_domains: Vec::new(),
                    is_active: true,
                },
                &user.id,
                crate::audit::management_event(
                    user.id.clone(),
                    "organization.self_service_create",
                    "organization",
                    None,
                    serde_json::json!({ "slug": "organization-atomic" }),
                ),
            )
            .await;
        assert!(
            matches!(result, Err(AppError::Database(message)) if message.contains("forced organization audit failure"))
        );
        with_conn!(db.clone(), |conn, _kind| {
            conn.batch_execute("DROP TRIGGER fail_organization_audit_outbox")
                .map_err(AppError::from)
        })
        .unwrap();
        assert!(
            db.list_organizations()
                .await
                .unwrap()
                .into_iter()
                .all(|organization| organization.slug != "organization-atomic")
        );
        assert!(
            db.active_user_organization(&user.id)
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn audit_webhook_outbox_claim_retry_and_expired_lease_recovery_are_fenced() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        db.insert_audit_event(crate::audit::management_event(
            "outbox-actor",
            "outbox.test",
            "test",
            Some("outbox-target".to_string()),
            serde_json::json!({}),
        ))
        .await
        .unwrap();

        let first = db.claim_audit_webhook_outbox(10).await.unwrap();
        assert_eq!(first.len(), 1);
        let first_id = first[0].id.clone();
        let first_attempts = first[0].attempts;
        let owner = first[0].lease_owner.clone().unwrap();
        assert!(
            !db.complete_audit_webhook_outbox(&first_id, "wrong-owner")
                .await
                .unwrap()
        );
        assert!(
            db.retry_audit_webhook_outbox(
                &first_id,
                &owner,
                first_attempts,
                "temporary failure".into()
            )
            .await
            .unwrap()
        );

        // Backoff keeps the row out of the next claim until it is due.
        let first_id_for_future = first_id.clone();
        with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "UPDATE audit_webhook_outbox SET next_attempt_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(util::now_ts() + 60)
                .bind::<Text, _>(first_id_for_future)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();
        assert!(db.claim_audit_webhook_outbox(10).await.unwrap().is_empty());
        let first_id_for_due = first_id.clone();
        with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "UPDATE audit_webhook_outbox SET next_attempt_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(util::now_ts() - 1)
                .bind::<Text, _>(first_id_for_due)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

        let second = db.claim_audit_webhook_outbox(10).await.unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].attempts, 1);
        let second_id = second[0].id.clone();
        let second_owner = second[0].lease_owner.clone().unwrap();

        // A worker that stopped without acknowledging the row is reclaimed
        // by the next claimant after its lease expires.
        let second_id_for_expiry = second_id.clone();
        with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "UPDATE audit_webhook_outbox SET lease_expires_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(util::now_ts() - 1)
                .bind::<Text, _>(second_id_for_expiry)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();
        let reclaimed = db.claim_audit_webhook_outbox(10).await.unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].id, second_id);
        assert_ne!(
            reclaimed[0].lease_owner.as_deref(),
            Some(second_owner.as_str())
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn scim_user_mutation_rejects_a_stale_row_snapshot() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("scim-cas@example.test", "scim-cas"))
            .await
            .unwrap();
        let expected_version = user.scim_concurrency_version();
        db.set_user_password(&user.id, "new-password-hash".to_string())
            .await
            .unwrap();

        let result = db
            .apply_scim_user_mutation(ScimUserMutationPlan {
                id: user.id.clone(),
                expected_version,
                email: "scim-cas-renamed@example.test".to_string(),
                username: "scim-cas-renamed".to_string(),
                display_name: user.display_name.clone(),
                phone: user.phone.clone(),
                is_admin: user.is_admin == 1,
                is_active: user.is_active == 1,
                password_hash: None,
                scope: None,
            })
            .await;
        assert!(matches!(
            result,
            Err(AppError::OAuth {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        let unchanged = db.find_user_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(unchanged.email, "scim-cas@example.test");
        assert_eq!(unchanged.username, "scim-cas");
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn scim_user_mutation_rechecks_application_scope_inside_write_transaction() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("scim-scope", "SCIM Scope"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "scim-scope-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let user = db
            .insert_user(test_user("scim-scope@example.test", "scim-scope"))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &user.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        let expected_version = user.scim_concurrency_version();
        let user_id = user.id.clone();
        let organization_id = organization.id.clone();
        let application_id = application.id.clone();
        let sql_user_id = user_id.clone();
        let sql_organization_id = organization_id.clone();
        with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "DELETE FROM organization_members WHERE organization_id = {} AND user_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(&sql_organization_id)
                .bind::<Text, _>(&sql_user_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

        let result = db
            .apply_scim_user_mutation(ScimUserMutationPlan {
                id: user_id.clone(),
                expected_version,
                email: "scim-scope-renamed@example.test".to_string(),
                username: "scim-scope-renamed".to_string(),
                display_name: user.display_name.clone(),
                phone: user.phone.clone(),
                is_admin: user.is_admin == 1,
                is_active: user.is_active == 1,
                password_hash: None,
                scope: Some(ScimUserMutationScope {
                    application_id: Some(application_id),
                    organization_id: Some(organization_id),
                }),
            })
            .await;
        assert!(matches!(
            result,
            Err(AppError::OAuth {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        let unchanged = db.find_user_by_id(&user_id).await.unwrap().unwrap();
        assert_eq!(unchanged.email, "scim-scope@example.test");
        assert_eq!(unchanged.username, "scim-scope");

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn scim_group_patch_rejects_a_stale_aggregate_version() {
        let (db, path) = sqlite_test_db().await;
        let group = db
            .insert_group(NewGroup {
                name: "SCIM CAS group".to_string(),
                description: None,
            })
            .await
            .unwrap();
        let first = db
            .apply_group_patch_plan(GroupPatchPlan {
                application_id: None,
                group_id: group.id.clone(),
                name: "SCIM CAS group v2".to_string(),
                description: None,
                member_ids: Vec::new(),
                create: false,
                expected_version: Some(group.version),
            })
            .await
            .unwrap();
        assert_eq!(first.version, group.version + 1);
        let result = db
            .apply_group_patch_plan(GroupPatchPlan {
                application_id: None,
                group_id: group.id.clone(),
                name: "stale overwrite".to_string(),
                description: None,
                member_ids: Vec::new(),
                create: false,
                expected_version: Some(group.version),
            })
            .await;
        assert!(matches!(
            result,
            Err(AppError::OAuth {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        assert_eq!(
            db.find_group_by_id(&group.id).await.unwrap().unwrap().name,
            "SCIM CAS group v2"
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_phone_uniqueness_migration_allows_shared_phone_insert_and_update() {
        for (case_name, phone_definition, explicit_phone_index) in [
            ("inline unique constraint", "phone TEXT UNIQUE", false),
            ("explicit unique index", "phone TEXT", true),
        ] {
            let mut conn = SqliteConnection::establish(":memory:").unwrap();
            let explicit_index_sql = explicit_phone_index.then_some(
                "CREATE UNIQUE INDEX IF NOT EXISTS \"legacy_users_phone_unique\" ON \"users\" (\"phone\" DESC);",
            );
            conn.batch_execute(&format!(
                "CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT,
                    {phone_definition},
                    password_hash TEXT NOT NULL,
                    email_verified_at INTEGER,
                    phone_verified_at INTEGER,
                    is_admin INTEGER NOT NULL,
                    is_active INTEGER NOT NULL,
                    archived_at INTEGER,
                    registration_source TEXT NOT NULL DEFAULT 'local',
                    last_login_at INTEGER,
                    last_login_ip TEXT,
                    last_oidc_client_id TEXT,
                    last_login_method TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                {}
                INSERT INTO users (id, email, username, phone, password_hash, is_admin, is_active, registration_source, created_at, updated_at)
                VALUES ('first', 'first@example.com', 'first', '+15550000000', 'hash', 0, 1, 'local', 1, 1);",
                explicit_index_sql.unwrap_or_default(),
            ))
            .unwrap();

            migrate_sqlite_phone_uniqueness(&mut conn).unwrap();
            migrate_sqlite_phone_uniqueness(&mut conn).unwrap();

            if explicit_phone_index {
                let index_count = sql_query(
                    "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'index' AND name = 'legacy_users_phone_unique'",
                )
                .get_result::<CountRow>(&mut conn)
                .unwrap()
                .count;
                assert_eq!(index_count, 0, "{case_name}");
            }

            conn.batch_execute(
                "INSERT INTO users (id, email, username, phone, password_hash, is_admin, is_active, registration_source, created_at, updated_at)
                 VALUES ('second', 'second@example.com', 'second', '+15550000000', 'hash', 0, 1, 'local', 1, 1);
                 INSERT INTO users (id, email, username, phone, password_hash, is_admin, is_active, registration_source, created_at, updated_at)
                 VALUES ('third', 'third@example.com', 'third', '+15551111111', 'hash', 0, 1, 'local', 1, 1);
                 UPDATE users SET phone = '+15550000000' WHERE id = 'third';",
            )
            .unwrap();
            let shared_phone_count =
                sql_query("SELECT COUNT(*) AS count FROM users WHERE phone = '+15550000000'")
                    .get_result::<CountRow>(&mut conn)
                    .unwrap()
                    .count;
            assert_eq!(shared_phone_count, 3, "{case_name}");
        }
    }

    #[test]
    fn first_user_registration_state_is_rechecked_inside_transaction() {
        assert!(ensure_first_user_registration_state(true, 0).is_ok());
        assert!(ensure_first_user_registration_state(false, 10).is_ok());
        assert!(matches!(
            ensure_first_user_registration_state(true, 1),
            Err(AppError::BadRequest(_))
        ));
        assert_eq!(count_all_users_sql(), "SELECT COUNT(*) AS count FROM users");
    }

    #[test]
    fn first_registered_user_admin_is_an_invariant() {
        assert!(registered_user_is_admin(true));
        assert!(!registered_user_is_admin(false));

        let settings = RegistrationSettingsRecord {
            id: "default".to_string(),
            allow_password_registration: 1,
            require_email_verification: 0,
            require_phone_verification: 0,
            allow_external_oidc_registration: 1,
            require_invitation: 0,
            first_user_direct_admin: 0,
            default_user_active: 1,
            updated_at: 1,
        };
        assert!(settings.public().first_user_direct_admin);
    }

    #[test]
    fn external_oidc_user_creation_can_check_existing_identity_inside_transaction() {
        for kind in [
            DatabaseKind::Sqlite,
            DatabaseKind::Postgres,
            DatabaseKind::Mysql,
        ] {
            let sql = external_identities::count_linked_identity_sql(kind);
            assert!(sql.contains("SELECT COUNT(*) AS count FROM linked_identities"));
            assert!(sql.contains("provider_slug ="));
            assert!(sql.contains("external_subject ="));
        }
    }

    #[test]
    fn verification_code_sql_targets_latest_unconsumed_code() {
        for kind in [
            DatabaseKind::Sqlite,
            DatabaseKind::Postgres,
            DatabaseKind::Mysql,
        ] {
            let select_sql = select_latest_verification_code_sql(kind);
            assert!(select_sql.contains("channel ="));
            assert!(select_sql.contains("target ="));
            assert!(select_sql.contains("purpose ="));
            assert!(select_sql.contains("consumed_at IS NULL"));
            assert!(select_sql.contains("ORDER BY created_at DESC, id DESC LIMIT 1"));

            let consume_sql = consume_verification_code_sql(kind);
            assert!(consume_sql.contains("SET consumed_at ="));
            assert!(consume_sql.contains("consumed_at IS NULL"));
        }
    }

    #[test]
    fn verification_resend_policy_uses_latest_issue_time() {
        let mut latest = verification_record("latest", "hash", 0, 5, 2_000);
        latest.created_at = 1_000;
        assert!(ensure_verification_resend_allowed(Some(&latest), 1_060, 60).is_ok());
        assert!(ensure_verification_resend_allowed(None, 1_000, 60).is_ok());
        assert!(matches!(
            ensure_verification_resend_allowed(Some(&latest), 1_030, 60),
            Err(AppError::BadRequest(message))
                if message == "verification code was sent too recently; retry after 30 seconds"
        ));
    }

    #[test]
    fn verification_code_verifier_distinguishes_code_states() {
        let now = 1_000;
        let code_hash = util::token_hash("123456");
        let valid = verification_record("code-id", &code_hash, 0, 5, now + 60);

        assert_eq!(
            valid.verify_hash(&code_hash, now).unwrap(),
            VerificationCodeDecision::Accepted("code-id".to_string())
        );
        assert_eq!(
            valid.verify_hash(&util::token_hash("000000"), now).unwrap(),
            VerificationCodeDecision::RejectedAttempt("code-id".to_string())
        );
        assert!(matches!(
            verification_record("expired", &code_hash, 0, 5, now - 1).verify_hash(&code_hash, now),
            Err(AppError::BadRequest(message)) if message == "verification code expired"
        ));
        assert!(matches!(
            verification_record("attempts", &code_hash, 5, 5, now + 60)
                .verify_hash(&code_hash, now),
            Err(AppError::BadRequest(message)) if message == "verification code attempts exceeded"
        ));
    }

    fn verification_record(
        id: &str,
        code_hash: &str,
        attempts: i32,
        max_attempts: i32,
        expires_at: i64,
    ) -> VerificationCodeRecord {
        VerificationCodeRecord {
            id: id.to_string(),
            channel: "email".to_string(),
            target: "user@example.com".to_string(),
            purpose: "registration".to_string(),
            code_hash: code_hash.to_string(),
            attempts,
            max_attempts,
            expires_at,
            consumed_at: None,
            created_at: 1,
        }
    }

    #[cfg(feature = "sqlite")]
    fn test_user(email: &str, username: &str) -> NewUser {
        NewUser {
            email: email.to_string(),
            username: username.to_string(),
            display_name: None,
            phone: None,
            password_hash: "test-hash".to_string(),
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: false,
            is_active: true,
            archived_at: None,
        }
    }

    #[cfg(feature = "sqlite")]
    fn test_bulk_user(
        email: &str,
        username: &str,
        organization_id: Option<&str>,
        organization_role: Option<&str>,
    ) -> NewBulkProvisionedUser {
        NewBulkProvisionedUser {
            user: test_user(email, username),
            organization_id: organization_id.map(ToOwned::to_owned),
            organization_role: organization_role.map(ToOwned::to_owned),
        }
    }

    #[cfg(feature = "sqlite")]
    fn test_invitation(
        code_type: AuthorizationCodeType,
        login_code_level: LoginCodeLevel,
        authorized_username: Option<&str>,
        authorized_user_id: Option<&str>,
        allowed_client_ids: Vec<String>,
    ) -> NewInvitation {
        NewInvitation {
            code_type,
            login_code_level,
            allowed_client_ids,
            organization_id: None,
            organization_role: None,
            description: None,
            authorized_email: None,
            authorized_username: authorized_username.map(ToOwned::to_owned),
            authorized_user_id: authorized_user_id.map(ToOwned::to_owned),
            authorized_display_name: None,
            expires_at: None,
            max_uses: None,
            is_active: true,
            created_by: None,
        }
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite_test_db() -> (Db, std::path::PathBuf) {
        sqlite_test_db_with_pool_size(1).await
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite_test_db_with_pool_size(pool_size: u32) -> (Db, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("gpt-sso-test-{}.sqlite3", uuid::Uuid::new_v4()));
        let db = connect_sqlite(&DatabaseSettings {
            kind: DatabaseKind::Sqlite,
            url: path.to_string_lossy().into_owned(),
            pool_size,
            run_migrations: true,
        })
        .unwrap();
        db.migrate().await.unwrap();
        (db, path)
    }

    #[cfg(feature = "sqlite")]
    async fn default_authorization_profile(
        db: &Db,
        application_id: &str,
    ) -> ApplicationAuthorizationProfileRecord {
        db.find_application_authorization_profile(application_id, "default")
            .await
            .unwrap()
            .expect("application migrations create a default authorization profile")
    }

    #[cfg(feature = "sqlite")]
    async fn replace_test_authorization_bindings(
        db: &Db,
        application_id: &str,
        profile_id: &str,
        update: AuthorizationBindingsUpdate,
    ) {
        db.replace_application_authorization_bindings_with_audit(
            application_id,
            profile_id,
            update,
            audit::management_event(
                "authorization-profile-test",
                "application.authorization_profile.bindings.test",
                "application_authorization_profile",
                Some(profile_id.to_string()),
                serde_json::json!({ "application_id": application_id }),
            ),
        )
        .await
        .unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn mutation_receipts_claim_once_and_preserve_replay_metadata() {
        let (db, path) = sqlite_test_db().await;
        let first = db
            .claim_mutation_receipt(
                "dedupe-receipt-test",
                "session:test",
                "POST",
                "/api/admin/applications",
                "key-1",
                "request-a",
            )
            .await
            .unwrap();
        let second = db
            .claim_mutation_receipt(
                "dedupe-receipt-test",
                "session:test",
                "POST",
                "/api/admin/applications",
                "key-1",
                "request-a",
            )
            .await
            .unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(second.status, "in_progress");
        assert_eq!(second.owner_token, first.owner_token);

        assert!(
            db.finalize_mutation_receipt(
                &first.id,
                first.owner_token.as_deref().unwrap(),
                "committed",
                200,
                Some(r#"{"id":"application-1"}"#.to_string()),
                Some("application/json".to_string()),
                None,
            )
            .await
            .unwrap()
        );
        let completed = db
            .find_mutation_receipt(&first.id, "session:test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completed.status, "committed");
        assert_eq!(completed.response_status, Some(200));
        assert_eq!(
            completed.response_content_type.as_deref(),
            Some("application/json")
        );
        assert!(completed.response_body.is_some());

        let same_key_different_request = db
            .claim_mutation_receipt(
                "dedupe-receipt-test",
                "session:test",
                "POST",
                "/api/admin/applications",
                "key-1",
                "request-b",
            )
            .await
            .unwrap();
        assert_eq!(same_key_different_request.id, first.id);
        assert_eq!(same_key_different_request.request_hash, "request-a");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn mutation_receipt_reclaim_fences_the_old_owner() {
        let (db, path) = sqlite_test_db().await;
        let first = db
            .claim_mutation_receipt_with_owner(
                "reclaim-receipt-test",
                "session:test",
                "POST",
                "/api/admin/applications",
                "key-1",
                "request-a",
                "owner-a",
            )
            .await
            .unwrap();

        let first_id = first.id.clone();
        with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "UPDATE mutation_receipts SET lease_expires_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(util::now_ts() - 1)
                .bind::<Text, _>(&first_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

        let reclaimed = db
            .claim_mutation_receipt_with_owner(
                "reclaim-receipt-test",
                "session:test",
                "POST",
                "/api/admin/applications",
                "key-1",
                "request-a",
                "owner-b",
            )
            .await
            .unwrap();
        assert_eq!(reclaimed.id, first.id);
        assert_eq!(reclaimed.owner_token.as_deref(), Some("owner-b"));
        assert!(reclaimed.lease_expires_at.unwrap() > util::now_ts());

        assert!(
            !db.finalize_mutation_receipt(
                &first.id,
                "owner-a",
                "committed",
                200,
                Some("old".to_string()),
                None,
                None,
            )
            .await
            .unwrap()
        );
        assert!(
            db.finalize_mutation_receipt(
                &first.id,
                "owner-b",
                "committed",
                200,
                Some("new".to_string()),
                None,
                None,
            )
            .await
            .unwrap()
        );
        let completed = db
            .find_mutation_receipt(&first.id, "session:test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completed.response_body.as_deref(), Some("new"));
        assert!(completed.owner_token.is_none());
        assert!(completed.lease_expires_at.is_none());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_discovery_idempotency_claims_and_replays_completed_result() {
        let (db, path) = sqlite_test_db().await;
        let first = db
            .claim_application_discovery_idempotency(
                "org-1",
                "request-1",
                "hash-1",
                "https://example.test",
            )
            .await
            .unwrap();
        let claim_token = match first {
            ApplicationDiscoveryIdempotencyClaim::Claimed { claim_token } => claim_token,
            other => panic!("expected a new claim, got {other:?}"),
        };
        assert_eq!(
            db.claim_application_discovery_idempotency(
                "org-1",
                "request-1",
                "hash-1",
                "https://example.test",
            )
            .await
            .unwrap(),
            ApplicationDiscoveryIdempotencyClaim::InProgress
        );
        db.complete_application_discovery_idempotency(
            "org-1",
            "request-1",
            &claim_token,
            "application-1",
        )
        .await
        .unwrap();
        assert_eq!(
            db.claim_application_discovery_idempotency(
                "org-1",
                "request-1",
                "hash-1",
                "https://example.test",
            )
            .await
            .unwrap(),
            ApplicationDiscoveryIdempotencyClaim::Completed {
                application_id: "application-1".to_string()
            }
        );
        assert!(matches!(
            db.claim_application_discovery_idempotency(
                "org-1",
                "request-1",
                "different-hash",
                "https://example.test",
            )
            .await,
            Err(AppError::BadRequest(_))
        ));
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn billing_wallet_lifecycle_is_atomic_idempotent_and_non_negative() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("billing@example.com", "billing-user"))
            .await
            .unwrap();
        let application_id = "billing-application";
        let global = db
            .ensure_user_wallet_account(&user.id, "CNY")
            .await
            .unwrap();
        let application_wallet = db
            .ensure_application_wallet_account(&user.id, application_id, "CNY")
            .await
            .unwrap();
        let settlement = db
            .ensure_settlement_wallet_account(application_id, "CNY")
            .await
            .unwrap();

        db.adjust_wallet(
            &global.id,
            Some(&user.id),
            None,
            "CNY",
            10_000,
            "seed-balance",
            serde_json::json!({"test": true}),
        )
        .await
        .unwrap();

        let hold = db
            .reserve_wallet_hold(
                &global.id,
                &user.id,
                application_id,
                "CNY",
                4_000,
                "charge-1",
                "reserve-1",
                util::now_ts() + 900,
            )
            .await
            .unwrap();
        let duplicate_hold = db
            .reserve_wallet_hold(
                &global.id,
                &user.id,
                application_id,
                "CNY",
                4_000,
                "charge-1",
                "reserve-1",
                util::now_ts() + 900,
            )
            .await
            .unwrap();
        assert_eq!(hold.id, duplicate_hold.id);
        let held_global = db
            .ensure_user_wallet_account(&user.id, "CNY")
            .await
            .unwrap();
        assert_eq!(held_global.available_minor, 6_000);
        assert_eq!(held_global.reserved_minor, 4_000);

        let committed_hold = db
            .commit_wallet_hold(&hold.id, &settlement.id, "commit-1")
            .await
            .unwrap();
        assert_eq!(committed_hold.status, "committed");
        let duplicate_commit = db
            .commit_wallet_hold(&hold.id, &settlement.id, "commit-2")
            .await
            .unwrap();
        assert_eq!(duplicate_commit.id, hold.id);
        let commit_transaction = db
            .find_wallet_transaction_by_operation("commit", "commit-1")
            .await
            .unwrap()
            .unwrap();

        let first_charge_refund = db
            .refund_committed_charge(&commit_transaction.id, &user.id, 1_000, "charge-refund-1")
            .await
            .unwrap();
        let duplicate_charge_refund = db
            .refund_committed_charge(&commit_transaction.id, &user.id, 1_000, "charge-refund-1")
            .await
            .unwrap();
        assert_eq!(first_charge_refund.id, duplicate_charge_refund.id);
        db.refund_committed_charge(&commit_transaction.id, &user.id, 3_000, "charge-refund-2")
            .await
            .unwrap();
        assert!(
            db.refund_committed_charge(&commit_transaction.id, &user.id, 1, "charge-refund-3")
                .await
                .is_err()
        );
        let settled = db
            .ensure_settlement_wallet_account(application_id, "CNY")
            .await
            .unwrap();
        assert_eq!(settled.available_minor, 0);

        let transferred = db
            .transfer_wallets(
                &user.id,
                &global.id,
                &application_wallet.id,
                "CNY",
                2_000,
                Some(application_id),
                "transfer-1",
            )
            .await
            .unwrap();
        let duplicate_transfer = db
            .transfer_wallets(
                &user.id,
                &global.id,
                &application_wallet.id,
                "CNY",
                2_000,
                Some(application_id),
                "transfer-1",
            )
            .await
            .unwrap();
        assert_eq!(transferred.id, duplicate_transfer.id);
        assert!(
            db.transfer_wallets(
                &user.id,
                &global.id,
                &application_wallet.id,
                "CNY",
                9_000,
                Some(application_id),
                "transfer-too-much",
            )
            .await
            .is_err()
        );
        db.transfer_wallets(
            &user.id,
            &application_wallet.id,
            &global.id,
            "CNY",
            2_000,
            Some(application_id),
            "transfer-2",
        )
        .await
        .unwrap();

        let release_hold = db
            .reserve_wallet_hold(
                &global.id,
                &user.id,
                application_id,
                "CNY",
                500,
                "release-1",
                "reserve-2",
                util::now_ts() + 900,
            )
            .await
            .unwrap();
        db.release_wallet_hold(&release_hold.id, "release-1")
            .await
            .unwrap();
        assert_eq!(
            db.release_wallet_hold(&release_hold.id, "release-2")
                .await
                .unwrap()
                .status,
            "released"
        );

        let order = db
            .insert_payment_order(NewPaymentOrder {
                user_id: user.id.clone(),
                provider_slug: "test-provider".to_string(),
                merchant_order_no: "SGT-test-order-1".to_string(),
                idempotency_key: Some("recharge-test-1".to_string()),
                currency: "CNY".to_string(),
                amount_minor: 5_000,
                subject: "test recharge".to_string(),
                checkout_kind: "redirect".to_string(),
                checkout_value: "https://pay.example.test/order".to_string(),
                expires_at: util::now_ts() + 900,
            })
            .await
            .unwrap();
        assert_eq!(order.idempotency_key.as_deref(), Some("recharge-test-1"));
        assert_eq!(
            db.find_payment_order_by_idempotency_key(&user.id, "test-provider", "recharge-test-1")
                .await
                .unwrap()
                .map(|found| found.id),
            Some(order.id.clone())
        );
        assert!(
            db.mark_payment_order_paid(&order.id, "", util::now_ts())
                .await
                .is_err()
        );
        let paid_order = db
            .mark_payment_order_paid(&order.id, "provider-trade-1", util::now_ts())
            .await
            .unwrap();
        assert_eq!(paid_order.status, "paid");
        assert_eq!(
            db.mark_payment_order_paid(&order.id, "provider-trade-1", util::now_ts())
                .await
                .unwrap()
                .id,
            order.id
        );
        assert!(
            db.mark_payment_order_paid(&order.id, "provider-trade-2", util::now_ts())
                .await
                .is_err()
        );

        let payment_refund = db
            .refund_payment_order(
                &order.id,
                1_000,
                "provider-refund-1",
                None,
                "test refund",
                "payment-refund-1",
            )
            .await
            .unwrap();
        let duplicate_payment_refund = db
            .refund_payment_order(
                &order.id,
                1_000,
                "provider-refund-1",
                None,
                "test refund",
                "payment-refund-1",
            )
            .await
            .unwrap();
        assert_eq!(payment_refund.id, duplicate_payment_refund.id);
        assert!(
            db.refund_payment_order(
                &order.id,
                5_000,
                "provider-refund-2",
                None,
                "too much",
                "payment-refund-2",
            )
            .await
            .is_err()
        );

        let final_global = db
            .ensure_user_wallet_account(&user.id, "CNY")
            .await
            .unwrap();
        assert_eq!(final_global.available_minor, 14_000);
        assert_eq!(final_global.reserved_minor, 0);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bootstrap_client_ensure_is_idempotent_and_secret_safe() {
        let (db, path) = sqlite_test_db().await;
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        settings.bootstrap.admin.create_on_startup = false;
        settings.external_oidc_providers.clear();
        settings.bootstrap.clients = vec![BootstrapClient {
            client_id: "ensure-worker".to_string(),
            client_name: "Ensure worker".to_string(),
            logo_uri: String::new(),
            client_secret: "first-secret".to_string(),
            client_secret_env: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["memory.service".to_string()],
            grant_types: vec!["client_credentials".to_string()],
            response_types: Vec::new(),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            require_pkce: false,
            require_confidential_client: false,
            service_account_enabled: true,
            service_account_permissions: vec!["users.read".to_string(), " users.read ".to_string()],
            audience: Some("memory-atlas".to_string()),
            rotate_secret: false,
        }];

        db.seed(&settings).await.unwrap();
        let first = db
            .find_client_by_client_id("ensure-worker")
            .await
            .unwrap()
            .unwrap();
        let first_hash = first.client_secret_hash.clone().unwrap();
        assert!(util::verify_password(&first_hash, "first-secret"));
        assert_eq!(first.audience, "memory-atlas");
        assert_eq!(first.service_account_enabled, 1);
        assert_eq!(
            util::from_json::<Vec<String>>(&first.service_account_permissions).unwrap(),
            vec!["users.read".to_string()]
        );

        settings.bootstrap.clients[0].client_name = "Updated worker".to_string();
        settings.bootstrap.clients[0].client_secret = "second-secret".to_string();
        settings.bootstrap.clients[0].audience = Some("memory-atlas-v2".to_string());
        db.seed(&settings).await.unwrap();
        let preserved = db
            .find_client_by_client_id("ensure-worker")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(preserved.client_name, "Updated worker");
        assert_eq!(preserved.audience, "memory-atlas-v2");
        assert_eq!(preserved.client_secret_hash, Some(first_hash.clone()));
        assert!(util::verify_password(
            preserved.client_secret_hash.as_deref().unwrap(),
            "first-secret"
        ));
        assert!(!util::verify_password(
            preserved.client_secret_hash.as_deref().unwrap(),
            "second-secret"
        ));

        settings.bootstrap.clients[0].rotate_secret = true;
        db.seed(&settings).await.unwrap();
        let rotated = db
            .find_client_by_client_id("ensure-worker")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(rotated.client_secret_hash, Some(first_hash));
        assert!(util::verify_password(
            rotated.client_secret_hash.as_deref().unwrap(),
            "second-secret"
        ));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn mfa_totp_challenge_completion_is_single_use_under_concurrency() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        db.upsert_totp_method("mfa-user", "JBSWY3DPEHPK3PXP".to_string())
            .await
            .unwrap();
        let challenge = db
            .create_mfa_challenge("mfa-user", "api_login", None, 300)
            .await
            .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(4));
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let db = db.clone();
            let barrier = barrier.clone();
            let challenge_id = challenge.id.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                db.complete_mfa_challenge_with_totp(&challenge_id, "mfa-user", 42)
                    .await
            }));
        }

        let mut successful_completions = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                successful_completions += 1;
            }
        }
        assert_eq!(successful_completions, 1);
        assert!(
            db.find_mfa_challenge(&challenge.id)
                .await
                .unwrap()
                .unwrap()
                .consumed_at
                .is_some()
        );
        assert_eq!(
            db.find_totp_method("mfa-user")
                .await
                .unwrap()
                .unwrap()
                .last_used_step,
            Some(42)
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn mfa_recovery_code_challenge_completion_is_single_use_under_concurrency() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        db.replace_recovery_codes("mfa-user", vec!["hash".to_string()])
            .await
            .unwrap();
        let recovery_code = db
            .list_unused_recovery_codes("mfa-user")
            .await
            .unwrap()
            .pop()
            .unwrap();
        let challenge = db
            .create_mfa_challenge("mfa-user", "api_login", None, 300)
            .await
            .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(4));
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let db = db.clone();
            let barrier = barrier.clone();
            let challenge_id = challenge.id.clone();
            let recovery_code_id = recovery_code.id.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                db.complete_mfa_challenge_with_recovery_code(
                    &challenge_id,
                    "mfa-user",
                    &recovery_code_id,
                )
                .await
            }));
        }

        let mut successful_completions = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                successful_completions += 1;
            }
        }
        assert_eq!(successful_completions, 1);
        assert!(
            db.list_recovery_codes("mfa-user")
                .await
                .unwrap()
                .into_iter()
                .all(|code| code.used_at.is_some())
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_saml_replay_claim_is_atomic_and_reclaims_expired_keys() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let db = db.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                db.claim_application_saml_replay(
                    "replay-key",
                    "application-a",
                    util::now_ts() + 300,
                )
                .await
            }));
        }
        let mut successful_claims = 0;
        for task in tasks {
            if task.await.unwrap().unwrap() {
                successful_claims += 1;
            }
        }
        assert_eq!(successful_claims, 1);

        assert!(
            db.claim_application_saml_replay("expired-key", "application-a", util::now_ts() - 1,)
                .await
                .unwrap()
        );
        assert!(
            db.claim_application_saml_replay("expired-key", "application-a", util::now_ts() + 300,)
                .await
                .unwrap()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_saml_interactions_are_single_use_scoped_and_expire() {
        let (db, path) = sqlite_test_db().await;
        let handle_hash = "interaction-hash";
        db.insert_application_saml_interaction(NewApplicationSamlInteraction {
            handle_hash: handle_hash.to_string(),
            application_id: "application-a".to_string(),
            request_id: "request-1".to_string(),
            sp_entity_id: "https://sp.example/metadata".to_string(),
            acs_url: "https://sp.example/acs".to_string(),
            relay_state: Some("state".to_string()),
            response_binding: "post".to_string(),
            expires_at: util::now_ts() + 300,
        })
        .await
        .unwrap();

        assert!(
            db.consume_application_saml_interaction(handle_hash, "application-b")
                .await
                .is_err()
        );
        let consumed = db
            .consume_application_saml_interaction(handle_hash, "application-a")
            .await
            .unwrap();
        assert_eq!(consumed.request_id, "request-1");
        assert_eq!(consumed.relay_state.as_deref(), Some("state"));
        assert!(
            db.consume_application_saml_interaction(handle_hash, "application-a")
                .await
                .is_err()
        );

        db.insert_application_saml_interaction(NewApplicationSamlInteraction {
            handle_hash: "expired-interaction".to_string(),
            application_id: "application-a".to_string(),
            request_id: String::new(),
            sp_entity_id: "https://sp.example/metadata".to_string(),
            acs_url: "https://sp.example/acs".to_string(),
            relay_state: None,
            response_binding: "post".to_string(),
            expires_at: util::now_ts() - 1,
        })
        .await
        .unwrap();
        assert!(
            db.consume_application_saml_interaction("expired-interaction", "application-a")
                .await
                .is_err()
        );

        let organization = db
            .insert_organization(test_organization("saml-cleanup", "SAML Cleanup"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "saml-cleanup-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        assert!(
            db.claim_application_saml_replay(
                "cleanup-replay",
                &application.id,
                util::now_ts() + 300,
            )
            .await
            .unwrap()
        );
        db.insert_application_saml_interaction(NewApplicationSamlInteraction {
            handle_hash: "cleanup-interaction".to_string(),
            application_id: application.id.clone(),
            request_id: String::new(),
            sp_entity_id: "https://sp.example/metadata".to_string(),
            acs_url: "https://sp.example/acs".to_string(),
            relay_state: None,
            response_binding: "post".to_string(),
            expires_at: util::now_ts() + 300,
        })
        .await
        .unwrap();
        db.delete_application(&application.id).await.unwrap();
        assert!(
            db.consume_application_saml_interaction("cleanup-interaction", &application.id)
                .await
                .is_err()
        );
        assert!(
            db.claim_application_saml_replay(
                "cleanup-replay",
                &application.id,
                util::now_ts() + 300,
            )
            .await
            .unwrap()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_saml_sessions_are_scoped_by_application_and_name_id() {
        let (db, path) = sqlite_test_db().await;
        db.insert_application_saml_session(NewApplicationSamlSession {
            session_index_hash: "session-index-a".to_string(),
            application_id: "application-a".to_string(),
            user_id: "user-a".to_string(),
            signet_session_id: "signet-session-a".to_string(),
            name_id_hash: "name-id-a".to_string(),
            expires_at: util::now_ts() + 300,
        })
        .await
        .unwrap();

        assert!(
            db.find_application_saml_session("session-index-a", "application-b")
                .await
                .unwrap()
                .is_none()
        );
        let record = db
            .find_application_saml_session("session-index-a", "application-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.signet_session_id, "signet-session-a");
        assert_eq!(
            db.list_application_saml_sessions_by_name_id("name-id-a", "application-a")
                .await
                .unwrap()
                .len(),
            1
        );
        db.delete_application_saml_session("session-index-a", "application-b")
            .await
            .unwrap();
        assert!(
            db.find_application_saml_session("session-index-a", "application-a")
                .await
                .unwrap()
                .is_some()
        );
        db.delete_application_saml_session("session-index-a", "application-a")
            .await
            .unwrap();
        assert!(
            db.find_application_saml_session("session-index-a", "application-a")
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_saml_interaction_consume_allows_only_one_concurrent_winner() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        db.insert_application_saml_interaction(NewApplicationSamlInteraction {
            handle_hash: "concurrent-interaction".to_string(),
            application_id: "application-a".to_string(),
            request_id: "request-concurrent".to_string(),
            sp_entity_id: "https://sp.example/metadata".to_string(),
            acs_url: "https://sp.example/acs".to_string(),
            relay_state: None,
            response_binding: "post".to_string(),
            expires_at: util::now_ts() + 300,
        })
        .await
        .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(4));
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let db = db.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                db.consume_application_saml_interaction("concurrent-interaction", "application-a")
                    .await
            }));
        }
        let mut successful_consumes = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                successful_consumes += 1;
            }
        }
        assert_eq!(successful_consumes, 1);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_cas_tickets_bind_to_service_and_support_pgt_revocation() {
        let (db, path) = sqlite_test_db().await;
        db.insert_application_cas_ticket(NewApplicationCasTicket {
            ticket_hash: "service-ticket-hash".to_string(),
            application_id: "application-a".to_string(),
            ticket_type: "service".to_string(),
            service: "https://portal.example.test/cas".to_string(),
            user_id: "user-a".to_string(),
            parent_ticket_hash: None,
            pgt_iou: None,
            expires_at: util::now_ts() + 300,
        })
        .await
        .unwrap();
        assert!(
            db.consume_application_cas_ticket(
                "service-ticket-hash",
                "application-a",
                "https://other.example.test/cas",
                &["service"],
            )
            .await
            .is_err()
        );
        let consumed = db
            .consume_application_cas_ticket(
                "service-ticket-hash",
                "application-a",
                "https://portal.example.test/cas",
                &["service"],
            )
            .await
            .unwrap();
        assert_eq!(consumed.user_id, "user-a");
        assert!(
            db.consume_application_cas_ticket(
                "service-ticket-hash",
                "application-a",
                "https://portal.example.test/cas",
                &["service"],
            )
            .await
            .is_err()
        );

        db.insert_application_cas_ticket(NewApplicationCasTicket {
            ticket_hash: "pgt-hash".to_string(),
            application_id: "application-a".to_string(),
            ticket_type: "proxy_granting".to_string(),
            service: "https://portal.example.test/pgt".to_string(),
            user_id: "user-a".to_string(),
            parent_ticket_hash: None,
            pgt_iou: Some("pgt-iou".to_string()),
            expires_at: util::now_ts() + 300,
        })
        .await
        .unwrap();
        assert!(
            db.find_application_cas_ticket("pgt-hash", "application-a", "proxy_granting")
                .await
                .unwrap()
                .is_some()
        );
        db.revoke_application_cas_ticket("pgt-hash").await.unwrap();
        assert!(
            db.find_application_cas_ticket("pgt-hash", "application-a", "proxy_granting")
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    fn test_organization(slug: &str, name: &str) -> NewOrganization {
        NewOrganization {
            slug: slug.to_string(),
            name: name.to_string(),
            kind: ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn test_application(organization_id: &str, slug: &str, access_mode: &str) -> NewApplication {
        NewApplication {
            organization_id: organization_id.to_string(),
            slug: slug.to_string(),
            name: format!("{slug} application"),
            description: None,
            access_mode: access_mode.to_string(),
            registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn test_ldap_provider(slug: &str, organization_id: Option<&str>) -> NewLdapProvider {
        NewLdapProvider {
            slug: slug.to_string(),
            display_name: format!("{slug} directory"),
            organization_id: organization_id.map(ToOwned::to_owned),
            url: "ldaps://directory.example.test".to_string(),
            starttls: false,
            bind_dn: "cn=reader,dc=example,dc=test".to_string(),
            bind_password: Some("secret".to_string()),
            base_dn: "dc=example,dc=test".to_string(),
            user_filter: "(&(objectClass=person)(uid={login}))".to_string(),
            user_id_attribute: "uid".to_string(),
            email_attribute: "mail".to_string(),
            username_attribute: "uid".to_string(),
            display_name_attribute: "cn".to_string(),
            phone_attribute: "telephoneNumber".to_string(),
            is_active: true,
            allow_login: true,
            allow_registration: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn test_client(client_id: &str, organization_id: &str) -> NewClient {
        NewClient {
            client_id: client_id.to_string(),
            client_secret_hash: None,
            client_name: format!("{client_id} client"),
            logo_uri: String::new(),
            organization_id: Some(organization_id.to_string()),
            redirect_uris: vec!["https://example.test/callback".to_string()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".to_string()],
            audience: String::new(),
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: true,
            require_mfa: false,
            require_pushed_authorization_requests: false,
            require_s256_pkce: false,
            require_confidential_client: false,
            require_dpop: false,
            require_account_selection: false,
            trust_email_verified: false,
            authorization_details_types: Vec::new(),
            subject_type: crate::subject::SUBJECT_TYPE_PUBLIC.to_string(),
            sector_identifier_uri: String::new(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: false,
            service_account_enabled: false,
            service_account_permissions: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn bootstrap_client(secret: &str) -> BootstrapClient {
        BootstrapClient {
            client_id: "bootstrap-worker".to_string(),
            client_name: "Bootstrap worker".to_string(),
            logo_uri: String::new(),
            client_secret: secret.to_string(),
            client_secret_env: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["memory.service".to_string()],
            grant_types: vec!["client_credentials".to_string()],
            response_types: Vec::new(),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            require_pkce: false,
            require_confidential_client: false,
            service_account_enabled: false,
            service_account_permissions: Vec::new(),
            audience: None,
            rotate_secret: false,
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bootstrap_client_ensure_reads_secret_from_environment() {
        let (db, path) = sqlite_test_db().await;
        let system = db.system_organization().await.unwrap();
        let env_name = format!("SIGNET_BOOTSTRAP_TEST_SECRET_{}", uuid::Uuid::new_v4());
        // Rust 2024 makes process-environment mutation explicit because tests
        // may otherwise race with unrelated environment readers.
        unsafe { std::env::set_var(&env_name, "environment-secret") };

        let mut client = bootstrap_client("");
        client.client_secret_env = Some(env_name.clone());
        let record = db
            .ensure_bootstrap_client(&client, &system.id)
            .await
            .unwrap();
        assert!(util::verify_password(
            record.client_secret_hash.as_deref().unwrap(),
            "environment-secret"
        ));

        unsafe { std::env::remove_var(&env_name) };
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn system_organization_is_created_and_immutable() {
        let (db, path) = sqlite_test_db().await;
        let system = db.system_organization().await.unwrap();
        assert_eq!(system.id, SIGNET_ORGANIZATION_ID);
        assert_eq!(system.kind, ORGANIZATION_KIND_SYSTEM);
        assert!(
            db.update_organization(&system.id, test_organization("not-signet", "Not Signet"),)
                .await
                .is_err()
        );
        assert!(db.delete_organization(&system.id).await.is_err());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn organization_context_and_application_access_are_tenant_scoped() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("acme", "Acme"))
            .await
            .unwrap();
        let member = db
            .insert_user(test_user("member@example.com", "member"))
            .await
            .unwrap();
        let outsider = db
            .insert_user(test_user("outsider@example.com", "outsider"))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &member.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        let context = db
            .set_active_user_organization(&member.id, &organization.id)
            .await
            .unwrap();
        assert_eq!(context.id, organization.id);
        assert!(
            db.set_active_user_organization(&outsider.id, &organization.id)
                .await
                .is_err()
        );

        let organization_app = db
            .insert_application(test_application(
                &organization.id,
                "member-portal",
                crate::applications::ACCESS_ORGANIZATION_MEMBERS,
            ))
            .await
            .unwrap();
        assert!(
            db.user_can_access_application(&organization_app, &member.id)
                .await
                .unwrap()
        );
        assert!(
            db.user_can_access_application(&organization_app, &outsider.id)
                .await
                .unwrap()
        );
        // Application membership rows are retained only for migration and
        // audit compatibility. They never deny a Signet account at login.
        db.replace_application_members(
            &organization_app.id,
            vec![NewApplicationMember {
                user_id: member.id.clone(),
                role: "member".to_string(),
                is_active: false,
            }],
        )
        .await
        .unwrap();
        assert!(
            db.user_can_access_application(&organization_app, &member.id)
                .await
                .unwrap()
        );
        db.replace_application_members(&organization_app.id, Vec::new())
            .await
            .unwrap();
        assert!(
            db.user_can_access_application(&organization_app, &member.id)
                .await
                .unwrap()
        );

        let assigned_app = db
            .insert_application(test_application(
                &organization.id,
                "restricted-portal",
                crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
            ))
            .await
            .unwrap();
        assert!(
            db.user_can_access_application(&assigned_app, &member.id)
                .await
                .unwrap()
        );
        db.replace_application_members(
            &assigned_app.id,
            vec![NewApplicationMember {
                user_id: member.id.clone(),
                role: "member".to_string(),
                is_active: true,
            }],
        )
        .await
        .unwrap();
        assert!(
            db.user_can_access_application(&assigned_app, &outsider.id)
                .await
                .unwrap()
        );
        // Removing an enterprise membership changes enterprise entitlements,
        // not the Signet login gate for an active account.
        db.replace_organization_members(&organization.id, Vec::new())
            .await
            .unwrap();
        assert!(
            db.user_can_access_application(&assigned_app, &member.id)
                .await
                .unwrap()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_modules_are_persisted_independently_per_website() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("module-org", "Module Org"))
            .await
            .unwrap();
        let first = db
            .insert_application(test_application(
                &organization.id,
                "first-website",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let second = db
            .insert_application(test_application(
                &organization.id,
                "second-website",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();

        let protocols = db
            .upsert_application_module(
                &first.id,
                "protocols",
                r#"{"oauth2_oidc":{"enabled":true}}"#,
                true,
            )
            .await
            .unwrap();
        assert_eq!(protocols.application_id, first.id);
        assert_eq!(protocols.module_key, "protocols");
        assert_eq!(protocols.is_enabled, 1);

        db.upsert_application_module(
            &first.id,
            "authorization",
            r#"{"inherit_enterprise_roles":true,"permissions":["support.read"]}"#,
            false,
        )
        .await
        .unwrap();
        let modules = db.list_application_modules(&first.id).await.unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].module_key, "authorization");
        assert_eq!(modules[1].module_key, "protocols");

        let updated = db
            .upsert_application_module(
                &first.id,
                "protocols",
                r#"{"oauth2_oidc":{"enabled":false},"saml2":{"enabled":true}}"#,
                false,
            )
            .await
            .unwrap();
        assert_eq!(updated.is_enabled, 0);
        assert!(updated.config_json.contains("saml2"));
        assert!(
            db.list_application_modules(&second.id)
                .await
                .unwrap()
                .is_empty()
        );

        db.delete_application_module(&first.id, "authorization")
            .await
            .unwrap();
        let remaining = db.list_application_modules(&first.id).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].module_key, "protocols");

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_scim_group_patch_validates_members_in_the_bound_application() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("scim-group-bound", "SCIM Group Bound"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "scim-group-bound-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let group = db
            .insert_application_scim_group(
                &application.id,
                NewGroup {
                    name: "Bound group".to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        let first = db
            .insert_user(test_user(
                "scim-group-first@example.com",
                "scim-group-first",
            ))
            .await
            .unwrap();
        let second = db
            .insert_user(test_user(
                "scim-group-second@example.com",
                "scim-group-second",
            ))
            .await
            .unwrap();
        for user in [&first, &second] {
            db.upsert_organization_member(
                &organization.id,
                &user.id,
                crate::organizations::ROLE_MEMBER,
            )
            .await
            .unwrap();
        }

        db.apply_group_patch_plan(GroupPatchPlan {
            application_id: Some(application.id.clone()),
            group_id: group.id.clone(),
            name: "Bound group".to_string(),
            description: None,
            member_ids: vec![first.id.clone(), second.id.clone()],
            create: false,
            expected_version: None,
        })
        .await
        .unwrap();
        let members = db
            .list_application_scim_group_members(&application.id, &group.id)
            .await
            .unwrap();
        assert_eq!(
            members
                .into_iter()
                .map(|member| member.id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first.id, second.id])
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_scim_group_create_rolls_back_binding_and_group_on_invalid_member() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("scim-group-create", "SCIM Group Create"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "scim-group-create-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let unbound_user = db
            .insert_user(test_user(
                "scim-group-unbound@example.com",
                "scim-group-unbound",
            ))
            .await
            .unwrap();
        let group_id = "scim-group-atomic-create".to_string();

        let result = db
            .apply_group_patch_plan(GroupPatchPlan {
                application_id: Some(application.id.clone()),
                group_id: group_id.clone(),
                name: "Atomic create".to_string(),
                description: None,
                member_ids: vec![unbound_user.id],
                create: true,
                expected_version: None,
            })
            .await;
        assert!(matches!(result, Err(AppError::BadRequest(_))));
        assert!(
            db.find_application_scim_group(&application.id, &group_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_application_scim_groups(&application.id)
                .await
                .unwrap()
                .is_empty()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn audited_application_mutations_commit_business_and_audit_together() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("audited-app", "Audited App"))
            .await
            .unwrap();
        let application = db
            .insert_application_with_audit(
                test_application(
                    &organization.id,
                    "audited-website",
                    crate::applications::ACCESS_ALL_SIGNET_USERS,
                ),
                crate::audit::management_event(
                    "actor",
                    "application.create",
                    "application",
                    None,
                    serde_json::json!({ "source": "test" }),
                ),
            )
            .await
            .unwrap();
        let module = db
            .upsert_application_module_with_audit(
                &application.id,
                "protocols",
                r#"{"oauth2_oidc":{"enabled":true}}"#,
                true,
                crate::audit::management_event(
                    "actor",
                    "application.module.update",
                    "application",
                    Some(application.id.clone()),
                    serde_json::json!({ "module": "protocols" }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(module.is_enabled, 1);

        let jwt_client = db
            .upsert_application_jwt_client(
                &application.id,
                NewApplicationJwtClient {
                    client_id: "audited-jwt".to_string(),
                    client_type: "confidential".to_string(),
                    is_active: true,
                },
            )
            .await
            .unwrap();
        let jwt_secret = db
            .rotate_application_jwt_secret_with_audit(
                &application.id,
                &jwt_client.client_id,
                &util::hash_password("audited-secret").unwrap(),
                300,
                crate::audit::management_event(
                    "actor",
                    "application.jwt_client.secret.rotate",
                    "application",
                    Some(application.id.clone()),
                    serde_json::json!({ "client_id": jwt_client.client_id }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(jwt_secret.jwt_client_id, jwt_client.id);

        let token = db
            .insert_application_scim_token_with_audit(
                NewApplicationScimToken {
                    id: "audited-scim-token".to_string(),
                    application_id: application.id.clone(),
                    token_prefix: "scim_v1_audited".to_string(),
                    token_hash: util::token_hash("scim_v1_audited_secret"),
                    scopes: vec!["scim.read".to_string()],
                    expires_at: None,
                },
                crate::audit::management_event(
                    "actor",
                    "application.scim_token.create",
                    "application",
                    Some(application.id.clone()),
                    serde_json::json!({ "token_id": "audited-scim-token" }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(token.token_hash, util::token_hash("scim_v1_audited_secret"));

        let events = db.list_audit_events(20).await.unwrap();
        for action in [
            "application.create",
            "application.module.update",
            "application.jwt_client.secret.rotate",
            "application.scim_token.create",
        ] {
            assert!(
                events.iter().any(|event| event.action == action
                    && event.target_id.as_deref() == Some(application.id.as_str())),
                "missing committed audit event: {action}"
            );
        }

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn audited_application_creation_rolls_back_when_audit_insert_fails() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("audit-rollback", "Audit Rollback"))
            .await
            .unwrap();
        with_conn!(db.clone(), |conn, _kind| {
            sql_query("DROP TABLE audit_events")
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

        let result = db
            .insert_application_with_audit(
                test_application(
                    &organization.id,
                    "audit-rollback-website",
                    crate::applications::ACCESS_ALL_SIGNET_USERS,
                ),
                crate::audit::management_event(
                    "actor",
                    "application.create",
                    "application",
                    None,
                    serde_json::json!({}),
                ),
            )
            .await;
        assert!(result.is_err());
        assert!(
            db.find_application_by_slug_in_organization(
                &organization.id,
                "audit-rollback-website",
            )
            .await
            .unwrap()
            .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_creation_with_initial_module_is_atomic() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization(
                "atomic-application",
                "Atomic Application",
            ))
            .await
            .unwrap();

        with_conn!(db.clone(), |conn, _kind| {
            sql_query("DROP TABLE audit_events")
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

        let result = db
            .insert_application_with_module_with_audit(
                test_application(
                    &organization.id,
                    "atomic-application-website",
                    crate::applications::ACCESS_ALL_SIGNET_USERS,
                ),
                "protocols",
                r#"{"website_url":"https://atomic.example"}"#,
                false,
                crate::audit::management_event(
                    "actor",
                    "application.create",
                    "application",
                    None,
                    serde_json::json!({}),
                ),
            )
            .await;
        assert!(result.is_err());
        assert!(
            db.find_application_by_slug_in_organization(
                &organization.id,
                "atomic-application-website",
            )
            .await
            .unwrap()
            .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn legacy_application_authorization_migrates_into_one_profile_idempotently() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("legacy-auth-org", "Legacy Auth Org"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "legacy-auth-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let user = db
            .insert_user(test_user(
                "legacy-auth-user@example.com",
                "legacy-auth-user",
            ))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &user.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        let group = db
            .insert_group(NewGroup {
                name: "Legacy Auth Group".to_string(),
                description: None,
            })
            .await
            .unwrap();
        db.replace_group_members(&group.id, vec![user.id.clone()])
            .await
            .unwrap();

        let profile = db
            .find_application_authorization_profile(&application.id, "default")
            .await
            .unwrap()
            .unwrap();
        let existing_role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("existing-profile-role".to_string()),
                profile_id: profile.id.clone(),
                role_key: "legacy".to_string(),
                name: "Existing legacy role".to_string(),
                description: None,
                permissions: vec!["existing.permission".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        let other_role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("other-profile-role".to_string()),
                profile_id: profile.id.clone(),
                role_key: "other".to_string(),
                name: "Other role".to_string(),
                description: None,
                permissions: Vec::new(),
                source: "manual".to_string(),
                is_default: true,
                is_active: true,
            })
            .await
            .unwrap();
        db.upsert_application_module(
            &application.id,
            "authorization",
            &serde_json::json!({
                "default_role": "legacy",
                "custom_roles": [{
                    "name": "config-extra",
                    "permissions": ["config.read"]
                }],
                "group_mappings": [{
                    "group": group.name,
                    "role": "config-extra"
                }],
                "organization_role_mappings": {
                    "admin": "config-extra"
                }
            })
            .to_string(),
            true,
        )
        .await
        .unwrap();

        let application_id = application.id.clone();
        let user_id = user.id.clone();
        let group_id = group.id.clone();
        with_conn!(db.clone(), |conn, _kind| {
            sql_query(
                "INSERT INTO application_roles (id, application_id, name, description, permissions, is_default, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>("legacy-role")
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>("legacy")
            .bind::<Nullable<Text>, _>(None::<String>)
            .bind::<Text, _>(r#"["legacy.read"]"#)
            .bind::<Integer, _>(1)
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            sql_query(
                "INSERT INTO application_user_roles (application_id, user_id, application_role_id, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>(&user_id)
            .bind::<Text, _>("legacy-role")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            sql_query(
                "INSERT INTO application_group_roles (application_id, group_id, application_role_id, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>(&group_id)
            .bind::<Text, _>("legacy-role")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            sql_query(
                "INSERT INTO application_organization_role_mappings (application_id, organization_role, application_role_id, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>("member")
            .bind::<Text, _>("legacy-role")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            sql_query(
                "INSERT INTO application_user_permission_overrides (application_id, user_id, permission, effect, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>(&user_id)
            .bind::<Text, _>("legacy.override")
            .bind::<Text, _>("allow")
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            Ok::<(), AppError>(())
        })
        .unwrap();

        db.migrate_legacy_application_authorization().await.unwrap();
        let first_snapshot = db
            .read_application_authorization_bindings(&application.id, &profile.id)
            .await
            .unwrap();
        let first_roles = db
            .list_application_profile_roles(&profile.id)
            .await
            .unwrap();
        assert_eq!(
            first_roles
                .iter()
                .filter(|role| role.is_default == 1)
                .map(|role| role.id.as_str())
                .collect::<Vec<_>>(),
            vec![existing_role.id.as_str()]
        );
        assert!(
            first_roles
                .iter()
                .any(|role| role.role_key == "config-extra")
        );
        assert!(
            !first_roles
                .iter()
                .any(|role| role.id == other_role.id && role.is_default == 1)
        );
        assert_eq!(
            first_snapshot.user_bindings[&user.id].user_role_ids,
            vec![existing_role.id.clone()]
        );
        let mut expected_group_role_ids = vec![
            existing_role.id.clone(),
            first_roles
                .iter()
                .find(|role| role.role_key == "config-extra")
                .unwrap()
                .id
                .clone(),
        ];
        expected_group_role_ids.sort();
        assert_eq!(
            first_snapshot.group_bindings[&group.id],
            expected_group_role_ids
        );
        assert_eq!(
            first_snapshot.organization_role_bindings["member"],
            vec![existing_role.id.clone()]
        );
        assert_eq!(
            first_snapshot.organization_role_bindings["admin"],
            vec![
                first_roles
                    .iter()
                    .find(|role| role.role_key == "config-extra")
                    .unwrap()
                    .id
                    .clone()
            ]
        );
        assert_eq!(
            first_snapshot.user_bindings[&user.id].user_permission_overrides[0].permission,
            "legacy.override"
        );

        db.migrate_legacy_application_authorization().await.unwrap();
        let second_snapshot = db
            .read_application_authorization_bindings(&application.id, &profile.id)
            .await
            .unwrap();
        let second_roles = db
            .list_application_profile_roles(&profile.id)
            .await
            .unwrap();
        assert_eq!(first_snapshot, second_snapshot);
        assert_eq!(first_roles.len(), second_roles.len());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn updating_application_role_preserves_id_bindings_and_default_invariant() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("role-org", "Role Org"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "role-website",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let user = db
            .insert_user(test_user("role-user@example.com", "role-user"))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &user.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        let profile = default_authorization_profile(&db, &application.id).await;
        let original = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: profile.id.clone(),
                role_key: "reader".to_string(),
                name: "reader".to_string(),
                source: "manual".to_string(),
                description: Some("Read access".to_string()),
                permissions: vec!["users.read".to_string()],
                is_default: true,
                is_active: true,
            })
            .await
            .unwrap();
        let other = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: profile.id.clone(),
                role_key: "operator".to_string(),
                name: "operator".to_string(),
                source: "manual".to_string(),
                description: None,
                permissions: vec!["users.manage".to_string()],
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        replace_test_authorization_bindings(
            &db,
            &application.id,
            &profile.id,
            AuthorizationBindingsUpdate {
                user_id: Some(user.id.clone()),
                group_id: None,
                user_role_ids: vec![original.id.clone()],
                user_permission_overrides: Vec::new(),
                group_role_ids: Vec::new(),
                organization_role_bindings: BTreeMap::new(),
            },
        )
        .await;

        let updated = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some(original.id.clone()),
                profile_id: profile.id.clone(),
                role_key: "editor".to_string(),
                name: "editor".to_string(),
                source: "manual".to_string(),
                description: Some("Updated access".to_string()),
                permissions: vec!["users.manage".to_string()],
                is_default: true,
                is_active: true,
            })
            .await
            .unwrap();
        assert_eq!(updated.id, original.id);
        assert_eq!(updated.name, "editor");
        assert_eq!(
            db.read_application_authorization_bindings(&application.id, &profile.id)
                .await
                .unwrap()
                .user_bindings[&user.id]
                .user_role_ids,
            vec![original.id.clone()]
        );
        assert_eq!(
            db.list_application_profile_roles(&profile.id)
                .await
                .unwrap()
                .into_iter()
                .filter(|role| role.is_default == 1)
                .map(|role| role.id)
                .collect::<Vec<_>>(),
            vec![original.id.clone()]
        );
        assert!(
            db.upsert_application_profile_role(NewApplicationProfileRole {
                id: Some(other.id.clone()),
                profile_id: profile.id,
                role_key: "editor".to_string(),
                name: "editor".to_string(),
                source: "manual".to_string(),
                description: None,
                permissions: Vec::new(),
                is_default: false,
                is_active: true,
            })
            .await
            .is_err()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_role_lifecycle_cleans_mappings_and_rechecks_entitlements() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization(
                "role-lifecycle-org",
                "Role Lifecycle Org",
            ))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "role-lifecycle-website",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let user = db
            .insert_user(test_user("role-lifecycle@example.com", "role-lifecycle"))
            .await
            .unwrap();
        db.upsert_organization_member(&organization.id, &user.id, crate::organizations::ROLE_ADMIN)
            .await
            .unwrap();
        let group = db
            .insert_group(NewGroup {
                name: "Role lifecycle group".to_string(),
                description: None,
            })
            .await
            .unwrap();
        db.replace_group_members(&group.id, vec![user.id.clone()])
            .await
            .unwrap();

        let profile = default_authorization_profile(&db, &application.id).await;
        let default_role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: profile.id.clone(),
                role_key: "base".to_string(),
                name: "base".to_string(),
                source: "manual".to_string(),
                description: None,
                permissions: vec!["app.read".to_string()],
                is_default: true,
                is_active: true,
            })
            .await
            .unwrap();
        let mapped_role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: profile.id.clone(),
                role_key: "operator".to_string(),
                name: "operator".to_string(),
                source: "manual".to_string(),
                description: None,
                permissions: vec!["app.read".to_string(), "app.write".to_string()],
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();

        assert!(
            db.upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: profile.id.clone(),
                role_key: "invalid-default".to_string(),
                name: "invalid-default".to_string(),
                source: "manual".to_string(),
                description: None,
                permissions: Vec::new(),
                is_default: true,
                is_active: false,
            })
            .await
            .is_err()
        );
        assert!(
            db.upsert_application_profile_role(NewApplicationProfileRole {
                id: Some(default_role.id.clone()),
                profile_id: profile.id.clone(),
                role_key: "base".to_string(),
                name: "base".to_string(),
                source: "manual".to_string(),
                description: None,
                permissions: vec!["app.read".to_string()],
                is_default: true,
                is_active: false,
            })
            .await
            .is_err()
        );
        assert!(
            db.delete_application_profile_role(&profile.id, &default_role.id)
                .await
                .is_err()
        );

        replace_test_authorization_bindings(
            &db,
            &application.id,
            &profile.id,
            AuthorizationBindingsUpdate {
                user_id: Some(user.id.clone()),
                group_id: Some(group.id.clone()),
                user_role_ids: vec![mapped_role.id.clone()],
                user_permission_overrides: vec![
                    AuthorizationBindingPermissionOverride {
                        permission: "app.read".to_string(),
                        effect: "allow".to_string(),
                    },
                    AuthorizationBindingPermissionOverride {
                        permission: "app.write".to_string(),
                        effect: "deny".to_string(),
                    },
                ],
                group_role_ids: vec![mapped_role.id.clone()],
                organization_role_bindings: BTreeMap::from([(
                    crate::organizations::ROLE_ADMIN.to_string(),
                    vec![mapped_role.id.clone()],
                )]),
            },
        )
        .await;

        let settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let state = crate::AppState {
            jwt: crate::jwt::JwtManager::new(&settings).unwrap(),
            settings,
            db: db.clone(),
        };
        let entitlements = crate::authorization::resolve_entitlements(
            &state,
            &application,
            &db.find_user_by_id(&user.id).await.unwrap().unwrap(),
        )
        .await
        .unwrap();
        assert!(entitlements.roles.iter().any(|role| role == "base"));
        assert!(entitlements.roles.iter().any(|role| role == "operator"));
        assert!(
            entitlements
                .permissions
                .iter()
                .any(|permission| permission == "app.read")
        );
        assert!(
            !entitlements
                .permissions
                .iter()
                .any(|permission| permission == "app.write")
        );

        // The resolver reads active role rows on every call. Changing or
        // disabling a role therefore revokes its website entitlement without
        // waiting for a previously issued token to expire.
        db.upsert_application_profile_role(NewApplicationProfileRole {
            id: Some(mapped_role.id.clone()),
            profile_id: profile.id.clone(),
            role_key: "operator".to_string(),
            name: "operator".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: vec!["app.read".to_string()],
            is_default: false,
            is_active: false,
        })
        .await
        .unwrap();
        let entitlements = crate::authorization::resolve_entitlements(
            &state,
            &application,
            &db.find_user_by_id(&user.id).await.unwrap().unwrap(),
        )
        .await
        .unwrap();
        assert!(!entitlements.roles.iter().any(|role| role == "operator"));
        assert!(entitlements.roles.iter().any(|role| role == "base"));
        let inactive_binding_result = db
            .replace_application_authorization_bindings_with_audit(
                &application.id,
                &profile.id,
                AuthorizationBindingsUpdate {
                    user_id: Some(user.id.clone()),
                    group_id: None,
                    user_role_ids: vec![mapped_role.id.clone()],
                    user_permission_overrides: Vec::new(),
                    group_role_ids: Vec::new(),
                    organization_role_bindings: BTreeMap::new(),
                },
                audit::management_event(
                    "authorization-profile-test",
                    "application.authorization_profile.bindings.test",
                    "application_authorization_profile",
                    Some(profile.id.clone()),
                    serde_json::json!({}),
                ),
            )
            .await;
        assert!(inactive_binding_result.is_err());

        // Deleting a non-default role removes all three kinds of binding in
        // the same transaction, leaving no dangling authorization edge.
        db.upsert_application_profile_role(NewApplicationProfileRole {
            id: Some(mapped_role.id.clone()),
            profile_id: profile.id.clone(),
            role_key: "operator".to_string(),
            name: "operator".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: vec!["app.read".to_string(), "app.write".to_string()],
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();
        db.delete_application_profile_role(&profile.id, &mapped_role.id)
            .await
            .unwrap();
        assert!(
            db.read_application_authorization_bindings(&application.id, &profile.id)
                .await
                .unwrap()
                .user_bindings
                .get(&user.id)
                .is_none_or(|binding| binding.user_role_ids.is_empty())
        );
        assert!(
            db.read_application_authorization_bindings(&application.id, &profile.id)
                .await
                .unwrap()
                .group_bindings
                .get(&group.id)
                .is_none_or(Vec::is_empty)
        );
        assert!(
            db.read_application_authorization_bindings(&application.id, &profile.id)
                .await
                .unwrap()
                .organization_role_bindings
                .get(crate::organizations::ROLE_ADMIN)
                .is_none_or(Vec::is_empty)
        );

        drop(state);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_entitlements_keep_login_open_but_scope_policy_to_tenant_members() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("entitlement-scope", "Entitlement Scope"))
            .await
            .unwrap();
        let other_organization = db
            .insert_organization(test_organization("entitlement-other", "Entitlement Other"))
            .await
            .unwrap();
        let member = db
            .insert_user(test_user(
                "entitlement-member@example.com",
                "entitlement-member",
            ))
            .await
            .unwrap();
        let outsider = db
            .insert_user(test_user(
                "entitlement-outsider@example.com",
                "entitlement-outsider",
            ))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &member.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        db.upsert_organization_member(
            &other_organization.id,
            &outsider.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();

        let group = db
            .insert_group(NewGroup {
                name: "Mixed entitlement group".to_string(),
                description: None,
            })
            .await
            .unwrap();
        db.replace_group_members(&group.id, vec![member.id.clone(), outsider.id.clone()])
            .await
            .unwrap();
        let outsider_only_group = db
            .insert_group(NewGroup {
                name: "Outsider-only entitlement group".to_string(),
                description: None,
            })
            .await
            .unwrap();
        db.replace_group_members(&outsider_only_group.id, vec![outsider.id.clone()])
            .await
            .unwrap();
        let scoped_groups = db
            .list_application_authorization_groups(&organization.id)
            .await
            .unwrap();
        assert!(scoped_groups.iter().any(|value| value.id == group.id));
        assert!(
            !scoped_groups
                .iter()
                .any(|value| value.id == outsider_only_group.id)
        );
        let enterprise_role = db
            .insert_role(NewRole {
                name: "mixed-enterprise-role".to_string(),
                description: None,
                is_system: false,
                permissions: vec!["enterprise.mixed".to_string()],
            })
            .await
            .unwrap();
        db.replace_group_roles(&group.id, vec![enterprise_role.id])
            .await
            .unwrap();

        let normalized_application = db
            .insert_application(test_application(
                &organization.id,
                "scoped-application",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let profile = default_authorization_profile(&db, &normalized_application.id).await;
        let application_role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: profile.id.clone(),
                role_key: "mixed-application-role".to_string(),
                name: "mixed-application-role".to_string(),
                source: "manual".to_string(),
                description: None,
                permissions: vec!["application.mixed".to_string()],
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        replace_test_authorization_bindings(
            &db,
            &normalized_application.id,
            &profile.id,
            AuthorizationBindingsUpdate {
                user_id: None,
                group_id: Some(group.id.clone()),
                user_role_ids: Vec::new(),
                user_permission_overrides: Vec::new(),
                group_role_ids: vec![application_role.id],
                organization_role_bindings: BTreeMap::new(),
            },
        )
        .await;

        let settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let state = crate::AppState {
            jwt: crate::jwt::JwtManager::new(&settings).unwrap(),
            settings,
            db: db.clone(),
        };
        let member_record = db.find_user_by_id(&member.id).await.unwrap().unwrap();
        let outsider_record = db.find_user_by_id(&outsider.id).await.unwrap().unwrap();

        assert!(
            crate::authorization::check_login_access(
                &state,
                &normalized_application,
                &outsider.id,
            )
            .await
            .unwrap()
            .allowed
        );
        let member_entitlements = crate::authorization::resolve_entitlements(
            &state,
            &normalized_application,
            &member_record,
        )
        .await
        .unwrap();
        assert!(
            member_entitlements
                .roles
                .iter()
                .any(|role| role == "mixed-application-role")
        );
        assert!(
            member_entitlements
                .roles
                .iter()
                .any(|role| role == "mixed-enterprise-role")
        );
        assert!(
            member_entitlements
                .permissions
                .iter()
                .any(|permission| permission == "application.mixed")
        );
        assert!(
            member_entitlements
                .groups
                .iter()
                .any(|name| name == "Mixed entitlement group")
        );

        let outsider_entitlements = crate::authorization::resolve_entitlements(
            &state,
            &normalized_application,
            &outsider_record,
        )
        .await
        .unwrap();
        assert!(
            !outsider_entitlements
                .roles
                .iter()
                .any(|role| role == "mixed-application-role")
        );
        assert!(
            !outsider_entitlements
                .roles
                .iter()
                .any(|role| role == "mixed-enterprise-role")
        );
        assert!(
            !outsider_entitlements
                .permissions
                .iter()
                .any(|permission| permission == "application.mixed")
        );
        assert!(outsider_entitlements.groups.is_empty());
        assert!(outsider_entitlements.organization_role.is_none());

        let legacy_application = db
            .insert_application(test_application(
                &organization.id,
                "legacy-scoped-application",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let legacy_profile = db
            .find_application_authorization_profile(&legacy_application.id, "default")
            .await
            .unwrap()
            .unwrap();
        db.upsert_application_profile_role(NewApplicationProfileRole {
            id: Some("legacy-member-role".to_string()),
            profile_id: legacy_profile.id.clone(),
            role_key: "legacy-member".to_string(),
            name: "Legacy member".to_string(),
            description: None,
            permissions: vec!["legacy.default".to_string()],
            source: "manual".to_string(),
            is_default: true,
            is_active: true,
        })
        .await
        .unwrap();
        let legacy_operator = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("legacy-operator-role".to_string()),
                profile_id: legacy_profile.id.clone(),
                role_key: "legacy-operator".to_string(),
                name: "Legacy operator".to_string(),
                description: None,
                permissions: vec!["legacy.mixed".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        db.replace_application_authorization_bindings_with_audit(
            &legacy_application.id,
            &legacy_profile.id,
            AuthorizationBindingsUpdate {
                user_id: None,
                group_id: Some(group.id.clone()),
                user_role_ids: Vec::new(),
                user_permission_overrides: Vec::new(),
                group_role_ids: vec![legacy_operator.id],
                organization_role_bindings: BTreeMap::new(),
            },
            audit::management_event(
                "authorization-profile-test",
                "application.authorization_profile.bindings.update",
                "application_authorization_profile",
                Some(legacy_profile.id.clone()),
                serde_json::json!({}),
            ),
        )
        .await
        .unwrap();
        let member_legacy =
            crate::authorization::resolve_entitlements(&state, &legacy_application, &member_record)
                .await
                .unwrap();
        let outsider_legacy = crate::authorization::resolve_entitlements(
            &state,
            &legacy_application,
            &outsider_record,
        )
        .await
        .unwrap();
        assert!(
            member_legacy
                .roles
                .iter()
                .any(|role| role == "legacy-operator")
        );
        assert!(
            member_legacy
                .permissions
                .iter()
                .any(|permission| permission == "legacy.mixed")
        );
        assert!(
            !outsider_legacy
                .roles
                .iter()
                .any(|role| role == "legacy-operator")
        );
        assert!(
            !outsider_legacy
                .permissions
                .iter()
                .any(|permission| permission == "legacy.mixed")
        );
        assert!(
            outsider_legacy
                .roles
                .iter()
                .any(|role| role == "legacy-member")
        );

        let profile_application = db
            .insert_application(test_application(
                &organization.id,
                "profile-scoped-application",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let profile = db
            .find_application_authorization_profile(&profile_application.id, "default")
            .await
            .unwrap()
            .unwrap();
        let profile_role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: profile.id.clone(),
                role_key: "profile-operator".to_string(),
                name: "Profile operator".to_string(),
                description: None,
                permissions: vec!["profile.mixed".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        db.replace_application_authorization_bindings_with_audit(
            &profile_application.id,
            &profile.id,
            AuthorizationBindingsUpdate {
                user_id: None,
                group_id: Some(group.id.clone()),
                user_role_ids: Vec::new(),
                user_permission_overrides: Vec::new(),
                group_role_ids: vec![profile_role.id],
                organization_role_bindings: BTreeMap::new(),
            },
            crate::audit::management_event(
                "authorization-profile-test",
                "application.authorization_profile.bindings.update",
                "application_authorization_profile",
                Some(profile.id.clone()),
                serde_json::json!({}),
            ),
        )
        .await
        .unwrap();
        let member_profile = crate::authorization::resolve_entitlements_for_profile(
            &state,
            &profile_application,
            &profile,
            &member_record,
        )
        .await
        .unwrap();
        let outsider_profile = crate::authorization::resolve_entitlements_for_profile(
            &state,
            &profile_application,
            &profile,
            &outsider_record,
        )
        .await
        .unwrap();
        assert!(
            member_profile
                .permissions
                .iter()
                .any(|permission| permission == "profile.mixed")
        );
        assert!(
            !outsider_profile
                .permissions
                .iter()
                .any(|permission| permission == "profile.mixed")
        );

        drop(state);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_scim_tokens_are_hash_only_scoped_and_single_use_by_state() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("scim-token-org", "SCIM Token Org"))
            .await
            .unwrap();
        let first = db
            .insert_application(test_application(
                &organization.id,
                "scim-first",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let second = db
            .insert_application(test_application(
                &organization.id,
                "scim-second",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let raw_token = "scim_v1_first_secret";
        let token = db
            .insert_application_scim_token(NewApplicationScimToken {
                id: "scim-token-first".to_string(),
                application_id: first.id.clone(),
                token_prefix: "scim_v1_first".to_string(),
                token_hash: util::token_hash(raw_token),
                scopes: vec!["scim.read".to_string()],
                expires_at: None,
            })
            .await
            .unwrap();
        assert_eq!(token.token_hash, util::token_hash(raw_token));
        assert_eq!(token.scopes, r#"["scim.read"]"#);
        assert!(
            db.find_active_application_scim_token(&util::token_hash(raw_token))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.find_active_application_scim_token(&util::token_hash("wrong"))
                .await
                .unwrap()
                .is_none()
        );

        db.touch_application_scim_token(&util::token_hash(raw_token))
            .await
            .unwrap();
        let touched = db
            .find_active_application_scim_token(&util::token_hash(raw_token))
            .await
            .unwrap()
            .unwrap();
        assert!(touched.last_used_at.is_some());

        let expired = "scim_v1_expired";
        db.insert_application_scim_token(NewApplicationScimToken {
            id: "scim-token-expired".to_string(),
            application_id: first.id.clone(),
            token_prefix: "scim_v1_expired".to_string(),
            token_hash: util::token_hash(expired),
            scopes: vec!["scim.read".to_string(), "scim.write".to_string()],
            expires_at: Some(util::now_ts() - 1),
        })
        .await
        .unwrap();
        assert!(
            db.find_active_application_scim_token(&util::token_hash(expired))
                .await
                .unwrap()
                .is_none()
        );

        let second_raw = "scim_v1_second_secret";
        db.insert_application_scim_token(NewApplicationScimToken {
            id: "scim-token-second".to_string(),
            application_id: second.id.clone(),
            token_prefix: "scim_v1_second".to_string(),
            token_hash: util::token_hash(second_raw),
            scopes: vec!["scim.write".to_string()],
            expires_at: None,
        })
        .await
        .unwrap();
        db.revoke_application_scim_token(&first.id, "scim-token-second")
            .await
            .unwrap();
        assert!(
            db.find_active_application_scim_token(&util::token_hash(second_raw))
                .await
                .unwrap()
                .is_some()
        );
        db.revoke_application_scim_token(&second.id, "scim-token-second")
            .await
            .unwrap();
        assert!(
            db.find_active_application_scim_token(&util::token_hash(second_raw))
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn directory_sync_deprovision_preserves_manual_members_and_other_owners() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization(
                "directory-boundary",
                "Directory Boundary",
            ))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "directory-boundary-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let other_application = db
            .insert_application(test_application(
                &organization.id,
                "directory-boundary-other-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();

        let manual = db
            .insert_user(test_user("manual@example.com", "manual"))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &manual.id,
            crate::organizations::ROLE_ADMIN,
        )
        .await
        .unwrap();
        db.upsert_directory_sync_membership(
            &application.id,
            "ldap-primary",
            &manual.id,
            false,
            util::now_ts(),
        )
        .await
        .unwrap();
        assert!(
            !db.deprovision_directory_sync_membership(
                &application.id,
                "ldap-primary",
                &organization.id,
                &manual.id,
            )
            .await
            .unwrap()
        );
        assert_eq!(
            db.list_organization_members(&organization.id)
                .await
                .unwrap()
                .into_iter()
                .find(|member| member.user_id == manual.id)
                .unwrap()
                .role,
            crate::organizations::ROLE_ADMIN
        );

        let synced = db
            .insert_user(test_user("synced@example.com", "synced"))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &synced.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        db.upsert_directory_sync_membership(
            &application.id,
            "ldap-primary",
            &synced.id,
            true,
            util::now_ts() + 10,
        )
        .await
        .unwrap();
        assert!(
            db.deprovision_directory_sync_membership(
                &application.id,
                "ldap-primary",
                &organization.id,
                &synced.id,
            )
            .await
            .unwrap()
        );
        assert!(
            !db.user_belongs_to_organization(&organization.id, &synced.id)
                .await
                .unwrap()
        );

        let shared = db
            .insert_user(test_user("shared@example.com", "shared"))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &shared.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        db.upsert_directory_sync_membership(
            &application.id,
            "ldap-primary",
            &shared.id,
            true,
            util::now_ts() + 10,
        )
        .await
        .unwrap();
        db.upsert_directory_sync_membership(
            &other_application.id,
            "ldap-secondary",
            &shared.id,
            true,
            util::now_ts() + 10,
        )
        .await
        .unwrap();
        assert!(
            !db.deprovision_directory_sync_membership(
                &application.id,
                "ldap-primary",
                &organization.id,
                &shared.id,
            )
            .await
            .unwrap()
        );
        assert!(
            db.user_belongs_to_organization(&organization.id, &shared.id)
                .await
                .unwrap()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_scim_groups_are_application_and_organization_scoped() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("group-boundary", "Group Boundary"))
            .await
            .unwrap();
        let other_organization = db
            .insert_organization(test_organization(
                "other-group-boundary",
                "Other Group Boundary",
            ))
            .await
            .unwrap();
        let first = db
            .insert_application(test_application(
                &organization.id,
                "group-first",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let second = db
            .insert_application(test_application(
                &organization.id,
                "group-second",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let same_org_user = db
            .insert_user(test_user("same-org@example.com", "same-org"))
            .await
            .unwrap();
        let other_org_user = db
            .insert_user(test_user("other-org@example.com", "other-org"))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &same_org_user.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        db.upsert_organization_member(
            &other_organization.id,
            &other_org_user.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();

        let group = db
            .insert_application_scim_group(
                &first.id,
                NewGroup {
                    name: "Directory group".to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        db.replace_application_scim_group_members(
            &first.id,
            &group.id,
            vec![same_org_user.id.clone()],
        )
        .await
        .unwrap();
        assert_eq!(
            db.list_application_scim_group_members(&first.id, &group.id)
                .await
                .unwrap()
                .len(),
            1
        );
        let (user_total, users) = db
            .list_users_page(
                UserListScope::Live,
                Some(&organization.id),
                Some(UserListFilter::UserName("SAME-ORG".to_string())),
                0,
                10,
            )
            .await
            .unwrap();
        assert_eq!(user_total, 1);
        assert_eq!(users[0].id, same_org_user.id);
        let (group_total, groups) = db
            .list_groups_page(
                Some(&first.id),
                Some(GroupListFilter::DisplayName("DIRECTORY GROUP".to_string())),
                0,
                10,
            )
            .await
            .unwrap();
        assert_eq!(group_total, 1);
        assert_eq!(groups[0].id, group.id);
        let member_refs = db
            .list_scim_group_member_refs_page(
                Some(&first.id),
                Some(GroupListFilter::Id(group.id.clone())),
                0,
                10,
            )
            .await
            .unwrap();
        assert_eq!(member_refs.len(), 1);
        assert_eq!(member_refs[0].user_id, same_org_user.id);
        assert!(
            db.list_application_scim_groups(&second.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.find_application_scim_group(&second.id, &group.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.replace_application_scim_group_members(
                &first.id,
                &group.id,
                vec![other_org_user.id],
            )
            .await
            .is_err()
        );

        db.delete_application_scim_group(&first.id, &group.id)
            .await
            .unwrap();
        assert!(db.find_group_by_id(&group.id).await.unwrap().is_none());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn active_signet_accounts_do_not_need_application_membership() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("active-account", "Active Account"))
            .await
            .unwrap();
        let user = db
            .insert_user(test_user("active@example.com", "active"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "active-website",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();

        assert!(
            db.user_can_access_application(&application, &user.id)
                .await
                .unwrap()
        );

        // A historical application_members row is not a login gate and does
        // not trigger a self-enrollment write on the next login.
        db.replace_application_members(
            &application.id,
            vec![NewApplicationMember {
                user_id: user.id.clone(),
                role: "member".to_string(),
                is_active: false,
            }],
        )
        .await
        .unwrap();
        assert!(
            db.user_can_access_application(&application, &user.id)
                .await
                .unwrap()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_identity_factor_collision_is_local_and_roster_updates_release_it() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("factor-co", "Factor Co"))
            .await
            .unwrap();
        let first = db
            .insert_user(test_user("first@example.com", "first"))
            .await
            .unwrap();
        let second = db
            .insert_user(test_user("second@example.com", "second"))
            .await
            .unwrap();
        for user in [&first, &second] {
            db.upsert_organization_member(
                &organization.id,
                &user.id,
                crate::organizations::ROLE_MEMBER,
            )
            .await
            .unwrap();
        }
        let application = db
            .insert_application(test_application(
                &organization.id,
                "unique-contact",
                crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
            ))
            .await
            .unwrap();
        db.replace_application_members(
            &application.id,
            vec![
                NewApplicationMember {
                    user_id: first.id.clone(),
                    role: "member".to_string(),
                    is_active: true,
                },
                NewApplicationMember {
                    user_id: second.id.clone(),
                    role: "member".to_string(),
                    is_active: true,
                },
            ],
        )
        .await
        .unwrap();
        db.replace_application_identity_bindings(
            &application.id,
            &first.id,
            vec![(
                crate::applications::FACTOR_EMAIL.to_string(),
                "digest".to_string(),
            )],
        )
        .await
        .unwrap();
        assert!(
            !db.application_identity_factor_is_available(
                &application.id,
                crate::applications::FACTOR_EMAIL,
                "digest",
                &second.id,
            )
            .await
            .unwrap()
        );
        // Keeping an unchanged assigned-account roster must not temporarily
        // release the first member's uniqueness reservation.
        db.replace_application_members(
            &application.id,
            vec![
                NewApplicationMember {
                    user_id: first.id.clone(),
                    role: "member".to_string(),
                    is_active: true,
                },
                NewApplicationMember {
                    user_id: second.id.clone(),
                    role: "member".to_string(),
                    is_active: true,
                },
            ],
        )
        .await
        .unwrap();
        assert!(
            !db.application_identity_factor_is_available(
                &application.id,
                crate::applications::FACTOR_EMAIL,
                "digest",
                &second.id,
            )
            .await
            .unwrap()
        );
        db.replace_application_members(
            &application.id,
            vec![NewApplicationMember {
                user_id: second.id.clone(),
                role: "member".to_string(),
                is_active: true,
            }],
        )
        .await
        .unwrap();
        assert!(
            db.application_identity_factor_is_available(
                &application.id,
                crate::applications::FACTOR_EMAIL,
                "digest",
                &second.id,
            )
            .await
            .unwrap()
        );

        // The same preservation rule applies to an enterprise roster edit:
        // a member that stays in the tenant keeps the reservation, while a
        // removed member releases it.
        db.replace_application_members(
            &application.id,
            vec![
                NewApplicationMember {
                    user_id: first.id.clone(),
                    role: "member".to_string(),
                    is_active: true,
                },
                NewApplicationMember {
                    user_id: second.id.clone(),
                    role: "member".to_string(),
                    is_active: true,
                },
            ],
        )
        .await
        .unwrap();
        db.replace_application_identity_bindings(
            &application.id,
            &first.id,
            vec![(
                crate::applications::FACTOR_EMAIL.to_string(),
                "digest".to_string(),
            )],
        )
        .await
        .unwrap();
        db.replace_organization_members(
            &organization.id,
            vec![
                OrganizationMemberInput {
                    user_id: first.id.clone(),
                    role: crate::organizations::ROLE_MEMBER.to_string(),
                },
                OrganizationMemberInput {
                    user_id: second.id.clone(),
                    role: crate::organizations::ROLE_MEMBER.to_string(),
                },
            ],
        )
        .await
        .unwrap();
        assert!(
            !db.application_identity_factor_is_available(
                &application.id,
                crate::applications::FACTOR_EMAIL,
                "digest",
                &second.id,
            )
            .await
            .unwrap()
        );
        db.replace_organization_members(
            &organization.id,
            vec![OrganizationMemberInput {
                user_id: second.id.clone(),
                role: crate::organizations::ROLE_MEMBER.to_string(),
            }],
        )
        .await
        .unwrap();
        assert!(
            db.application_identity_factor_is_available(
                &application.id,
                crate::applications::FACTOR_EMAIL,
                "digest",
                &second.id,
            )
            .await
            .unwrap()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn contact_changes_and_deactivation_release_the_correct_identity_leases() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("contact-leases", "Contact Leases"))
            .await
            .unwrap();
        let mut first_input = test_user("first-contact@example.com", "first-contact");
        first_input.phone = Some("+12025550123".to_string());
        first_input.email_verified_at = Some(util::now_ts());
        first_input.phone_verified_at = Some(util::now_ts());
        let first = db.insert_user(first_input).await.unwrap();
        let second = db
            .insert_user(test_user("second-contact@example.com", "second-contact"))
            .await
            .unwrap();
        for user in [&first, &second] {
            db.upsert_organization_member(
                &organization.id,
                &user.id,
                crate::organizations::ROLE_MEMBER,
            )
            .await
            .unwrap();
        }
        let application = db
            .insert_application(test_application(
                &organization.id,
                "contact-uniqueness",
                crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
            ))
            .await
            .unwrap();
        db.replace_application_members(
            &application.id,
            vec![
                NewApplicationMember {
                    user_id: first.id.clone(),
                    role: "member".to_string(),
                    is_active: true,
                },
                NewApplicationMember {
                    user_id: second.id.clone(),
                    role: "member".to_string(),
                    is_active: true,
                },
            ],
        )
        .await
        .unwrap();
        let leases = || {
            vec![
                (
                    crate::applications::FACTOR_EMAIL.to_string(),
                    "old-email".to_string(),
                ),
                (
                    crate::applications::FACTOR_PHONE.to_string(),
                    "phone".to_string(),
                ),
            ]
        };
        db.replace_application_identity_bindings(&application.id, &first.id, leases())
            .await
            .unwrap();

        let updated = db
            .update_user(UserUpdate {
                id: &first.id,
                email: "first-contact-new@example.com".to_string(),
                username: first.username.clone(),
                display_name: first.display_name.clone(),
                phone: first.phone.clone(),
                is_admin: first.is_admin == 1,
                is_active: true,
            })
            .await
            .unwrap();
        assert!(updated.email_verified_at.is_none());
        assert!(updated.phone_verified_at.is_some());
        assert!(
            db.application_identity_factor_is_available(
                &application.id,
                crate::applications::FACTOR_EMAIL,
                "old-email",
                &second.id,
            )
            .await
            .unwrap()
        );
        assert!(
            !db.application_identity_factor_is_available(
                &application.id,
                crate::applications::FACTOR_PHONE,
                "phone",
                &second.id,
            )
            .await
            .unwrap()
        );

        let updated = db
            .update_user(UserUpdate {
                id: &updated.id,
                email: updated.email.clone(),
                username: updated.username.clone(),
                display_name: updated.display_name.clone(),
                phone: Some("+12025550124".to_string()),
                is_admin: updated.is_admin == 1,
                is_active: true,
            })
            .await
            .unwrap();
        assert!(updated.phone_verified_at.is_none());
        assert!(
            db.application_identity_factor_is_available(
                &application.id,
                crate::applications::FACTOR_PHONE,
                "phone",
                &second.id,
            )
            .await
            .unwrap()
        );

        // Deactivation through the profile update, the dedicated disable
        // endpoint and archival all release every remaining lease.
        db.replace_application_identity_bindings(&application.id, &updated.id, leases())
            .await
            .unwrap();
        let deactivated = db
            .update_user(UserUpdate {
                id: &updated.id,
                email: updated.email.clone(),
                username: updated.username.clone(),
                display_name: updated.display_name.clone(),
                phone: updated.phone.clone(),
                is_admin: updated.is_admin == 1,
                is_active: false,
            })
            .await
            .unwrap();
        assert_eq!(deactivated.is_active, 0);
        for (factor, digest) in leases() {
            assert!(
                db.application_identity_factor_is_available(
                    &application.id,
                    &factor,
                    &digest,
                    &second.id,
                )
                .await
                .unwrap()
            );
        }

        db.enable_user(&updated.id).await.unwrap();
        db.replace_application_identity_bindings(&application.id, &updated.id, leases())
            .await
            .unwrap();
        db.disable_user(&updated.id).await.unwrap();
        for (factor, digest) in leases() {
            assert!(
                db.application_identity_factor_is_available(
                    &application.id,
                    &factor,
                    &digest,
                    &second.id,
                )
                .await
                .unwrap()
            );
        }

        db.enable_user(&updated.id).await.unwrap();
        db.replace_application_identity_bindings(&application.id, &updated.id, leases())
            .await
            .unwrap();
        db.archive_user(&updated.id).await.unwrap();
        for (factor, digest) in leases() {
            assert!(
                db.application_identity_factor_is_available(
                    &application.id,
                    &factor,
                    &digest,
                    &second.id,
                )
                .await
                .unwrap()
            );
        }

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn browser_context_accounts_are_ordered_by_session_login_time() {
        let (db, path) = sqlite_test_db().await;
        let older_user = db
            .insert_user(test_user("older-session@example.com", "older-session"))
            .await
            .unwrap();
        let newer_user = db
            .insert_user(test_user("newer-session@example.com", "newer-session"))
            .await
            .unwrap();
        let context_id = "browser-context-login-time";
        db.insert_browser_context(context_id, "csrf", 600)
            .await
            .unwrap();
        let (older_session, _) = db
            .insert_session(&older_user.id, 600, SessionMetadata::default())
            .await
            .unwrap();
        let (newer_session, _) = db
            .insert_session(&newer_user.id, 600, SessionMetadata::default())
            .await
            .unwrap();
        let older_account = db
            .attach_browser_context_account(context_id, &older_user.id, &older_session.id)
            .await
            .unwrap();
        let newer_account = db
            .attach_browser_context_account(context_id, &newer_user.id, &newer_session.id)
            .await
            .unwrap();

        // Make selection recency deliberately disagree with login recency.
        // The list must follow the session's successful-login timestamp.
        let older_session_id = older_session.id.clone();
        let newer_session_id = newer_session.id.clone();
        let older_account_id = older_account.id.clone();
        let newer_account_id = newer_account.id.clone();
        with_conn!(db, |conn, kind| {
            let update_session = format!(
                "UPDATE sessions SET created_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(&update_session)
                .bind::<BigInt, _>(10)
                .bind::<Text, _>(older_session_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            sql_query(update_session)
                .bind::<BigInt, _>(20)
                .bind::<Text, _>(newer_session_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let update_selection = format!(
                "UPDATE browser_context_accounts SET last_selected_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(&update_selection)
                .bind::<BigInt, _>(30)
                .bind::<Text, _>(older_account_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            sql_query(update_selection)
                .bind::<BigInt, _>(5)
                .bind::<Text, _>(newer_account_id)
                .execute(&mut conn)
                .map_err(AppError::from)
        })
        .unwrap();

        let accounts = db.list_browser_context_accounts(context_id).await.unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].id, newer_account.id);
        assert_eq!(accounts[1].id, older_account.id);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bulk_provisioning_creates_memberships_and_rolls_back_the_entire_batch() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "corp".to_string(),
                name: "Corp".to_string(),
                kind: ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();

        let rejected = db
            .insert_bulk_provisioned_users(vec![
                test_bulk_user(
                    "first@example.com",
                    "first",
                    Some(&organization.id),
                    Some(crate::organizations::ROLE_MEMBER),
                ),
                test_bulk_user(
                    "blocked@other.test",
                    "blocked",
                    Some(&organization.id),
                    Some(crate::organizations::ROLE_ADMIN),
                ),
            ])
            .await;
        assert!(matches!(
            rejected,
            Err(AppError::BadRequest(message))
                if message == "email is not allowed by the organization policy"
        ));
        assert!(
            db.find_user_by_email("first@example.com")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_organization_members(&organization.id)
                .await
                .unwrap()
                .is_empty()
        );

        let created = db
            .insert_bulk_provisioned_users(vec![
                test_bulk_user(
                    "owner@example.com",
                    "owner",
                    Some(&organization.id),
                    Some(crate::organizations::ROLE_OWNER),
                ),
                test_bulk_user(
                    "member@example.com",
                    "member",
                    Some(&organization.id),
                    Some(crate::organizations::ROLE_MEMBER),
                ),
            ])
            .await
            .unwrap();
        assert_eq!(created.len(), 2);
        let memberships = db
            .list_organization_members(&organization.id)
            .await
            .unwrap();
        assert_eq!(memberships.len(), 2);
        assert!(memberships.iter().any(|membership| {
            membership.user_id == created[0].id
                && membership.role == crate::organizations::ROLE_OWNER
        }));
        assert!(memberships.iter().any(|membership| {
            membership.user_id == created[1].id
                && membership.role == crate::organizations::ROLE_MEMBER
        }));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bulk_provisioning_never_overwrites_an_existing_identity() {
        let (db, path) = sqlite_test_db().await;
        let existing = db
            .insert_user(test_user("existing@example.com", "existing"))
            .await
            .unwrap();

        let result = db
            .insert_bulk_provisioned_users(vec![test_bulk_user(
                "existing@example.com",
                "different",
                None,
                None,
            )])
            .await;
        assert!(matches!(
            result,
            Err(AppError::BadRequest(message))
                if message == "user email or username already exists"
        ));
        let after = db
            .find_user_by_email("existing@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.id, existing.id);
        assert_eq!(after.username, "existing");
        assert!(
            db.find_user_by_username("different")
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn trial_enrollment_code_creates_only_new_restricted_organization_members() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "trial-team".to_string(),
                name: "Trial Team".to_string(),
                kind: ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();
        db.insert_user(test_user("taken@example.com", "taken"))
            .await
            .unwrap();
        let mut invitation = test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::TrialEnrollment,
            None,
            None,
            vec!["trial-client".to_string()],
        );
        invitation.organization_id = Some(organization.id.clone());
        invitation.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
        invitation.expires_at = Some(util::now_ts() + 300);
        invitation.max_uses = Some(2);
        let (stored, code) = db.insert_invitation(invitation).await.unwrap();

        let collision = db
            .redeem_trial_enrollment_code_for_new_user(
                &code,
                NewTrialEnrollmentUser {
                    email: "taken@example.com".to_string(),
                    username: "new-name".to_string(),
                    display_name: None,
                    password_hash: "hash".to_string(),
                },
            )
            .await;
        assert!(
            matches!(collision, Err(AppError::BadRequest(message)) if message.contains("existing account"))
        );
        assert_eq!(
            db.find_invitation_by_id(&stored.id)
                .await
                .unwrap()
                .unwrap()
                .uses_count,
            0
        );

        let redemption = db
            .redeem_trial_enrollment_code_for_new_user(
                &code,
                NewTrialEnrollmentUser {
                    email: "visitor@example.com".to_string(),
                    username: "visitor".to_string(),
                    display_name: Some("Visitor".to_string()),
                    password_hash: "hash".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(redemption.organization_id, organization.id);
        assert_eq!(redemption.user.is_admin, 0);
        assert_eq!(
            redemption.user.registration_source,
            UserRegistrationSource::AuthorizationCode.as_str()
        );
        let enrollment = db
            .find_trial_enrollment_for_user(&redemption.user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(enrollment.invitation_id, stored.id);
        assert!(enrollment.allows_client("trial-client").unwrap());
        assert!(!enrollment.allows_client("other-client").unwrap());
        let members = db
            .list_organization_members(&organization.id)
            .await
            .unwrap();
        assert!(members.iter().any(|member| {
            member.user_id == redemption.user.id && member.role == crate::organizations::ROLE_MEMBER
        }));
        let authorization_code_users = db
            .list_users(UserListScope::AuthorizationCode)
            .await
            .unwrap();
        assert_eq!(authorization_code_users.len(), 1);
        assert_eq!(authorization_code_users[0].id, redemption.user.id);

        db.update_invitation(InvitationUpdate {
            id: &stored.id,
            description: None,
            authorized_email: None,
            authorized_username: None,
            authorized_display_name: None,
            expires_at: Some(util::now_ts() + 300),
            max_uses: Some(2),
            is_active: false,
        })
        .await
        .unwrap();
        let revoked = db
            .find_trial_enrollment_for_user(&redemption.user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(revoked.revoked_at.is_some());
        assert!(
            db.find_active_trial_enrollment_for_user(&redemption.user.id)
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn organization_registration_invitation_creates_a_normal_member_account() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "invite-team".to_string(),
                name: "Invite Team".to_string(),
                kind: ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();
        let mut invitation = test_invitation(
            AuthorizationCodeType::Registration,
            LoginCodeLevel::AccountRecovery,
            None,
            None,
            Vec::new(),
        );
        invitation.organization_id = Some(organization.id.clone());
        invitation.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
        invitation.authorized_email = Some("invited@example.com".to_string());
        invitation.expires_at = Some(util::now_ts() + 300);
        invitation.max_uses = Some(1);
        let (stored, code) = db.insert_invitation(invitation).await.unwrap();

        let user = db
            .redeem_registration_code_for_new_user(
                &code,
                NewUser {
                    email: "invited@example.com".to_string(),
                    username: "invited".to_string(),
                    display_name: Some("Invited member".to_string()),
                    phone: None,
                    password_hash: "hash".to_string(),
                    email_verified_at: Some(util::now_ts()),
                    phone_verified_at: None,
                    is_admin: false,
                    is_active: true,
                    archived_at: None,
                },
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            user.registration_source,
            UserRegistrationSource::AuthorizationCode.as_str()
        );
        let memberships = db.list_user_organizations(&user.id).await.unwrap();
        assert!(memberships.iter().any(|membership| {
            membership.id == organization.id && membership.role == crate::organizations::ROLE_MEMBER
        }));
        assert_eq!(
            db.list_organization_registration_invitations(&organization.id)
                .await
                .unwrap()
                .into_iter()
                .map(|invitation| invitation.id)
                .collect::<Vec<_>>(),
            vec![stored.id]
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_enrollment_codes_grant_only_their_own_assigned_application() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization(
                "app-enrollment",
                "Application Enrollment",
            ))
            .await
            .unwrap();
        let mut application = test_application(
            &organization.id,
            "restricted-app",
            crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
        );
        application.registration_mode = crate::applications::REGISTRATION_INVITATION.to_string();
        let application = db.insert_application(application).await.unwrap();
        let client = db
            .insert_client_for_application(
                &application.id,
                test_client("restricted-enrollment-client", &organization.id),
            )
            .await
            .unwrap();

        let mut unrelated = test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::TrialEnrollment,
            None,
            None,
            vec![client.client_id.clone()],
        );
        unrelated.organization_id = Some(organization.id.clone());
        unrelated.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
        unrelated.expires_at = Some(util::now_ts() + 300);
        unrelated.max_uses = Some(1);
        let (_, unrelated_code) = db.insert_invitation(unrelated).await.unwrap();
        let unrelated_user = db
            .redeem_trial_enrollment_code_for_new_user(
                &unrelated_code,
                NewTrialEnrollmentUser {
                    email: "unrelated@example.com".to_string(),
                    username: "unrelated".to_string(),
                    display_name: None,
                    password_hash: "hash".to_string(),
                },
            )
            .await
            .unwrap()
            .user;
        assert!(
            db.user_can_access_application(&application, &unrelated_user.id)
                .await
                .unwrap()
        );

        let mut invitation = test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::TrialEnrollment,
            None,
            None,
            vec![client.client_id.clone()],
        );
        invitation.organization_id = Some(organization.id.clone());
        invitation.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
        invitation.expires_at = Some(util::now_ts() + 300);
        invitation.max_uses = Some(1);
        let (invitation, enrollment_code) = db.insert_invitation(invitation).await.unwrap();
        db.link_application_enrollment_code(&application.id, &invitation.id)
            .await
            .unwrap();
        let enrollment = db
            .redeem_trial_enrollment_code_for_new_user(
                &enrollment_code,
                NewTrialEnrollmentUser {
                    email: "application-member@example.com".to_string(),
                    username: "application-member".to_string(),
                    display_name: None,
                    password_hash: "hash".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(
            db.user_can_access_application(&application, &enrollment.user.id)
                .await
                .unwrap()
        );
        assert_eq!(
            db.list_application_enrollment_codes(&application.id)
                .await
                .unwrap()
                .len(),
            1
        );

        db.delete_invitation(&invitation.id).await.unwrap();
        assert!(
            db.list_application_enrollment_codes(&application.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.find_active_trial_enrollment_for_user(&enrollment.user.id)
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn normal_application_enrollment_code_creates_a_reusable_enterprise_member() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("normal-enroll", "Normal Enroll"))
            .await
            .unwrap();
        let mut application = test_application(
            &organization.id,
            "employee-app",
            crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
        );
        application.registration_mode = crate::applications::REGISTRATION_INVITATION.to_string();
        let application = db.insert_application(application).await.unwrap();
        let client = db
            .insert_client_for_application(
                &application.id,
                test_client("employee-app-client", &organization.id),
            )
            .await
            .unwrap();

        let mut invitation = test_invitation(
            AuthorizationCodeType::Registration,
            LoginCodeLevel::AccountRecovery,
            None,
            None,
            vec![client.client_id],
        );
        invitation.organization_id = Some(organization.id.clone());
        invitation.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
        invitation.expires_at = Some(util::now_ts() + 300);
        invitation.max_uses = Some(1);
        let (invitation, code) = db.insert_invitation(invitation).await.unwrap();
        db.link_application_enrollment_code(&application.id, &invitation.id)
            .await
            .unwrap();
        assert_eq!(
            db.find_application_for_enrollment_code(&invitation.id)
                .await
                .unwrap()
                .unwrap()
                .id,
            application.id
        );

        let user = db
            .redeem_registration_code_for_new_user(
                &code,
                NewUser {
                    email: "employee@example.com".to_string(),
                    username: "employee".to_string(),
                    display_name: None,
                    phone: None,
                    password_hash: "hash".to_string(),
                    email_verified_at: Some(util::now_ts()),
                    phone_verified_at: None,
                    is_admin: false,
                    is_active: true,
                    archived_at: None,
                },
                Vec::new(),
            )
            .await
            .unwrap();
        assert!(
            db.list_user_organizations(&user.id)
                .await
                .unwrap()
                .iter()
                .any(|membership| membership.id == organization.id)
        );
        assert!(
            db.user_can_access_application(&application, &user.id)
                .await
                .unwrap()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn managed_client_starts_with_a_locked_explicit_application() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("locked-client", "Locked Client"))
            .await
            .unwrap();
        let client = db
            .insert_client(test_client("locked-client-oidc", &organization.id))
            .await
            .unwrap();
        let compatibility = db
            .find_application_for_client(&client.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            compatibility.access_mode,
            crate::applications::ACCESS_ALL_SIGNET_USERS
        );

        let application = db.harden_new_client_application(&client.id).await.unwrap();
        assert_eq!(application.organization_id, organization.id);
        assert_eq!(
            application.access_mode,
            crate::applications::ACCESS_ALL_SIGNET_USERS
        );
        assert_eq!(
            application.registration_mode,
            crate::applications::REGISTRATION_DISABLED
        );
        assert_eq!(application.is_active, 1);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn website_manifest_removes_profiles_and_client_links_from_the_snapshot() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("website-snapshot", "Website Snapshot"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "website-snapshot",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        db.upsert_application_discovery(NewApplicationDiscovery {
            application_id: application.id.clone(),
            management_mode: crate::application_discovery::MANAGEMENT_MODE_WEBSITE.to_string(),
            website_url: "https://website.example".to_string(),
            fetch_secret_ciphertext: "encrypted-fetch-secret".to_string(),
            signing_public_jwks: "{}".to_string(),
            last_verified_revision: None,
            last_verified_version: None,
            last_verified_digest: None,
            last_verified_expires_at: None,
            sync_status: crate::application_discovery::SYNC_PENDING.to_string(),
            last_fetched_at: None,
            last_success_at: None,
            last_error: None,
            snapshot_json: None,
            operator_disabled: false,
        })
        .await
        .unwrap();

        let old_client = test_client("website-old-client", &organization.id);
        let old_client_id = old_client.client_id.clone();
        let profile = crate::application_discovery::NormalizedProfile {
            permissions: vec![crate::application_discovery::NormalizedPermission {
                key: "website.read".to_string(),
                label: "Website read".to_string(),
                description: None,
            }],
            roles: vec![crate::application_discovery::NormalizedRole {
                key: "member".to_string(),
                name: "Member".to_string(),
                description: None,
                permissions: vec!["website.read".to_string()],
                is_default: true,
            }],
        };
        let mut profiles = BTreeMap::new();
        profiles.insert("default".to_string(), profile.clone());
        profiles.insert(old_client_id.clone(), profile);
        db.apply_application_contract(
            &application.id,
            crate::application_discovery::VerifiedApplicationManifest {
                application_id: application.slug.clone(),
                revision: 1,
                version: "v1".to_string(),
                digest: "digest-1".to_string(),
                issued_at: util::now_ts(),
                expires_at: util::now_ts() + 300,
                revoke_removed_clients: true,
                clients: vec![old_client],
                client_protocols: [(old_client_id.clone(), "oidc".to_string())]
                    .into_iter()
                    .collect(),
                protocols: serde_json::json!({
                    "website_url": "https://website.example",
                    "oauth2_oidc": {"enabled": true, "client_ids": [old_client_id]}
                }),
                login_adapters: serde_json::json!({
                    "enabled": true,
                    "allow_signet_password": true,
                    "provider_ids": []
                }),
                directory_sync: serde_json::json!({
                    "enabled": false,
                    "scim_enabled": false,
                    "sync_groups": false
                }),
                authorization: serde_json::json!({
                    "inherit_enterprise_roles": true,
                    "default_role": "member",
                    "claims": []
                }),
                authorization_mappings: Default::default(),
                profiles,
                redacted_payload: serde_json::json!({}),
            },
        )
        .await
        .unwrap();
        let old_profile = db
            .find_application_authorization_profile(&application.id, &old_client_id)
            .await
            .unwrap()
            .unwrap();

        let mut default_profiles = BTreeMap::new();
        default_profiles.insert(
            "default".to_string(),
            crate::application_discovery::NormalizedProfile {
                permissions: vec![crate::application_discovery::NormalizedPermission {
                    key: "website.read".to_string(),
                    label: "Website read".to_string(),
                    description: None,
                }],
                roles: vec![crate::application_discovery::NormalizedRole {
                    key: "member".to_string(),
                    name: "Member".to_string(),
                    description: None,
                    permissions: vec!["website.read".to_string()],
                    is_default: true,
                }],
            },
        );
        db.apply_application_contract(
            &application.id,
            crate::application_discovery::VerifiedApplicationManifest {
                application_id: application.slug,
                revision: 2,
                version: "v2".to_string(),
                digest: "digest-2".to_string(),
                issued_at: util::now_ts(),
                expires_at: util::now_ts() + 300,
                revoke_removed_clients: false,
                clients: Vec::new(),
                client_protocols: BTreeMap::new(),
                protocols: serde_json::json!({
                    "website_url": "https://website.example",
                    "oauth2_oidc": {"enabled": false, "client_ids": []}
                }),
                login_adapters: serde_json::json!({
                    "enabled": true,
                    "allow_signet_password": true,
                    "provider_ids": []
                }),
                directory_sync: serde_json::json!({
                    "enabled": false,
                    "scim_enabled": false,
                    "sync_groups": false
                }),
                authorization: serde_json::json!({
                    "inherit_enterprise_roles": true,
                    "default_role": "member",
                    "claims": []
                }),
                authorization_mappings: Default::default(),
                profiles: default_profiles,
                redacted_payload: serde_json::json!({}),
            },
        )
        .await
        .unwrap();

        assert!(
            db.find_application_authorization_profile(&application.id, &old_client_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_application_profile_roles(&old_profile.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.list_application_authorization_profiles(&application.id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db.find_client_by_client_id(&old_client_id)
                .await
                .unwrap()
                .unwrap()
                .is_active,
            1
        );
        assert_eq!(
            db.find_application_for_client(
                &db.find_client_by_client_id(&old_client_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
            )
            .await
            .unwrap()
            .unwrap()
            .id,
            application.id
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn detached_or_deleted_application_clients_receive_a_locked_fallback() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("fallback-client", "Fallback Client"))
            .await
            .unwrap();

        let detached_client = db
            .insert_client(test_client("detach-client", &organization.id))
            .await
            .unwrap();
        let original = db
            .harden_new_client_application(&detached_client.id)
            .await
            .unwrap();
        db.unlink_client_from_application(&detached_client.id)
            .await
            .unwrap();
        let detached_fallback = db
            .find_application_for_client(&detached_client.id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(detached_fallback.id, original.id);
        assert_eq!(
            detached_fallback.access_mode,
            crate::applications::ACCESS_ALL_SIGNET_USERS
        );
        assert_eq!(
            detached_fallback.registration_mode,
            crate::applications::REGISTRATION_DISABLED
        );

        let deleted_client = db
            .insert_client(test_client("delete-client", &organization.id))
            .await
            .unwrap();
        let deleted_application = db
            .harden_new_client_application(&deleted_client.id)
            .await
            .unwrap();
        let deleted_jwt_client = db
            .upsert_application_jwt_client(
                &deleted_application.id,
                NewApplicationJwtClient {
                    client_id: "delete-jwt-client".to_string(),
                    client_type: "confidential".to_string(),
                    is_active: true,
                },
            )
            .await
            .unwrap();
        db.rotate_application_jwt_secret(
            &deleted_application.id,
            &deleted_jwt_client.client_id,
            &util::hash_password("delete-secret").unwrap(),
            300,
        )
        .await
        .unwrap();
        db.delete_application(&deleted_application.id)
            .await
            .unwrap();
        let deleted_fallback = db
            .find_application_for_client(&deleted_client.id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(deleted_fallback.id, deleted_application.id);
        assert_eq!(
            deleted_fallback.access_mode,
            crate::applications::ACCESS_ALL_SIGNET_USERS
        );
        assert_eq!(
            deleted_fallback.registration_mode,
            crate::applications::REGISTRATION_DISABLED
        );
        assert_eq!(deleted_fallback.is_active, 1);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn oidc_client_binding_is_exclusive_and_detach_delete_are_safe() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("binding-moves", "Binding Moves"))
            .await
            .unwrap();
        let first = db
            .insert_application(test_application(
                &organization.id,
                "binding-first",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let second = db
            .insert_application(test_application(
                &organization.id,
                "binding-second",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        db.upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
            id: "binding-second-profile".to_string(),
            application_id: second.id.clone(),
            profile_key: "binding-second".to_string(),
            connection_kind: "oidc".to_string(),
            connection_id: None,
            source_mode: "manual".to_string(),
            remote_version: None,
            remote_digest: None,
            sync_status: "manual".to_string(),
            last_synced_at: None,
            last_error: None,
        })
        .await
        .unwrap();
        let foreign_organization = db
            .insert_organization(test_organization("binding-foreign", "Binding Foreign"))
            .await
            .unwrap();
        let foreign_application = db
            .insert_application(test_application(
                &foreign_organization.id,
                "binding-foreign-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let client = db
            .insert_client_for_application(
                &first.id,
                test_client("binding-exclusive-client", &organization.id),
            )
            .await
            .unwrap();
        let client_profile_id = db
            .find_application_client_binding(&client.id)
            .await
            .unwrap()
            .unwrap()
            .authorization_profile_id;

        db.link_client_to_application(&first.id, &client.id, "oidc", &client_profile_id)
            .await
            .unwrap();
        assert_eq!(
            db.list_application_client_ids(&first.id).await.unwrap(),
            vec![client.id.clone()]
        );
        assert!(
            db.link_client_to_application(&foreign_application.id, &client.id, "oidc", "default")
                .await
                .is_err()
        );
        assert_eq!(
            db.find_application_for_client(&client.id)
                .await
                .unwrap()
                .unwrap()
                .id,
            first.id
        );

        assert!(matches!(
            db.link_client_to_application(
                &first.id,
                &client.id,
                "oidc",
                "binding-second-profile"
            )
            .await,
            Err(AppError::BadRequest(message))
                if message == "authorization profile must belong to the application"
        ));

        db.upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
            id: "updated".to_string(),
            application_id: first.id.clone(),
            profile_key: "updated".to_string(),
            connection_kind: "oidc".to_string(),
            connection_id: Some(client.id.clone()),
            source_mode: "manual".to_string(),
            remote_version: None,
            remote_digest: None,
            sync_status: "manual".to_string(),
            last_synced_at: None,
            last_error: None,
        })
        .await
        .unwrap();

        db.link_client_to_application(&first.id, &client.id, "oidc", "updated")
            .await
            .unwrap();
        assert_eq!(
            db.find_application_client_binding(&client.id)
                .await
                .unwrap()
                .unwrap()
                .authorization_profile_id,
            "updated"
        );
        assert!(matches!(
            db.link_client_to_application(&second.id, &client.id, "oidc", "default")
                .await,
            Err(AppError::BadRequest(message)) if message == "OIDC client already belongs to another application"
        ));
        assert_eq!(
            db.list_application_client_ids(&first.id).await.unwrap(),
            vec![client.id.clone()]
        );
        assert!(
            db.list_application_client_ids(&second.id)
                .await
                .unwrap()
                .is_empty()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn dynamic_client_graph_rolls_back_when_registration_insert_fails() {
        let (db, path) = sqlite_test_db().await;
        let system = db.system_organization().await.unwrap();
        let client_id = "dynamic-registration-rollback";
        let applications_before = db
            .list_applications(Some(SIGNET_ORGANIZATION_ID))
            .await
            .unwrap()
            .len();

        // The trigger fails at the last graph write, after the client,
        // application, physical profile, and binding have been inserted.
        // This exercises the real database transaction rather than a
        // validation failure that happens before any row is written.
        with_conn!(db, |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_dynamic_registration BEFORE INSERT ON client_registrations BEGIN SELECT RAISE(ABORT, 'forced dynamic registration failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();

        let result = db
            .register_dynamic_client_graph(
                test_client(client_id, &system.id),
                util::token_hash("dynamic-registration-token"),
            )
            .await;
        assert!(matches!(
            result,
            Err(AppError::Database(message))
                if message.contains("forced dynamic registration failure")
        ));
        assert!(
            db.find_client_by_client_id(client_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.list_applications(Some(SIGNET_ORGANIZATION_ID))
                .await
                .unwrap()
                .len(),
            applications_before
        );

        with_conn!(db, |conn, _kind| {
            conn.batch_execute("DROP TRIGGER fail_dynamic_registration")
                .map_err(AppError::from)
        })
        .unwrap();
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn dynamic_client_graph_allocates_a_bounded_collision_suffix() {
        let (db, path) = sqlite_test_db().await;
        let system = db.system_organization().await.unwrap();
        let client_id = "dynamic-slug-collision";
        let base_slug = application_slug_base(client_id);
        for slug in [&base_slug, &format!("{base_slug}-2")] {
            db.insert_application(test_application(
                &system.id,
                slug,
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        }

        let client = db
            .register_dynamic_client_graph(
                test_client(client_id, &system.id),
                util::token_hash("dynamic-slug-token"),
            )
            .await
            .unwrap();
        let application = db
            .find_application_for_client(&client.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            application.slug,
            application_slug_collision_candidate(&base_slug, client_id)
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn application_slug_base_disambiguates_noncanonical_client_ids() {
        let canonical = application_slug_base("client-id");
        let disambiguated = application_slug_base("Client.ID");
        assert_ne!(canonical, disambiguated);
        assert!(disambiguated.len() <= 64);
        assert!(crate::applications::normalize_application_slug(&disambiguated).is_ok());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_oidc_client_graph_is_atomic_and_profile_bound() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("graph-app", "Graph App"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "graph-application",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        // Force a failure after the client insert would have happened. A
        // profile-key collision must roll back the complete aggregate rather
        // than leave an unbound client for a later reconciliation pass.
        db.upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
            id: "graph-existing-profile".to_string(),
            application_id: application.id.clone(),
            profile_key: "graph-rollback-client".to_string(),
            connection_kind: "oidc".to_string(),
            connection_id: None,
            source_mode: "manual".to_string(),
            remote_version: None,
            remote_digest: None,
            sync_status: "manual".to_string(),
            last_synced_at: None,
            last_error: None,
        })
        .await
        .unwrap();
        let rollback_result = db
            .create_application_oidc_client_graph(
                &application.id,
                test_client("graph-rollback-client", &organization.id),
                Vec::new(),
            )
            .await;
        assert!(matches!(
            rollback_result,
            Err(AppError::BadRequest(message))
                if message == "authorization profile key is already used by another connection"
        ));
        assert!(
            db.find_client_by_client_id("graph-rollback-client")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.find_application_client_binding_by_public_client_id("graph-rollback-client")
                .await
                .unwrap()
                .is_none()
        );

        // Exercise a failure after the profile, auth domain, and binding have
        // already been written. A real database trigger is used here because
        // malformed mapper input is rejected before the aggregate transaction
        // in the HTTP layer and would not test rollback at the mapper step.
        with_conn!(db, |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_graph_mapper BEFORE INSERT ON client_claim_mappers BEGIN SELECT RAISE(ABORT, 'forced graph mapper failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();
        let mapper_rollback_result = db
            .create_application_oidc_client_graph(
                &application.id,
                test_client("graph-mapper-rollback", &organization.id),
                vec![NewClientClaimMapper {
                    claim_name: "department".to_string(),
                    source: "static".to_string(),
                    source_value: "engineering".to_string(),
                    value_type: "string".to_string(),
                    include_in_id_token: true,
                    include_in_access_token: false,
                    include_in_userinfo: false,
                    is_active: true,
                    sort_order: 0,
                }],
            )
            .await;
        assert!(matches!(
            mapper_rollback_result,
            Err(AppError::Database(message)) if message.contains("forced graph mapper failure")
        ));
        assert!(
            db.find_client_by_client_id("graph-mapper-rollback")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.find_application_authorization_profile(&application.id, "graph-mapper-rollback")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.find_application_client_binding_by_public_client_id("graph-mapper-rollback")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.find_application_auth_domain(&application.id)
                .await
                .unwrap()
                .is_none()
        );
        with_conn!(db, |conn, _kind| {
            conn.batch_execute("DROP TRIGGER fail_graph_mapper")
                .map_err(AppError::from)
        })
        .unwrap();
        let client_input = test_client("graph-client", &organization.id);
        let client = db
            .create_application_oidc_client_graph(
                &application.id,
                client_input.clone(),
                vec![NewClientClaimMapper {
                    claim_name: "department".to_string(),
                    source: "static".to_string(),
                    source_value: "engineering".to_string(),
                    value_type: "string".to_string(),
                    include_in_id_token: true,
                    include_in_access_token: true,
                    include_in_userinfo: false,
                    is_active: true,
                    sort_order: 0,
                }],
            )
            .await
            .unwrap();
        let binding = db
            .find_application_client_binding(&client.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(binding.application_id, application.id);
        assert_ne!(binding.authorization_profile_id, "default");
        let profile = db
            .find_application_authorization_profile_by_id(&binding.authorization_profile_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(profile.profile_key, "graph-client");
        assert_eq!(profile.connection_id.as_deref(), Some(client.id.as_str()));
        assert_eq!(
            db.list_client_claim_mappers(&client.id)
                .await
                .unwrap()
                .len(),
            1
        );
        let graph = db.read_application_graph(&application.id).await.unwrap();
        assert_eq!(graph.bindings.len(), 1);
        assert_eq!(graph.clients.len(), 1);
        assert_eq!(graph.claim_mappers.len(), 1);
        assert_eq!(graph.organizations.len(), 1);
        assert_eq!(graph.profiles.len(), 3);
        assert!(
            graph
                .profiles
                .iter()
                .any(|profile| profile.profile_key == "graph-rollback-client")
        );
        assert!(
            graph
                .profiles
                .iter()
                .any(|profile| profile.profile_key == "graph-client")
        );

        let mut updated_input = client_input;
        updated_input.client_id = "graph-client-renamed".to_string();
        updated_input.client_name = "Graph Client Renamed".to_string();
        let updated = db
            .update_application_oidc_client_graph(
                &application.id,
                &client.id,
                updated_input,
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(updated.client_id, "graph-client-renamed");
        let updated_binding = db
            .find_application_client_binding(&client.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated_binding.authorization_profile_id,
            binding.authorization_profile_id
        );
        let renamed_profile = db
            .find_application_authorization_profile_by_id(&binding.authorization_profile_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(renamed_profile.profile_key, "graph-client-renamed");
        assert!(
            db.list_client_claim_mappers(&client.id)
                .await
                .unwrap()
                .is_empty()
        );

        db.delete_application_oidc_client_graph(&application.id, &client.id)
            .await
            .unwrap();
        assert!(db.find_client_by_id(&client.id).await.unwrap().is_none());
        assert!(
            db.find_application_authorization_profile_by_id(&binding.authorization_profile_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.find_application_client_binding(&client.id)
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_jwt_clients_support_rotation_revoke_and_one_time_codes() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("jwt-clients", "JWT Clients"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "jwt-client-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let user = db
            .insert_user(test_user("jwt-user@example.com", "jwt-user"))
            .await
            .unwrap();

        let public_client = db
            .upsert_application_jwt_client(
                &application.id,
                NewApplicationJwtClient {
                    client_id: "public-client".to_string(),
                    client_type: "public".to_string(),
                    is_active: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(public_client.client_type, "public");
        assert!(
            !db.verify_application_jwt_secret(&application.id, &public_client.client_id, "secret")
                .await
                .unwrap()
        );
        assert!(
            db.rotate_application_jwt_secret(
                &application.id,
                &public_client.client_id,
                &util::hash_password("secret").unwrap(),
                300,
            )
            .await
            .is_err()
        );

        let confidential_client = db
            .upsert_application_jwt_client(
                &application.id,
                NewApplicationJwtClient {
                    client_id: "confidential-client".to_string(),
                    client_type: "confidential".to_string(),
                    is_active: true,
                },
            )
            .await
            .unwrap();
        let first_secret = "jwt-secret-first";
        let first_hash = util::hash_password(first_secret).unwrap();
        db.rotate_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            &first_hash,
            300,
        )
        .await
        .unwrap();
        assert!(
            db.verify_application_jwt_secret(
                &application.id,
                &confidential_client.client_id,
                first_secret,
            )
            .await
            .unwrap()
        );
        assert!(
            !db.verify_application_jwt_secret(
                &application.id,
                &confidential_client.client_id,
                "wrong-secret",
            )
            .await
            .unwrap()
        );

        let second_secret = "jwt-secret-second";
        db.rotate_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            &util::hash_password(second_secret).unwrap(),
            300,
        )
        .await
        .unwrap();
        assert!(
            db.verify_application_jwt_secret(
                &application.id,
                &confidential_client.client_id,
                first_secret,
            )
            .await
            .unwrap()
        );
        assert!(
            db.verify_application_jwt_secret(
                &application.id,
                &confidential_client.client_id,
                second_secret,
            )
            .await
            .unwrap()
        );
        let secrets = db
            .list_application_jwt_secrets(&application.id, &confidential_client.client_id)
            .await
            .unwrap();
        assert_eq!(secrets.len(), 2);
        assert!(secrets.iter().all(
            |record| record.secret_hash != first_secret && record.secret_hash != second_secret
        ));

        db.revoke_application_jwt_secrets(&application.id, &confidential_client.client_id)
            .await
            .unwrap();
        assert!(
            !db.verify_application_jwt_secret(
                &application.id,
                &confidential_client.client_id,
                first_secret,
            )
            .await
            .unwrap()
        );
        assert!(
            !db.verify_application_jwt_secret(
                &application.id,
                &confidential_client.client_id,
                second_secret,
            )
            .await
            .unwrap()
        );

        db.rotate_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            &util::hash_password("disabled-secret").unwrap(),
            300,
        )
        .await
        .unwrap();
        db.upsert_application_jwt_client(
            &application.id,
            NewApplicationJwtClient {
                client_id: confidential_client.client_id.clone(),
                client_type: "confidential".to_string(),
                is_active: false,
            },
        )
        .await
        .unwrap();
        assert!(
            !db.verify_application_jwt_secret(
                &application.id,
                &confidential_client.client_id,
                "disabled-secret",
            )
            .await
            .unwrap()
        );

        let raw_code = "jwt-one-time-code";
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
        let challenge = util::sha256_base64url(verifier);
        db.insert_application_jwt_code(NewApplicationJwtCode {
            code_hash: util::token_hash(raw_code),
            application_id: application.id.clone(),
            client_id: public_client.client_id.clone(),
            redirect_uri: "https://example.test/jwt/callback".to_string(),
            user_id: user.id.clone(),
            nonce: Some("nonce".to_string()),
            code_challenge: Some(challenge.clone()),
            code_challenge_method: Some("S256".to_string()),
            expires_at: util::now_ts() + 60,
        })
        .await
        .unwrap();
        let consumed = db
            .consume_application_jwt_code(
                &util::token_hash(raw_code),
                &application.id,
                &public_client.client_id,
                "https://example.test/jwt/callback",
                &challenge,
                "S256",
            )
            .await
            .unwrap();
        assert_eq!(consumed.user_id, user.id);
        assert!(
            db.consume_application_jwt_code(
                &util::token_hash(raw_code),
                &application.id,
                &public_client.client_id,
                "https://example.test/jwt/callback",
                &challenge,
                "S256",
            )
            .await
            .is_err()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn deleting_an_organization_removes_members_and_cleans_authorization_codes() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "deleted-team".to_string(),
                name: "Deleted Team".to_string(),
                kind: ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();
        let member = db
            .insert_user(test_user("member@example.com", "member"))
            .await
            .unwrap();
        db.replace_organization_members(
            &organization.id,
            vec![OrganizationMemberInput {
                user_id: member.id.clone(),
                role: crate::organizations::ROLE_MEMBER.to_string(),
            }],
        )
        .await
        .unwrap();

        let mut trial_code = test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::TrialEnrollment,
            None,
            None,
            vec!["trial-client".to_string()],
        );
        trial_code.organization_id = Some(organization.id.clone());
        trial_code.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
        trial_code.expires_at = Some(util::now_ts() + 300);
        trial_code.max_uses = Some(2);
        let (trial_invitation, trial_secret) = db.insert_invitation(trial_code).await.unwrap();
        let trial_user = db
            .redeem_trial_enrollment_code_for_new_user(
                &trial_secret,
                NewTrialEnrollmentUser {
                    email: "trial-user@example.com".to_string(),
                    username: "trial-user".to_string(),
                    display_name: None,
                    password_hash: "hash".to_string(),
                },
            )
            .await
            .unwrap()
            .user;

        // The API rejects this shape, but old/manual data can contain it.
        // It has an independent allowed-client scope, so deletion removes only
        // the stale organization metadata instead of destroying the code.
        let mut legacy_code = test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::AdminUniversal,
            None,
            None,
            vec!["other-client".to_string()],
        );
        legacy_code.organization_id = Some(organization.id.clone());
        legacy_code.organization_role = Some(crate::organizations::ROLE_ADMIN.to_string());
        let (legacy_invitation, _) = db.insert_invitation(legacy_code).await.unwrap();

        assert_eq!(
            db.list_organization_member_counts()
                .await
                .unwrap()
                .get(&organization.id),
            Some(&2)
        );

        db.delete_organization(&organization.id).await.unwrap();

        assert!(
            db.find_organization_by_id(&organization.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_organization_members(&organization.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.list_user_organizations(&member.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.list_user_organizations(&trial_user.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.find_invitation_by_id(&trial_invitation.id)
                .await
                .unwrap()
                .is_none()
        );

        let enrollment = db
            .find_trial_enrollment_for_user(&trial_user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(enrollment.revoked_at.is_some());
        assert!(
            db.find_active_trial_enrollment_for_user(&trial_user.id)
                .await
                .unwrap()
                .is_none()
        );

        let legacy_after = db
            .find_invitation_by_id(&legacy_invitation.id)
            .await
            .unwrap()
            .unwrap();
        assert!(legacy_after.organization_id.is_none());
        assert!(legacy_after.organization_role.is_none());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn account_recovery_code_stays_bound_to_the_user_id_after_a_username_rename() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("rename-target@example.com", "rename-target"))
            .await
            .unwrap();
        let (invitation, code) = db
            .insert_invitation(test_invitation(
                AuthorizationCodeType::Login,
                LoginCodeLevel::AccountRecovery,
                Some("rename-target"),
                Some(&user.id),
                Vec::new(),
            ))
            .await
            .unwrap();
        db.update_user(UserUpdate {
            id: &user.id,
            email: user.email.clone(),
            username: "renamed-target".to_string(),
            display_name: user.display_name.clone(),
            phone: user.phone.clone(),
            is_admin: false,
            is_active: true,
        })
        .await
        .unwrap();

        let original_name = db
            .redeem_account_recovery_code(&code, &user.id, &user.email)
            .await
            .unwrap();
        let current_name = db
            .redeem_account_recovery_code(&code, &user.id, &user.email)
            .await
            .unwrap();

        assert!(
            db.redeem_account_recovery_code(&code, &user.id, "different@example.com")
                .await
                .is_err()
        );

        assert_eq!(original_name.user.id, user.id);
        assert_eq!(current_name.user.id, user.id);
        let stored = db
            .find_invitation_by_id(&invitation.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.authorized_user_id.as_deref(), Some(user.id.as_str()));
        assert_eq!(stored.uses_count, 2);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn account_recovery_code_never_falls_back_after_bound_user_deletion() {
        let (db, path) = sqlite_test_db().await;
        let original = db
            .insert_user(test_user("deleted-target@example.com", "reused-name"))
            .await
            .unwrap();
        let (invitation, code) = db
            .insert_invitation(test_invitation(
                AuthorizationCodeType::Login,
                LoginCodeLevel::AccountRecovery,
                Some("reused-name"),
                Some(&original.id),
                Vec::new(),
            ))
            .await
            .unwrap();
        db.permanently_delete_user(&original.id).await.unwrap();
        let replacement = db
            .insert_user(test_user("replacement@example.com", "reused-name"))
            .await
            .unwrap();

        assert!(
            db.redeem_account_recovery_code(&code, &replacement.id, &replacement.email)
                .await
                .is_err()
        );
        let stored = db
            .find_invitation_by_id(&invitation.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.authorized_user_id.as_deref(),
            Some(original.id.as_str())
        );
        assert_eq!(stored.is_active, 0);
        assert_eq!(stored.uses_count, 0);
        assert_ne!(replacement.id, original.id);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn account_recovery_code_rejects_an_unbound_or_missing_account() {
        let (db, path) = sqlite_test_db().await;
        let (invitation, code) = db
            .insert_invitation(test_invitation(
                AuthorizationCodeType::Login,
                LoginCodeLevel::AccountRecovery,
                Some("new-temporary-user"),
                None,
                Vec::new(),
            ))
            .await
            .unwrap();

        assert!(
            db.redeem_account_recovery_code(&code, "missing-user-id", "missing@example.com")
                .await
                .is_err()
        );
        assert!(
            db.find_user_by_username("new-temporary-user")
                .await
                .unwrap()
                .is_none()
        );
        let stored = db
            .find_invitation_by_id(&invitation.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.authorized_user_id, None);
        assert_eq!(stored.uses_count, 0);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn temporary_account_detection_ignores_registration_and_universal_redemptions() {
        let (db, path) = sqlite_test_db().await;
        let (registration, registration_code) = db
            .insert_invitation(test_invitation(
                AuthorizationCodeType::Registration,
                LoginCodeLevel::AccountRecovery,
                None,
                None,
                Vec::new(),
            ))
            .await
            .unwrap();
        let registered = db
            .redeem_registration_code_for_new_user(
                &registration_code,
                test_user("registered-only@example.com", "registered-only"),
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            registered.registration_source,
            UserRegistrationSource::AuthorizationCode.as_str()
        );
        assert!(
            !db.user_has_invitation_redemption(&registered.id)
                .await
                .unwrap()
        );

        let universal_user = db
            .insert_user(test_user("universal-only@example.com", "universal-only"))
            .await
            .unwrap();
        assert_eq!(
            universal_user.registration_source,
            UserRegistrationSource::Local.as_str()
        );
        let (_universal, universal_code) = db
            .insert_invitation(test_invitation(
                AuthorizationCodeType::Login,
                LoginCodeLevel::AdminUniversal,
                None,
                None,
                vec!["client-a".to_string()],
            ))
            .await
            .unwrap();
        assert!(
            db.redeem_account_recovery_code(
                &universal_code,
                &universal_user.id,
                &universal_user.email,
            )
            .await
            .is_err()
        );
        db.redeem_admin_login_code_for_oidc_grant(AdminLoginCodeRedemptionInput {
            code: &universal_code,
            user_id: &universal_user.id,
            email: &universal_user.email,
            trusted_client_id: "client-a",
            interaction_request_hash: "universal-interaction-hash",
            credential_hash: "universal-credential-hash",
            ttl_seconds: 60,
        })
        .await
        .unwrap();
        assert!(
            !db.user_has_invitation_redemption(&universal_user.id)
                .await
                .unwrap()
        );

        let recovery_user = db
            .insert_user(test_user("recovery-only@example.com", "recovery-only"))
            .await
            .unwrap();
        assert_eq!(
            recovery_user.registration_source,
            UserRegistrationSource::Local.as_str()
        );
        let (_recovery, recovery_code) = db
            .insert_invitation(test_invitation(
                AuthorizationCodeType::Login,
                LoginCodeLevel::AccountRecovery,
                Some("recovery-only"),
                Some(&recovery_user.id),
                Vec::new(),
            ))
            .await
            .unwrap();
        db.redeem_account_recovery_code(&recovery_code, &recovery_user.id, &recovery_user.email)
            .await
            .unwrap();
        assert!(
            db.user_has_invitation_redemption(&recovery_user.id)
                .await
                .unwrap()
        );
        assert!(
            db.find_invitation_by_id(&registration.id)
                .await
                .unwrap()
                .is_some()
        );

        // Simulate an installation that existed before registration_source
        // was introduced. A repeated migration must restore only the account
        // that was actually created by a registration code, not an ordinary
        // user who later redeemed a login-only recovery code.
        let db_for_update = db.clone();
        let registered_id = registered.id.clone();
        with_conn!(db_for_update, |conn, kind| {
            let sql = format!(
                "UPDATE users SET registration_source = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(UserRegistrationSource::Local.as_str())
                .bind::<Text, _>(registered_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();
        db.migrate().await.unwrap();

        let backfilled_registered = db.find_user_by_id(&registered.id).await.unwrap().unwrap();
        let backfilled_recovery = db
            .find_user_by_id(&recovery_user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            backfilled_registered.registration_source,
            UserRegistrationSource::AuthorizationCode.as_str()
        );
        assert_eq!(
            backfilled_recovery.registration_source,
            UserRegistrationSource::Local.as_str()
        );
        let authorization_code_users = db
            .list_users(UserListScope::AuthorizationCode)
            .await
            .unwrap();
        assert_eq!(authorization_code_users.len(), 1);
        assert_eq!(authorization_code_users[0].id, registered.id);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn disabling_an_invitation_revokes_outstanding_oidc_login_grants() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("grant-revoke@example.com", "grant-revoke"))
            .await
            .unwrap();
        let (invitation, code) = db
            .insert_invitation(test_invitation(
                AuthorizationCodeType::Login,
                LoginCodeLevel::AdminUniversal,
                None,
                None,
                vec!["client-a".to_string()],
            ))
            .await
            .unwrap();
        db.redeem_admin_login_code_for_oidc_grant(AdminLoginCodeRedemptionInput {
            code: &code,
            user_id: &user.id,
            email: &user.email,
            trusted_client_id: "client-a",
            interaction_request_hash: "revoke-interaction-hash",
            credential_hash: "revoke-credential-hash",
            ttl_seconds: 60,
        })
        .await
        .unwrap();
        assert!(
            db.find_oidc_login_grant("revoke-credential-hash", "revoke-interaction-hash")
                .await
                .unwrap()
                .is_some()
        );

        let disabled = db
            .update_invitation(InvitationUpdate {
                id: &invitation.id,
                description: invitation.description.clone(),
                authorized_email: invitation.authorized_email.clone(),
                authorized_username: invitation.authorized_username.clone(),
                authorized_display_name: invitation.authorized_display_name.clone(),
                expires_at: invitation.expires_at,
                max_uses: invitation.max_uses,
                is_active: false,
            })
            .await
            .unwrap();
        assert_eq!(disabled.is_active, 0);
        assert!(
            db.find_oidc_login_grant("revoke-credential-hash", "revoke-interaction-hash")
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    async fn user_auth_state_row_count(db: &Db, table: &str, column: &str, user_id: &str) -> i64 {
        let table = table.to_string();
        let column = column.to_string();
        let user_id = user_id.to_string();
        with_conn!(db, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM {table} WHERE {column} = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count)
                .map_err(AppError::from)
        })
        .unwrap()
    }

    #[cfg(feature = "sqlite")]
    async fn assert_user_auth_state_count(db: &Db, user_id: &str, expected: i64) {
        for (table, column) in USER_AUTH_STATE_TABLES {
            assert_eq!(
                user_auth_state_row_count(db, table, column, user_id).await,
                expected,
                "{table}.{column} should have {expected} rows for user {user_id}"
            );
        }
    }

    #[cfg(feature = "sqlite")]
    async fn insert_user_auth_state(db: &Db, user_id: &str, suffix: &str) -> String {
        let now = util::now_ts();
        let (session, _cookie_value) = db
            .insert_session(user_id, 600, SessionMetadata::default())
            .await
            .unwrap();
        let browser_context_id = format!("browser-context-{suffix}");
        db.insert_browser_context(&browser_context_id, "csrf", 600)
            .await
            .unwrap();
        let account = db
            .attach_browser_context_account(&browser_context_id, user_id, &session.id)
            .await
            .unwrap();
        db.mint_browser_account_session_credential(&browser_context_id, &account.id)
            .await
            .unwrap();
        db.insert_authorization_code(NewAuthorizationCode {
            code: format!("auth-code-{suffix}"),
            client_id: "client".to_string(),
            user_id: user_id.to_string(),
            application_id: None,
            authorization_profile_id: None,
            auth_context_id: None,
            session_id: None,
            redirect_uri: "https://client.example/callback".to_string(),
            scope: "openid".to_string(),
            resource: None,
            authorization_details: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            auth_time: now,
            acr: crate::assurance::ACR_PASSWORD.to_string(),
            amr: vec!["pwd".to_string()],
            expires_at: now + 600,
        })
        .await
        .unwrap();
        db.insert_refresh_token(
            "client".to_string(),
            RefreshTokenInput {
                token_hash: format!("refresh-token-{suffix}"),
                user_id: user_id.to_string(),
                scope: "openid".to_string(),
                resource: None,
                authorization_details: None,
                dpop_jkt: None,
                auth_context_id: None,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();
        let user_code_hash = format!("user-code-hash-{suffix}");
        db.insert_device_authorization(NewDeviceAuthorization {
            device_code_hash: format!("device-code-hash-{suffix}"),
            user_code_hash: user_code_hash.clone(),
            user_code_display: "ABCD-EFGH".to_string(),
            client_id: "client".to_string(),
            scope: "openid".to_string(),
            resource: None,
            authorization_details: None,
            expires_at: now + 600,
            interval_seconds: 5,
        })
        .await
        .unwrap();
        db.authorize_device_authorization(&user_code_hash, user_id)
            .await
            .unwrap();
        db.create_webauthn_challenge(Some(user_id), "login", "{}".to_string(), 600)
            .await
            .unwrap();
        let user_id = user_id.to_string();
        let suffix = suffix.to_string();
        with_conn!(db, |conn, kind| {
            let sql = format!(
                "INSERT INTO oidc_login_grants (credential_hash, invitation_id, user_id, client_id, interaction_request_hash, auth_time, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9)
            );
            sql_query(sql)
                .bind::<Text, _>(format!("credential-{suffix}"))
                .bind::<Text, _>(format!("invitation-{suffix}"))
                .bind::<Text, _>(user_id)
                .bind::<Text, _>("client")
                .bind::<Text, _>(format!("interaction-{suffix}"))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now + 600)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();
        session.id
    }

    #[cfg(feature = "sqlite")]
    async fn session_link_count(db: &Db, table: &str, session_id: &str) -> i64 {
        let table = table.to_string();
        let session_id = session_id.to_string();
        with_conn!(db, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM {table} WHERE session_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(session_id)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count)
                .map_err(AppError::from)
        })
        .unwrap()
    }

    #[cfg(feature = "sqlite")]
    async fn load_verification_code(db: &Db, id: &str) -> VerificationCodeRecord {
        let id = id.to_string();
        with_conn!(db, |conn, kind| {
            sql_query(select_verification_code_by_id_sql(kind))
                .bind::<Text, _>(id)
                .get_result::<VerificationCodeRecord>(&mut conn)
                .map_err(AppError::from)
        })
        .unwrap()
    }

    #[cfg(feature = "sqlite")]
    fn refresh_token_replacement(token_hash: &str, user_id: &str) -> RefreshTokenInput {
        RefreshTokenInput {
            token_hash: token_hash.to_string(),
            user_id: user_id.to_string(),
            scope: "openid profile".to_string(),
            resource: Some("https://api.example/".to_string()),
            authorization_details: None,
            dpop_jkt: None,
            auth_context_id: None,
            expires_at: util::now_ts() + 600,
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn concurrent_refresh_token_rotation_has_one_winner() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        let now = util::now_ts();
        db.insert_refresh_token(
            "client".to_string(),
            RefreshTokenInput {
                token_hash: "old-refresh-hash".to_string(),
                user_id: "user".to_string(),
                scope: "openid profile".to_string(),
                resource: Some("https://api.example/".to_string()),
                authorization_details: None,
                dpop_jkt: None,
                auth_context_id: None,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();

        let first_db = db.clone();
        let second_db = db.clone();
        let (first, second) = tokio::join!(
            first_db.rotate_refresh_token(
                "old-refresh-hash",
                "client",
                refresh_token_replacement("new-refresh-hash-1", "user"),
            ),
            second_db.rotate_refresh_token(
                "old-refresh-hash",
                "client",
                refresh_token_replacement("new-refresh-hash-2", "user"),
            )
        );

        let outcomes = [first.unwrap(), second.unwrap()];
        assert_eq!(outcomes.iter().filter(|&&rotated| rotated).count(), 1);
        let inserted = [
            db.find_refresh_token("new-refresh-hash-1")
                .await
                .unwrap()
                .is_some(),
            db.find_refresh_token("new-refresh-hash-2")
                .await
                .unwrap()
                .is_some(),
        ];
        assert_eq!(inserted.iter().filter(|&&exists| exists).count(), 1);
        assert!(
            db.find_refresh_token("old-refresh-hash")
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn interaction_request_update_requires_live_unconsumed_client_binding() {
        let (db, path) = sqlite_test_db().await;
        db.insert_pushed_authorization_request(NewPushedAuthorizationRequest {
            request_uri_hash: "reauth-interaction-hash".to_string(),
            client_id: "client".to_string(),
            request_json: "{\"state\":\"pending\"}".to_string(),
            expires_at: util::now_ts() + 600,
        })
        .await
        .unwrap();

        assert!(
            db.update_unconsumed_pushed_authorization_request(
                "reauth-interaction-hash",
                "other-client",
                "{\"state\":\"pending\"}",
                "{\"state\":\"forged\"}",
            )
            .await
            .is_err()
        );
        let updated = db
            .update_unconsumed_pushed_authorization_request(
                "reauth-interaction-hash",
                "client",
                "{\"state\":\"pending\"}",
                "{\"state\":\"complete\"}",
            )
            .await
            .unwrap();
        assert_eq!(updated.request_json, "{\"state\":\"complete\"}");
        db.consume_pushed_authorization_request("reauth-interaction-hash")
            .await
            .unwrap();
        assert!(
            db.update_unconsumed_pushed_authorization_request(
                "reauth-interaction-hash",
                "client",
                "{\"state\":\"complete\"}",
                "{\"state\":\"replayed\"}",
            )
            .await
            .is_err()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn concurrent_interaction_request_compare_and_swap_has_one_winner() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        db.insert_pushed_authorization_request(NewPushedAuthorizationRequest {
            request_uri_hash: "concurrent-reauth-interaction".to_string(),
            client_id: "client".to_string(),
            request_json: "{\"state\":\"pending\"}".to_string(),
            expires_at: util::now_ts() + 600,
        })
        .await
        .unwrap();

        let first_db = db.clone();
        let second_db = db.clone();
        let (first, second) = tokio::join!(
            first_db.update_unconsumed_pushed_authorization_request(
                "concurrent-reauth-interaction",
                "client",
                "{\"state\":\"pending\"}",
                "{\"state\":\"first\"}",
            ),
            second_db.update_unconsumed_pushed_authorization_request(
                "concurrent-reauth-interaction",
                "client",
                "{\"state\":\"pending\"}",
                "{\"state\":\"second\"}",
            )
        );
        assert_eq!(
            [first.is_ok(), second.is_ok()]
                .into_iter()
                .filter(|won| *won)
                .count(),
            1
        );
        let stored = db
            .find_pushed_authorization_request("concurrent-reauth-interaction")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            stored.request_json.as_str(),
            "{\"state\":\"first\"}" | "{\"state\":\"second\"}"
        ));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn pushed_authorization_request_consumption_has_one_concurrent_winner() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        db.insert_pushed_authorization_request(NewPushedAuthorizationRequest {
            request_uri_hash: "concurrent-request-uri-hash".to_string(),
            client_id: "client".to_string(),
            request_json: "{}".to_string(),
            expires_at: util::now_ts() + 600,
        })
        .await
        .unwrap();

        let first_db = db.clone();
        let second_db = db.clone();
        let (first, second) = tokio::join!(
            first_db.consume_pushed_authorization_request("concurrent-request-uri-hash"),
            second_db.consume_pushed_authorization_request("concurrent-request-uri-hash")
        );
        assert_eq!(
            [first.is_ok(), second.is_ok()]
                .into_iter()
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert!(
            db.consume_pushed_authorization_request("concurrent-request-uri-hash")
                .await
                .is_err()
        );
        assert!(
            db.find_pushed_authorization_request("concurrent-request-uri-hash")
                .await
                .unwrap()
                .unwrap()
                .consumed_at
                .is_some()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn refresh_token_rotation_rolls_back_revoke_when_insert_fails() {
        let (db, path) = sqlite_test_db().await;
        let now = util::now_ts();
        for token_hash in ["old-refresh-hash", "duplicate-refresh-hash"] {
            db.insert_refresh_token(
                "client".to_string(),
                RefreshTokenInput {
                    token_hash: token_hash.to_string(),
                    user_id: "user".to_string(),
                    scope: "openid".to_string(),
                    resource: None,
                    authorization_details: None,
                    dpop_jkt: None,
                    auth_context_id: None,
                    expires_at: now + 600,
                },
            )
            .await
            .unwrap();
        }

        assert!(
            db.rotate_refresh_token(
                "old-refresh-hash",
                "client",
                refresh_token_replacement("duplicate-refresh-hash", "user"),
            )
            .await
            .is_err()
        );
        assert_eq!(
            db.find_refresh_token("old-refresh-hash")
                .await
                .unwrap()
                .unwrap()
                .revoked_at,
            None
        );
        assert!(
            db.rotate_refresh_token(
                "old-refresh-hash",
                "client",
                refresh_token_replacement("unique-refresh-hash", "user"),
            )
            .await
            .unwrap()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn device_authorization_persists_resource_and_authorization_details() {
        let (db, path) = sqlite_test_db().await;
        let details = r#"[{"type":"resource_access","locations":["https://api.example/"],"actions":["read"]}]"#;

        let created = db
            .insert_device_authorization(NewDeviceAuthorization {
                device_code_hash: "device-hash".to_string(),
                user_code_hash: "user-hash".to_string(),
                user_code_display: "ABCD-EFGH".to_string(),
                client_id: "client".to_string(),
                scope: "openid".to_string(),
                resource: Some("https://api.example/".to_string()),
                authorization_details: Some(details.to_string()),
                expires_at: util::now_ts() + 600,
                interval_seconds: 5,
            })
            .await
            .unwrap();

        assert_eq!(created.resource.as_deref(), Some("https://api.example/"));
        assert_eq!(created.authorization_details.as_deref(), Some(details));
        let fetched = db
            .find_device_authorization_by_device_code_hash("device-hash")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.resource.as_deref(), Some("https://api.example/"));
        assert_eq!(fetched.authorization_details.as_deref(), Some(details));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn device_authorization_transitions_are_atomic_and_report_current_state() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        let now = util::now_ts();
        db.insert_device_authorization(NewDeviceAuthorization {
            device_code_hash: "atomic-device-code".to_string(),
            user_code_hash: "atomic-user-code".to_string(),
            user_code_display: "ABCD-EFGH".to_string(),
            client_id: "client".to_string(),
            scope: "openid".to_string(),
            resource: None,
            authorization_details: None,
            expires_at: now + 600,
            interval_seconds: 5,
        })
        .await
        .unwrap();

        let first_db = db.clone();
        let second_db = db.clone();
        let (first_poll, second_poll) = tokio::join!(
            first_db.poll_device_authorization("atomic-device-code", now),
            second_db.poll_device_authorization("atomic-device-code", now),
        );
        let first_poll = first_poll.unwrap();
        let second_poll = second_poll.unwrap();
        assert_eq!(
            usize::from(first_poll.changed) + usize::from(second_poll.changed),
            1
        );
        assert!(
            (first_poll.status == DeviceAuthorizationStatus::Pending
                && second_poll.status == DeviceAuthorizationStatus::SlowDown)
                || (second_poll.status == DeviceAuthorizationStatus::Pending
                    && first_poll.status == DeviceAuthorizationStatus::SlowDown)
        );

        let approved = db
            .authorize_device_authorization("atomic-user-code", "user-1")
            .await
            .unwrap();
        assert!(approved.changed);
        assert_eq!(approved.status, DeviceAuthorizationStatus::Authorized);

        let denied_after_approval = db
            .deny_device_authorization("atomic-user-code")
            .await
            .unwrap();
        assert!(!denied_after_approval.changed);
        assert_eq!(
            denied_after_approval.status,
            DeviceAuthorizationStatus::Authorized
        );

        let first_db = db.clone();
        let second_db = db.clone();
        let (first_consume, second_consume) = tokio::join!(
            first_db.consume_device_authorization("atomic-device-code"),
            second_db.consume_device_authorization("atomic-device-code"),
        );
        let first_consume = first_consume.unwrap();
        let second_consume = second_consume.unwrap();
        assert_eq!(
            usize::from(first_consume.changed) + usize::from(second_consume.changed),
            1
        );
        assert_eq!(first_consume.status, DeviceAuthorizationStatus::Consumed);
        assert_eq!(second_consume.status, DeviceAuthorizationStatus::Consumed);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn device_authorization_approve_and_deny_have_one_winner() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        let now = util::now_ts();
        db.insert_device_authorization(NewDeviceAuthorization {
            device_code_hash: "approve-deny-device-code".to_string(),
            user_code_hash: "approve-deny-user-code".to_string(),
            user_code_display: "IJKL-MNOP".to_string(),
            client_id: "client".to_string(),
            scope: "openid".to_string(),
            resource: None,
            authorization_details: None,
            expires_at: now + 600,
            interval_seconds: 5,
        })
        .await
        .unwrap();

        let approve_db = db.clone();
        let deny_db = db.clone();
        let (approve, deny) = tokio::join!(
            approve_db.authorize_device_authorization("approve-deny-user-code", "user-1"),
            deny_db.deny_device_authorization("approve-deny-user-code"),
        );
        let approve = approve.unwrap();
        let deny = deny.unwrap();
        assert_eq!(usize::from(approve.changed) + usize::from(deny.changed), 1);
        if approve.changed {
            assert_eq!(approve.status, DeviceAuthorizationStatus::Authorized);
            assert_eq!(deny.status, DeviceAuthorizationStatus::Authorized);
        } else {
            assert_eq!(deny.status, DeviceAuthorizationStatus::Denied);
            assert_eq!(approve.status, DeviceAuthorizationStatus::Denied);
        }

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn disabling_user_through_profile_update_clears_auth_state() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("deactivate@example.com", "deactivate"))
            .await
            .unwrap();
        let _session_id = insert_user_auth_state(&db, &user.id, "deactivate").await;
        assert_user_auth_state_count(&db, &user.id, 1).await;

        let updated = db
            .update_user(UserUpdate {
                id: &user.id,
                email: user.email.clone(),
                username: user.username.clone(),
                display_name: user.display_name.clone(),
                phone: user.phone.clone(),
                is_admin: user.is_admin == 1,
                is_active: false,
            })
            .await
            .unwrap();

        assert_eq!(updated.is_active, 0);
        assert_user_auth_state_count(&db, &user.id, 0).await;

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn archive_user_clears_auth_state() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("archive@example.com", "archive"))
            .await
            .unwrap();
        let _session_id = insert_user_auth_state(&db, &user.id, "archive").await;
        assert_user_auth_state_count(&db, &user.id, 1).await;

        db.archive_user(&user.id).await.unwrap();
        let archived = db.find_user_by_id(&user.id).await.unwrap().unwrap();

        assert_eq!(archived.is_active, 0);
        assert!(archived.archived_at.is_some());
        assert_user_auth_state_count(&db, &user.id, 0).await;

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn user_lifecycle_batch_is_atomic_deduplicated_and_cleans_auth_state() {
        let (db, path) = sqlite_test_db().await;
        let first = db
            .insert_user(test_user("batch-first@example.com", "batch-first"))
            .await
            .unwrap();
        let second = db
            .insert_user(test_user("batch-second@example.com", "batch-second"))
            .await
            .unwrap();
        insert_user_auth_state(&db, &first.id, "batch-first").await;
        insert_user_auth_state(&db, &second.id, "batch-second").await;

        let missing_id = "batch-missing".to_string();
        let rejected = db
            .apply_user_lifecycle_batch(
                "actor",
                vec![first.id.clone(), missing_id],
                UserLifecycleBatchAction::Disable,
            )
            .await;
        assert!(matches!(rejected, Err(AppError::NotFound)));
        assert_eq!(
            db.find_user_by_id(&first.id)
                .await
                .unwrap()
                .unwrap()
                .is_active,
            1
        );
        assert_user_auth_state_count(&db, &first.id, 1).await;

        let changed = db
            .apply_user_lifecycle_batch(
                "actor",
                vec![first.id.clone(), second.id.clone(), first.id.clone()],
                UserLifecycleBatchAction::Disable,
            )
            .await
            .unwrap();
        assert_eq!(changed, 2);
        for user in [&first, &second] {
            assert_eq!(
                db.find_user_by_id(&user.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_active,
                0
            );
            assert_user_auth_state_count(&db, &user.id, 0).await;
        }
        let events = db.list_audit_events(20).await.unwrap();
        assert!(events.iter().any(|event| {
            event.action == "user.bulk.disable"
                && event.target_kind == "user_bulk"
                && event.details.contains("\"count\":2")
        }));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn permanent_user_deletion_is_complete_and_preserves_audit_history() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("deleted@example.com", "deleted"))
            .await
            .unwrap();
        let session_id = insert_user_auth_state(&db, &user.id, "deleted").await;
        let (recovery_invitation, _recovery_code) = db
            .insert_invitation(test_invitation(
                AuthorizationCodeType::Login,
                LoginCodeLevel::AccountRecovery,
                Some(&user.username),
                Some(&user.id),
                Vec::new(),
            ))
            .await
            .unwrap();
        db.insert_audit_event(crate::audit::management_event(
            user.id.clone(),
            "user.test_event",
            "user",
            Some(user.id.clone()),
            serde_json::json!({ "email": user.email }),
        ))
        .await
        .unwrap();

        db.permanently_delete_user(&user.id).await.unwrap();

        assert!(db.find_user_by_id(&user.id).await.unwrap().is_none());
        assert_user_auth_state_count(&db, &user.id, 0).await;
        for table in ["session_credentials", "browser_context_accounts"] {
            assert_eq!(session_link_count(&db, table, &session_id).await, 0);
        }
        let invalidated = db
            .find_invitation_by_id(&recovery_invitation.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(invalidated.is_active, 0);
        assert_eq!(
            invalidated.authorized_user_id.as_deref(),
            Some(user.id.as_str())
        );
        let audit_events = db.list_audit_events(10).await.unwrap();
        assert!(audit_events.iter().any(|event| {
            event.action == "user.test_event"
                && event.actor_user_id.as_deref() == Some(user.id.as_str())
                && event.target_id.as_deref() == Some(user.id.as_str())
        }));
        assert!(matches!(
            db.permanently_delete_user(&user.id).await,
            Err(AppError::NotFound)
        ));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn captcha_challenge_is_one_time_use() {
        let (db, path) = sqlite_test_db().await;
        let record = db
            .create_captcha_challenge("user@example.com", "2 + 3 = ?", "5", 300)
            .await
            .unwrap();

        db.consume_captcha_challenge(&record.id, "user@example.com", "5")
            .await
            .unwrap();
        assert!(matches!(
            db.consume_captcha_challenge(&record.id, "user@example.com", "5")
                .await,
            Err(AppError::BadRequest(message)) if message == "captcha challenge is invalid"
        ));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn captcha_concurrent_correct_answers_have_one_winner() {
        let (db, path) = sqlite_test_db_with_pool_size(4).await;
        let record = db
            .create_captcha_challenge("concurrent@example.com", "2 + 3 = ?", "5", 300)
            .await
            .unwrap();
        let id = record.id.clone();
        let first_db = db.clone();
        let second_db = db.clone();
        let (first, second) = tokio::join!(
            first_db.consume_captcha_challenge(&id, "concurrent@example.com", "5"),
            second_db.consume_captcha_challenge(&id, "concurrent@example.com", "5"),
        );

        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(first.is_err() || second.is_err());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn iap_application_crud_normalizes_policy_fields() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("iap-crud", "IAP CRUD"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "iap-crud-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let created = db
            .insert_iap_application(NewIapApplication {
                application_id: application.id.clone(),
                slug: "docs".to_string(),
                name: "Docs".to_string(),
                description: Some("Internal docs".to_string()),
                external_host: "docs.example.com".to_string(),
                path_prefix: "/private".to_string(),
                required_organization_id: Some("org-id".to_string()),
                required_organization_roles: vec![
                    "member".to_string(),
                    "admin".to_string(),
                    "member".to_string(),
                ],
                required_permissions: vec!["users.read".to_string()],
                is_active: true,
            })
            .await
            .unwrap();

        assert_eq!(created.slug, "docs");
        assert_eq!(
            created.required_organization_roles().unwrap(),
            vec!["admin".to_string(), "member".to_string()]
        );
        assert_eq!(
            created.required_permissions().unwrap(),
            vec!["users.read".to_string()]
        );
        assert_eq!(db.list_active_iap_applications().await.unwrap().len(), 1);

        let updated = db
            .update_iap_application(
                &created.id,
                NewIapApplication {
                    application_id: application.id.clone(),
                    slug: "docs".to_string(),
                    name: "Docs".to_string(),
                    description: None,
                    external_host: "docs.example.com".to_string(),
                    path_prefix: "/".to_string(),
                    required_organization_id: None,
                    required_organization_roles: Vec::new(),
                    required_permissions: vec!["users.manage".to_string()],
                    is_active: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.path_prefix, "/");
        assert_eq!(updated.is_active, 0);
        assert!(db.list_active_iap_applications().await.unwrap().is_empty());

        let bad_permission = db
            .insert_iap_application(NewIapApplication {
                application_id: application.id,
                slug: "bad".to_string(),
                name: "Bad".to_string(),
                description: None,
                external_host: "bad.example.com".to_string(),
                path_prefix: "/".to_string(),
                required_organization_id: None,
                required_organization_roles: Vec::new(),
                required_permissions: vec!["unknown.permission".to_string()],
                is_active: true,
            })
            .await;
        assert!(matches!(
            bad_permission,
            Err(AppError::BadRequest(message)) if message == "unknown permission: unknown.permission"
        ));

        db.delete_iap_application(&created.id).await.unwrap();
        assert!(db.list_iap_applications().await.unwrap().is_empty());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn verification_code_issue_respects_resend_interval() {
        let (db, path) = sqlite_test_db().await;
        let first = db
            .insert_verification_code(NewVerificationCode {
                channel: "email",
                target: "resend@example.com",
                purpose: "registration",
                code_hash: util::token_hash("123456"),
                ttl_seconds: 600,
                resend_interval_seconds: 60,
                max_attempts: 5,
            })
            .await
            .unwrap();

        let second = db
            .insert_verification_code(NewVerificationCode {
                channel: "email",
                target: "resend@example.com",
                purpose: "registration",
                code_hash: util::token_hash("654321"),
                ttl_seconds: 600,
                resend_interval_seconds: 60,
                max_attempts: 5,
            })
            .await;

        assert!(matches!(
            second,
            Err(AppError::BadRequest(message))
                if message.starts_with("verification code was sent too recently")
        ));
        assert_eq!(
            load_verification_code(&db, &first.id).await.code_hash,
            util::token_hash("123456")
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn verification_delivery_cleanup_allows_retry_without_resend_delay() {
        let (db, path) = sqlite_test_db().await;
        let first = db
            .insert_verification_code(NewVerificationCode {
                channel: "email",
                target: "cleanup@example.com",
                purpose: "registration",
                code_hash: util::token_hash("123456"),
                ttl_seconds: 600,
                resend_interval_seconds: 60,
                max_attempts: 5,
            })
            .await
            .unwrap();

        assert!(
            db.delete_unconsumed_verification_code(&first.id)
                .await
                .unwrap()
        );

        let second = db
            .insert_verification_code(NewVerificationCode {
                channel: "email",
                target: "cleanup@example.com",
                purpose: "registration",
                code_hash: util::token_hash("654321"),
                ttl_seconds: 600,
                resend_interval_seconds: 60,
                max_attempts: 5,
            })
            .await
            .unwrap();
        assert_eq!(second.target, "cleanup@example.com");
        let first_id = first.id.clone();
        let first_after_cleanup = with_conn!(db, |conn, kind| {
            sql_query(select_verification_code_by_id_sql(kind))
                .bind::<Text, _>(first_id)
                .get_result::<VerificationCodeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
        .unwrap();
        assert!(first_after_cleanup.is_none());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn verification_cleanup_does_not_delete_consumed_codes() {
        let (db, path) = sqlite_test_db().await;
        let code = "123456";
        let record = db
            .insert_verification_code(NewVerificationCode {
                channel: "email",
                target: "consumed-cleanup@example.com",
                purpose: "registration",
                code_hash: util::token_hash(code),
                ttl_seconds: 600,
                resend_interval_seconds: 1,
                max_attempts: 5,
            })
            .await
            .unwrap();

        db.consume_verification_code(
            "email",
            "consumed-cleanup@example.com",
            "registration",
            code,
        )
        .await
        .unwrap();
        assert!(
            !db.delete_unconsumed_verification_code(&record.id)
                .await
                .unwrap()
        );
        assert!(
            load_verification_code(&db, &record.id)
                .await
                .consumed_at
                .is_some()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn registered_user_creation_keeps_valid_code_when_identity_conflicts() {
        let (db, path) = sqlite_test_db().await;
        let email = "verified@example.com";
        let code = "123456";
        let verification_code = db
            .insert_verification_code(NewVerificationCode {
                channel: "email",
                target: email,
                purpose: "registration",
                code_hash: util::token_hash(code),
                ttl_seconds: 600,
                resend_interval_seconds: 1,
                max_attempts: 5,
            })
            .await
            .unwrap();
        db.insert_user(test_user(email, "existing")).await.unwrap();

        let result = db
            .insert_registered_user(
                test_user(email, "new-user"),
                false,
                vec![VerificationCodeClaim::new(
                    "email",
                    email,
                    "registration",
                    code,
                )],
            )
            .await;

        assert!(matches!(
            result,
            Err(AppError::BadRequest(message)) if message == "user email or username already exists"
        ));
        assert_eq!(
            load_verification_code(&db, &verification_code.id)
                .await
                .consumed_at,
            None
        );

        db.consume_verification_code("email", email, "registration", code)
            .await
            .unwrap();
        assert!(
            load_verification_code(&db, &verification_code.id)
                .await
                .consumed_at
                .is_some()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn external_oidc_user_creation_can_join_provider_organization() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "corp".to_string(),
                name: "Corp".to_string(),
                kind: ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();

        let user = db
            .insert_external_oidc_user(
                test_user("member@example.com", "member"),
                "corp-oidc",
                "external-subject",
                Some("member@example.com".to_string()),
                Some(organization.id.clone()),
                true,
            )
            .await
            .unwrap();

        let memberships = db.list_user_organizations(&user.id).await.unwrap();
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].id, organization.id);
        assert_eq!(memberships[0].role, crate::organizations::ROLE_MEMBER);

        let members = db
            .list_organization_members(&organization.id)
            .await
            .unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].user_id, user.id);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn external_oidc_provider_persists_login_switch() {
        let (db, path) = sqlite_test_db().await;
        let provider = NewExternalOidcProvider {
            slug: "corp".to_string(),
            display_name: "Corp OIDC".to_string(),
            organization_id: None,
            issuer: "https://idp.example.com".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            redirect_path: "/api/register/oidc/corp/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            email_domains: vec!["example.com".to_string()],
            is_active: true,
            allow_login: false,
            allow_registration: true,
        };

        let created = db
            .insert_external_oidc_provider(provider.clone())
            .await
            .unwrap();
        assert_eq!(created.allow_login, 0);
        assert!(!created.clone().public().unwrap().allow_login);

        let mut updated = provider;
        updated.display_name = "Corp Login".to_string();
        updated.allow_login = true;
        updated.allow_registration = false;
        let saved = db
            .update_external_oidc_provider(&created.id, updated)
            .await
            .unwrap();

        assert_eq!(saved.allow_login, 1);
        assert_eq!(saved.allow_registration, 0);
        let public = saved.public().unwrap();
        assert!(public.allow_login);
        assert!(!public.allow_registration);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn deleting_external_oidc_provider_removes_reusable_identity_links() {
        let (db, path) = sqlite_test_db().await;
        let user = db
            .insert_user(test_user("former-idp-user@example.com", "former-idp-user"))
            .await
            .unwrap();
        let provider = db
            .insert_external_oidc_provider(NewExternalOidcProvider {
                slug: "reusable-tenant-idp".to_string(),
                display_name: "Reusable tenant IdP".to_string(),
                organization_id: None,
                issuer: "https://idp.example.com".to_string(),
                client_id: "client".to_string(),
                client_secret: "secret".to_string(),
                authorization_endpoint: "https://idp.example.com/authorize".to_string(),
                token_endpoint: "https://idp.example.com/token".to_string(),
                userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
                redirect_path: "/api/register/oidc/reusable-tenant-idp/callback".to_string(),
                scopes: vec!["openid".to_string()],
                email_domains: Vec::new(),
                is_active: true,
                allow_login: true,
                allow_registration: true,
            })
            .await
            .unwrap();
        db.insert_linked_identity(
            &user.id,
            &provider.slug,
            "former-subject",
            Some(user.email.clone()),
        )
        .await
        .unwrap();

        db.delete_external_oidc_provider(&provider.id)
            .await
            .unwrap();
        assert!(
            db.find_linked_identity(&provider.slug, "former-subject")
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn external_oidc_user_creation_respects_provider_organization_email_policy() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "corp".to_string(),
                name: "Corp".to_string(),
                kind: ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();

        let result = db
            .insert_external_oidc_user(
                test_user("member@other.test", "blocked-member"),
                "corp-oidc",
                "external-subject",
                Some("member@other.test".to_string()),
                Some(organization.id.clone()),
                true,
            )
            .await;

        assert!(matches!(result, Err(AppError::Forbidden)));
        assert!(
            db.list_organization_members(&organization.id)
                .await
                .unwrap()
                .is_empty()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn registered_user_creation_records_invalid_code_attempt_before_transaction() {
        let (db, path) = sqlite_test_db().await;
        let email = "wrong-code@example.com";
        let verification_code = db
            .insert_verification_code(NewVerificationCode {
                channel: "email",
                target: email,
                purpose: "registration",
                code_hash: util::token_hash("123456"),
                ttl_seconds: 600,
                resend_interval_seconds: 1,
                max_attempts: 5,
            })
            .await
            .unwrap();

        let result = db
            .insert_registered_user(
                test_user(email, "wrong-code"),
                false,
                vec![VerificationCodeClaim::new(
                    "email",
                    email,
                    "registration",
                    "000000",
                )],
            )
            .await;

        assert!(matches!(
            result,
            Err(AppError::BadRequest(message)) if message == "verification code is invalid"
        ));
        let record = load_verification_code(&db, &verification_code.id).await;
        assert_eq!(record.attempts, 1);
        assert_eq!(record.consumed_at, None);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn registered_user_creation_consumes_valid_code_after_user_insert() {
        let (db, path) = sqlite_test_db().await;
        let email = "new-verified@example.com";
        let code = "123456";
        let verification_code = db
            .insert_verification_code(NewVerificationCode {
                channel: "email",
                target: email,
                purpose: "registration",
                code_hash: util::token_hash(code),
                ttl_seconds: 600,
                resend_interval_seconds: 1,
                max_attempts: 5,
            })
            .await
            .unwrap();

        let user = db
            .insert_registered_user(
                test_user(email, "new-verified"),
                false,
                vec![VerificationCodeClaim::new(
                    "email",
                    email,
                    "registration",
                    code,
                )],
            )
            .await
            .unwrap();

        assert_eq!(user.email, email);
        assert!(
            load_verification_code(&db, &verification_code.id)
                .await
                .consumed_at
                .is_some()
        );
        assert!(matches!(
            db.consume_verification_code("email", email, "registration", code)
                .await,
            Err(AppError::BadRequest(message)) if message == "verification code is missing"
        ));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn audited_group_mutation_rolls_back_when_audit_insert_fails() {
        let (db, path) = sqlite_test_db().await;
        let group = db
            .insert_group(NewGroup {
                name: "audited-group".to_string(),
                description: None,
            })
            .await
            .unwrap();
        let user = db
            .insert_user(test_user("audited-group@example.com", "audited-group"))
            .await
            .unwrap();

        with_conn!(db.clone(), |conn, _kind| {
            sql_query("DROP TABLE audit_events")
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

        assert!(
            db.replace_group_members_with_audit(
                &group.id,
                vec![user.id.clone()],
                crate::audit::management_event(
                    "actor",
                    "group.members.update",
                    "group",
                    Some(group.id.clone()),
                    serde_json::json!({ "user_ids": [user.id] }),
                ),
            )
            .await
            .is_err()
        );
        assert!(db.list_group_members(&group.id).await.unwrap().is_empty());

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn deleting_group_cleans_application_and_profile_edges() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("group-delete", "Group Delete"))
            .await
            .unwrap();
        let application = db
            .insert_application(test_application(
                &organization.id,
                "group-delete-app",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ))
            .await
            .unwrap();
        let member = db
            .insert_user(test_user("group-delete@example.com", "group-delete"))
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &member.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        let group = db
            .insert_application_scim_group(
                &application.id,
                NewGroup {
                    name: "application-group".to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        db.replace_group_members(&group.id, vec![member.id.clone()])
            .await
            .unwrap();
        let profile = default_authorization_profile(&db, &application.id).await;
        let role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: profile.id.clone(),
                role_key: "group-role".to_string(),
                name: "group-role".to_string(),
                source: "manual".to_string(),
                description: None,
                permissions: vec!["group.read".to_string()],
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        replace_test_authorization_bindings(
            &db,
            &application.id,
            &profile.id,
            AuthorizationBindingsUpdate {
                user_id: None,
                group_id: Some(group.id.clone()),
                user_role_ids: Vec::new(),
                user_permission_overrides: Vec::new(),
                group_role_ids: vec![role.id],
                organization_role_bindings: BTreeMap::new(),
            },
        )
        .await;

        db.delete_group(&group.id).await.unwrap();
        assert!(db.find_group_by_id(&group.id).await.unwrap().is_none());
        assert!(
            db.list_application_scim_groups(&application.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.read_application_authorization_bindings(&application.id, &profile.id)
                .await
                .unwrap()
                .group_bindings
                .get(&group.id)
                .is_none_or(Vec::is_empty)
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn deleting_ldap_provider_revokes_reusable_slug_identity_and_sync_state() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(test_organization("ldap-owner", "LDAP Owner"))
            .await
            .unwrap();
        let provider = db
            .insert_ldap_provider(test_ldap_provider(
                "reusable-directory",
                Some(&organization.id),
            ))
            .await
            .unwrap();
        let user = db
            .insert_user(test_user("ldap-linked@example.com", "ldap-linked"))
            .await
            .unwrap();
        db.insert_linked_identity(
            &user.id,
            &provider.provider_key(),
            "external-subject",
            Some("ldap-linked@example.com".to_string()),
        )
        .await
        .unwrap();
        db.start_directory_sync_run("removed-application", &provider.id)
            .await
            .unwrap();

        db.delete_ldap_provider(&provider.id).await.unwrap();
        assert!(
            db.find_linked_identity(&provider.provider_key(), "external-subject")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_directory_sync_runs("removed-application", 20)
                .await
                .unwrap()
                .is_empty()
        );

        let replacement = db
            .insert_ldap_provider(test_ldap_provider("reusable-directory", None))
            .await
            .unwrap();
        assert!(
            db.find_linked_identity(&replacement.provider_key(), "external-subject")
                .await
                .unwrap()
                .is_none()
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }
}

macro_rules! insert_client_in_connection {
    ($conn:expr, $kind:expr, $client:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let client = $client;
    let id = uuid::Uuid::new_v4().to_string();
    let now = util::now_ts();
    let redirect_uris = util::to_json(&client.redirect_uris)?;
    let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
    let scopes = util::to_json(&client.scopes)?;
    let grant_types = util::to_json(&client.grant_types)?;
    let response_types = util::to_json(&client.response_types)?;
    let authorization_details_types = util::to_json(&client.authorization_details_types)?;
    let service_account_permissions = util::to_json(&client.service_account_permissions)?;
    let sql = format!(
        "INSERT INTO clients (id, client_id, client_secret_hash, client_name, logo_uri, organization_id, redirect_uris, post_logout_redirect_uris, scopes, audience, grant_types, response_types, token_endpoint_auth_method, require_pkce, require_mfa, require_pushed_authorization_requests, require_s256_pkce, require_confidential_client, require_dpop, require_account_selection, trust_email_verified, authorization_details_types, subject_type, sector_identifier_uri, jwks_uri, jwks, backchannel_logout_uri, backchannel_logout_session_required, frontchannel_logout_uri, frontchannel_logout_session_required, service_account_enabled, service_account_permissions, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
        ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
        ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16), ph(kind, 17), ph(kind, 18),
        ph(kind, 19), ph(kind, 20), ph(kind, 21), ph(kind, 22), ph(kind, 23), ph(kind, 24),
        ph(kind, 25), ph(kind, 26), ph(kind, 27), ph(kind, 28), ph(kind, 29), ph(kind, 30),
        ph(kind, 31), ph(kind, 32), ph(kind, 33), ph(kind, 34), ph(kind, 35)
    );
    sql_query(sql)
        .bind::<Text, _>(&id)
        .bind::<Text, _>(&client.client_id)
        .bind::<Nullable<Text>, _>(&client.client_secret_hash)
        .bind::<Text, _>(&client.client_name)
        .bind::<Text, _>(&client.logo_uri)
        .bind::<Nullable<Text>, _>(&client.organization_id)
        .bind::<Text, _>(redirect_uris)
        .bind::<Text, _>(post_logout_redirect_uris)
        .bind::<Text, _>(scopes)
        .bind::<Text, _>(client.audience.trim())
        .bind::<Text, _>(grant_types)
        .bind::<Text, _>(response_types)
        .bind::<Text, _>(&client.token_endpoint_auth_method)
        .bind::<Integer, _>(i32::from(client.require_pkce))
        .bind::<Integer, _>(i32::from(client.require_mfa))
        .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
        .bind::<Integer, _>(i32::from(client.require_s256_pkce))
        .bind::<Integer, _>(i32::from(client.require_confidential_client))
        .bind::<Integer, _>(i32::from(client.require_dpop))
        .bind::<Integer, _>(i32::from(client.require_account_selection))
        .bind::<Integer, _>(i32::from(client.trust_email_verified))
        .bind::<Text, _>(authorization_details_types)
        .bind::<Text, _>(&client.subject_type)
        .bind::<Text, _>(&client.sector_identifier_uri)
        .bind::<Text, _>(&client.jwks_uri)
        .bind::<Text, _>(&client.jwks)
        .bind::<Text, _>(&client.backchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
        .bind::<Text, _>(&client.frontchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
        .bind::<Integer, _>(i32::from(client.service_account_enabled))
        .bind::<Text, _>(service_account_permissions)
        .bind::<Integer, _>(i32::from(client.is_active))
        .bind::<BigInt, _>(now)
        .bind::<BigInt, _>(now)
        .execute(conn)
        .map_err(AppError::from)?;
        Ok(id)
    }};
}

macro_rules! update_client_in_connection {
    ($conn:expr, $kind:expr, $id:expr, $client:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let id = $id;
        let client = $client;
    let now = util::now_ts();
    let redirect_uris = util::to_json(&client.redirect_uris)?;
    let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
    let scopes = util::to_json(&client.scopes)?;
    let grant_types = util::to_json(&client.grant_types)?;
    let response_types = util::to_json(&client.response_types)?;
    let authorization_details_types = util::to_json(&client.authorization_details_types)?;
    let service_account_permissions = util::to_json(&client.service_account_permissions)?;
    let sql = format!(
        "UPDATE clients SET client_id = {}, client_secret_hash = {}, client_name = {}, logo_uri = {}, organization_id = {}, redirect_uris = {}, post_logout_redirect_uris = {}, scopes = {}, audience = {}, grant_types = {}, response_types = {}, token_endpoint_auth_method = {}, require_pkce = {}, require_mfa = {}, require_pushed_authorization_requests = {}, require_s256_pkce = {}, require_confidential_client = {}, require_dpop = {}, require_account_selection = {}, trust_email_verified = {}, authorization_details_types = {}, subject_type = {}, sector_identifier_uri = {}, jwks_uri = {}, jwks = {}, backchannel_logout_uri = {}, backchannel_logout_session_required = {}, frontchannel_logout_uri = {}, frontchannel_logout_session_required = {}, service_account_enabled = {}, service_account_permissions = {}, is_active = {}, updated_at = {} WHERE id = {}",
        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
        ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
        ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16), ph(kind, 17), ph(kind, 18),
        ph(kind, 19), ph(kind, 20), ph(kind, 21), ph(kind, 22), ph(kind, 23), ph(kind, 24),
        ph(kind, 25), ph(kind, 26), ph(kind, 27), ph(kind, 28), ph(kind, 29), ph(kind, 30),
        ph(kind, 31), ph(kind, 32), ph(kind, 33), ph(kind, 34)
    );
    let affected = sql_query(sql)
        .bind::<Text, _>(&client.client_id)
        .bind::<Nullable<Text>, _>(&client.client_secret_hash)
        .bind::<Text, _>(&client.client_name)
        .bind::<Text, _>(&client.logo_uri)
        .bind::<Nullable<Text>, _>(&client.organization_id)
        .bind::<Text, _>(redirect_uris)
        .bind::<Text, _>(post_logout_redirect_uris)
        .bind::<Text, _>(scopes)
        .bind::<Text, _>(client.audience.trim())
        .bind::<Text, _>(grant_types)
        .bind::<Text, _>(response_types)
        .bind::<Text, _>(&client.token_endpoint_auth_method)
        .bind::<Integer, _>(i32::from(client.require_pkce))
        .bind::<Integer, _>(i32::from(client.require_mfa))
        .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
        .bind::<Integer, _>(i32::from(client.require_s256_pkce))
        .bind::<Integer, _>(i32::from(client.require_confidential_client))
        .bind::<Integer, _>(i32::from(client.require_dpop))
        .bind::<Integer, _>(i32::from(client.require_account_selection))
        .bind::<Integer, _>(i32::from(client.trust_email_verified))
        .bind::<Text, _>(authorization_details_types)
        .bind::<Text, _>(&client.subject_type)
        .bind::<Text, _>(&client.sector_identifier_uri)
        .bind::<Text, _>(&client.jwks_uri)
        .bind::<Text, _>(&client.jwks)
        .bind::<Text, _>(&client.backchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
        .bind::<Text, _>(&client.frontchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
        .bind::<Integer, _>(i32::from(client.service_account_enabled))
        .bind::<Text, _>(service_account_permissions)
        .bind::<Integer, _>(i32::from(client.is_active))
        .bind::<BigInt, _>(now)
        .bind::<Text, _>(id)
        .execute(conn)
        .map_err(AppError::from)?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
        Ok(())
    }};
}

macro_rules! upsert_application_module_in_connection {
    ($conn:expr, $kind:expr, $application_id:expr, $module_key:expr, $config:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let application_id = $application_id;
        let module_key = $module_key;
        let config = $config;
    let object = config
        .as_object()
        .ok_or_else(|| AppError::Internal("discovery module is not an object".to_string()))?;
    let config_json = util::to_json(config)?;
    let enabled = object
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(!object.is_empty());
    let now = util::now_ts();
    let count_sql = format!(
        "SELECT COUNT(*) AS count FROM application_modules WHERE application_id = {} AND module_key = {}",
        ph(kind, 1), ph(kind, 2)
    );
    let exists = sql_query(count_sql)
        .bind::<Text, _>(application_id)
        .bind::<Text, _>(module_key)
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        > 0;
    if exists {
        let sql = format!(
            "UPDATE application_modules SET config_json = {}, is_enabled = {}, updated_at = {} WHERE application_id = {} AND module_key = {}",
            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5)
        );
        sql_query(sql)
            .bind::<Text, _>(config_json)
            .bind::<Integer, _>(i32::from(enabled))
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(module_key)
            .execute(conn)
            .map_err(AppError::from)?;
    } else {
        let sql = format!(
            "INSERT INTO application_modules (application_id, module_key, config_json, is_enabled, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
        );
        sql_query(sql)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(module_key)
            .bind::<Text, _>(config_json)
            .bind::<Integer, _>(i32::from(enabled))
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(conn)
            .map_err(AppError::from)?;
    }
        Ok(())
    }};
}

macro_rules! upsert_website_profile_in_connection {
    ($conn:expr, $kind:expr, $application_id:expr, $profile_key:expr, $connection_id:expr, $connection_kind:expr, $version:expr, $digest:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let application_id = $application_id;
        let profile_key = $profile_key;
        let connection_id = $connection_id;
        let connection_kind = $connection_kind;
        let version = $version;
        let digest = $digest;
    let now = util::now_ts();
    let existing_sql = format!(
        "{} WHERE application_id = {} AND profile_key = {}",
        select_application_authorization_profile_sql(),
        ph(kind, 1),
        ph(kind, 2)
    );
    let existing = sql_query(existing_sql)
        .bind::<Text, _>(application_id)
        .bind::<Text, _>(profile_key)
        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
        .optional()
        .map_err(AppError::from)?;
    let profile_id = existing
        .as_ref()
        .map(|profile| profile.id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if existing.is_some() {
        let sql = format!(
            "UPDATE application_authorization_profiles SET connection_kind = {}, connection_id = {}, source_mode = {}, remote_version = {}, remote_digest = {}, sync_status = {}, last_synced_at = {}, last_error = {}, updated_at = {} WHERE id = {}",
            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10)
        );
        sql_query(sql)
            .bind::<Text, _>(connection_kind)
            .bind::<Nullable<Text>, _>(&connection_id)
            .bind::<Text, _>(crate::application_discovery::SOURCE_MODE_DISCOVERY)
            .bind::<Nullable<Text>, _>(Some(version.to_string()))
            .bind::<Nullable<Text>, _>(Some(digest.to_string()))
            .bind::<Text, _>(crate::application_discovery::SYNC_SYNCED)
            .bind::<Nullable<BigInt>, _>(Some(now))
            .bind::<Nullable<Text>, _>(None::<String>)
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(&profile_id)
            .execute(conn)
            .map_err(AppError::from)?;
    } else {
        let sql = format!(
            "INSERT INTO application_authorization_profiles (id, application_id, profile_key, connection_kind, connection_id, source_mode, remote_version, remote_digest, sync_status, last_synced_at, last_error, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12), ph(kind, 13)
        );
        sql_query(sql)
            .bind::<Text, _>(&profile_id)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(profile_key)
            .bind::<Text, _>(connection_kind)
            .bind::<Nullable<Text>, _>(&connection_id)
            .bind::<Text, _>(crate::application_discovery::SOURCE_MODE_DISCOVERY)
            .bind::<Nullable<Text>, _>(Some(version.to_string()))
            .bind::<Nullable<Text>, _>(Some(digest.to_string()))
            .bind::<Text, _>(crate::application_discovery::SYNC_SYNCED)
            .bind::<Nullable<BigInt>, _>(Some(now))
            .bind::<Nullable<Text>, _>(None::<String>)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(conn)
            .map_err(AppError::from)?;
    }
        Ok(profile_id)
    }};
}

macro_rules! replace_website_profile_permissions_in_connection {
    ($conn:expr, $kind:expr, $profile_id:expr, $profile:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let profile_id = $profile_id;
        let profile = $profile;
    let now = util::now_ts();
    let deactivate_sql = format!(
        "UPDATE application_permission_definitions SET is_active = {}, source = {}, updated_at = {} WHERE profile_id = {}",
        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
    );
    sql_query(deactivate_sql)
        .bind::<Integer, _>(0)
        .bind::<Text, _>(crate::application_discovery::SOURCE_WEBSITE)
        .bind::<BigInt, _>(now)
        .bind::<Text, _>(profile_id)
        .execute(conn)
        .map_err(AppError::from)?;
    for permission in &profile.permissions {
        let count_sql = format!(
            "SELECT COUNT(*) AS count FROM application_permission_definitions WHERE profile_id = {} AND permission_key = {}",
            ph(kind, 1), ph(kind, 2)
        );
        let exists = sql_query(count_sql)
            .bind::<Text, _>(profile_id)
            .bind::<Text, _>(&permission.key)
            .get_result::<CountRow>(conn)
            .map_err(AppError::from)?
            .count
            > 0;
        if exists {
            let sql = format!(
                "UPDATE application_permission_definitions SET label = {}, description = {}, source = {}, is_active = {}, updated_at = {} WHERE profile_id = {} AND permission_key = {}",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(&permission.label)
                .bind::<Nullable<Text>, _>(&permission.description)
                .bind::<Text, _>(crate::application_discovery::SOURCE_WEBSITE)
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(profile_id)
                .bind::<Text, _>(&permission.key)
                .execute(conn)
                .map_err(AppError::from)?;
        } else {
            let sql = format!(
                "INSERT INTO application_permission_definitions (profile_id, permission_key, label, description, source, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
            );
            sql_query(sql)
                .bind::<Text, _>(profile_id)
                .bind::<Text, _>(&permission.key)
                .bind::<Text, _>(&permission.label)
                .bind::<Nullable<Text>, _>(&permission.description)
                .bind::<Text, _>(crate::application_discovery::SOURCE_WEBSITE)
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(conn)
                .map_err(AppError::from)?;
        }
    }
        Ok(())
    }};
}

macro_rules! replace_website_profile_roles_in_connection {
    ($conn:expr, $kind:expr, $profile_id:expr, $profile:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let profile_id = $profile_id;
        let profile = $profile;
    let now = util::now_ts();
    let deactivate_sql = format!(
        "UPDATE application_profile_roles SET is_active = {}, is_default = 0, source = {}, updated_at = {} WHERE profile_id = {}",
        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
    );
    sql_query(deactivate_sql)
        .bind::<Integer, _>(0)
        .bind::<Text, _>(crate::application_discovery::SOURCE_WEBSITE)
        .bind::<BigInt, _>(now)
        .bind::<Text, _>(profile_id)
        .execute(conn)
        .map_err(AppError::from)?;
    for role in &profile.roles {
        let permissions = util::to_json(&role.permissions)?;
        if role.is_default {
            let clear_default_sql = format!(
                "UPDATE application_profile_roles SET is_default = 0, updated_at = {} WHERE profile_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(clear_default_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(profile_id)
                .execute(conn)
                .map_err(AppError::from)?;
        }
        let existing_sql = format!(
            "{} WHERE profile_id = {} AND role_key = {}",
            select_application_profile_role_sql(),
            ph(kind, 1),
            ph(kind, 2)
        );
        let existing = sql_query(existing_sql)
            .bind::<Text, _>(profile_id)
            .bind::<Text, _>(&role.key)
            .get_result::<ApplicationProfileRoleRecord>(conn)
            .optional()
            .map_err(AppError::from)?;
        if let Some(existing) = existing {
            let sql = format!(
                "UPDATE application_profile_roles SET name = {}, description = {}, permissions = {}, source = {}, is_default = {}, is_active = {}, updated_at = {} WHERE profile_id = {} AND id = {}",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9)
            );
            sql_query(sql)
                .bind::<Text, _>(&role.name)
                .bind::<Nullable<Text>, _>(&role.description)
                .bind::<Text, _>(permissions)
                .bind::<Text, _>(crate::application_discovery::SOURCE_WEBSITE)
                .bind::<Integer, _>(i32::from(role.is_default))
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(profile_id)
                .bind::<Text, _>(&existing.id)
                .execute(conn)
                .map_err(AppError::from)?;
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let sql = format!(
                "INSERT INTO application_profile_roles (id, profile_id, role_key, name, description, permissions, source, is_default, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(profile_id)
                .bind::<Text, _>(&role.key)
                .bind::<Text, _>(&role.name)
                .bind::<Nullable<Text>, _>(&role.description)
                .bind::<Text, _>(permissions)
                .bind::<Text, _>(crate::application_discovery::SOURCE_WEBSITE)
                .bind::<Integer, _>(i32::from(role.is_default))
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(conn)
                .map_err(AppError::from)?;
        }
    }
        Ok(())
    }};
}

trait WebsiteDiscoveryConnection {
    fn website_discovery_insert_client(
        &mut self,
        kind: DatabaseKind,
        client: &NewClient,
    ) -> AppResult<String>;

    fn website_discovery_update_client(
        &mut self,
        kind: DatabaseKind,
        id: &str,
        client: &NewClient,
    ) -> AppResult<()>;

    fn website_discovery_upsert_module(
        &mut self,
        kind: DatabaseKind,
        application_id: &str,
        module_key: &str,
        config: &serde_json::Value,
    ) -> AppResult<()>;

    fn website_discovery_upsert_profile(
        &mut self,
        kind: DatabaseKind,
        application_id: &str,
        profile_key: &str,
        connection_id: Option<&str>,
        connection_kind: &str,
        version: &str,
        digest: &str,
    ) -> AppResult<String>;

    fn website_discovery_replace_permissions(
        &mut self,
        kind: DatabaseKind,
        profile_id: &str,
        profile: &crate::application_discovery::NormalizedProfile,
    ) -> AppResult<()>;

    fn website_discovery_replace_roles(
        &mut self,
        kind: DatabaseKind,
        profile_id: &str,
        profile: &crate::application_discovery::NormalizedProfile,
    ) -> AppResult<()>;
}

macro_rules! impl_website_discovery_connection {
    ($connection:ty) => {
        impl WebsiteDiscoveryConnection for $connection {
            fn website_discovery_insert_client(
                &mut self,
                kind: DatabaseKind,
                client: &NewClient,
            ) -> AppResult<String> {
                insert_client_in_connection!(self, kind, client)
            }

            fn website_discovery_update_client(
                &mut self,
                kind: DatabaseKind,
                id: &str,
                client: &NewClient,
            ) -> AppResult<()> {
                update_client_in_connection!(self, kind, id, client)
            }

            fn website_discovery_upsert_module(
                &mut self,
                kind: DatabaseKind,
                application_id: &str,
                module_key: &str,
                config: &serde_json::Value,
            ) -> AppResult<()> {
                upsert_application_module_in_connection!(
                    self,
                    kind,
                    application_id,
                    module_key,
                    config
                )
            }

            fn website_discovery_upsert_profile(
                &mut self,
                kind: DatabaseKind,
                application_id: &str,
                profile_key: &str,
                connection_id: Option<&str>,
                connection_kind: &str,
                version: &str,
                digest: &str,
            ) -> AppResult<String> {
                upsert_website_profile_in_connection!(
                    self,
                    kind,
                    application_id,
                    profile_key,
                    connection_id,
                    connection_kind,
                    version,
                    digest
                )
            }

            fn website_discovery_replace_permissions(
                &mut self,
                kind: DatabaseKind,
                profile_id: &str,
                profile: &crate::application_discovery::NormalizedProfile,
            ) -> AppResult<()> {
                replace_website_profile_permissions_in_connection!(self, kind, profile_id, profile)
            }

            fn website_discovery_replace_roles(
                &mut self,
                kind: DatabaseKind,
                profile_id: &str,
                profile: &crate::application_discovery::NormalizedProfile,
            ) -> AppResult<()> {
                replace_website_profile_roles_in_connection!(self, kind, profile_id, profile)
            }
        }
    };
}

#[cfg(feature = "sqlite")]
impl_website_discovery_connection!(SqliteConnection);
#[cfg(feature = "postgres")]
impl_website_discovery_connection!(PgConnection);
#[cfg(feature = "mysql")]
impl_website_discovery_connection!(MysqlConnection);

mod account_credentials;
mod application_authorization;
mod application_sso_persistence;
mod applications;
mod audit_persistence;
mod auth_challenges;
mod authorization;
mod authorization_bindings;
mod authorization_codes;
mod authorization_profiles;
mod authorization_transients;
mod billing;
mod browser_sessions;
mod client_applications;
mod client_registration;
mod client_security;
mod database_lifecycle;
mod directory_sync;
mod external_identities;
mod mfa;
mod mfa_challenges;
mod mutation_receipts;
mod organization_persistence;
mod organizations;
mod rbac;
mod refresh_tokens;
mod scim;
mod scim_persistence;
mod settings_persistence;
mod signing_keys;
mod sql;
mod user_cleanup;
mod user_directory;
mod user_lifecycle;
mod user_lifecycle_core;
mod user_persistence;
mod webauthn;

fn migration_sql(kind: DatabaseKind) -> Vec<&'static str> {
    match kind {
        DatabaseKind::Sqlite => SQLITE_MIGRATIONS.to_vec(),
        DatabaseKind::Postgres => POSTGRES_MIGRATIONS.to_vec(),
        DatabaseKind::Mysql => MYSQL_MIGRATIONS.to_vec(),
    }
}

fn is_ignorable_migration_error(statement: &str, error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    let duplicate_column = statement.contains("ADD COLUMN")
        && (lower.contains("duplicate column") || lower.contains("already exists"));
    let statement_upper = statement.trim_start().to_ascii_uppercase();
    let duplicate_index = (statement_upper.starts_with("CREATE INDEX")
        || statement_upper.starts_with("CREATE UNIQUE INDEX"))
        && (lower.contains("duplicate") || lower.contains("already exists"));
    duplicate_column || duplicate_index
}

const SQLITE_MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT,
        phone TEXT,
        password_hash TEXT NOT NULL,
        email_verified_at INTEGER,
        phone_verified_at INTEGER,
        is_admin INTEGER NOT NULL,
        is_active INTEGER NOT NULL,
        archived_at INTEGER,
        registration_source TEXT NOT NULL DEFAULT 'local',
        last_login_at INTEGER,
        last_login_ip TEXT,
        last_oidc_client_id TEXT,
        last_login_method TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE users ADD COLUMN archived_at INTEGER",
    "ALTER TABLE users ADD COLUMN registration_source TEXT NOT NULL DEFAULT 'local'",
    "CREATE INDEX IF NOT EXISTS idx_users_archive_active_created ON users(archived_at, is_active, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_users_registration_source_lifecycle ON users(registration_source, archived_at, is_active, created_at)",
    "CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL UNIQUE,
        client_secret_hash TEXT,
        client_name TEXT NOT NULL,
        logo_uri TEXT NOT NULL DEFAULT '',
        organization_id TEXT,
        redirect_uris TEXT NOT NULL,
        post_logout_redirect_uris TEXT NOT NULL,
        scopes TEXT NOT NULL,
        audience TEXT NOT NULL DEFAULT '',
        grant_types TEXT NOT NULL,
        response_types TEXT NOT NULL,
        token_endpoint_auth_method TEXT NOT NULL,
        require_pkce INTEGER NOT NULL,
        require_mfa INTEGER NOT NULL DEFAULT 0,
        require_pushed_authorization_requests INTEGER NOT NULL DEFAULT 0,
        require_s256_pkce INTEGER NOT NULL DEFAULT 0,
        require_confidential_client INTEGER NOT NULL DEFAULT 0,
        require_dpop INTEGER NOT NULL DEFAULT 0,
        require_account_selection INTEGER NOT NULL DEFAULT 0,
        trust_email_verified INTEGER NOT NULL DEFAULT 0,
        authorization_details_types TEXT NOT NULL DEFAULT '[]',
        subject_type TEXT NOT NULL DEFAULT 'public',
        sector_identifier_uri TEXT NOT NULL DEFAULT '',
        jwks_uri TEXT NOT NULL DEFAULT '',
        jwks TEXT NOT NULL DEFAULT '',
        backchannel_logout_uri TEXT NOT NULL DEFAULT '',
        backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0,
        frontchannel_logout_uri TEXT NOT NULL DEFAULT '',
        frontchannel_logout_session_required INTEGER NOT NULL DEFAULT 0,
        service_account_enabled INTEGER NOT NULL DEFAULT 0,
        service_account_permissions TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE clients ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'public'",
    "ALTER TABLE clients ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_pushed_authorization_requests INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_s256_pkce INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_confidential_client INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_dpop INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_account_selection INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN trust_email_verified INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN authorization_details_types TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE clients ADD COLUMN sector_identifier_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN jwks_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN jwks TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN frontchannel_logout_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN frontchannel_logout_session_required INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN service_account_enabled INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN service_account_permissions TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE clients ADD COLUMN audience TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN logo_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN organization_id TEXT",
    "CREATE INDEX IF NOT EXISTS idx_clients_organization ON clients(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS client_registrations (
        client_db_id TEXT PRIMARY KEY,
        registration_access_token_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS client_assertion_jtis (
        client_id TEXT NOT NULL,
        jti TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (client_id, jti)
    )",
    "CREATE INDEX IF NOT EXISTS idx_client_assertion_jtis_expires ON client_assertion_jtis(expires_at)",
    "CREATE TABLE IF NOT EXISTS client_claim_mappers (
        id TEXT PRIMARY KEY,
        client_db_id TEXT NOT NULL,
        claim_name TEXT NOT NULL,
        source TEXT NOT NULL,
        source_value TEXT NOT NULL,
        value_type TEXT NOT NULL,
        include_in_id_token INTEGER NOT NULL,
        include_in_access_token INTEGER NOT NULL,
        include_in_userinfo INTEGER NOT NULL,
        is_active INTEGER NOT NULL,
        sort_order INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_client_claim_mappers_client ON client_claim_mappers(client_db_id, sort_order)",
    "CREATE TABLE IF NOT EXISTS signing_keys (
        id TEXT PRIMARY KEY,
        kid TEXT NOT NULL UNIQUE,
        private_key_pem TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        activated_at INTEGER,
        retired_at INTEGER
    )",
    "CREATE INDEX IF NOT EXISTS idx_signing_keys_active_created ON signing_keys(is_active, created_at)",
    "CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        csrf_token TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        login_method TEXT,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "ALTER TABLE sessions ADD COLUMN ip_address TEXT",
    "ALTER TABLE sessions ADD COLUMN user_agent TEXT",
    "ALTER TABLE sessions ADD COLUMN login_method TEXT",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user_expires ON sessions(user_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS browser_contexts (
        id TEXT PRIMARY KEY,
        csrf_token TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_browser_contexts_expires ON browser_contexts(expires_at)",
    "CREATE TABLE IF NOT EXISTS browser_context_accounts (
        id TEXT PRIMARY KEY,
        browser_context_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL UNIQUE,
        added_at INTEGER NOT NULL,
        last_selected_at INTEGER,
        UNIQUE(browser_context_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_browser_context_accounts_context ON browser_context_accounts(browser_context_id, last_selected_at)",
    "CREATE TABLE IF NOT EXISTS session_credentials (
        credential_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        browser_context_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_session_credentials_session ON session_credentials(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_session_credentials_context ON session_credentials(browser_context_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS account_login_flows (
        id_hash TEXT PRIMARY KEY,
        browser_context_id TEXT NOT NULL,
        return_to TEXT NOT NULL,
        expected_user_id TEXT,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "ALTER TABLE account_login_flows ADD COLUMN expected_user_id TEXT",
    "CREATE INDEX IF NOT EXISTS idx_account_login_flows_context_expires ON account_login_flows(browser_context_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS mfa_totp_methods (
        user_id TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        last_used_step INTEGER,
        enabled_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS mfa_totp_setups (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        secret TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_mfa_totp_setups_user_id ON mfa_totp_setups(user_id)",
    "CREATE TABLE IF NOT EXISTS mfa_challenges (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        return_to TEXT,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_purpose ON mfa_challenges(user_id, purpose, consumed_at)",
    "CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        used_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id, used_at)",
    "CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        credential_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        passkey_json TEXT NOT NULL,
        last_used_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id, created_at)",
    "CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        purpose TEXT NOT NULL,
        state_json TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_purpose ON webauthn_challenges(user_id, purpose, consumed_at)",
    "CREATE TABLE IF NOT EXISTS authorization_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        application_id TEXT,
        authorization_profile_id TEXT,
        auth_context_id TEXT,
        session_id TEXT,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT,
        authorization_details TEXT,
        nonce TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        auth_time INTEGER NOT NULL,
        acr TEXT NOT NULL DEFAULT 'urn:gpt-sso:acr:loa:1',
        amr TEXT NOT NULL DEFAULT '[]',
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "ALTER TABLE authorization_codes ADD COLUMN resource TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN authorization_details TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN session_id TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN auth_context_id TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN application_id TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN authorization_profile_id TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN auth_time INTEGER",
    "ALTER TABLE authorization_codes ADD COLUMN acr TEXT NOT NULL DEFAULT 'urn:gpt-sso:acr:loa:1'",
    "ALTER TABLE authorization_codes ADD COLUMN amr TEXT NOT NULL DEFAULT '[]'",
    "CREATE TABLE IF NOT EXISTS oidc_login_grants (
        credential_hash TEXT PRIMARY KEY,
        invitation_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        interaction_request_hash TEXT NOT NULL UNIQUE,
        auth_time INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_oidc_login_grants_client_expires ON oidc_login_grants(client_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_oidc_login_grants_user_expires ON oidc_login_grants(user_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS pushed_authorization_requests (
        request_uri_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        request_json TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_pushed_authorization_requests_client_expires ON pushed_authorization_requests(client_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS device_authorizations (
        device_code_hash TEXT PRIMARY KEY,
        user_code_hash TEXT NOT NULL UNIQUE,
        user_code_display TEXT NOT NULL,
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT,
        authorization_details TEXT,
        expires_at INTEGER NOT NULL,
        interval_seconds INTEGER NOT NULL,
        authorized_user_id TEXT,
        authorized_at INTEGER,
        denied_at INTEGER,
        consumed_at INTEGER,
        last_poll_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_device_authorizations_client_expires ON device_authorizations(client_id, expires_at)",
    "ALTER TABLE device_authorizations ADD COLUMN resource TEXT",
    "ALTER TABLE device_authorizations ADD COLUMN authorization_details TEXT",
    "CREATE TABLE IF NOT EXISTS refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        application_id TEXT,
        authorization_profile_id TEXT,
        auth_context_id TEXT,
        user_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT,
        authorization_details TEXT,
        dpop_jkt TEXT,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "ALTER TABLE refresh_tokens ADD COLUMN resource TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN authorization_details TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN application_id TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN authorization_profile_id TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN auth_context_id TEXT",
    "CREATE TABLE IF NOT EXISTS dpop_proofs (
        jkt TEXT NOT NULL,
        jti TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (jkt, jti)
    )",
    "CREATE INDEX IF NOT EXISTS idx_dpop_proofs_expires ON dpop_proofs(expires_at)",
    "CREATE TABLE IF NOT EXISTS client_grants (
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        authorization_profile_id TEXT NOT NULL DEFAULT 'default',
        granted_scopes TEXT NOT NULL,
        granted_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        revoked_at INTEGER,
        PRIMARY KEY (user_id, client_id, authorization_profile_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_client_grants_client ON client_grants(client_id, revoked_at)",
    "CREATE TABLE IF NOT EXISTS registration_settings (
        id TEXT PRIMARY KEY,
        allow_password_registration INTEGER NOT NULL,
        require_email_verification INTEGER NOT NULL,
        require_phone_verification INTEGER NOT NULL,
        allow_external_oidc_registration INTEGER NOT NULL,
        require_invitation INTEGER NOT NULL,
        first_user_direct_admin INTEGER NOT NULL,
        default_user_active INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS security_policy (
        id TEXT PRIMARY KEY,
        password_min_length INTEGER NOT NULL,
        password_require_uppercase INTEGER NOT NULL,
        password_require_lowercase INTEGER NOT NULL,
        password_require_digit INTEGER NOT NULL,
        password_require_symbol INTEGER NOT NULL,
        password_reject_user_info INTEGER NOT NULL,
        login_lockout_enabled INTEGER NOT NULL,
        max_failed_login_attempts INTEGER NOT NULL,
        failure_window_seconds INTEGER NOT NULL,
        lockout_seconds INTEGER NOT NULL,
        trusted_ip_cidrs TEXT NOT NULL DEFAULT '[]',
        require_mfa_outside_trusted_networks INTEGER NOT NULL DEFAULT 0,
        allowed_ip_cidrs TEXT NOT NULL DEFAULT '[]',
        blocked_ip_cidrs TEXT NOT NULL DEFAULT '[]',
        allowed_email_domains TEXT NOT NULL DEFAULT '[]',
        blocked_email_domains TEXT NOT NULL DEFAULT '[]',
        captcha_enabled INTEGER NOT NULL DEFAULT 0,
        captcha_after_failed_attempts INTEGER NOT NULL DEFAULT 3,
        captcha_ttl_seconds INTEGER NOT NULL DEFAULT 300,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE security_policy ADD COLUMN trusted_ip_cidrs TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN require_mfa_outside_trusted_networks INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE security_policy ADD COLUMN allowed_ip_cidrs TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN blocked_ip_cidrs TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN allowed_email_domains TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN blocked_email_domains TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN captcha_enabled INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE security_policy ADD COLUMN captcha_after_failed_attempts INTEGER NOT NULL DEFAULT 3",
    "ALTER TABLE security_policy ADD COLUMN captcha_ttl_seconds INTEGER NOT NULL DEFAULT 300",
    "CREATE TABLE IF NOT EXISTS runtime_settings (
        id TEXT PRIMARY KEY,
        public_base_url TEXT NOT NULL,
        issuer TEXT NOT NULL,
        trust_proxy_headers INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS verification_codes (
        id TEXT PRIMARY KEY,
        channel TEXT NOT NULL,
        target TEXT NOT NULL,
        purpose TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        max_attempts INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_verification_codes_target ON verification_codes(channel, target, purpose)",
    "CREATE TABLE IF NOT EXISTS invitations (
        id TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL UNIQUE,
        code_prefix TEXT NOT NULL,
        code_reveal_key_id TEXT,
        code_reveal_ciphertext TEXT,
        code_type TEXT NOT NULL DEFAULT 'login',
        login_code_level TEXT NOT NULL DEFAULT 'account_recovery',
        allowed_client_ids TEXT,
        organization_id TEXT,
        organization_role TEXT,
        description TEXT,
        authorized_email TEXT,
        authorized_username TEXT,
        authorized_user_id TEXT,
        authorized_display_name TEXT,
        expires_at INTEGER,
        max_uses INTEGER,
        uses_count INTEGER NOT NULL,
        is_active INTEGER NOT NULL,
        created_by TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE invitations ADD COLUMN code_type TEXT NOT NULL DEFAULT 'login'",
    "ALTER TABLE invitations ADD COLUMN code_reveal_key_id TEXT",
    "ALTER TABLE invitations ADD COLUMN code_reveal_ciphertext TEXT",
    "ALTER TABLE invitations ADD COLUMN login_code_level TEXT NOT NULL DEFAULT 'account_recovery'",
    "ALTER TABLE invitations ADD COLUMN allowed_client_ids TEXT",
    "ALTER TABLE invitations ADD COLUMN organization_id TEXT",
    "ALTER TABLE invitations ADD COLUMN organization_role TEXT",
    "ALTER TABLE invitations ADD COLUMN authorized_email TEXT",
    "ALTER TABLE invitations ADD COLUMN authorized_username TEXT",
    "ALTER TABLE invitations ADD COLUMN authorized_user_id TEXT",
    "ALTER TABLE invitations ADD COLUMN authorized_display_name TEXT",
    "CREATE TABLE IF NOT EXISTS invitation_redemptions (
        id TEXT PRIMARY KEY,
        invitation_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        redeemed_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS trial_enrollments (
        user_id TEXT PRIMARY KEY,
        invitation_id TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        organization_role TEXT NOT NULL,
        allowed_client_ids TEXT NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_trial_enrollments_invitation ON trial_enrollments(invitation_id, revoked_at)",
    "CREATE TABLE IF NOT EXISTS login_events (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        login_at INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        method TEXT NOT NULL,
        oidc_client_id TEXT,
        external_provider TEXT
    )",
    "CREATE INDEX IF NOT EXISTS idx_login_events_user_id ON login_events(user_id, login_at)",
    "CREATE TABLE IF NOT EXISTS login_failures (
        id TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        reason TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_login_failures_subject_created ON login_failures(subject, created_at)",
    "CREATE TABLE IF NOT EXISTS captcha_challenges (
        id TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        prompt TEXT NOT NULL,
        answer_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_captcha_challenges_subject ON captcha_challenges(subject, consumed_at, expires_at)",
    "CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        actor_user_id TEXT,
        actor_client_id TEXT,
        action TEXT NOT NULL,
        target_kind TEXT NOT NULL,
        target_id TEXT,
        outcome TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at)",
    "CREATE TABLE IF NOT EXISTS mutation_receipts (
        id TEXT PRIMARY KEY,
        dedupe_hash TEXT NOT NULL UNIQUE,
        scope_key TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        response_status INTEGER,
        response_body TEXT,
        response_content_type TEXT,
        error_code TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        completed_at INTEGER,
        owner_token TEXT,
        lease_expires_at INTEGER
    )",
    "ALTER TABLE mutation_receipts ADD COLUMN owner_token TEXT",
    "ALTER TABLE mutation_receipts ADD COLUMN lease_expires_at INTEGER",
    "CREATE INDEX IF NOT EXISTS idx_mutation_receipts_scope_status ON mutation_receipts(scope_key, status, updated_at)",
    "CREATE TABLE IF NOT EXISTS audit_webhooks (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        secret TEXT NOT NULL,
        actions TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        timeout_seconds INTEGER NOT NULL,
        last_delivered_at INTEGER,
        last_status_code INTEGER,
        last_error TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_webhooks_active ON audit_webhooks(is_active, created_at)",
    "CREATE TABLE IF NOT EXISTS audit_webhook_outbox (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER NOT NULL,
        lease_owner TEXT,
        lease_expires_at INTEGER,
        last_error TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_webhook_outbox_due ON audit_webhook_outbox(state, next_attempt_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_webhook_outbox_lease ON audit_webhook_outbox(state, lease_expires_at)",
    "CREATE TABLE IF NOT EXISTS roles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        is_system INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS role_permissions (
        role_id TEXT NOT NULL,
        permission TEXT NOT NULL,
        PRIMARY KEY (role_id, permission)
    )",
    "CREATE TABLE IF NOT EXISTS user_roles (
        user_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        PRIMARY KEY (user_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS access_groups (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        version INTEGER NOT NULL DEFAULT 0
    )",
    "ALTER TABLE access_groups ADD COLUMN version INTEGER NOT NULL DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS group_members (
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        PRIMARY KEY (group_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id, group_id)",
    "CREATE TABLE IF NOT EXISTS group_roles (
        group_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        PRIMARY KEY (group_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL DEFAULT 'tenant',
        description TEXT,
        allowed_email_domains TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE organizations ADD COLUMN allowed_email_domains TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE organizations ADD COLUMN kind TEXT NOT NULL DEFAULT 'tenant'",
    "CREATE INDEX IF NOT EXISTS idx_organizations_active_slug ON organizations(is_active, slug)",
    "CREATE TABLE IF NOT EXISTS organization_members (
        organization_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (organization_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_organization_members_user ON organization_members(user_id, organization_id)",
    "CREATE TABLE IF NOT EXISTS user_organization_contexts (
        user_id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_user_organization_contexts_organization ON user_organization_contexts(organization_id, user_id)",
    "CREATE TABLE IF NOT EXISTS applications (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        slug TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        access_mode TEXT NOT NULL,
        registration_mode TEXT NOT NULL,
        account_selection_mode TEXT NOT NULL,
        unique_identity_factors TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(organization_id, slug)
    )",
    "CREATE INDEX IF NOT EXISTS idx_applications_organization_active ON applications(organization_id, is_active, name)",
    "CREATE TABLE IF NOT EXISTS application_auth_domains (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL UNIQUE,
        assurance_policy TEXT NOT NULL DEFAULT 'default',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_auth_domains_active ON application_auth_domains(application_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_client_bindings (
        application_id TEXT NOT NULL,
        client_db_id TEXT NOT NULL UNIQUE,
        protocol TEXT NOT NULL,
        authorization_profile_id TEXT NOT NULL DEFAULT 'default',
        auth_domain_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, client_db_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_client_bindings_application ON application_client_bindings(application_id, created_at)",
    "CREATE TABLE IF NOT EXISTS application_auth_contexts (
        id TEXT PRIMARY KEY,
        auth_domain_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        acr TEXT NOT NULL,
        amr TEXT NOT NULL DEFAULT '[]',
        authenticated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_auth_contexts_lookup ON application_auth_contexts(auth_domain_id, user_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS application_enrollment_codes (
        application_id TEXT NOT NULL,
        invitation_id TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, invitation_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_enrollment_codes_application ON application_enrollment_codes(application_id, created_at)",
    "CREATE TABLE IF NOT EXISTS application_members (
        application_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_members_user ON application_members(user_id, application_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_identity_bindings (
        application_id TEXT NOT NULL,
        factor_type TEXT NOT NULL,
        factor_digest TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, factor_type, factor_digest)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_identity_bindings_user ON application_identity_bindings(application_id, user_id)",
    "CREATE TABLE IF NOT EXISTS application_modules (
        application_id TEXT NOT NULL,
        module_key TEXT NOT NULL,
        config_json TEXT NOT NULL DEFAULT '{}',
        is_enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, module_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_modules_application ON application_modules(application_id, module_key)",
    "CREATE TABLE IF NOT EXISTS application_billing_settings (
        application_id TEXT PRIMARY KEY,
        accept_signet_balance INTEGER NOT NULL DEFAULT 0,
        wallet_mode TEXT NOT NULL DEFAULT 'shared',
        supported_currencies TEXT NOT NULL DEFAULT '[]',
        mode_locked_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS wallet_accounts (
        id TEXT PRIMARY KEY,
        account_kind TEXT NOT NULL,
        scope_key TEXT NOT NULL UNIQUE,
        user_id TEXT,
        application_id TEXT,
        currency TEXT NOT NULL,
        available_minor INTEGER NOT NULL DEFAULT 0,
        reserved_minor INTEGER NOT NULL DEFAULT 0,
        version INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_wallet_accounts_user ON wallet_accounts(user_id, currency, account_kind)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_accounts_application ON wallet_accounts(application_id, currency, account_kind)",
    "CREATE TABLE IF NOT EXISTS wallet_transactions (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        user_id TEXT,
        application_id TEXT,
        currency TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        source_wallet_id TEXT,
        destination_wallet_id TEXT,
        hold_id TEXT,
        idempotency_key TEXT NOT NULL,
        external_provider TEXT,
        external_order_id TEXT,
        metadata TEXT NOT NULL DEFAULT '{}',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(kind, idempotency_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_user ON wallet_transactions(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_application ON wallet_transactions(application_id, created_at)",
    "CREATE TABLE IF NOT EXISTS wallet_entries (
        id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        available_delta_minor INTEGER NOT NULL,
        reserved_delta_minor INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_wallet_entries_wallet ON wallet_entries(wallet_id, created_at)",
    "CREATE TABLE IF NOT EXISTS wallet_holds (
        id TEXT PRIMARY KEY,
        hold_kind TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        user_id TEXT,
        application_id TEXT,
        currency TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        status TEXT NOT NULL,
        reference TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(hold_kind, idempotency_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_wallet_holds_wallet ON wallet_holds(wallet_id, status, expires_at)",
    "CREATE TABLE IF NOT EXISTS payment_orders (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider_slug TEXT NOT NULL,
        merchant_order_no TEXT NOT NULL,
        idempotency_key TEXT,
        provider_trade_id TEXT,
        currency TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        subject TEXT NOT NULL,
        status TEXT NOT NULL,
        checkout_kind TEXT NOT NULL,
        checkout_value TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        paid_at INTEGER,
        last_error TEXT,
        lease_owner TEXT,
        lease_expires_at INTEGER,
        lease_generation INTEGER NOT NULL DEFAULT 0,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        next_retry_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(provider_slug, merchant_order_no)
    )",
    "ALTER TABLE payment_orders ADD COLUMN idempotency_key TEXT",
    "ALTER TABLE payment_orders ADD COLUMN lease_owner TEXT",
    "ALTER TABLE payment_orders ADD COLUMN lease_expires_at INTEGER",
    "ALTER TABLE payment_orders ADD COLUMN lease_generation INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE payment_orders ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE payment_orders ADD COLUMN next_retry_at INTEGER",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_payment_orders_idempotency ON payment_orders(user_id, provider_slug, idempotency_key)",
    "CREATE INDEX IF NOT EXISTS idx_payment_orders_user ON payment_orders(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_payment_orders_reconcile ON payment_orders(status, next_retry_at, lease_expires_at, updated_at)",
    "CREATE TABLE IF NOT EXISTS payment_refunds (
        id TEXT PRIMARY KEY,
        payment_order_id TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        status TEXT NOT NULL,
        provider_refund_id TEXT,
        requested_by TEXT,
        reason TEXT NOT NULL,
        idempotency_key TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE payment_refunds ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS idx_payment_refunds_order ON payment_refunds(payment_order_id, created_at)",
    "CREATE TABLE IF NOT EXISTS application_scim_tokens (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        scopes TEXT NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        last_used_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_scim_tokens_application ON application_scim_tokens(application_id, revoked_at, created_at)",
    "CREATE TABLE IF NOT EXISTS application_scim_groups (
        application_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, group_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_scim_groups_group ON application_scim_groups(group_id, application_id)",
    "CREATE TABLE IF NOT EXISTS directory_sync_runs (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        status TEXT NOT NULL,
        total_seen INTEGER NOT NULL DEFAULT 0,
        created_count INTEGER NOT NULL DEFAULT 0,
        updated_count INTEGER NOT NULL DEFAULT 0,
        disabled_count INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        cursor TEXT,
        started_at INTEGER NOT NULL,
        finished_at INTEGER
    )",
    "CREATE INDEX IF NOT EXISTS idx_directory_sync_runs_application ON directory_sync_runs(application_id, started_at)",
    "CREATE TABLE IF NOT EXISTS directory_sync_leases (
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        owner_run_id TEXT NOT NULL UNIQUE,
        acquired_at INTEGER NOT NULL,
        heartbeat_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, provider_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_directory_sync_leases_expiry ON directory_sync_leases(expires_at)",
    "CREATE TABLE IF NOT EXISTS directory_sync_checkpoints (
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        cursor TEXT,
        last_success_at INTEGER NOT NULL,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, provider_id)
    )",
    "CREATE TABLE IF NOT EXISTS directory_sync_memberships (
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        managed INTEGER NOT NULL DEFAULT 1,
        last_seen_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, provider_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_directory_sync_memberships_user ON directory_sync_memberships(user_id, managed)",
    "CREATE TABLE IF NOT EXISTS directory_sync_groups (
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        external_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        last_seen_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, provider_id, external_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_directory_sync_groups_group ON directory_sync_groups(group_id)",
    "CREATE TABLE IF NOT EXISTS application_roles (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        permissions TEXT NOT NULL DEFAULT '[]',
        is_default INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(application_id, name)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_roles_application ON application_roles(application_id, is_active, name)",
    "CREATE TABLE IF NOT EXISTS application_user_roles (
        application_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        application_role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, user_id, application_role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_user_roles_user ON application_user_roles(application_id, user_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_group_roles (
        application_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        application_role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, group_id, application_role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_group_roles_group ON application_group_roles(application_id, group_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_organization_role_mappings (
        application_id TEXT NOT NULL,
        organization_role TEXT NOT NULL,
        application_role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, organization_role, application_role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_org_role_mappings_role ON application_organization_role_mappings(application_id, organization_role, is_active)",
    "CREATE TABLE IF NOT EXISTS application_user_permission_overrides (
        application_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        permission TEXT NOT NULL,
        effect TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (application_id, user_id, permission)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_permission_overrides_user ON application_user_permission_overrides(application_id, user_id, effect)",
    "CREATE TABLE IF NOT EXISTS application_authorization_profiles (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        profile_key TEXT NOT NULL,
        connection_kind TEXT NOT NULL,
        connection_id TEXT,
        source_mode TEXT NOT NULL,
        remote_version TEXT,
        remote_digest TEXT,
        sync_status TEXT NOT NULL DEFAULT 'manual',
        last_synced_at INTEGER,
        last_error TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(application_id, profile_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_auth_profiles_application ON application_authorization_profiles(application_id, profile_key)",
    "CREATE TABLE IF NOT EXISTS application_authorization_migration_state (
        application_id TEXT PRIMARY KEY,
        migrated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS application_permission_definitions (
        profile_id TEXT NOT NULL,
        permission_key TEXT NOT NULL,
        label TEXT NOT NULL,
        description TEXT,
        source TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (profile_id, permission_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_permission_definitions_profile ON application_permission_definitions(profile_id, is_active, permission_key)",
    "CREATE TABLE IF NOT EXISTS application_profile_roles (
        id TEXT PRIMARY KEY,
        profile_id TEXT NOT NULL,
        role_key TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        permissions TEXT NOT NULL DEFAULT '[]',
        source TEXT NOT NULL,
        is_default INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(profile_id, role_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_roles_profile ON application_profile_roles(profile_id, is_active, role_key)",
    "CREATE TABLE IF NOT EXISTS application_profile_user_roles (
        profile_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (profile_id, user_id, role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_user_roles_user ON application_profile_user_roles(profile_id, user_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_profile_group_roles (
        profile_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (profile_id, group_id, role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_group_roles_group ON application_profile_group_roles(profile_id, group_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_profile_organization_roles (
        profile_id TEXT NOT NULL,
        organization_role TEXT NOT NULL,
        role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (profile_id, organization_role, role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_org_roles_role ON application_profile_organization_roles(profile_id, organization_role, is_active)",
    "CREATE TABLE IF NOT EXISTS application_profile_permission_overrides (
        profile_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        permission TEXT NOT NULL,
        effect TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (profile_id, user_id, permission)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_permission_overrides_user ON application_profile_permission_overrides(profile_id, user_id, effect)",
    "CREATE TABLE IF NOT EXISTS application_discovery (
        application_id TEXT PRIMARY KEY,
        management_mode TEXT NOT NULL DEFAULT 'signet_managed',
        website_url TEXT NOT NULL,
        fetch_secret_ciphertext TEXT NOT NULL DEFAULT '',
        signing_public_jwks TEXT NOT NULL DEFAULT '',
        last_verified_revision BIGINT,
        last_verified_version TEXT,
        last_verified_digest TEXT,
        last_verified_expires_at BIGINT,
        sync_status TEXT NOT NULL DEFAULT 'unconfigured',
        last_fetched_at BIGINT,
        last_success_at BIGINT,
        last_error TEXT,
        snapshot_json TEXT,
        operator_disabled INTEGER NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        lease_owner TEXT,
        lease_expires_at BIGINT,
        lease_generation BIGINT NOT NULL DEFAULT 0
    )",
    "ALTER TABLE application_discovery ADD COLUMN lease_owner TEXT",
    "ALTER TABLE application_discovery ADD COLUMN lease_expires_at BIGINT",
    "ALTER TABLE application_discovery ADD COLUMN lease_generation BIGINT NOT NULL DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS idx_application_discovery_mode_status ON application_discovery(management_mode, sync_status)",
    "CREATE TABLE IF NOT EXISTS application_discovery_idempotency (
        organization_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        origin TEXT NOT NULL,
        application_id TEXT,
        claim_token TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (organization_id, idempotency_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_discovery_idempotency_updated ON application_discovery_idempotency(status, updated_at)",
    "CREATE TABLE IF NOT EXISTS iap_applications (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        external_host TEXT NOT NULL,
        path_prefix TEXT NOT NULL,
        required_organization_id TEXT,
        required_organization_roles TEXT NOT NULL,
        required_permissions TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE iap_applications ADD COLUMN application_id TEXT",
    "CREATE INDEX IF NOT EXISTS idx_iap_applications_application ON iap_applications(application_id, is_active)",
    "CREATE INDEX IF NOT EXISTS idx_iap_applications_match ON iap_applications(is_active, external_host, path_prefix)",
    "CREATE TABLE IF NOT EXISTS linked_identities (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider_slug TEXT NOT NULL,
        external_subject TEXT NOT NULL,
        external_email TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(provider_slug, external_subject)
    )",
    "CREATE INDEX IF NOT EXISTS idx_linked_identities_user ON linked_identities(user_id)",
    "CREATE TABLE IF NOT EXISTS ldap_providers (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        organization_id TEXT,
        url TEXT NOT NULL,
        starttls INTEGER NOT NULL,
        bind_dn TEXT NOT NULL,
        bind_password TEXT NOT NULL,
        base_dn TEXT NOT NULL,
        user_filter TEXT NOT NULL,
        user_id_attribute TEXT NOT NULL,
        email_attribute TEXT NOT NULL,
        username_attribute TEXT NOT NULL,
        display_name_attribute TEXT NOT NULL,
        phone_attribute TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        allow_login INTEGER NOT NULL,
        allow_registration INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE ldap_providers ADD COLUMN organization_id TEXT",
    "CREATE INDEX IF NOT EXISTS idx_ldap_providers_organization ON ldap_providers(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS external_oidc_providers (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        organization_id TEXT,
        issuer TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        authorization_endpoint TEXT NOT NULL,
        token_endpoint TEXT NOT NULL,
        userinfo_endpoint TEXT NOT NULL,
        redirect_path TEXT NOT NULL,
        scopes TEXT NOT NULL,
        email_domains TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        allow_login INTEGER NOT NULL DEFAULT 1,
        allow_registration INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE external_oidc_providers ADD COLUMN organization_id TEXT",
    "ALTER TABLE external_oidc_providers ADD COLUMN email_domains TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE external_oidc_providers ADD COLUMN allow_login INTEGER NOT NULL DEFAULT 1",
    "CREATE INDEX IF NOT EXISTS idx_external_oidc_providers_organization ON external_oidc_providers(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS external_oidc_states (
        state TEXT PRIMARY KEY,
        provider_slug TEXT NOT NULL,
        nonce TEXT NOT NULL,
        return_to TEXT,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS login_settings (
        id TEXT PRIMARY KEY,
        brand_logo_url TEXT NOT NULL DEFAULT '',
        email_domains TEXT NOT NULL,
        quick_links TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE login_settings ADD COLUMN brand_logo_url TEXT NOT NULL DEFAULT ''",
    "CREATE TABLE IF NOT EXISTS application_jwt_codes (
        code_hash TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        user_id TEXT NOT NULL,
        nonce TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_jwt_codes_application_expires ON application_jwt_codes(application_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS application_jwt_clients (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_type TEXT NOT NULL DEFAULT 'public',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(application_id, client_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_jwt_clients_application ON application_jwt_clients(application_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_jwt_client_secrets (
        id TEXT PRIMARY KEY,
        jwt_client_id TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_jwt_client_secrets_active ON application_jwt_client_secrets(jwt_client_id, revoked_at, expires_at)",
    "CREATE TABLE IF NOT EXISTS application_saml_replays (
        replay_key TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_replays_expiry ON application_saml_replays(expires_at, application_id)",
    "CREATE TABLE IF NOT EXISTS application_saml_interactions (
        handle_hash TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        sp_entity_id TEXT NOT NULL,
        acs_url TEXT NOT NULL,
        relay_state TEXT,
        response_binding TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_interactions_expiry ON application_saml_interactions(expires_at, application_id)",
    "CREATE TABLE IF NOT EXISTS application_saml_sessions (
        session_index_hash TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        signet_session_id TEXT NOT NULL,
        name_id_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_sessions_lookup ON application_saml_sessions(application_id, name_id_hash, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_sessions_signet_session ON application_saml_sessions(signet_session_id)",
    "CREATE TABLE IF NOT EXISTS application_cas_tickets (
        ticket_hash TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        ticket_type TEXT NOT NULL,
        service TEXT NOT NULL,
        user_id TEXT NOT NULL,
        parent_ticket_hash TEXT,
        pgt_iou TEXT,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        revoked_at INTEGER,
        created_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_cas_tickets_application ON application_cas_tickets(application_id, ticket_type, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_application_cas_tickets_user ON application_cas_tickets(application_id, user_id, revoked_at)",
    "ALTER TABLE application_jwt_codes ADD COLUMN client_id TEXT NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS idx_authorization_codes_client ON authorization_codes(client_id)",
    "CREATE INDEX IF NOT EXISTS idx_authorization_codes_application ON authorization_codes(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_authorization_codes_user ON authorization_codes(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id)",
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_application ON refresh_tokens(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_oidc_login_grants_invitation ON oidc_login_grants(invitation_id)",
    "CREATE INDEX IF NOT EXISTS idx_invitation_redemptions_invitation ON invitation_redemptions(invitation_id)",
    "CREATE INDEX IF NOT EXISTS idx_device_authorizations_user ON device_authorizations(authorized_user_id)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_source ON wallet_transactions(source_wallet_id)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_destination ON wallet_transactions(destination_wallet_id)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_holds_application ON wallet_holds(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_application_group_roles_subject ON application_group_roles(group_id)",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_group_roles_subject ON application_profile_group_roles(group_id)",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_replays_application ON application_saml_replays(application_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_interactions_application ON application_saml_interactions(application_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_application_discovery_idempotency_application ON application_discovery_idempotency(organization_id, application_id)",
];

const POSTGRES_MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT,
        phone TEXT,
        password_hash TEXT NOT NULL,
        email_verified_at BIGINT,
        phone_verified_at BIGINT,
        is_admin INTEGER NOT NULL,
        is_active INTEGER NOT NULL,
        archived_at BIGINT,
        registration_source TEXT NOT NULL DEFAULT 'local',
        last_login_at BIGINT,
        last_login_ip TEXT,
        last_oidc_client_id TEXT,
        last_login_method TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS archived_at BIGINT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS registration_source TEXT NOT NULL DEFAULT 'local'",
    "CREATE INDEX IF NOT EXISTS idx_users_archive_active_created ON users(archived_at, is_active, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_users_registration_source_lifecycle ON users(registration_source, archived_at, is_active, created_at)",
    "CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL UNIQUE,
        client_secret_hash TEXT,
        client_name TEXT NOT NULL,
        logo_uri TEXT NOT NULL DEFAULT '',
        organization_id TEXT,
        redirect_uris TEXT NOT NULL,
        post_logout_redirect_uris TEXT NOT NULL,
        scopes TEXT NOT NULL,
        audience TEXT NOT NULL DEFAULT '',
        grant_types TEXT NOT NULL,
        response_types TEXT NOT NULL,
        token_endpoint_auth_method TEXT NOT NULL,
        require_pkce INTEGER NOT NULL,
        require_mfa INTEGER NOT NULL DEFAULT 0,
        require_pushed_authorization_requests INTEGER NOT NULL DEFAULT 0,
        require_s256_pkce INTEGER NOT NULL DEFAULT 0,
        require_confidential_client INTEGER NOT NULL DEFAULT 0,
        require_dpop INTEGER NOT NULL DEFAULT 0,
        require_account_selection INTEGER NOT NULL DEFAULT 0,
        trust_email_verified INTEGER NOT NULL DEFAULT 0,
        authorization_details_types TEXT NOT NULL DEFAULT '[]',
        subject_type TEXT NOT NULL DEFAULT 'public',
        sector_identifier_uri TEXT NOT NULL DEFAULT '',
        jwks_uri TEXT NOT NULL DEFAULT '',
        jwks TEXT NOT NULL DEFAULT '',
        backchannel_logout_uri TEXT NOT NULL DEFAULT '',
        backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0,
        frontchannel_logout_uri TEXT NOT NULL DEFAULT '',
        frontchannel_logout_session_required INTEGER NOT NULL DEFAULT 0,
        service_account_enabled INTEGER NOT NULL DEFAULT 0,
        service_account_permissions TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS subject_type TEXT NOT NULL DEFAULT 'public'",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS require_mfa INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS require_pushed_authorization_requests INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS require_s256_pkce INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS require_confidential_client INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS require_dpop INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS require_account_selection INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS trust_email_verified INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS authorization_details_types TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS sector_identifier_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS jwks_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS jwks TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS frontchannel_logout_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS frontchannel_logout_session_required INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS service_account_enabled INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS service_account_permissions TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS audience TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS logo_uri TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS organization_id TEXT",
    "CREATE INDEX IF NOT EXISTS idx_clients_organization ON clients(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS client_registrations (
        client_db_id TEXT PRIMARY KEY,
        registration_access_token_hash TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS client_assertion_jtis (
        client_id TEXT NOT NULL,
        jti TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (client_id, jti)
    )",
    "CREATE INDEX IF NOT EXISTS idx_client_assertion_jtis_expires ON client_assertion_jtis(expires_at)",
    "CREATE TABLE IF NOT EXISTS client_claim_mappers (
        id TEXT PRIMARY KEY,
        client_db_id TEXT NOT NULL,
        claim_name TEXT NOT NULL,
        source TEXT NOT NULL,
        source_value TEXT NOT NULL,
        value_type TEXT NOT NULL,
        include_in_id_token INTEGER NOT NULL,
        include_in_access_token INTEGER NOT NULL,
        include_in_userinfo INTEGER NOT NULL,
        is_active INTEGER NOT NULL,
        sort_order INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_client_claim_mappers_client ON client_claim_mappers(client_db_id, sort_order)",
    "CREATE TABLE IF NOT EXISTS signing_keys (
        id TEXT PRIMARY KEY,
        kid TEXT NOT NULL UNIQUE,
        private_key_pem TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        activated_at BIGINT,
        retired_at BIGINT
    )",
    "CREATE INDEX IF NOT EXISTS idx_signing_keys_active_created ON signing_keys(is_active, created_at)",
    "CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        csrf_token TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        login_method TEXT,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS login_method TEXT",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user_expires ON sessions(user_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS browser_contexts (
        id TEXT PRIMARY KEY,
        csrf_token TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_browser_contexts_expires ON browser_contexts(expires_at)",
    "CREATE TABLE IF NOT EXISTS browser_context_accounts (
        id TEXT PRIMARY KEY,
        browser_context_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL UNIQUE,
        added_at BIGINT NOT NULL,
        last_selected_at BIGINT,
        UNIQUE(browser_context_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_browser_context_accounts_context ON browser_context_accounts(browser_context_id, last_selected_at)",
    "CREATE TABLE IF NOT EXISTS session_credentials (
        credential_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        browser_context_id TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_session_credentials_session ON session_credentials(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_session_credentials_context ON session_credentials(browser_context_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS account_login_flows (
        id_hash TEXT PRIMARY KEY,
        browser_context_id TEXT NOT NULL,
        return_to TEXT NOT NULL,
        expected_user_id TEXT,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "ALTER TABLE account_login_flows ADD COLUMN IF NOT EXISTS expected_user_id TEXT",
    "CREATE INDEX IF NOT EXISTS idx_account_login_flows_context_expires ON account_login_flows(browser_context_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS mfa_totp_methods (
        user_id TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        last_used_step BIGINT,
        enabled_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS mfa_totp_setups (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        secret TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_mfa_totp_setups_user_id ON mfa_totp_setups(user_id)",
    "CREATE TABLE IF NOT EXISTS mfa_challenges (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        return_to TEXT,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_purpose ON mfa_challenges(user_id, purpose, consumed_at)",
    "CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        used_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id, used_at)",
    "CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        credential_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        passkey_json TEXT NOT NULL,
        last_used_at BIGINT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id, created_at)",
    "CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        purpose TEXT NOT NULL,
        state_json TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_purpose ON webauthn_challenges(user_id, purpose, consumed_at)",
    "CREATE TABLE IF NOT EXISTS authorization_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        application_id TEXT,
        authorization_profile_id TEXT,
        auth_context_id TEXT,
        session_id TEXT,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT,
        authorization_details TEXT,
        nonce TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        auth_time BIGINT NOT NULL,
        acr TEXT NOT NULL DEFAULT 'urn:gpt-sso:acr:loa:1',
        amr TEXT NOT NULL DEFAULT '[]',
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS resource TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS authorization_details TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS session_id TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS auth_context_id TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS application_id TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS authorization_profile_id TEXT",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS auth_time BIGINT",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS acr TEXT NOT NULL DEFAULT 'urn:gpt-sso:acr:loa:1'",
    "ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS amr TEXT NOT NULL DEFAULT '[]'",
    "CREATE TABLE IF NOT EXISTS oidc_login_grants (
        credential_hash TEXT PRIMARY KEY,
        invitation_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        interaction_request_hash TEXT NOT NULL UNIQUE,
        auth_time BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_oidc_login_grants_client_expires ON oidc_login_grants(client_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_oidc_login_grants_user_expires ON oidc_login_grants(user_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS pushed_authorization_requests (
        request_uri_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        request_json TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_pushed_authorization_requests_client_expires ON pushed_authorization_requests(client_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS device_authorizations (
        device_code_hash TEXT PRIMARY KEY,
        user_code_hash TEXT NOT NULL UNIQUE,
        user_code_display TEXT NOT NULL,
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT,
        authorization_details TEXT,
        expires_at BIGINT NOT NULL,
        interval_seconds INTEGER NOT NULL,
        authorized_user_id TEXT,
        authorized_at BIGINT,
        denied_at BIGINT,
        consumed_at BIGINT,
        last_poll_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_device_authorizations_client_expires ON device_authorizations(client_id, expires_at)",
    "ALTER TABLE device_authorizations ADD COLUMN IF NOT EXISTS resource TEXT",
    "ALTER TABLE device_authorizations ADD COLUMN IF NOT EXISTS authorization_details TEXT",
    "CREATE TABLE IF NOT EXISTS refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        application_id TEXT,
        authorization_profile_id TEXT,
        auth_context_id TEXT,
        user_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT,
        authorization_details TEXT,
        dpop_jkt TEXT,
        expires_at BIGINT NOT NULL,
        revoked_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS resource TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS authorization_details TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS dpop_jkt TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS application_id TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS authorization_profile_id TEXT",
    "ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS auth_context_id TEXT",
    "CREATE TABLE IF NOT EXISTS dpop_proofs (
        jkt TEXT NOT NULL,
        jti TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (jkt, jti)
    )",
    "CREATE INDEX IF NOT EXISTS idx_dpop_proofs_expires ON dpop_proofs(expires_at)",
    "CREATE TABLE IF NOT EXISTS client_grants (
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        authorization_profile_id TEXT NOT NULL DEFAULT 'default',
        granted_scopes TEXT NOT NULL,
        granted_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        revoked_at BIGINT,
        PRIMARY KEY (user_id, client_id, authorization_profile_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_client_grants_client ON client_grants(client_id, revoked_at)",
    "CREATE TABLE IF NOT EXISTS registration_settings (
        id TEXT PRIMARY KEY,
        allow_password_registration INTEGER NOT NULL,
        require_email_verification INTEGER NOT NULL,
        require_phone_verification INTEGER NOT NULL,
        allow_external_oidc_registration INTEGER NOT NULL,
        require_invitation INTEGER NOT NULL,
        first_user_direct_admin INTEGER NOT NULL,
        default_user_active INTEGER NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS security_policy (
        id TEXT PRIMARY KEY,
        password_min_length INTEGER NOT NULL,
        password_require_uppercase INTEGER NOT NULL,
        password_require_lowercase INTEGER NOT NULL,
        password_require_digit INTEGER NOT NULL,
        password_require_symbol INTEGER NOT NULL,
        password_reject_user_info INTEGER NOT NULL,
        login_lockout_enabled INTEGER NOT NULL,
        max_failed_login_attempts INTEGER NOT NULL,
        failure_window_seconds BIGINT NOT NULL,
        lockout_seconds BIGINT NOT NULL,
        trusted_ip_cidrs TEXT NOT NULL DEFAULT '[]',
        require_mfa_outside_trusted_networks INTEGER NOT NULL DEFAULT 0,
        allowed_ip_cidrs TEXT NOT NULL DEFAULT '[]',
        blocked_ip_cidrs TEXT NOT NULL DEFAULT '[]',
        allowed_email_domains TEXT NOT NULL DEFAULT '[]',
        blocked_email_domains TEXT NOT NULL DEFAULT '[]',
        captcha_enabled INTEGER NOT NULL DEFAULT 0,
        captcha_after_failed_attempts INTEGER NOT NULL DEFAULT 3,
        captcha_ttl_seconds BIGINT NOT NULL DEFAULT 300,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS trusted_ip_cidrs TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS require_mfa_outside_trusted_networks INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS allowed_ip_cidrs TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS blocked_ip_cidrs TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS allowed_email_domains TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS blocked_email_domains TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS captcha_enabled INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS captcha_after_failed_attempts INTEGER NOT NULL DEFAULT 3",
    "ALTER TABLE security_policy ADD COLUMN IF NOT EXISTS captcha_ttl_seconds BIGINT NOT NULL DEFAULT 300",
    "CREATE TABLE IF NOT EXISTS runtime_settings (
        id TEXT PRIMARY KEY,
        public_base_url TEXT NOT NULL,
        issuer TEXT NOT NULL,
        trust_proxy_headers INTEGER NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS verification_codes (
        id TEXT PRIMARY KEY,
        channel TEXT NOT NULL,
        target TEXT NOT NULL,
        purpose TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        max_attempts INTEGER NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_verification_codes_target ON verification_codes(channel, target, purpose)",
    "CREATE TABLE IF NOT EXISTS invitations (
        id TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL UNIQUE,
        code_prefix TEXT NOT NULL,
        code_reveal_key_id TEXT,
        code_reveal_ciphertext TEXT,
        code_type TEXT NOT NULL DEFAULT 'login',
        login_code_level TEXT NOT NULL DEFAULT 'account_recovery',
        allowed_client_ids TEXT,
        organization_id TEXT,
        organization_role TEXT,
        description TEXT,
        authorized_email TEXT,
        authorized_username TEXT,
        authorized_user_id TEXT,
        authorized_display_name TEXT,
        expires_at BIGINT,
        max_uses INTEGER,
        uses_count INTEGER NOT NULL,
        is_active INTEGER NOT NULL,
        created_by TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS code_type TEXT NOT NULL DEFAULT 'login'",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS code_reveal_key_id TEXT",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS code_reveal_ciphertext TEXT",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS login_code_level TEXT NOT NULL DEFAULT 'account_recovery'",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS allowed_client_ids TEXT",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS organization_id TEXT",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS organization_role TEXT",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS authorized_email TEXT",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS authorized_username TEXT",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS authorized_user_id TEXT",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS authorized_display_name TEXT",
    "CREATE TABLE IF NOT EXISTS invitation_redemptions (
        id TEXT PRIMARY KEY,
        invitation_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        redeemed_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS trial_enrollments (
        user_id TEXT PRIMARY KEY,
        invitation_id TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        organization_role TEXT NOT NULL,
        allowed_client_ids TEXT NOT NULL,
        expires_at BIGINT,
        revoked_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_trial_enrollments_invitation ON trial_enrollments(invitation_id, revoked_at)",
    "CREATE TABLE IF NOT EXISTS login_events (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        login_at BIGINT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        method TEXT NOT NULL,
        oidc_client_id TEXT,
        external_provider TEXT
    )",
    "CREATE INDEX IF NOT EXISTS idx_login_events_user_id ON login_events(user_id, login_at)",
    "CREATE TABLE IF NOT EXISTS login_failures (
        id TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        reason TEXT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_login_failures_subject_created ON login_failures(subject, created_at)",
    "CREATE TABLE IF NOT EXISTS captcha_challenges (
        id TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        prompt TEXT NOT NULL,
        answer_hash TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_captcha_challenges_subject ON captcha_challenges(subject, consumed_at, expires_at)",
    "CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        actor_user_id TEXT,
        actor_client_id TEXT,
        action TEXT NOT NULL,
        target_kind TEXT NOT NULL,
        target_id TEXT,
        outcome TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at)",
    "CREATE TABLE IF NOT EXISTS mutation_receipts (
        id TEXT PRIMARY KEY,
        dedupe_hash TEXT NOT NULL UNIQUE,
        scope_key TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        response_status INTEGER,
        response_body TEXT,
        response_content_type TEXT,
        error_code TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        completed_at BIGINT,
        owner_token TEXT,
        lease_expires_at BIGINT
    )",
    "ALTER TABLE mutation_receipts ADD COLUMN owner_token TEXT NULL",
    "ALTER TABLE mutation_receipts ADD COLUMN lease_expires_at BIGINT NULL",
    "CREATE INDEX IF NOT EXISTS idx_mutation_receipts_scope_status ON mutation_receipts(scope_key, status, updated_at)",
    "CREATE TABLE IF NOT EXISTS audit_webhooks (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        secret TEXT NOT NULL,
        actions TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        timeout_seconds INTEGER NOT NULL,
        last_delivered_at BIGINT,
        last_status_code INTEGER,
        last_error TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_webhooks_active ON audit_webhooks(is_active, created_at)",
    "CREATE TABLE IF NOT EXISTS audit_webhook_outbox (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at BIGINT NOT NULL,
        lease_owner TEXT,
        lease_expires_at BIGINT,
        last_error TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_webhook_outbox_due ON audit_webhook_outbox(state, next_attempt_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_webhook_outbox_lease ON audit_webhook_outbox(state, lease_expires_at)",
    "CREATE TABLE IF NOT EXISTS roles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        is_system INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS role_permissions (
        role_id TEXT NOT NULL,
        permission TEXT NOT NULL,
        PRIMARY KEY (role_id, permission)
    )",
    "CREATE TABLE IF NOT EXISTS user_roles (
        user_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        PRIMARY KEY (user_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS access_groups (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        version BIGINT NOT NULL DEFAULT 0
    )",
    "ALTER TABLE access_groups ADD COLUMN version BIGINT NOT NULL DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS group_members (
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        PRIMARY KEY (group_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id, group_id)",
    "CREATE TABLE IF NOT EXISTS group_roles (
        group_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        PRIMARY KEY (group_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL DEFAULT 'tenant',
        description TEXT,
        allowed_email_domains TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS allowed_email_domains TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'tenant'",
    "CREATE INDEX IF NOT EXISTS idx_organizations_active_slug ON organizations(is_active, slug)",
    "CREATE TABLE IF NOT EXISTS organization_members (
        organization_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (organization_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_organization_members_user ON organization_members(user_id, organization_id)",
    "CREATE TABLE IF NOT EXISTS user_organization_contexts (
        user_id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_user_organization_contexts_organization ON user_organization_contexts(organization_id, user_id)",
    "CREATE TABLE IF NOT EXISTS applications (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        slug TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        access_mode TEXT NOT NULL,
        registration_mode TEXT NOT NULL,
        account_selection_mode TEXT NOT NULL,
        unique_identity_factors TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(organization_id, slug)
    )",
    "CREATE INDEX IF NOT EXISTS idx_applications_organization_active ON applications(organization_id, is_active, name)",
    "CREATE TABLE IF NOT EXISTS application_auth_domains (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL UNIQUE,
        assurance_policy TEXT NOT NULL DEFAULT 'default',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_auth_domains_active ON application_auth_domains(application_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_client_bindings (
        application_id TEXT NOT NULL,
        client_db_id TEXT NOT NULL UNIQUE,
        protocol TEXT NOT NULL,
        authorization_profile_id TEXT NOT NULL DEFAULT 'default',
        auth_domain_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, client_db_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_client_bindings_application ON application_client_bindings(application_id, created_at)",
    "CREATE TABLE IF NOT EXISTS application_auth_contexts (
        id TEXT PRIMARY KEY,
        auth_domain_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        acr TEXT NOT NULL,
        amr TEXT NOT NULL DEFAULT '[]',
        authenticated_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        revoked_at BIGINT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_auth_contexts_lookup ON application_auth_contexts(auth_domain_id, user_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS application_enrollment_codes (
        application_id TEXT NOT NULL,
        invitation_id TEXT NOT NULL UNIQUE,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, invitation_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_enrollment_codes_application ON application_enrollment_codes(application_id, created_at)",
    "CREATE TABLE IF NOT EXISTS application_members (
        application_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_members_user ON application_members(user_id, application_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_identity_bindings (
        application_id TEXT NOT NULL,
        factor_type TEXT NOT NULL,
        factor_digest TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, factor_type, factor_digest)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_identity_bindings_user ON application_identity_bindings(application_id, user_id)",
    "CREATE TABLE IF NOT EXISTS application_modules (
        application_id TEXT NOT NULL,
        module_key TEXT NOT NULL,
        config_json TEXT NOT NULL,
        is_enabled INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, module_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_modules_application ON application_modules(application_id, module_key)",
    "CREATE TABLE IF NOT EXISTS application_billing_settings (
        application_id TEXT PRIMARY KEY,
        accept_signet_balance INTEGER NOT NULL DEFAULT 0,
        wallet_mode TEXT NOT NULL DEFAULT 'shared',
        supported_currencies TEXT NOT NULL DEFAULT '[]',
        mode_locked_at BIGINT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS wallet_accounts (
        id TEXT PRIMARY KEY,
        account_kind TEXT NOT NULL,
        scope_key TEXT NOT NULL UNIQUE,
        user_id TEXT,
        application_id TEXT,
        currency TEXT NOT NULL,
        available_minor BIGINT NOT NULL DEFAULT 0,
        reserved_minor BIGINT NOT NULL DEFAULT 0,
        version BIGINT NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_wallet_accounts_user ON wallet_accounts(user_id, currency, account_kind)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_accounts_application ON wallet_accounts(application_id, currency, account_kind)",
    "CREATE TABLE IF NOT EXISTS wallet_transactions (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        user_id TEXT,
        application_id TEXT,
        currency TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        source_wallet_id TEXT,
        destination_wallet_id TEXT,
        hold_id TEXT,
        idempotency_key TEXT NOT NULL,
        external_provider TEXT,
        external_order_id TEXT,
        metadata TEXT NOT NULL DEFAULT '{}',
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(kind, idempotency_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_user ON wallet_transactions(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_application ON wallet_transactions(application_id, created_at)",
    "CREATE TABLE IF NOT EXISTS wallet_entries (
        id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        available_delta_minor BIGINT NOT NULL,
        reserved_delta_minor BIGINT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_wallet_entries_wallet ON wallet_entries(wallet_id, created_at)",
    "CREATE TABLE IF NOT EXISTS wallet_holds (
        id TEXT PRIMARY KEY,
        hold_kind TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        user_id TEXT,
        application_id TEXT,
        currency TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        status TEXT NOT NULL,
        reference TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(hold_kind, idempotency_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_wallet_holds_wallet ON wallet_holds(wallet_id, status, expires_at)",
    "CREATE TABLE IF NOT EXISTS payment_orders (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider_slug TEXT NOT NULL,
        merchant_order_no TEXT NOT NULL,
        idempotency_key TEXT,
        provider_trade_id TEXT,
        currency TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        subject TEXT NOT NULL,
        status TEXT NOT NULL,
        checkout_kind TEXT NOT NULL,
        checkout_value TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        paid_at BIGINT,
        last_error TEXT,
        lease_owner TEXT,
        lease_expires_at BIGINT,
        lease_generation BIGINT NOT NULL DEFAULT 0,
        attempt_count BIGINT NOT NULL DEFAULT 0,
        next_retry_at BIGINT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(provider_slug, merchant_order_no)
    )",
    "ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS idempotency_key TEXT",
    "ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS lease_owner TEXT",
    "ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS lease_expires_at BIGINT",
    "ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS lease_generation BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS attempt_count BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS next_retry_at BIGINT",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_payment_orders_idempotency ON payment_orders(user_id, provider_slug, idempotency_key)",
    "CREATE INDEX IF NOT EXISTS idx_payment_orders_user ON payment_orders(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_payment_orders_reconcile ON payment_orders(status, next_retry_at, lease_expires_at, updated_at)",
    "CREATE TABLE IF NOT EXISTS payment_refunds (
        id TEXT PRIMARY KEY,
        payment_order_id TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        status TEXT NOT NULL,
        provider_refund_id TEXT,
        requested_by TEXT,
        reason TEXT NOT NULL,
        idempotency_key TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE payment_refunds ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS idx_payment_refunds_order ON payment_refunds(payment_order_id, created_at)",
    "CREATE TABLE IF NOT EXISTS application_scim_tokens (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        scopes TEXT NOT NULL,
        expires_at BIGINT,
        revoked_at BIGINT,
        last_used_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_scim_tokens_application ON application_scim_tokens(application_id, revoked_at, created_at)",
    "CREATE TABLE IF NOT EXISTS application_scim_groups (
        application_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, group_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_scim_groups_group ON application_scim_groups(group_id, application_id)",
    "CREATE TABLE IF NOT EXISTS directory_sync_runs (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        status TEXT NOT NULL,
        total_seen BIGINT NOT NULL DEFAULT 0,
        created_count BIGINT NOT NULL DEFAULT 0,
        updated_count BIGINT NOT NULL DEFAULT 0,
        disabled_count BIGINT NOT NULL DEFAULT 0,
        error TEXT,
        cursor TEXT,
        started_at BIGINT NOT NULL,
        finished_at BIGINT
    )",
    "CREATE INDEX IF NOT EXISTS idx_directory_sync_runs_application ON directory_sync_runs(application_id, started_at)",
    "CREATE TABLE IF NOT EXISTS directory_sync_leases (
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        owner_run_id TEXT NOT NULL UNIQUE,
        acquired_at BIGINT NOT NULL,
        heartbeat_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, provider_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_directory_sync_leases_expiry ON directory_sync_leases(expires_at)",
    "CREATE TABLE IF NOT EXISTS directory_sync_checkpoints (
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        cursor TEXT,
        last_success_at BIGINT NOT NULL,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, provider_id)
    )",
    "CREATE TABLE IF NOT EXISTS directory_sync_memberships (
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        managed INTEGER NOT NULL DEFAULT 1,
        last_seen_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, provider_id, user_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_directory_sync_memberships_user ON directory_sync_memberships(user_id, managed)",
    "CREATE TABLE IF NOT EXISTS directory_sync_groups (
        application_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        external_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        last_seen_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, provider_id, external_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_directory_sync_groups_group ON directory_sync_groups(group_id)",
    "CREATE TABLE IF NOT EXISTS application_roles (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        permissions TEXT NOT NULL DEFAULT '[]',
        is_default INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(application_id, name)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_roles_application ON application_roles(application_id, is_active, name)",
    "CREATE TABLE IF NOT EXISTS application_user_roles (
        application_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        application_role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, user_id, application_role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_user_roles_user ON application_user_roles(application_id, user_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_group_roles (
        application_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        application_role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, group_id, application_role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_group_roles_group ON application_group_roles(application_id, group_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_organization_role_mappings (
        application_id TEXT NOT NULL,
        organization_role TEXT NOT NULL,
        application_role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, organization_role, application_role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_org_role_mappings_role ON application_organization_role_mappings(application_id, organization_role, is_active)",
    "CREATE TABLE IF NOT EXISTS application_user_permission_overrides (
        application_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        permission TEXT NOT NULL,
        effect TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, user_id, permission)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_permission_overrides_user ON application_user_permission_overrides(application_id, user_id, effect)",
    "CREATE TABLE IF NOT EXISTS application_authorization_profiles (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        profile_key TEXT NOT NULL,
        connection_kind TEXT NOT NULL,
        connection_id TEXT,
        source_mode TEXT NOT NULL,
        remote_version TEXT,
        remote_digest TEXT,
        sync_status TEXT NOT NULL DEFAULT 'manual',
        last_synced_at BIGINT,
        last_error TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(application_id, profile_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_auth_profiles_application ON application_authorization_profiles(application_id, profile_key)",
    "CREATE TABLE IF NOT EXISTS application_authorization_migration_state (
        application_id TEXT PRIMARY KEY,
        migrated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS application_permission_definitions (
        profile_id TEXT NOT NULL,
        permission_key TEXT NOT NULL,
        label TEXT NOT NULL,
        description TEXT,
        source TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, permission_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_permission_definitions_profile ON application_permission_definitions(profile_id, is_active, permission_key)",
    "CREATE TABLE IF NOT EXISTS application_profile_roles (
        id TEXT PRIMARY KEY,
        profile_id TEXT NOT NULL,
        role_key TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        permissions TEXT NOT NULL DEFAULT '[]',
        source TEXT NOT NULL,
        is_default INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(profile_id, role_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_roles_profile ON application_profile_roles(profile_id, is_active, role_key)",
    "CREATE TABLE IF NOT EXISTS application_profile_user_roles (
        profile_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, user_id, role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_user_roles_user ON application_profile_user_roles(profile_id, user_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_profile_group_roles (
        profile_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, group_id, role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_group_roles_group ON application_profile_group_roles(profile_id, group_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_profile_organization_roles (
        profile_id TEXT NOT NULL,
        organization_role TEXT NOT NULL,
        role_id TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, organization_role, role_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_org_roles_role ON application_profile_organization_roles(profile_id, organization_role, is_active)",
    "CREATE TABLE IF NOT EXISTS application_profile_permission_overrides (
        profile_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        permission TEXT NOT NULL,
        effect TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, user_id, permission)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_permission_overrides_user ON application_profile_permission_overrides(profile_id, user_id, effect)",
    "CREATE TABLE IF NOT EXISTS application_discovery (
        application_id TEXT PRIMARY KEY,
        management_mode TEXT NOT NULL DEFAULT 'signet_managed',
        website_url TEXT NOT NULL,
        fetch_secret_ciphertext TEXT NOT NULL DEFAULT '',
        signing_public_jwks TEXT NOT NULL DEFAULT '',
        last_verified_revision BIGINT,
        last_verified_version TEXT,
        last_verified_digest TEXT,
        last_verified_expires_at BIGINT,
        sync_status TEXT NOT NULL DEFAULT 'unconfigured',
        last_fetched_at BIGINT,
        last_success_at BIGINT,
        last_error TEXT,
        snapshot_json TEXT,
        operator_disabled INTEGER NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        lease_owner TEXT,
        lease_expires_at BIGINT,
        lease_generation BIGINT NOT NULL DEFAULT 0
    )",
    "ALTER TABLE application_discovery ADD COLUMN lease_owner TEXT NULL",
    "ALTER TABLE application_discovery ADD COLUMN lease_expires_at BIGINT NULL",
    "ALTER TABLE application_discovery ADD COLUMN lease_generation BIGINT NOT NULL DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS idx_application_discovery_mode_status ON application_discovery(management_mode, sync_status)",
    "CREATE TABLE IF NOT EXISTS application_discovery_idempotency (
        organization_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        origin TEXT NOT NULL,
        application_id TEXT,
        claim_token TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (organization_id, idempotency_key)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_discovery_idempotency_updated ON application_discovery_idempotency(status, updated_at)",
    "CREATE TABLE IF NOT EXISTS iap_applications (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        external_host TEXT NOT NULL,
        path_prefix TEXT NOT NULL,
        required_organization_id TEXT,
        required_organization_roles TEXT NOT NULL,
        required_permissions TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE iap_applications ADD COLUMN application_id TEXT",
    "CREATE INDEX IF NOT EXISTS idx_iap_applications_application ON iap_applications(application_id, is_active)",
    "CREATE INDEX IF NOT EXISTS idx_iap_applications_match ON iap_applications(is_active, external_host, path_prefix)",
    "CREATE TABLE IF NOT EXISTS linked_identities (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider_slug TEXT NOT NULL,
        external_subject TEXT NOT NULL,
        external_email TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(provider_slug, external_subject)
    )",
    "CREATE INDEX IF NOT EXISTS idx_linked_identities_user ON linked_identities(user_id)",
    "CREATE TABLE IF NOT EXISTS ldap_providers (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        organization_id TEXT,
        url TEXT NOT NULL,
        starttls INTEGER NOT NULL,
        bind_dn TEXT NOT NULL,
        bind_password TEXT NOT NULL,
        base_dn TEXT NOT NULL,
        user_filter TEXT NOT NULL,
        user_id_attribute TEXT NOT NULL,
        email_attribute TEXT NOT NULL,
        username_attribute TEXT NOT NULL,
        display_name_attribute TEXT NOT NULL,
        phone_attribute TEXT NOT NULL,
        is_active INTEGER NOT NULL,
        allow_login INTEGER NOT NULL,
        allow_registration INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE ldap_providers ADD COLUMN IF NOT EXISTS organization_id TEXT",
    "CREATE INDEX IF NOT EXISTS idx_ldap_providers_organization ON ldap_providers(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS external_oidc_providers (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        organization_id TEXT,
        issuer TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        authorization_endpoint TEXT NOT NULL,
        token_endpoint TEXT NOT NULL,
        userinfo_endpoint TEXT NOT NULL,
        redirect_path TEXT NOT NULL,
        scopes TEXT NOT NULL,
        email_domains TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        allow_login INTEGER NOT NULL DEFAULT 1,
        allow_registration INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE external_oidc_providers ADD COLUMN IF NOT EXISTS organization_id TEXT",
    "ALTER TABLE external_oidc_providers ADD COLUMN IF NOT EXISTS email_domains TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE external_oidc_providers ADD COLUMN IF NOT EXISTS allow_login INTEGER NOT NULL DEFAULT 1",
    "CREATE INDEX IF NOT EXISTS idx_external_oidc_providers_organization ON external_oidc_providers(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS external_oidc_states (
        state TEXT PRIMARY KEY,
        provider_slug TEXT NOT NULL,
        nonce TEXT NOT NULL,
        return_to TEXT,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS login_settings (
        id TEXT PRIMARY KEY,
        brand_logo_url TEXT NOT NULL DEFAULT '',
        email_domains TEXT NOT NULL,
        quick_links TEXT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE login_settings ADD COLUMN IF NOT EXISTS brand_logo_url TEXT NOT NULL DEFAULT ''",
    "CREATE TABLE IF NOT EXISTS application_jwt_codes (
        code_hash TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        user_id TEXT NOT NULL,
        nonce TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_jwt_codes_application_expires ON application_jwt_codes(application_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS application_jwt_clients (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_type TEXT NOT NULL DEFAULT 'public',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(application_id, client_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_jwt_clients_application ON application_jwt_clients(application_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_jwt_client_secrets (
        id TEXT PRIMARY KEY,
        jwt_client_id TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT,
        revoked_at BIGINT
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_jwt_client_secrets_active ON application_jwt_client_secrets(jwt_client_id, revoked_at, expires_at)",
    "CREATE TABLE IF NOT EXISTS application_saml_replays (
        replay_key TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_replays_expiry ON application_saml_replays(expires_at, application_id)",
    "CREATE TABLE IF NOT EXISTS application_saml_interactions (
        handle_hash TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        sp_entity_id TEXT NOT NULL,
        acs_url TEXT NOT NULL,
        relay_state TEXT NULL,
        response_binding TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_interactions_expiry ON application_saml_interactions(expires_at, application_id)",
    "CREATE TABLE IF NOT EXISTS application_saml_sessions (
        session_index_hash TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        signet_session_id TEXT NOT NULL,
        name_id_hash TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_sessions_lookup ON application_saml_sessions(application_id, name_id_hash, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_sessions_signet_session ON application_saml_sessions(signet_session_id)",
    "CREATE TABLE IF NOT EXISTS application_cas_tickets (
        ticket_hash TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        ticket_type TEXT NOT NULL,
        service TEXT NOT NULL,
        user_id TEXT NOT NULL,
        parent_ticket_hash TEXT,
        pgt_iou TEXT,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT,
        revoked_at BIGINT,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_application_cas_tickets_application ON application_cas_tickets(application_id, ticket_type, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_application_cas_tickets_user ON application_cas_tickets(application_id, user_id, revoked_at)",
    "ALTER TABLE application_jwt_codes ADD COLUMN IF NOT EXISTS client_id TEXT NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS idx_authorization_codes_client ON authorization_codes(client_id)",
    "CREATE INDEX IF NOT EXISTS idx_authorization_codes_application ON authorization_codes(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_authorization_codes_user ON authorization_codes(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id)",
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_application ON refresh_tokens(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_oidc_login_grants_invitation ON oidc_login_grants(invitation_id)",
    "CREATE INDEX IF NOT EXISTS idx_invitation_redemptions_invitation ON invitation_redemptions(invitation_id)",
    "CREATE INDEX IF NOT EXISTS idx_device_authorizations_user ON device_authorizations(authorized_user_id)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_source ON wallet_transactions(source_wallet_id)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_destination ON wallet_transactions(destination_wallet_id)",
    "CREATE INDEX IF NOT EXISTS idx_wallet_holds_application ON wallet_holds(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_application_group_roles_subject ON application_group_roles(group_id)",
    "CREATE INDEX IF NOT EXISTS idx_application_profile_group_roles_subject ON application_profile_group_roles(group_id)",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_replays_application ON application_saml_replays(application_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_application_saml_interactions_application ON application_saml_interactions(application_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_application_discovery_idempotency_application ON application_discovery_idempotency(organization_id, application_id)",
];

const MYSQL_MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(64) PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        username VARCHAR(255) NOT NULL UNIQUE,
        phone VARCHAR(64),
        display_name TEXT NULL,
        password_hash TEXT NOT NULL,
        email_verified_at BIGINT NULL,
        phone_verified_at BIGINT NULL,
        is_admin INT NOT NULL,
        is_active INT NOT NULL,
        archived_at BIGINT NULL,
        registration_source VARCHAR(32) NOT NULL DEFAULT 'local',
        last_login_at BIGINT NULL,
        last_login_ip VARCHAR(128) NULL,
        last_oidc_client_id VARCHAR(255) NULL,
        last_login_method VARCHAR(64) NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE users ADD COLUMN archived_at BIGINT NULL",
    "ALTER TABLE users ADD COLUMN registration_source VARCHAR(32) NOT NULL DEFAULT 'local'",
    "CREATE INDEX idx_users_archive_active_created ON users(archived_at, is_active, created_at)",
    "CREATE INDEX idx_users_registration_source_lifecycle ON users(registration_source, archived_at, is_active, created_at)",
    "CREATE TABLE IF NOT EXISTS clients (
        id VARCHAR(64) PRIMARY KEY,
        client_id VARCHAR(255) NOT NULL UNIQUE,
        client_secret_hash TEXT NULL,
        client_name TEXT NOT NULL,
        logo_uri VARCHAR(2048) NOT NULL DEFAULT '',
        organization_id VARCHAR(64) NULL,
        redirect_uris TEXT NOT NULL,
        post_logout_redirect_uris TEXT NOT NULL,
        scopes TEXT NOT NULL,
        audience VARCHAR(2048) NOT NULL DEFAULT '',
        grant_types TEXT NOT NULL,
        response_types TEXT NOT NULL,
        token_endpoint_auth_method VARCHAR(64) NOT NULL,
        require_pkce INT NOT NULL,
        require_mfa INT NOT NULL DEFAULT 0,
        require_pushed_authorization_requests INT NOT NULL DEFAULT 0,
        require_s256_pkce INT NOT NULL DEFAULT 0,
        require_confidential_client INT NOT NULL DEFAULT 0,
        require_dpop INT NOT NULL DEFAULT 0,
        require_account_selection INT NOT NULL DEFAULT 0,
        trust_email_verified INT NOT NULL DEFAULT 0,
        authorization_details_types TEXT NOT NULL,
        subject_type VARCHAR(16) NOT NULL DEFAULT 'public',
        sector_identifier_uri VARCHAR(2048) NOT NULL DEFAULT '',
        jwks_uri VARCHAR(2048) NOT NULL DEFAULT '',
        jwks LONGTEXT NULL,
        backchannel_logout_uri VARCHAR(2048) NOT NULL DEFAULT '',
        backchannel_logout_session_required INT NOT NULL DEFAULT 0,
        frontchannel_logout_uri VARCHAR(2048) NOT NULL DEFAULT '',
        frontchannel_logout_session_required INT NOT NULL DEFAULT 0,
        service_account_enabled INT NOT NULL DEFAULT 0,
        service_account_permissions TEXT NOT NULL,
        is_active INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE clients ADD COLUMN subject_type VARCHAR(16) NOT NULL DEFAULT 'public'",
    "ALTER TABLE clients ADD COLUMN require_mfa INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_pushed_authorization_requests INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_s256_pkce INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_confidential_client INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_dpop INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN require_account_selection INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN trust_email_verified INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN authorization_details_types TEXT NULL",
    "ALTER TABLE clients ADD COLUMN sector_identifier_uri VARCHAR(2048) NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN jwks_uri VARCHAR(2048) NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN jwks LONGTEXT NULL",
    "ALTER TABLE clients ADD COLUMN backchannel_logout_uri VARCHAR(2048) NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN backchannel_logout_session_required INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN frontchannel_logout_uri VARCHAR(2048) NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN frontchannel_logout_session_required INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN service_account_enabled INT NOT NULL DEFAULT 0",
    "ALTER TABLE clients ADD COLUMN service_account_permissions TEXT NULL",
    "ALTER TABLE clients ADD COLUMN audience VARCHAR(2048) NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN logo_uri VARCHAR(2048) NOT NULL DEFAULT ''",
    "ALTER TABLE clients ADD COLUMN organization_id VARCHAR(64) NULL",
    "CREATE INDEX idx_clients_organization ON clients(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS client_registrations (
        client_db_id VARCHAR(64) PRIMARY KEY,
        registration_access_token_hash VARCHAR(128) NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS client_assertion_jtis (
        client_id VARCHAR(255) NOT NULL,
        jti VARCHAR(255) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (client_id, jti),
        INDEX idx_client_assertion_jtis_expires (expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS client_claim_mappers (
        id VARCHAR(64) PRIMARY KEY,
        client_db_id VARCHAR(64) NOT NULL,
        claim_name VARCHAR(128) NOT NULL,
        source VARCHAR(32) NOT NULL,
        source_value TEXT NOT NULL,
        value_type VARCHAR(32) NOT NULL,
        include_in_id_token INT NOT NULL,
        include_in_access_token INT NOT NULL,
        include_in_userinfo INT NOT NULL,
        is_active INT NOT NULL,
        sort_order INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_client_claim_mappers_client (client_db_id, sort_order)
    )",
    "CREATE TABLE IF NOT EXISTS signing_keys (
        id VARCHAR(64) PRIMARY KEY,
        kid VARCHAR(128) NOT NULL UNIQUE,
        private_key_pem TEXT NOT NULL,
        is_active INT NOT NULL,
        created_at BIGINT NOT NULL,
        activated_at BIGINT NULL,
        retired_at BIGINT NULL,
        INDEX idx_signing_keys_active_created (is_active, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS sessions (
        id VARCHAR(128) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        csrf_token VARCHAR(128) NOT NULL,
        ip_address VARCHAR(128) NULL,
        user_agent TEXT NULL,
        login_method VARCHAR(64) NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_sessions_user_id (user_id),
        INDEX idx_sessions_user_expires (user_id, expires_at)
    )",
    "ALTER TABLE sessions ADD COLUMN ip_address VARCHAR(128) NULL",
    "ALTER TABLE sessions ADD COLUMN user_agent TEXT NULL",
    "ALTER TABLE sessions ADD COLUMN login_method VARCHAR(64) NULL",
    "CREATE INDEX idx_sessions_user_expires ON sessions(user_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS browser_contexts (
        id VARCHAR(128) PRIMARY KEY,
        csrf_token VARCHAR(128) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_browser_contexts_expires (expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS browser_context_accounts (
        id VARCHAR(64) PRIMARY KEY,
        browser_context_id VARCHAR(128) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        session_id VARCHAR(128) NOT NULL UNIQUE,
        added_at BIGINT NOT NULL,
        last_selected_at BIGINT NULL,
        UNIQUE KEY idx_browser_context_accounts_user (browser_context_id, user_id),
        INDEX idx_browser_context_accounts_context (browser_context_id, last_selected_at)
    )",
    "CREATE TABLE IF NOT EXISTS session_credentials (
        credential_id VARCHAR(128) PRIMARY KEY,
        session_id VARCHAR(128) NOT NULL,
        browser_context_id VARCHAR(128) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_session_credentials_session (session_id),
        INDEX idx_session_credentials_context (browser_context_id, expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS account_login_flows (
        id_hash VARCHAR(128) PRIMARY KEY,
        browser_context_id VARCHAR(128) NOT NULL,
        return_to TEXT NOT NULL,
        expected_user_id VARCHAR(64) NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_account_login_flows_context_expires (browser_context_id, expires_at)
    )",
    "ALTER TABLE account_login_flows ADD COLUMN expected_user_id VARCHAR(64) NULL",
    "CREATE TABLE IF NOT EXISTS mfa_totp_methods (
        user_id VARCHAR(64) PRIMARY KEY,
        secret TEXT NOT NULL,
        last_used_step BIGINT NULL,
        enabled_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS mfa_totp_setups (
        id VARCHAR(128) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        secret TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_mfa_totp_setups_user_id (user_id)
    )",
    "CREATE TABLE IF NOT EXISTS mfa_challenges (
        id VARCHAR(128) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        purpose VARCHAR(64) NOT NULL,
        return_to TEXT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_mfa_challenges_user_purpose (user_id, purpose, consumed_at)
    )",
    "CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        code_hash TEXT NOT NULL,
        used_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_mfa_recovery_codes_user_id (user_id, used_at)
    )",
    "CREATE TABLE IF NOT EXISTS passkeys (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        credential_id VARCHAR(512) NOT NULL UNIQUE,
        name VARCHAR(160) NOT NULL,
        passkey_json TEXT NOT NULL,
        last_used_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_passkeys_user_id (user_id, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id VARCHAR(128) PRIMARY KEY,
        user_id VARCHAR(64) NULL,
        purpose VARCHAR(64) NOT NULL,
        state_json TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_webauthn_challenges_user_purpose (user_id, purpose, consumed_at)
    )",
    "CREATE TABLE IF NOT EXISTS authorization_codes (
        code VARCHAR(128) PRIMARY KEY,
        client_id VARCHAR(255) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        application_id VARCHAR(128) NULL,
        authorization_profile_id VARCHAR(128) NULL,
        auth_context_id VARCHAR(128) NULL,
        session_id VARCHAR(128) NULL,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT NULL,
        authorization_details TEXT NULL,
        nonce TEXT NULL,
        code_challenge TEXT NULL,
        code_challenge_method VARCHAR(16) NULL,
        auth_time BIGINT NOT NULL,
        acr VARCHAR(255) NOT NULL DEFAULT 'urn:gpt-sso:acr:loa:1',
        amr TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL
    )",
    "ALTER TABLE authorization_codes ADD COLUMN resource TEXT NULL",
    "ALTER TABLE authorization_codes ADD COLUMN authorization_details TEXT NULL",
    "ALTER TABLE authorization_codes ADD COLUMN session_id VARCHAR(128) NULL",
    "ALTER TABLE authorization_codes ADD COLUMN auth_context_id VARCHAR(128) NULL",
    "ALTER TABLE authorization_codes ADD COLUMN application_id VARCHAR(128) NULL",
    "ALTER TABLE authorization_codes ADD COLUMN authorization_profile_id VARCHAR(128) NULL",
    "ALTER TABLE authorization_codes ADD COLUMN auth_time BIGINT NULL",
    "ALTER TABLE authorization_codes ADD COLUMN acr VARCHAR(255) NOT NULL DEFAULT 'urn:gpt-sso:acr:loa:1'",
    "ALTER TABLE authorization_codes ADD COLUMN amr TEXT NULL",
    "CREATE TABLE IF NOT EXISTS oidc_login_grants (
        credential_hash VARCHAR(128) PRIMARY KEY,
        invitation_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        interaction_request_hash VARCHAR(128) NOT NULL UNIQUE,
        auth_time BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_oidc_login_grants_client_expires (client_id, expires_at),
        INDEX idx_oidc_login_grants_user_expires (user_id, expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS pushed_authorization_requests (
        request_uri_hash VARCHAR(128) PRIMARY KEY,
        client_id VARCHAR(255) NOT NULL,
        request_json TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_pushed_authorization_requests_client_expires (client_id, expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS device_authorizations (
        device_code_hash VARCHAR(128) PRIMARY KEY,
        user_code_hash VARCHAR(128) NOT NULL UNIQUE,
        user_code_display VARCHAR(16) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT NULL,
        authorization_details TEXT NULL,
        expires_at BIGINT NOT NULL,
        interval_seconds INT NOT NULL,
        authorized_user_id VARCHAR(64) NULL,
        authorized_at BIGINT NULL,
        denied_at BIGINT NULL,
        consumed_at BIGINT NULL,
        last_poll_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_device_authorizations_client_expires (client_id, expires_at)
    )",
    "ALTER TABLE device_authorizations ADD COLUMN resource TEXT NULL",
    "ALTER TABLE device_authorizations ADD COLUMN authorization_details TEXT NULL",
    "CREATE TABLE IF NOT EXISTS refresh_tokens (
        token_hash VARCHAR(128) PRIMARY KEY,
        client_id VARCHAR(255) NOT NULL,
        application_id VARCHAR(128) NULL,
        authorization_profile_id VARCHAR(128) NULL,
        auth_context_id VARCHAR(128) NULL,
        user_id VARCHAR(64) NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT NULL,
        authorization_details TEXT NULL,
        dpop_jkt VARCHAR(128) NULL,
        expires_at BIGINT NOT NULL,
        revoked_at BIGINT NULL,
        created_at BIGINT NOT NULL
    )",
    "ALTER TABLE refresh_tokens ADD COLUMN resource TEXT NULL",
    "ALTER TABLE refresh_tokens ADD COLUMN authorization_details TEXT NULL",
    "ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt VARCHAR(128) NULL",
    "ALTER TABLE refresh_tokens ADD COLUMN application_id VARCHAR(128) NULL",
    "ALTER TABLE refresh_tokens ADD COLUMN authorization_profile_id VARCHAR(128) NULL",
    "ALTER TABLE refresh_tokens ADD COLUMN auth_context_id VARCHAR(128) NULL",
    "CREATE TABLE IF NOT EXISTS dpop_proofs (
        jkt VARCHAR(128) NOT NULL,
        jti VARCHAR(255) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (jkt, jti),
        INDEX idx_dpop_proofs_expires (expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS client_grants (
        user_id VARCHAR(64) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        authorization_profile_id VARCHAR(128) NOT NULL DEFAULT 'default',
        granted_scopes TEXT NOT NULL,
        granted_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        revoked_at BIGINT NULL,
        PRIMARY KEY (user_id, client_id, authorization_profile_id),
        INDEX idx_client_grants_client (client_id, revoked_at)
    )",
    "CREATE TABLE IF NOT EXISTS registration_settings (
        id VARCHAR(32) PRIMARY KEY,
        allow_password_registration INT NOT NULL,
        require_email_verification INT NOT NULL,
        require_phone_verification INT NOT NULL,
        allow_external_oidc_registration INT NOT NULL,
        require_invitation INT NOT NULL,
        first_user_direct_admin INT NOT NULL,
        default_user_active INT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS security_policy (
        id VARCHAR(32) PRIMARY KEY,
        password_min_length INT NOT NULL,
        password_require_uppercase INT NOT NULL,
        password_require_lowercase INT NOT NULL,
        password_require_digit INT NOT NULL,
        password_require_symbol INT NOT NULL,
        password_reject_user_info INT NOT NULL,
        login_lockout_enabled INT NOT NULL,
        max_failed_login_attempts INT NOT NULL,
        failure_window_seconds BIGINT NOT NULL,
        lockout_seconds BIGINT NOT NULL,
        trusted_ip_cidrs TEXT NOT NULL,
        require_mfa_outside_trusted_networks INT NOT NULL DEFAULT 0,
        allowed_ip_cidrs TEXT NOT NULL,
        blocked_ip_cidrs TEXT NOT NULL,
        allowed_email_domains TEXT NOT NULL,
        blocked_email_domains TEXT NOT NULL,
        captcha_enabled INT NOT NULL DEFAULT 0,
        captcha_after_failed_attempts INT NOT NULL DEFAULT 3,
        captcha_ttl_seconds BIGINT NOT NULL DEFAULT 300,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE security_policy ADD COLUMN trusted_ip_cidrs TEXT NULL",
    "ALTER TABLE security_policy ADD COLUMN require_mfa_outside_trusted_networks INT NOT NULL DEFAULT 0",
    "ALTER TABLE security_policy ADD COLUMN allowed_ip_cidrs TEXT NULL",
    "ALTER TABLE security_policy ADD COLUMN blocked_ip_cidrs TEXT NULL",
    "ALTER TABLE security_policy ADD COLUMN allowed_email_domains TEXT NULL",
    "ALTER TABLE security_policy ADD COLUMN blocked_email_domains TEXT NULL",
    "ALTER TABLE security_policy ADD COLUMN captcha_enabled INT NOT NULL DEFAULT 0",
    "ALTER TABLE security_policy ADD COLUMN captcha_after_failed_attempts INT NOT NULL DEFAULT 3",
    "ALTER TABLE security_policy ADD COLUMN captcha_ttl_seconds BIGINT NOT NULL DEFAULT 300",
    "CREATE TABLE IF NOT EXISTS runtime_settings (
        id VARCHAR(32) PRIMARY KEY,
        public_base_url TEXT NOT NULL,
        issuer TEXT NOT NULL,
        trust_proxy_headers INT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS verification_codes (
        id VARCHAR(64) PRIMARY KEY,
        channel VARCHAR(16) NOT NULL,
        target VARCHAR(255) NOT NULL,
        purpose VARCHAR(64) NOT NULL,
        code_hash VARCHAR(128) NOT NULL,
        attempts INT NOT NULL,
        max_attempts INT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_verification_codes_target (channel, target, purpose)
    )",
    "CREATE TABLE IF NOT EXISTS invitations (
        id VARCHAR(64) PRIMARY KEY,
        code_hash VARCHAR(128) NOT NULL UNIQUE,
        code_prefix VARCHAR(32) NOT NULL,
        code_reveal_key_id VARCHAR(128) NULL,
        code_reveal_ciphertext TEXT NULL,
        code_type VARCHAR(32) NOT NULL DEFAULT 'login',
        login_code_level VARCHAR(32) NOT NULL DEFAULT 'account_recovery',
        allowed_client_ids TEXT NULL,
        organization_id VARCHAR(64) NULL,
        organization_role VARCHAR(32) NULL,
        description TEXT NULL,
        authorized_email VARCHAR(255) NULL,
        authorized_username VARCHAR(255) NULL,
        authorized_user_id VARCHAR(64) NULL,
        authorized_display_name TEXT NULL,
        expires_at BIGINT NULL,
        max_uses INT NULL,
        uses_count INT NOT NULL,
        is_active INT NOT NULL,
        created_by VARCHAR(64) NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE invitations ADD COLUMN code_type VARCHAR(32) NOT NULL DEFAULT 'login'",
    "ALTER TABLE invitations ADD COLUMN code_reveal_key_id VARCHAR(128) NULL",
    "ALTER TABLE invitations ADD COLUMN code_reveal_ciphertext TEXT NULL",
    "ALTER TABLE invitations ADD COLUMN login_code_level VARCHAR(32) NOT NULL DEFAULT 'account_recovery'",
    "ALTER TABLE invitations ADD COLUMN allowed_client_ids TEXT NULL",
    "ALTER TABLE invitations ADD COLUMN organization_id VARCHAR(64) NULL",
    "ALTER TABLE invitations ADD COLUMN organization_role VARCHAR(32) NULL",
    "ALTER TABLE invitations ADD COLUMN authorized_email VARCHAR(255) NULL",
    "ALTER TABLE invitations ADD COLUMN authorized_username VARCHAR(255) NULL",
    "ALTER TABLE invitations ADD COLUMN authorized_user_id VARCHAR(64) NULL",
    "ALTER TABLE invitations ADD COLUMN authorized_display_name TEXT NULL",
    "CREATE TABLE IF NOT EXISTS invitation_redemptions (
        id VARCHAR(64) PRIMARY KEY,
        invitation_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        redeemed_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS trial_enrollments (
        user_id VARCHAR(64) PRIMARY KEY,
        invitation_id VARCHAR(64) NOT NULL,
        organization_id VARCHAR(64) NOT NULL,
        organization_role VARCHAR(32) NOT NULL,
        allowed_client_ids TEXT NOT NULL,
        expires_at BIGINT NULL,
        revoked_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_trial_enrollments_invitation (invitation_id, revoked_at)
    )",
    "CREATE TABLE IF NOT EXISTS login_events (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        login_at BIGINT NOT NULL,
        ip_address VARCHAR(128) NULL,
        user_agent TEXT NULL,
        method VARCHAR(64) NOT NULL,
        oidc_client_id VARCHAR(255) NULL,
        external_provider VARCHAR(255) NULL,
        INDEX idx_login_events_user_id (user_id, login_at)
    )",
    "CREATE TABLE IF NOT EXISTS login_failures (
        id VARCHAR(64) PRIMARY KEY,
        subject VARCHAR(255) NOT NULL,
        ip_address VARCHAR(128) NULL,
        user_agent TEXT NULL,
        reason VARCHAR(64) NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_login_failures_subject_created (subject, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS captcha_challenges (
        id VARCHAR(64) PRIMARY KEY,
        subject VARCHAR(255) NOT NULL,
        prompt VARCHAR(255) NOT NULL,
        answer_hash TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_captcha_challenges_subject (subject, consumed_at, expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS audit_events (
        id VARCHAR(64) PRIMARY KEY,
        actor_user_id VARCHAR(64) NULL,
        actor_client_id VARCHAR(255) NULL,
        action VARCHAR(128) NOT NULL,
        target_kind VARCHAR(128) NOT NULL,
        target_id VARCHAR(255) NULL,
        outcome VARCHAR(32) NOT NULL,
        ip_address VARCHAR(128) NULL,
        user_agent TEXT NULL,
        details TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_audit_events_created (created_at)
    )",
    "CREATE TABLE IF NOT EXISTS mutation_receipts (
        id VARCHAR(64) PRIMARY KEY,
        dedupe_hash VARCHAR(128) NOT NULL UNIQUE,
        scope_key VARCHAR(128) NOT NULL,
        method VARCHAR(16) NOT NULL,
        path VARCHAR(1024) NOT NULL,
        idempotency_key VARCHAR(255) NOT NULL,
        request_hash VARCHAR(128) NOT NULL,
        status VARCHAR(32) NOT NULL,
        response_status INT NULL,
        response_body TEXT NULL,
        response_content_type VARCHAR(255) NULL,
        error_code VARCHAR(128) NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        completed_at BIGINT NULL,
        owner_token VARCHAR(128) NULL,
        lease_expires_at BIGINT NULL,
        INDEX idx_mutation_receipts_scope_status (scope_key, status, updated_at)
    )",
    "ALTER TABLE mutation_receipts ADD COLUMN owner_token VARCHAR(128) NULL",
    "ALTER TABLE mutation_receipts ADD COLUMN lease_expires_at BIGINT NULL",
    "CREATE TABLE IF NOT EXISTS audit_webhooks (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(160) NOT NULL,
        url VARCHAR(2048) NOT NULL,
        secret TEXT NOT NULL,
        actions TEXT NOT NULL,
        is_active INT NOT NULL,
        timeout_seconds INT NOT NULL,
        last_delivered_at BIGINT NULL,
        last_status_code INT NULL,
        last_error TEXT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_audit_webhooks_active (is_active, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS audit_webhook_outbox (
        id VARCHAR(64) PRIMARY KEY,
        event_id VARCHAR(64) NOT NULL UNIQUE,
        state VARCHAR(32) NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at BIGINT NOT NULL,
        lease_owner VARCHAR(64) NULL,
        lease_expires_at BIGINT NULL,
        last_error TEXT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_audit_webhook_outbox_due (state, next_attempt_at),
        INDEX idx_audit_webhook_outbox_lease (state, lease_expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS roles (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(128) NOT NULL UNIQUE,
        description TEXT NULL,
        is_system INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS role_permissions (
        role_id VARCHAR(64) NOT NULL,
        permission VARCHAR(128) NOT NULL,
        PRIMARY KEY (role_id, permission)
    )",
    "CREATE TABLE IF NOT EXISTS user_roles (
        user_id VARCHAR(64) NOT NULL,
        role_id VARCHAR(64) NOT NULL,
        PRIMARY KEY (user_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS access_groups (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(128) NOT NULL UNIQUE,
        description TEXT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        version BIGINT NOT NULL DEFAULT 0
    )",
    "ALTER TABLE access_groups ADD COLUMN version BIGINT NOT NULL DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS group_members (
        group_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        PRIMARY KEY (group_id, user_id),
        INDEX idx_group_members_user (user_id, group_id)
    )",
    "CREATE TABLE IF NOT EXISTS group_roles (
        group_id VARCHAR(64) NOT NULL,
        role_id VARCHAR(64) NOT NULL,
        PRIMARY KEY (group_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS organizations (
        id VARCHAR(64) PRIMARY KEY,
        slug VARCHAR(64) NOT NULL UNIQUE,
        name VARCHAR(160) NOT NULL UNIQUE,
        kind VARCHAR(16) NOT NULL DEFAULT 'tenant',
        description TEXT NULL,
        allowed_email_domains TEXT NOT NULL,
        is_active INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_organizations_active_slug (is_active, slug)
    )",
    "ALTER TABLE organizations ADD COLUMN allowed_email_domains TEXT NULL",
    "ALTER TABLE organizations ADD COLUMN kind VARCHAR(16) NOT NULL DEFAULT 'tenant'",
    "CREATE TABLE IF NOT EXISTS organization_members (
        organization_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        role VARCHAR(32) NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (organization_id, user_id),
        INDEX idx_organization_members_user (user_id, organization_id)
    )",
    "CREATE TABLE IF NOT EXISTS user_organization_contexts (
        user_id VARCHAR(64) PRIMARY KEY,
        organization_id VARCHAR(64) NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_user_organization_contexts_organization (organization_id, user_id)
    )",
    "CREATE TABLE IF NOT EXISTS applications (
        id VARCHAR(64) PRIMARY KEY,
        organization_id VARCHAR(64) NOT NULL,
        slug VARCHAR(64) NOT NULL,
        name VARCHAR(160) NOT NULL,
        description TEXT NULL,
        access_mode VARCHAR(32) NOT NULL,
        registration_mode VARCHAR(32) NOT NULL,
        account_selection_mode VARCHAR(16) NOT NULL,
        unique_identity_factors TEXT NOT NULL,
        is_active INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_applications_organization_slug (organization_id, slug),
        INDEX idx_applications_organization_active (organization_id, is_active, name)
    )",
    "CREATE TABLE IF NOT EXISTS application_auth_domains (
        id VARCHAR(64) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL UNIQUE,
        assurance_policy VARCHAR(64) NOT NULL DEFAULT 'default',
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE INDEX idx_application_auth_domains_active ON application_auth_domains(application_id, is_active)",
    "CREATE TABLE IF NOT EXISTS application_client_bindings (
        application_id VARCHAR(64) NOT NULL,
        client_db_id VARCHAR(64) NOT NULL UNIQUE,
        protocol VARCHAR(64) NOT NULL,
        authorization_profile_id VARCHAR(64) NOT NULL DEFAULT 'default',
        auth_domain_id VARCHAR(64) NOT NULL,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, client_db_id),
        INDEX idx_application_client_bindings_application (application_id, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS application_auth_contexts (
        id VARCHAR(64) PRIMARY KEY,
        auth_domain_id VARCHAR(128) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        acr VARCHAR(255) NOT NULL,
        amr TEXT NOT NULL,
        authenticated_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        revoked_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_application_auth_contexts_lookup (auth_domain_id, user_id, expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS application_enrollment_codes (
        application_id VARCHAR(64) NOT NULL,
        invitation_id VARCHAR(64) NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, invitation_id),
        UNIQUE KEY uq_application_enrollment_invitation (invitation_id),
        INDEX idx_application_enrollment_codes_application (application_id, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS application_members (
        application_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        role VARCHAR(64) NOT NULL,
        is_active INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, user_id),
        INDEX idx_application_members_user (user_id, application_id, is_active)
    )",
    "CREATE TABLE IF NOT EXISTS application_identity_bindings (
        application_id VARCHAR(64) NOT NULL,
        factor_type VARCHAR(16) NOT NULL,
        factor_digest VARCHAR(128) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, factor_type, factor_digest),
        INDEX idx_application_identity_bindings_user (application_id, user_id)
    )",
    "CREATE TABLE IF NOT EXISTS application_modules (
        application_id VARCHAR(255) NOT NULL,
        module_key VARCHAR(128) NOT NULL,
        config_json TEXT NOT NULL,
        is_enabled INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, module_key),
        INDEX idx_application_modules_application (application_id, module_key)
    )",
    "CREATE TABLE IF NOT EXISTS application_billing_settings (
        application_id VARCHAR(64) PRIMARY KEY,
        accept_signet_balance INT NOT NULL DEFAULT 0,
        wallet_mode VARCHAR(16) NOT NULL DEFAULT 'shared',
        supported_currencies TEXT NOT NULL,
        mode_locked_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS wallet_accounts (
        id VARCHAR(64) PRIMARY KEY,
        account_kind VARCHAR(32) NOT NULL,
        scope_key VARCHAR(512) NOT NULL UNIQUE,
        user_id VARCHAR(64) NULL,
        application_id VARCHAR(64) NULL,
        currency VARCHAR(3) NOT NULL,
        available_minor BIGINT NOT NULL DEFAULT 0,
        reserved_minor BIGINT NOT NULL DEFAULT 0,
        version BIGINT NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_wallet_accounts_user (user_id, currency, account_kind),
        INDEX idx_wallet_accounts_application (application_id, currency, account_kind)
    )",
    "CREATE TABLE IF NOT EXISTS wallet_transactions (
        id VARCHAR(64) PRIMARY KEY,
        kind VARCHAR(32) NOT NULL,
        status VARCHAR(32) NOT NULL,
        user_id VARCHAR(64) NULL,
        application_id VARCHAR(64) NULL,
        currency VARCHAR(3) NOT NULL,
        amount_minor BIGINT NOT NULL,
        source_wallet_id VARCHAR(64) NULL,
        destination_wallet_id VARCHAR(64) NULL,
        hold_id VARCHAR(64) NULL,
        idempotency_key VARCHAR(255) NOT NULL,
        external_provider VARCHAR(128) NULL,
        external_order_id VARCHAR(255) NULL,
        metadata TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_wallet_transaction_operation (kind, idempotency_key),
        INDEX idx_wallet_transactions_user (user_id, created_at),
        INDEX idx_wallet_transactions_application (application_id, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS wallet_entries (
        id VARCHAR(64) PRIMARY KEY,
        transaction_id VARCHAR(64) NOT NULL,
        wallet_id VARCHAR(64) NOT NULL,
        available_delta_minor BIGINT NOT NULL,
        reserved_delta_minor BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_wallet_entries_wallet (wallet_id, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS wallet_holds (
        id VARCHAR(64) PRIMARY KEY,
        hold_kind VARCHAR(32) NOT NULL,
        wallet_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NULL,
        application_id VARCHAR(64) NULL,
        currency VARCHAR(3) NOT NULL,
        amount_minor BIGINT NOT NULL,
        status VARCHAR(32) NOT NULL,
        reference VARCHAR(255) NOT NULL,
        idempotency_key VARCHAR(255) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_wallet_hold_operation (hold_kind, idempotency_key),
        INDEX idx_wallet_holds_wallet (wallet_id, status, expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS payment_orders (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        provider_slug VARCHAR(128) NOT NULL,
        merchant_order_no VARCHAR(255) NOT NULL,
        idempotency_key VARCHAR(255) NULL,
        provider_trade_id VARCHAR(255) NULL,
        currency VARCHAR(3) NOT NULL,
        amount_minor BIGINT NOT NULL,
        subject VARCHAR(255) NOT NULL,
        status VARCHAR(32) NOT NULL,
        checkout_kind VARCHAR(32) NOT NULL,
        checkout_value TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        paid_at BIGINT NULL,
        last_error TEXT NULL,
        lease_owner VARCHAR(128) NULL,
        lease_expires_at BIGINT NULL,
        lease_generation BIGINT NOT NULL DEFAULT 0,
        attempt_count BIGINT NOT NULL DEFAULT 0,
        next_retry_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_payment_order_merchant (provider_slug, merchant_order_no),
        INDEX idx_payment_orders_user (user_id, created_at),
        INDEX idx_payment_orders_status (status, expires_at),
        INDEX idx_payment_orders_reconcile (status, next_retry_at, lease_expires_at, updated_at)
    )",
    "ALTER TABLE payment_orders ADD COLUMN idempotency_key VARCHAR(255) NULL",
    "ALTER TABLE payment_orders ADD COLUMN lease_owner VARCHAR(128) NULL",
    "ALTER TABLE payment_orders ADD COLUMN lease_expires_at BIGINT NULL",
    "ALTER TABLE payment_orders ADD COLUMN lease_generation BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE payment_orders ADD COLUMN attempt_count BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE payment_orders ADD COLUMN next_retry_at BIGINT NULL",
    "CREATE UNIQUE INDEX uq_payment_orders_idempotency ON payment_orders(user_id, provider_slug, idempotency_key)",
    "CREATE TABLE IF NOT EXISTS payment_refunds (
        id VARCHAR(64) PRIMARY KEY,
        payment_order_id VARCHAR(64) NOT NULL,
        amount_minor BIGINT NOT NULL,
        status VARCHAR(32) NOT NULL,
        provider_refund_id VARCHAR(255) NULL,
        requested_by VARCHAR(64) NULL,
        reason VARCHAR(512) NOT NULL,
        idempotency_key VARCHAR(255) NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_payment_refunds_order (payment_order_id, created_at)
    )",
    "ALTER TABLE payment_refunds ADD COLUMN idempotency_key VARCHAR(255) NOT NULL DEFAULT ''",
    "CREATE TABLE IF NOT EXISTS application_scim_tokens (
        id VARCHAR(64) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        token_prefix VARCHAR(32) NOT NULL,
        token_hash VARCHAR(128) NOT NULL UNIQUE,
        scopes TEXT NOT NULL,
        expires_at BIGINT NULL,
        revoked_at BIGINT NULL,
        last_used_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_application_scim_tokens_application (application_id, revoked_at, created_at)
    )",
    "CREATE TABLE IF NOT EXISTS application_scim_groups (
        application_id VARCHAR(64) NOT NULL,
        group_id VARCHAR(64) NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, group_id)
    )",
    "CREATE INDEX idx_application_scim_groups_group ON application_scim_groups(group_id, application_id)",
    "CREATE TABLE IF NOT EXISTS directory_sync_runs (
        id VARCHAR(64) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        provider_id VARCHAR(64) NOT NULL,
        status VARCHAR(32) NOT NULL,
        total_seen BIGINT NOT NULL DEFAULT 0,
        created_count BIGINT NOT NULL DEFAULT 0,
        updated_count BIGINT NOT NULL DEFAULT 0,
        disabled_count BIGINT NOT NULL DEFAULT 0,
        error TEXT NULL,
        cursor TEXT NULL,
        started_at BIGINT NOT NULL,
        finished_at BIGINT NULL,
        INDEX idx_directory_sync_runs_application (application_id, started_at)
    )",
    "CREATE TABLE IF NOT EXISTS directory_sync_leases (
        application_id VARCHAR(64) NOT NULL,
        provider_id VARCHAR(64) NOT NULL,
        owner_run_id VARCHAR(64) NOT NULL UNIQUE,
        acquired_at BIGINT NOT NULL,
        heartbeat_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, provider_id),
        INDEX idx_directory_sync_leases_expiry (expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS directory_sync_checkpoints (
        application_id VARCHAR(64) NOT NULL,
        provider_id VARCHAR(64) NOT NULL,
        cursor TEXT NULL,
        last_success_at BIGINT NOT NULL,
        consecutive_failures INT NOT NULL DEFAULT 0,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, provider_id)
    )",
    "CREATE TABLE IF NOT EXISTS directory_sync_memberships (
        application_id VARCHAR(64) NOT NULL,
        provider_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        managed INT NOT NULL DEFAULT 1,
        last_seen_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, provider_id, user_id),
        INDEX idx_directory_sync_memberships_user (user_id, managed)
    )",
    "CREATE TABLE IF NOT EXISTS directory_sync_groups (
        application_id VARCHAR(64) NOT NULL,
        provider_id VARCHAR(64) NOT NULL,
        external_id VARCHAR(255) NOT NULL,
        group_id VARCHAR(64) NOT NULL,
        last_seen_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, provider_id, external_id),
        INDEX idx_directory_sync_groups_group (group_id)
    )",
    "CREATE TABLE IF NOT EXISTS application_roles (
        id VARCHAR(64) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        name VARCHAR(128) NOT NULL,
        description TEXT NULL,
        permissions TEXT NOT NULL,
        is_default INT NOT NULL DEFAULT 0,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_application_roles_application_name (application_id, name),
        INDEX idx_application_roles_application (application_id, is_active, name)
    )",
    "CREATE TABLE IF NOT EXISTS application_user_roles (
        application_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        application_role_id VARCHAR(64) NOT NULL,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, user_id, application_role_id),
        INDEX idx_application_user_roles_user (application_id, user_id, is_active)
    )",
    "CREATE TABLE IF NOT EXISTS application_group_roles (
        application_id VARCHAR(64) NOT NULL,
        group_id VARCHAR(64) NOT NULL,
        application_role_id VARCHAR(64) NOT NULL,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, group_id, application_role_id),
        INDEX idx_application_group_roles_group (application_id, group_id, is_active)
    )",
    "CREATE TABLE IF NOT EXISTS application_organization_role_mappings (
        application_id VARCHAR(64) NOT NULL,
        organization_role VARCHAR(64) NOT NULL,
        application_role_id VARCHAR(64) NOT NULL,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, organization_role, application_role_id),
        INDEX idx_application_org_role_mappings_role (application_id, organization_role, is_active)
    )",
    "CREATE TABLE IF NOT EXISTS application_user_permission_overrides (
        application_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        permission VARCHAR(128) NOT NULL,
        effect VARCHAR(16) NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (application_id, user_id, permission),
        INDEX idx_application_permission_overrides_user (application_id, user_id, effect)
    )",
    "CREATE TABLE IF NOT EXISTS application_authorization_profiles (
        id VARCHAR(64) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        profile_key VARCHAR(255) NOT NULL,
        connection_kind VARCHAR(32) NOT NULL,
        connection_id VARCHAR(255) NULL,
        source_mode VARCHAR(32) NOT NULL,
        remote_version VARCHAR(255) NULL,
        remote_digest VARCHAR(128) NULL,
        sync_status VARCHAR(32) NOT NULL DEFAULT 'manual',
        last_synced_at BIGINT NULL,
        last_error TEXT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_application_auth_profile (application_id, profile_key),
        INDEX idx_application_auth_profiles_application (application_id, profile_key)
    )",
    "CREATE TABLE IF NOT EXISTS application_authorization_migration_state (
        application_id VARCHAR(64) PRIMARY KEY,
        migrated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS application_permission_definitions (
        profile_id VARCHAR(64) NOT NULL,
        permission_key VARCHAR(256) NOT NULL,
        label VARCHAR(160) NOT NULL,
        description TEXT NULL,
        source VARCHAR(32) NOT NULL,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, permission_key),
        INDEX idx_application_permission_definitions_profile (profile_id, is_active, permission_key)
    )",
    "CREATE TABLE IF NOT EXISTS application_profile_roles (
        id VARCHAR(64) PRIMARY KEY,
        profile_id VARCHAR(64) NOT NULL,
        role_key VARCHAR(128) NOT NULL,
        name VARCHAR(160) NOT NULL,
        description TEXT NULL,
        permissions TEXT NOT NULL,
        source VARCHAR(32) NOT NULL,
        is_default INT NOT NULL DEFAULT 0,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_application_profile_role (profile_id, role_key),
        INDEX idx_application_profile_roles_profile (profile_id, is_active, role_key)
    )",
    "CREATE TABLE IF NOT EXISTS application_profile_user_roles (
        profile_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        role_id VARCHAR(64) NOT NULL,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, user_id, role_id),
        INDEX idx_application_profile_user_roles_user (profile_id, user_id, is_active)
    )",
    "CREATE TABLE IF NOT EXISTS application_profile_group_roles (
        profile_id VARCHAR(64) NOT NULL,
        group_id VARCHAR(64) NOT NULL,
        role_id VARCHAR(64) NOT NULL,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, group_id, role_id),
        INDEX idx_application_profile_group_roles_group (profile_id, group_id, is_active)
    )",
    "CREATE TABLE IF NOT EXISTS application_profile_organization_roles (
        profile_id VARCHAR(64) NOT NULL,
        organization_role VARCHAR(64) NOT NULL,
        role_id VARCHAR(64) NOT NULL,
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, organization_role, role_id),
        INDEX idx_application_profile_org_roles_role (profile_id, organization_role, is_active)
    )",
    "CREATE TABLE IF NOT EXISTS application_profile_permission_overrides (
        profile_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        permission VARCHAR(256) NOT NULL,
        effect VARCHAR(16) NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (profile_id, user_id, permission),
        INDEX idx_application_profile_permission_overrides_user (profile_id, user_id, effect)
    )",
    "CREATE TABLE IF NOT EXISTS application_discovery (
        application_id VARCHAR(64) PRIMARY KEY,
        management_mode VARCHAR(32) NOT NULL DEFAULT 'signet_managed',
        website_url VARCHAR(2048) NOT NULL,
        fetch_secret_ciphertext TEXT NOT NULL,
        signing_public_jwks LONGTEXT NOT NULL,
        last_verified_revision BIGINT NULL,
        last_verified_version VARCHAR(255) NULL,
        last_verified_digest VARCHAR(128) NULL,
        last_verified_expires_at BIGINT NULL,
        sync_status VARCHAR(32) NOT NULL DEFAULT 'unconfigured',
        last_fetched_at BIGINT NULL,
        last_success_at BIGINT NULL,
        last_error TEXT NULL,
        snapshot_json LONGTEXT NULL,
        operator_disabled INT NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        lease_owner VARCHAR(128) NULL,
        lease_expires_at BIGINT NULL,
        lease_generation BIGINT NOT NULL DEFAULT 0,
        INDEX idx_application_discovery_mode_status (management_mode, sync_status)
    )",
    "ALTER TABLE application_discovery ADD COLUMN lease_owner VARCHAR(128) NULL",
    "ALTER TABLE application_discovery ADD COLUMN lease_expires_at BIGINT NULL",
    "ALTER TABLE application_discovery ADD COLUMN lease_generation BIGINT NOT NULL DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS application_discovery_idempotency (
        organization_id VARCHAR(64) NOT NULL,
        idempotency_key VARCHAR(128) NOT NULL,
        request_hash VARCHAR(128) NOT NULL,
        origin VARCHAR(2048) NOT NULL,
        application_id VARCHAR(64) NULL,
        claim_token VARCHAR(128) NOT NULL,
        status VARCHAR(32) NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (organization_id, idempotency_key),
        INDEX idx_application_discovery_idempotency_updated (status, updated_at)
    )",
    "CREATE TABLE IF NOT EXISTS iap_applications (
        id VARCHAR(64) PRIMARY KEY,
        slug VARCHAR(128) NOT NULL UNIQUE,
        name VARCHAR(160) NOT NULL,
        description TEXT NULL,
        external_host VARCHAR(255) NOT NULL,
        path_prefix VARCHAR(2048) NOT NULL,
        required_organization_id VARCHAR(64) NULL,
        required_organization_roles TEXT NOT NULL,
        required_permissions TEXT NOT NULL,
        is_active INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_iap_applications_match (is_active, external_host, path_prefix(255))
    )",
    "ALTER TABLE iap_applications ADD COLUMN application_id VARCHAR(64) NULL",
    "CREATE INDEX idx_iap_applications_application ON iap_applications(application_id, is_active)",
    "CREATE TABLE IF NOT EXISTS linked_identities (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        provider_slug VARCHAR(255) NOT NULL,
        external_subject VARCHAR(255) NOT NULL,
        external_email VARCHAR(255) NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_linked_identity (provider_slug, external_subject)
    )",
    "CREATE INDEX idx_linked_identities_user ON linked_identities(user_id)",
    "CREATE TABLE IF NOT EXISTS ldap_providers (
        id VARCHAR(64) PRIMARY KEY,
        slug VARCHAR(255) NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        organization_id VARCHAR(64) NULL,
        url TEXT NOT NULL,
        starttls INT NOT NULL,
        bind_dn TEXT NOT NULL,
        bind_password TEXT NOT NULL,
        base_dn TEXT NOT NULL,
        user_filter TEXT NOT NULL,
        user_id_attribute VARCHAR(128) NOT NULL,
        email_attribute VARCHAR(128) NOT NULL,
        username_attribute VARCHAR(128) NOT NULL,
        display_name_attribute VARCHAR(128) NOT NULL,
        phone_attribute VARCHAR(128) NOT NULL,
        is_active INT NOT NULL,
        allow_login INT NOT NULL,
        allow_registration INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE ldap_providers ADD COLUMN organization_id VARCHAR(64) NULL",
    "CREATE INDEX idx_ldap_providers_organization ON ldap_providers(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS external_oidc_providers (
        id VARCHAR(64) PRIMARY KEY,
        slug VARCHAR(255) NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        organization_id VARCHAR(64) NULL,
        issuer TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        authorization_endpoint TEXT NOT NULL,
        token_endpoint TEXT NOT NULL,
        userinfo_endpoint TEXT NOT NULL,
        redirect_path TEXT NOT NULL,
        scopes TEXT NOT NULL,
        email_domains TEXT NOT NULL,
        is_active INT NOT NULL,
        allow_login INT NOT NULL DEFAULT 1,
        allow_registration INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE external_oidc_providers ADD COLUMN organization_id VARCHAR(64) NULL",
    "ALTER TABLE external_oidc_providers ADD COLUMN email_domains TEXT NULL",
    "ALTER TABLE external_oidc_providers ADD COLUMN allow_login INT NOT NULL DEFAULT 1",
    "CREATE INDEX idx_external_oidc_providers_organization ON external_oidc_providers(organization_id, is_active)",
    "CREATE TABLE IF NOT EXISTS external_oidc_states (
        state VARCHAR(128) PRIMARY KEY,
        provider_slug VARCHAR(255) NOT NULL,
        nonce VARCHAR(128) NOT NULL,
        return_to TEXT NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS login_settings (
        id VARCHAR(32) PRIMARY KEY,
        brand_logo_url VARCHAR(2048) NOT NULL,
        email_domains TEXT NOT NULL,
        quick_links TEXT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE login_settings ADD COLUMN brand_logo_url VARCHAR(2048) NOT NULL DEFAULT ''",
    "CREATE TABLE IF NOT EXISTS application_jwt_codes (
        code_hash VARCHAR(128) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        redirect_uri TEXT NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        nonce VARCHAR(255) NULL,
        code_challenge VARCHAR(255) NULL,
        code_challenge_method VARCHAR(32) NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        created_at BIGINT NOT NULL
    )",
    "CREATE INDEX idx_application_jwt_codes_application_expires ON application_jwt_codes(application_id, expires_at)",
    "CREATE TABLE IF NOT EXISTS application_jwt_clients (
        id VARCHAR(64) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        client_type VARCHAR(32) NOT NULL DEFAULT 'public',
        is_active INT NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE KEY uq_application_jwt_clients_application_client (application_id, client_id),
        INDEX idx_application_jwt_clients_application (application_id, is_active)
    )",
    "CREATE TABLE IF NOT EXISTS application_jwt_client_secrets (
        id VARCHAR(64) PRIMARY KEY,
        jwt_client_id VARCHAR(64) NOT NULL,
        secret_hash VARCHAR(512) NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NULL,
        revoked_at BIGINT NULL,
        INDEX idx_application_jwt_client_secrets_active (jwt_client_id, revoked_at, expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS application_saml_replays (
        replay_key VARCHAR(255) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_application_saml_replays_expiry (expires_at, application_id)
    )",
    "CREATE TABLE IF NOT EXISTS application_saml_interactions (
        handle_hash VARCHAR(128) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        request_id VARCHAR(255) NOT NULL,
        sp_entity_id TEXT NOT NULL,
        acs_url TEXT NOT NULL,
        relay_state VARCHAR(80) NULL,
        response_binding VARCHAR(64) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_application_saml_interactions_expiry (expires_at, application_id)
    )",
    "CREATE TABLE IF NOT EXISTS application_saml_sessions (
        session_index_hash VARCHAR(128) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        signet_session_id VARCHAR(64) NOT NULL,
        name_id_hash VARCHAR(128) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_application_saml_sessions_lookup (application_id, name_id_hash, expires_at),
        INDEX idx_application_saml_sessions_signet_session (signet_session_id)
    )",
    "CREATE TABLE IF NOT EXISTS application_cas_tickets (
        ticket_hash VARCHAR(128) PRIMARY KEY,
        application_id VARCHAR(64) NOT NULL,
        ticket_type VARCHAR(32) NOT NULL,
        service TEXT NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        parent_ticket_hash VARCHAR(128) NULL,
        pgt_iou VARCHAR(128) NULL,
        expires_at BIGINT NOT NULL,
        consumed_at BIGINT NULL,
        revoked_at BIGINT NULL,
        created_at BIGINT NOT NULL,
        INDEX idx_application_cas_tickets_application (application_id, ticket_type, expires_at),
        INDEX idx_application_cas_tickets_user (application_id, user_id, revoked_at)
    )",
    "ALTER TABLE application_jwt_codes ADD COLUMN client_id VARCHAR(255) NOT NULL DEFAULT ''",
    "CREATE INDEX idx_authorization_codes_client ON authorization_codes(client_id)",
    "CREATE INDEX idx_authorization_codes_application ON authorization_codes(application_id)",
    "CREATE INDEX idx_authorization_codes_user ON authorization_codes(user_id)",
    "CREATE INDEX idx_refresh_tokens_client ON refresh_tokens(client_id)",
    "CREATE INDEX idx_refresh_tokens_application ON refresh_tokens(application_id)",
    "CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id)",
    "CREATE INDEX idx_oidc_login_grants_invitation ON oidc_login_grants(invitation_id)",
    "CREATE INDEX idx_invitation_redemptions_invitation ON invitation_redemptions(invitation_id)",
    "CREATE INDEX idx_device_authorizations_user ON device_authorizations(authorized_user_id)",
    "CREATE INDEX idx_wallet_transactions_source ON wallet_transactions(source_wallet_id)",
    "CREATE INDEX idx_wallet_transactions_destination ON wallet_transactions(destination_wallet_id)",
    "CREATE INDEX idx_wallet_holds_application ON wallet_holds(application_id)",
    "CREATE INDEX idx_application_group_roles_subject ON application_group_roles(group_id)",
    "CREATE INDEX idx_application_profile_group_roles_subject ON application_profile_group_roles(group_id)",
    "CREATE INDEX idx_application_saml_replays_application ON application_saml_replays(application_id, expires_at)",
    "CREATE INDEX idx_application_saml_interactions_application ON application_saml_interactions(application_id, expires_at)",
    "CREATE INDEX idx_application_discovery_idempotency_application ON application_discovery_idempotency(organization_id, application_id)",
];
