use crate::{
    access::Permission,
    config::{DatabaseKind, DatabaseSettings, Settings},
    error::{AppError, AppResult},
    organizations::OrganizationEmailPolicy,
    util,
};
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
};

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

macro_rules! latest_verification_code {
    ($conn:expr, $kind:expr, $claim:expr) => {{
        let claim = $claim;
        sql_query(select_latest_verification_code_sql($kind))
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
        sql_query(increment_verification_attempts_sql($kind))
            .bind::<Text, _>($id)
            .execute($conn)
            .map_err(AppError::from)?
    }};
}

macro_rules! mark_verification_code_consumed {
    ($conn:expr, $kind:expr, $now:expr, $id:expr) => {{
        sql_query(consume_verification_code_sql($kind))
            .bind::<BigInt, _>($now)
            .bind::<Text, _>($id)
            .execute($conn)
            .map_err(AppError::from)?
    }};
}

const USER_AUTH_STATE_TABLES: &[(&str, &str)] = &[
    ("sessions", "user_id"),
    ("authorization_codes", "user_id"),
    ("oidc_login_grants", "user_id"),
    ("refresh_tokens", "user_id"),
    ("device_authorizations", "authorized_user_id"),
    ("webauthn_challenges", "user_id"),
];

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

#[derive(Debug, Clone, Copy)]
pub enum UserListScope {
    Live,
    Active,
    Disabled,
    Archived,
    AuthorizationCode,
    All,
}

impl UserListScope {
    fn where_sql(self) -> &'static str {
        match self {
            UserListScope::Live => "WHERE archived_at IS NULL",
            UserListScope::Active => "WHERE archived_at IS NULL AND is_active = 1",
            UserListScope::Disabled => "WHERE archived_at IS NULL AND is_active = 0",
            UserListScope::Archived => "WHERE archived_at IS NOT NULL",
            UserListScope::AuthorizationCode => "WHERE registration_source = 'authorization_code'",
            UserListScope::All => "",
        }
    }

    fn order_sql(self) -> &'static str {
        match self {
            UserListScope::Archived => "archived_at DESC, created_at DESC",
            UserListScope::AuthorizationCode | UserListScope::All => {
                "archived_at IS NOT NULL ASC, is_active DESC, created_at DESC"
            }
            UserListScope::Live | UserListScope::Active | UserListScope::Disabled => {
                "is_active DESC, created_at DESC"
            }
        }
    }
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
pub struct PushedAuthorizationRequestRecord {
    #[diesel(sql_type = Text)]
    pub request_uri_hash: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub request_json: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewPushedAuthorizationRequest {
    pub request_uri_hash: String,
    pub client_id: String,
    pub request_json: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct DeviceAuthorizationRecord {
    #[diesel(sql_type = Text)]
    pub device_code_hash: String,
    #[diesel(sql_type = Text)]
    pub user_code_hash: String,
    #[diesel(sql_type = Text)]
    pub user_code_display: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub scope: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub resource: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorization_details: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Integer)]
    pub interval_seconds: i32,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorized_user_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub authorized_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub denied_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_poll_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewDeviceAuthorization {
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub user_code_display: String,
    pub client_id: String,
    pub scope: String,
    pub resource: Option<String>,
    pub authorization_details: Option<String>,
    pub expires_at: i64,
    pub interval_seconds: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct RefreshTokenRecord {
    #[diesel(sql_type = Text)]
    pub token_hash: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
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
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct UserConsentRecord {
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
pub struct UserConsentWithClientRecord {
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

#[derive(Debug, Clone, Copy, Serialize)]
pub struct LoginFailureSummary {
    pub count: i64,
    pub latest_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct CaptchaChallengeRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub subject: String,
    #[diesel(sql_type = Text)]
    pub prompt: String,
    #[diesel(sql_type = Text)]
    pub answer_hash: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
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

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct VerificationCodeRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub channel: String,
    #[diesel(sql_type = Text)]
    pub target: String,
    #[diesel(sql_type = Text)]
    pub purpose: String,
    #[diesel(sql_type = Text)]
    pub code_hash: String,
    #[diesel(sql_type = Integer)]
    pub attempts: i32,
    #[diesel(sql_type = Integer)]
    pub max_attempts: i32,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewVerificationCode<'a> {
    pub channel: &'a str,
    pub target: &'a str,
    pub purpose: &'a str,
    pub code_hash: String,
    pub ttl_seconds: i64,
    pub resend_interval_seconds: i64,
    pub max_attempts: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerificationCodeDecision {
    Accepted(String),
    RejectedAttempt(String),
}

trait VerificationCodeVerifier {
    fn verify_hash(&self, code_hash: &str, now: i64) -> AppResult<VerificationCodeDecision>;
}

impl VerificationCodeVerifier for VerificationCodeRecord {
    fn verify_hash(&self, code_hash: &str, now: i64) -> AppResult<VerificationCodeDecision> {
        if self.expires_at < now {
            return Err(AppError::BadRequest(
                "verification code expired".to_string(),
            ));
        }
        if self.attempts >= self.max_attempts {
            return Err(AppError::BadRequest(
                "verification code attempts exceeded".to_string(),
            ));
        }
        if self.code_hash != code_hash {
            return Ok(VerificationCodeDecision::RejectedAttempt(self.id.clone()));
        }
        Ok(VerificationCodeDecision::Accepted(self.id.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct VerificationCodeClaim {
    pub channel: String,
    pub target: String,
    pub purpose: String,
    pub code: String,
}

impl VerificationCodeClaim {
    pub fn new(channel: &str, target: &str, purpose: &str, code: &str) -> Self {
        Self {
            channel: channel.to_string(),
            target: target.to_string(),
            purpose: purpose.to_string(),
            code: code.trim().to_string(),
        }
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
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct OrganizationRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub name: String,
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

#[derive(Debug, Clone)]
pub struct NewGroup {
    pub name: String,
    pub description: Option<String>,
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
struct LoginFailureSummaryRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    latest_at: Option<i64>,
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

async fn blocking<T>(f: impl FnOnce() -> AppResult<T> + Send + 'static) -> AppResult<T>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| AppError::Internal(err.to_string()))?
}

fn ph(kind: DatabaseKind, index: usize) -> String {
    match kind {
        DatabaseKind::Postgres => format!("${index}"),
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "?".to_string(),
    }
}

fn select_user_sql() -> &'static str {
    "SELECT id, email, username, display_name, phone, password_hash, email_verified_at, phone_verified_at, is_admin, is_active, archived_at, registration_source, last_login_at, last_login_ip, last_oidc_client_id, last_login_method, created_at, updated_at FROM users"
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

fn select_ldap_provider_sql() -> &'static str {
    "SELECT id, slug, display_name, url, starttls, bind_dn, bind_password, base_dn, user_filter, user_id_attribute, email_attribute, username_attribute, display_name_attribute, phone_attribute, is_active, allow_login, allow_registration, created_at, updated_at FROM ldap_providers"
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

fn count_linked_identity_sql(kind: DatabaseKind) -> String {
    format!(
        "SELECT COUNT(*) AS count FROM linked_identities WHERE provider_slug = {} AND external_subject = {}",
        ph(kind, 1),
        ph(kind, 2)
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
    "SELECT id, client_id, client_secret_hash, client_name, COALESCE(logo_uri, '') AS logo_uri, organization_id, redirect_uris, post_logout_redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method, require_pkce, COALESCE(require_mfa, 0) AS require_mfa, COALESCE(require_pushed_authorization_requests, 0) AS require_pushed_authorization_requests, COALESCE(require_s256_pkce, 0) AS require_s256_pkce, COALESCE(require_confidential_client, 0) AS require_confidential_client, COALESCE(require_dpop, 0) AS require_dpop, COALESCE(require_account_selection, 0) AS require_account_selection, COALESCE(trust_email_verified, 0) AS trust_email_verified, COALESCE(authorization_details_types, '[]') AS authorization_details_types, subject_type, sector_identifier_uri, COALESCE(jwks_uri, '') AS jwks_uri, COALESCE(jwks, '') AS jwks, COALESCE(backchannel_logout_uri, '') AS backchannel_logout_uri, COALESCE(backchannel_logout_session_required, 0) AS backchannel_logout_session_required, COALESCE(frontchannel_logout_uri, '') AS frontchannel_logout_uri, COALESCE(frontchannel_logout_session_required, 0) AS frontchannel_logout_session_required, COALESCE(service_account_enabled, 0) AS service_account_enabled, COALESCE(service_account_permissions, '[]') AS service_account_permissions, is_active, created_at, updated_at FROM clients"
}

fn select_client_claim_mapper_sql() -> &'static str {
    "SELECT id, client_db_id, claim_name, source, source_value, value_type, include_in_id_token, include_in_access_token, include_in_userinfo, is_active, sort_order, created_at, updated_at FROM client_claim_mappers"
}

fn select_iap_application_sql() -> &'static str {
    "SELECT id, slug, name, description, external_host, path_prefix, required_organization_id, required_organization_roles, required_permissions, is_active, created_at, updated_at FROM iap_applications"
}

fn select_device_authorization_sql() -> &'static str {
    "SELECT device_code_hash, user_code_hash, user_code_display, client_id, scope, resource, authorization_details, expires_at, interval_seconds, authorized_user_id, authorized_at, denied_at, consumed_at, last_poll_at, created_at FROM device_authorizations"
}

fn select_external_oidc_provider_sql() -> &'static str {
    "SELECT id, slug, display_name, organization_id, issuer, client_id, client_secret, authorization_endpoint, token_endpoint, userinfo_endpoint, redirect_path, scopes, COALESCE(email_domains, '[]') AS email_domains, is_active, COALESCE(allow_login, 1) AS allow_login, allow_registration, created_at, updated_at FROM external_oidc_providers"
}

fn select_pushed_authorization_request_sql() -> &'static str {
    "SELECT request_uri_hash, client_id, request_json, expires_at, consumed_at, created_at FROM pushed_authorization_requests"
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

fn select_verification_code_sql() -> &'static str {
    "SELECT id, channel, target, purpose, code_hash, attempts, max_attempts, expires_at, consumed_at, created_at FROM verification_codes"
}

fn select_passkey_sql() -> &'static str {
    "SELECT id, user_id, credential_id, name, passkey_json, last_used_at, created_at, updated_at FROM passkeys"
}

fn select_webauthn_challenge_sql() -> &'static str {
    "SELECT id, user_id, purpose, state_json, expires_at, consumed_at, created_at FROM webauthn_challenges"
}

fn select_verification_code_by_id_sql(kind: DatabaseKind) -> String {
    format!(
        "{} WHERE id = {}",
        select_verification_code_sql(),
        ph(kind, 1)
    )
}

fn select_latest_verification_code_sql(kind: DatabaseKind) -> String {
    format!(
        "{} WHERE channel = {} AND target = {} AND purpose = {} AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1",
        select_verification_code_sql(),
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3)
    )
}

fn select_latest_verification_issue_sql(kind: DatabaseKind) -> String {
    format!(
        "{} WHERE channel = {} AND target = {} AND purpose = {} ORDER BY created_at DESC LIMIT 1",
        select_verification_code_sql(),
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3)
    )
}

fn ensure_verification_resend_allowed(
    latest: Option<&VerificationCodeRecord>,
    now: i64,
    resend_interval_seconds: i64,
) -> AppResult<()> {
    let Some(latest) = latest else {
        return Ok(());
    };
    let retry_at = latest.created_at + resend_interval_seconds;
    if retry_at > now {
        return Err(AppError::BadRequest(format!(
            "verification code was sent too recently; retry after {} seconds",
            retry_at - now
        )));
    }
    Ok(())
}

fn increment_verification_attempts_sql(kind: DatabaseKind) -> String {
    format!(
        "UPDATE verification_codes SET attempts = attempts + 1 WHERE id = {}",
        ph(kind, 1)
    )
}

fn consume_verification_code_sql(kind: DatabaseKind) -> String {
    format!(
        "UPDATE verification_codes SET consumed_at = {} WHERE id = {} AND consumed_at IS NULL",
        ph(kind, 1),
        ph(kind, 2)
    )
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
    "SELECT id, slug, name, description, COALESCE(allowed_email_domains, '[]') AS allowed_email_domains, is_active, created_at, updated_at FROM organizations"
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

impl Db {
    pub fn connect(settings: &Settings) -> AppResult<Self> {
        match settings.database.kind {
            DatabaseKind::Sqlite => connect_sqlite(&settings.database),
            DatabaseKind::Postgres => connect_postgres(&settings.database),
            DatabaseKind::Mysql => connect_mysql(&settings.database),
        }
    }

    pub async fn ping(&self) -> AppResult<()> {
        with_conn!(self, |conn, _kind| {
            conn.batch_execute("SELECT 1")
                .map_err(|err| AppError::Database(err.to_string()))
        })
    }

    pub async fn migrate(&self) -> AppResult<()> {
        with_conn!(self, |conn, kind| {
            for statement in migration_sql(kind) {
                if let Err(err) = conn.batch_execute(statement) {
                    let message = err.to_string();
                    if !is_ignorable_migration_error(statement, &message) {
                        return Err(AppError::Database(message));
                    }
                }
            }
            Ok(())
        })?;
        self.remove_legacy_phone_uniqueness().await?;
        with_conn!(self, |conn, kind| {
            // This data repair is deliberately outside the static migration
            // arrays: those arrays run on every startup and MySQL keeps them
            // schema-only. The statement is idempotent and only touches
            // legacy rows which still carry the default source.
            sql_query(authorization_code_registration_source_backfill_sql(kind))
                .bind::<Text, _>(UserRegistrationSource::AuthorizationCode.as_str())
                .bind::<Text, _>(UserRegistrationSource::Local.as_str())
                .bind::<Text, _>(AuthorizationCodeType::Registration.as_str())
                .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(())
        })
    }

    /// Older installations treated phone as an identity key. Phone is now a
    /// verification contact and may legitimately be shared across accounts.
    async fn remove_legacy_phone_uniqueness(&self) -> AppResult<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(pool) => {
                let pool = pool.clone();
                blocking(move || {
                    let mut conn = pool
                        .get()
                        .map_err(|err| AppError::Database(err.to_string()))?;
                    migrate_sqlite_phone_uniqueness(&mut conn)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => {
                let pool = pool.clone();
                blocking(move || {
                    let mut conn = pool
                        .get()
                        .map_err(|err| AppError::Database(err.to_string()))?;
                    migrate_postgres_phone_uniqueness(&mut conn)
                })
                .await
            }
            #[cfg(feature = "mysql")]
            Self::Mysql(pool) => {
                let pool = pool.clone();
                blocking(move || {
                    let mut conn = pool
                        .get()
                        .map_err(|err| AppError::Database(err.to_string()))?;
                    migrate_mysql_phone_uniqueness(&mut conn)
                })
                .await
            }
        }
    }

    pub async fn seed(&self, settings: &Settings) -> AppResult<()> {
        let admin = &settings.bootstrap.admin;
        if admin.create_on_startup && self.find_user_by_email(&admin.email).await?.is_none() {
            let password_hash = util::hash_password(&admin.password)?;
            self.insert_user(NewUser {
                email: admin.email.clone(),
                username: admin.username.clone(),
                display_name: Some(admin.display_name.clone()),
                phone: None,
                password_hash,
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: true,
                is_active: true,
                archived_at: None,
            })
            .await?;
        }

        self.upsert_registration_settings(NewRegistrationSettings {
            allow_password_registration: settings.registration.allow_password_registration,
            require_email_verification: settings.registration.require_email_verification,
            require_phone_verification: settings.registration.require_phone_verification,
            allow_external_oidc_registration: settings
                .registration
                .allow_external_oidc_registration,
            require_invitation: settings.registration.require_invitation,
            first_user_direct_admin: settings.registration.first_user_direct_admin,
            default_user_active: settings.registration.default_user_active,
        })
        .await?;

        self.ensure_security_policy(NewSecurityPolicy {
            password_min_length: settings.security.password_min_length as i32,
            password_require_uppercase: false,
            password_require_lowercase: false,
            password_require_digit: false,
            password_require_symbol: false,
            password_reject_user_info: true,
            login_lockout_enabled: true,
            max_failed_login_attempts: 5,
            failure_window_seconds: 900,
            lockout_seconds: 900,
            trusted_ip_cidrs: Vec::new(),
            require_mfa_outside_trusted_networks: false,
            allowed_ip_cidrs: Vec::new(),
            blocked_ip_cidrs: Vec::new(),
            allowed_email_domains: Vec::new(),
            blocked_email_domains: Vec::new(),
            captcha_enabled: false,
            captcha_after_failed_attempts: 3,
            captcha_ttl_seconds: 300,
        })
        .await?;

        self.ensure_runtime_settings(NewRuntimeSettings {
            public_base_url: settings.server.public_base_url.clone(),
            issuer: settings.oidc.issuer.clone(),
            trust_proxy_headers: settings.server.trust_proxy_headers,
        })
        .await?;

        self.ensure_login_settings(NewLoginSettings {
            brand_logo_url: String::new(),
            email_domains: Vec::new(),
            quick_links: vec![default_openai_quick_link()],
        })
        .await?;

        self.ensure_system_roles().await?;

        for provider in &settings.external_oidc_providers {
            if self
                .find_external_oidc_provider(&provider.slug)
                .await?
                .is_none()
            {
                self.insert_external_oidc_provider(NewExternalOidcProvider {
                    slug: provider.slug.clone(),
                    display_name: provider.display_name.clone(),
                    organization_id: provider
                        .organization_id
                        .as_ref()
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    issuer: provider.issuer.clone(),
                    client_id: provider.client_id.clone(),
                    client_secret: provider.client_secret.clone(),
                    authorization_endpoint: provider.authorization_endpoint.clone(),
                    token_endpoint: provider.token_endpoint.clone(),
                    userinfo_endpoint: provider.userinfo_endpoint.clone(),
                    redirect_path: provider.redirect_path.clone(),
                    scopes: provider.scopes.clone(),
                    email_domains: crate::security_policy::normalize_email_domain_rules(
                        provider.email_domains.clone(),
                    )?,
                    is_active: provider.enabled,
                    allow_login: provider.allow_login,
                    allow_registration: provider.allow_registration,
                })
                .await?;
            }
        }

        for client in &settings.bootstrap.clients {
            if self
                .find_client_by_client_id(&client.client_id)
                .await?
                .is_none()
            {
                let client_secret_hash = if client.client_secret.is_empty() {
                    None
                } else {
                    crate::client_assertion::store_client_secret(
                        &client.token_endpoint_auth_method,
                        &client.client_secret,
                    )?
                };
                self.insert_client(NewClient {
                    client_id: client.client_id.clone(),
                    client_secret_hash,
                    client_name: client.client_name.clone(),
                    logo_uri: client.logo_uri.clone(),
                    organization_id: None,
                    redirect_uris: client.redirect_uris.clone(),
                    post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
                    scopes: client.scopes.clone(),
                    grant_types: client.grant_types.clone(),
                    response_types: client.response_types.clone(),
                    token_endpoint_auth_method: client.token_endpoint_auth_method.clone(),
                    require_pkce: client.require_pkce,
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
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn find_user_by_email(&self, email: &str) -> AppResult<Option<UserRecord>> {
        let email = email.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE email = {}", select_user_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(email)
                .get_result::<UserRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_user_by_username(&self, username: &str) -> AppResult<Option<UserRecord>> {
        let username = username.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE username = {}", select_user_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(username)
                .get_result::<UserRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_user_by_id(&self, id: &str) -> AppResult<Option<UserRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<UserRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_users(&self, scope: UserListScope) -> AppResult<Vec<UserRecord>> {
        with_conn!(self, |conn, kind| {
            let _ = kind;
            let sql = format!(
                "{} {} ORDER BY {}",
                select_user_sql(),
                scope.where_sql(),
                scope.order_sql()
            );
            sql_query(sql)
                .load::<UserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn count_users(&self, scope: UserListScope) -> AppResult<i64> {
        #[derive(diesel::QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = BigInt)]
            count: i64,
        }
        with_conn!(self, |conn, _kind| {
            let sql = if scope.where_sql().is_empty() {
                "SELECT COUNT(*) AS count FROM users".to_string()
            } else {
                format!("SELECT COUNT(*) AS count FROM users {}", scope.where_sql())
            };
            sql_query(sql)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count)
                .map_err(AppError::from)
        })
    }

    pub async fn user_count(&self) -> AppResult<i64> {
        self.count_users(UserListScope::All).await
    }

    pub async fn insert_user(&self, user: NewUser) -> AppResult<UserRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let identity = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "user email or username already exists"
                )?;
                sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(user.email)
                    .bind::<Text, _>(user.username)
                    .bind::<Nullable<Text>, _>(user.display_name)
                    .bind::<Nullable<Text>, _>(user.phone)
                    .bind::<Text, _>(user.password_hash)
                    .bind::<Nullable<BigInt>, _>(user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(user.phone_verified_at)
                    .bind::<Integer, _>(i32::from(user.is_admin))
                    .bind::<Integer, _>(i32::from(user.is_active))
                    .bind::<Nullable<BigInt>, _>(user.archived_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Inserts a complete enterprise-provisioning batch in one transaction.
    ///
    /// The method validates the identity availability and the optional
    /// organization membership inside the transaction as well as at the API
    /// preflight layer.  The second check makes a concurrent account creation
    /// fail closed: no partial users or memberships can remain from a batch.
    pub async fn insert_bulk_provisioned_users(
        &self,
        users: Vec<NewBulkProvisionedUser>,
    ) -> AppResult<Vec<UserRecord>> {
        if users.is_empty() {
            return Ok(Vec::new());
        }

        let entries = users
            .into_iter()
            .map(|entry| (uuid::Uuid::new_v4().to_string(), entry))
            .collect::<Vec<_>>();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<Vec<UserRecord>, AppError, _>(|conn| {
                let mut inserted = Vec::with_capacity(entries.len());
                for (id, entry) in &entries {
                    if entry.user.is_admin {
                        return Err(AppError::BadRequest(
                            "bulk provisioning cannot create administrators".to_string(),
                        ));
                    }
                    if entry.user.archived_at.is_some() {
                        return Err(AppError::BadRequest(
                            "bulk provisioning cannot create archived accounts".to_string(),
                        ));
                    }

                    let identity = UserIdentityCandidate::insert(&entry.user);
                    ensure_user_identity_available!(
                        conn,
                        kind,
                        identity,
                        "user email or username already exists"
                    )?;

                    let membership = match (
                        entry.organization_id.as_deref(),
                        entry.organization_role.as_deref(),
                    ) {
                        (None, None) => None,
                        (Some(_), None) => {
                            return Err(AppError::BadRequest(
                                "organization membership role is required".to_string(),
                            ));
                        }
                        (None, Some(_)) => {
                            return Err(AppError::BadRequest(
                                "organization membership requires an organization".to_string(),
                            ));
                        }
                        (Some(organization_id), Some(role)) => {
                            let role = crate::organizations::normalize_role(role)?;
                            let sql = format!(
                                "{} WHERE id = {}",
                                select_organization_sql(),
                                ph(kind, 1)
                            );
                            let organization = sql_query(sql)
                                .bind::<Text, _>(organization_id)
                                .get_result::<OrganizationRecord>(conn)
                                .optional()
                                .map_err(AppError::from)?
                                .ok_or_else(|| {
                                    AppError::BadRequest(
                                        "organization does not reference an existing organization"
                                            .to_string(),
                                    )
                                })?;
                            if organization.is_active != 1 {
                                return Err(AppError::BadRequest(
                                    "organization is inactive".to_string(),
                                ));
                            }
                            if !organization.allows_email(&entry.user.email)? {
                                return Err(AppError::BadRequest(
                                    "email is not allowed by the organization policy".to_string(),
                                ));
                            }
                            Some((organization.id, role))
                        }
                    };

                    sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                        .bind::<Text, _>(id)
                        .bind::<Text, _>(&entry.user.email)
                        .bind::<Text, _>(&entry.user.username)
                        .bind::<Nullable<Text>, _>(entry.user.display_name.clone())
                        .bind::<Nullable<Text>, _>(entry.user.phone.clone())
                        .bind::<Text, _>(&entry.user.password_hash)
                        .bind::<Nullable<BigInt>, _>(entry.user.email_verified_at)
                        .bind::<Nullable<BigInt>, _>(entry.user.phone_verified_at)
                        .bind::<Integer, _>(i32::from(entry.user.is_admin))
                        .bind::<Integer, _>(i32::from(entry.user.is_active))
                        .bind::<Nullable<BigInt>, _>(entry.user.archived_at)
                        .bind::<Nullable<BigInt>, _>(None::<i64>)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(|error| match error {
                            diesel::result::Error::DatabaseError(
                                diesel::result::DatabaseErrorKind::UniqueViolation,
                                _,
                            ) => AppError::BadRequest(
                                "user email or username already exists".to_string(),
                            ),
                            other => AppError::from(other),
                        })?;

                    if let Some((organization_id, role)) = membership {
                        let sql = format!(
                            "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3),
                            ph(kind, 4),
                            ph(kind, 5)
                        );
                        sql_query(sql)
                            .bind::<Text, _>(organization_id)
                            .bind::<Text, _>(id)
                            .bind::<Text, _>(role)
                            .bind::<BigInt, _>(now)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }

                    let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                    inserted.push(
                        sql_query(sql)
                            .bind::<Text, _>(id)
                            .get_result::<UserRecord>(conn)
                            .map_err(AppError::from)?,
                    );
                }
                Ok(inserted)
            })
        })
    }

    pub async fn insert_registered_user(
        &self,
        user: NewUser,
        expected_first_user: bool,
        verification_claims: Vec<VerificationCodeClaim>,
    ) -> AppResult<UserRecord> {
        if !verification_claims.is_empty() {
            self.verify_verification_claims(verification_claims.clone())
                .await?;
        }

        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let identity = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                ensure_first_user_registration_still_first!(conn, expected_first_user)?;
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "user email or username already exists"
                )?;

                let mut verification_code_ids = Vec::with_capacity(verification_claims.len());
                for claim in &verification_claims {
                    let code_hash = util::token_hash(&claim.code);
                    let record = latest_verification_code!(conn, kind, claim).ok_or_else(|| {
                        AppError::BadRequest("verification code is missing".to_string())
                    })?;
                    match record.verify_hash(&code_hash, now)? {
                        VerificationCodeDecision::Accepted(id) => verification_code_ids.push(id),
                        VerificationCodeDecision::RejectedAttempt(_) => {
                            return Err(AppError::BadRequest(
                                "verification code is invalid".to_string(),
                            ));
                        }
                    }
                }

                sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(user.email)
                    .bind::<Text, _>(user.username)
                    .bind::<Nullable<Text>, _>(user.display_name)
                    .bind::<Nullable<Text>, _>(user.phone)
                    .bind::<Text, _>(user.password_hash)
                    .bind::<Nullable<BigInt>, _>(user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(user.phone_verified_at)
                    .bind::<Integer, _>(i32::from(user.is_admin))
                    .bind::<Integer, _>(i32::from(user.is_active))
                    .bind::<Nullable<BigInt>, _>(user.archived_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                for verification_code_id in &verification_code_ids {
                    let affected =
                        mark_verification_code_consumed!(conn, kind, now, verification_code_id);
                    if affected == 0 {
                        return Err(AppError::BadRequest(
                            "verification code is missing".to_string(),
                        ));
                    }
                }

                let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn update_user(&self, update: UserUpdate<'_>) -> AppResult<UserRecord> {
        let UserUpdate {
            id,
            email,
            username,
            display_name,
            phone,
            is_admin,
            is_active,
        } = update;
        let id = id.to_string();
        let now = util::now_ts();
        let identity = UserIdentityCandidate::update(&id, email.clone(), username.clone());
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "user email or username already exists"
                )?;
                if !is_active {
                    clear_user_auth_state_for_conn!(conn, kind, &id)?;
                }
                let sql = format!(
                    "UPDATE users SET email = {}, username = {}, display_name = {}, phone = {}, is_admin = {}, is_active = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8)
                );
                sql_query(sql)
                    .bind::<Text, _>(email)
                    .bind::<Text, _>(username)
                    .bind::<Nullable<Text>, _>(display_name)
                    .bind::<Nullable<Text>, _>(phone)
                    .bind::<Integer, _>(i32::from(is_admin))
                    .bind::<Integer, _>(i32::from(is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn set_user_password(&self, id: &str, password_hash: String) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE users SET password_hash = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(password_hash)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn clear_user_auth_state(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            clear_user_auth_state_for_conn!(&mut conn, kind, &id)
        })
    }

    pub async fn enable_user(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE users SET is_active = {}, archived_at = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(sql)
                .bind::<Integer, _>(1)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn disable_user(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            clear_user_auth_state_for_conn!(&mut conn, kind, &id)?;
            let sql = format!(
                "UPDATE users SET is_active = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Integer, _>(0)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn archive_user(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            clear_user_auth_state_for_conn!(&mut conn, kind, &id)?;
            let sql = format!(
                "UPDATE users SET is_active = {}, archived_at = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(sql)
                .bind::<Integer, _>(0)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn permanently_delete_user(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                clear_user_auth_state_for_conn!(conn, kind, &id)?;
                for table in [
                    "user_consents",
                    "user_roles",
                    "group_members",
                    "organization_members",
                    "mfa_totp_methods",
                    "mfa_totp_setups",
                    "mfa_recovery_codes",
                    "mfa_challenges",
                    "passkeys",
                    "linked_identities",
                    "login_events",
                    "invitation_redemptions",
                    "trial_enrollments",
                ] {
                    let sql = format!("DELETE FROM {table} WHERE user_id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let invalidate_recovery_codes_sql = format!(
                    "UPDATE invitations SET is_active = 0, updated_at = {} WHERE authorized_user_id = {} AND code_type = {} AND login_code_level = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(invalidate_recovery_codes_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::AccountRecovery.as_str())
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!("DELETE FROM users WHERE id = {}", ph(kind, 1));
                let affected = sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::NotFound);
                }
                Ok(())
            })
        })
    }

    pub async fn find_client_by_client_id(
        &self,
        client_id: &str,
    ) -> AppResult<Option<ClientRecord>> {
        let client_id = client_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE client_id = {}", select_client_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(client_id)
                .get_result::<ClientRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_client_by_id(&self, id: &str) -> AppResult<Option<ClientRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ClientRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_clients(&self) -> AppResult<Vec<ClientRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!("{} ORDER BY created_at DESC", select_client_sql());
            sql_query(sql)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_backchannel_logout_clients_for_user(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<ClientRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE is_active = 1 AND COALESCE(backchannel_logout_uri, '') <> '' AND client_id IN (SELECT DISTINCT oidc_client_id FROM login_events WHERE user_id = {} AND oidc_client_id IS NOT NULL) ORDER BY updated_at DESC",
                select_client_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_frontchannel_logout_clients_for_user(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<ClientRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE is_active = 1 AND COALESCE(frontchannel_logout_uri, '') <> '' AND client_id IN (SELECT DISTINCT oidc_client_id FROM login_events WHERE user_id = {} AND oidc_client_id IS NOT NULL) ORDER BY updated_at DESC",
                select_client_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_client(&self, client: NewClient) -> AppResult<ClientRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let redirect_uris = util::to_json(&client.redirect_uris)?;
        let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
        let scopes = util::to_json(&client.scopes)?;
        let grant_types = util::to_json(&client.grant_types)?;
        let response_types = util::to_json(&client.response_types)?;
        let authorization_details_types = util::to_json(&client.authorization_details_types)?;
        let service_account_permissions = util::to_json(&client.service_account_permissions)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO clients (id, client_id, client_secret_hash, client_name, logo_uri, organization_id, redirect_uris, post_logout_redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method, require_pkce, require_mfa, require_pushed_authorization_requests, require_s256_pkce, require_confidential_client, require_dpop, require_account_selection, trust_email_verified, authorization_details_types, subject_type, sector_identifier_uri, jwks_uri, jwks, backchannel_logout_uri, backchannel_logout_session_required, frontchannel_logout_uri, frontchannel_logout_session_required, service_account_enabled, service_account_permissions, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(client.client_id)
                .bind::<Nullable<Text>, _>(client.client_secret_hash)
                .bind::<Text, _>(client.client_name)
                .bind::<Text, _>(client.logo_uri)
                .bind::<Nullable<Text>, _>(client.organization_id)
                .bind::<Text, _>(redirect_uris)
                .bind::<Text, _>(post_logout_redirect_uris)
                .bind::<Text, _>(scopes)
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
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_client(&self, id: &str, client: NewClient) -> AppResult<ClientRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let redirect_uris = util::to_json(&client.redirect_uris)?;
        let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
        let scopes = util::to_json(&client.scopes)?;
        let grant_types = util::to_json(&client.grant_types)?;
        let response_types = util::to_json(&client.response_types)?;
        let authorization_details_types = util::to_json(&client.authorization_details_types)?;
        let service_account_permissions = util::to_json(&client.service_account_permissions)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE clients SET client_id = {}, client_secret_hash = {}, client_name = {}, logo_uri = {}, organization_id = {}, redirect_uris = {}, post_logout_redirect_uris = {}, scopes = {}, grant_types = {}, response_types = {}, token_endpoint_auth_method = {}, require_pkce = {}, require_mfa = {}, require_pushed_authorization_requests = {}, require_s256_pkce = {}, require_confidential_client = {}, require_dpop = {}, require_account_selection = {}, trust_email_verified = {}, authorization_details_types = {}, subject_type = {}, sector_identifier_uri = {}, jwks_uri = {}, jwks = {}, backchannel_logout_uri = {}, backchannel_logout_session_required = {}, frontchannel_logout_uri = {}, frontchannel_logout_session_required = {}, service_account_enabled = {}, service_account_permissions = {}, is_active = {}, updated_at = {} WHERE id = {}",
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
                ph(kind, 33)
            );
            sql_query(sql)
                .bind::<Text, _>(client.client_id)
                .bind::<Nullable<Text>, _>(client.client_secret_hash)
                .bind::<Text, _>(client.client_name)
                .bind::<Text, _>(client.logo_uri)
                .bind::<Nullable<Text>, _>(client.organization_id)
                .bind::<Text, _>(redirect_uris)
                .bind::<Text, _>(post_logout_redirect_uris)
                .bind::<Text, _>(scopes)
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
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_iap_applications(&self) -> AppResult<Vec<IapApplicationRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!(
                "{} ORDER BY is_active DESC, name ASC",
                select_iap_application_sql()
            );
            sql_query(sql)
                .load::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_active_iap_applications(&self) -> AppResult<Vec<IapApplicationRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!(
                "{} WHERE is_active = 1 ORDER BY LENGTH(path_prefix) DESC, name ASC",
                select_iap_application_sql()
            );
            sql_query(sql)
                .load::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_iap_application_by_id(
        &self,
        id: &str,
    ) -> AppResult<Option<IapApplicationRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                select_iap_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<IapApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_iap_application(
        &self,
        app: NewIapApplication,
    ) -> AppResult<IapApplicationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let roles = util::to_json(&dedupe_nonempty(app.required_organization_roles))?;
        let permissions = util::to_json(&normalize_permission_keys(app.required_permissions)?)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO iap_applications (id, slug, name, description, external_host, path_prefix, required_organization_id, required_organization_roles, required_permissions, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                .bind::<Text, _>(&id)
                .bind::<Text, _>(app.slug)
                .bind::<Text, _>(app.name)
                .bind::<Nullable<Text>, _>(app.description)
                .bind::<Text, _>(app.external_host)
                .bind::<Text, _>(app.path_prefix)
                .bind::<Nullable<Text>, _>(app.required_organization_id)
                .bind::<Text, _>(roles)
                .bind::<Text, _>(permissions)
                .bind::<Integer, _>(i32::from(app.is_active))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE id = {}",
                select_iap_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_iap_application(
        &self,
        id: &str,
        app: NewIapApplication,
    ) -> AppResult<IapApplicationRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let roles = util::to_json(&dedupe_nonempty(app.required_organization_roles))?;
        let permissions = util::to_json(&normalize_permission_keys(app.required_permissions)?)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE iap_applications SET slug = {}, name = {}, description = {}, external_host = {}, path_prefix = {}, required_organization_id = {}, required_organization_roles = {}, required_permissions = {}, is_active = {}, updated_at = {} WHERE id = {}",
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
                ph(kind, 11)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(app.slug)
                .bind::<Text, _>(app.name)
                .bind::<Nullable<Text>, _>(app.description)
                .bind::<Text, _>(app.external_host)
                .bind::<Text, _>(app.path_prefix)
                .bind::<Nullable<Text>, _>(app.required_organization_id)
                .bind::<Text, _>(roles)
                .bind::<Text, _>(permissions)
                .bind::<Integer, _>(i32::from(app.is_active))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            let sql = format!(
                "{} WHERE id = {}",
                select_iap_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_iap_application(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("DELETE FROM iap_applications WHERE id = {}", ph(kind, 1));
            let affected = sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                Err(AppError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    pub async fn insert_client_assertion_jti(
        &self,
        client_id: &str,
        jti: &str,
        expires_at: i64,
    ) -> AppResult<()> {
        let client_id = client_id.to_string();
        let jti = jti.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let delete_sql = format!(
                "DELETE FROM client_assertion_jtis WHERE expires_at < {}",
                ph(kind, 1)
            );
            sql_query(delete_sql)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let insert_sql = format!(
                "INSERT INTO client_assertion_jtis (client_id, jti, expires_at, created_at) VALUES ({}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(client_id)
                .bind::<Text, _>(jti)
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn insert_dpop_proof_jti(
        &self,
        jkt: &str,
        jti: &str,
        expires_at: i64,
    ) -> AppResult<()> {
        let jkt = jkt.to_string();
        let jti = jti.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let delete_sql = format!("DELETE FROM dpop_proofs WHERE expires_at < {}", ph(kind, 1));
            sql_query(delete_sql)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let insert_sql = format!(
                "INSERT INTO dpop_proofs (jkt, jti, expires_at, created_at) VALUES ({}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(jkt)
                .bind::<Text, _>(jti)
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn insert_session(
        &self,
        user_id: &str,
        ttl_seconds: i64,
        metadata: SessionMetadata,
    ) -> AppResult<(SessionRecord, String)> {
        let (id, cookie_value) = util::new_session_credentials();
        let csrf_token = util::random_token(32);
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO sessions (id, user_id, csrf_token, ip_address, user_agent, login_method, expires_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&csrf_token)
                .bind::<Nullable<Text>, _>(metadata.ip_address.as_deref())
                .bind::<Nullable<Text>, _>(metadata.user_agent.as_deref())
                .bind::<Nullable<Text>, _>(metadata.login_method.as_deref())
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok((
                SessionRecord {
                    id,
                    user_id,
                    csrf_token,
                    ip_address: metadata.ip_address,
                    user_agent: metadata.user_agent,
                    login_method: metadata.login_method,
                    expires_at,
                    created_at: now,
                },
                cookie_value,
            ))
        })
    }

    pub async fn find_session(&self, id: &str) -> AppResult<Option<SessionRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, csrf_token, ip_address, user_agent, login_method, expires_at, created_at FROM sessions WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<SessionRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_session_by_credential(
        &self,
        credential_id: &str,
    ) -> AppResult<Option<SessionRecord>> {
        let credential_id = credential_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT sessions.id, sessions.user_id, sessions.csrf_token, sessions.ip_address, sessions.user_agent, sessions.login_method, sessions.expires_at, sessions.created_at FROM session_credentials INNER JOIN sessions ON sessions.id = session_credentials.session_id WHERE session_credentials.credential_id = {} AND session_credentials.expires_at >= {} AND sessions.expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(credential_id)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .get_result::<SessionRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_user_sessions(&self, user_id: &str) -> AppResult<Vec<SessionRecord>> {
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, csrf_token, ip_address, user_agent, login_method, expires_at, created_at FROM sessions WHERE user_id = {} AND expires_at >= {} ORDER BY created_at DESC",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<BigInt, _>(now)
                .load::<SessionRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_session(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                for (table, column) in [
                    ("session_credentials", "session_id"),
                    ("browser_context_accounts", "session_id"),
                ] {
                    let sql = format!("DELETE FROM {table} WHERE {column} = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!("DELETE FROM sessions WHERE id = {}", ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_user_session(&self, user_id: &str, session_id: &str) -> AppResult<bool> {
        let user_id = user_id.to_string();
        let session_id = session_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<bool, AppError, _>(|conn| {
                let exists_sql = format!(
                    "SELECT COUNT(*) AS count FROM sessions WHERE user_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let exists = sql_query(exists_sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&session_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    > 0;
                if !exists {
                    return Ok(false);
                }
                for (table, column) in [
                    ("session_credentials", "session_id"),
                    ("browser_context_accounts", "session_id"),
                ] {
                    let sql = format!("DELETE FROM {table} WHERE {column} = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&session_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "DELETE FROM sessions WHERE user_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(user_id)
                    .bind::<Text, _>(session_id)
                    .execute(conn)
                    .map(|affected| affected > 0)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_browser_context(
        &self,
        id: &str,
        csrf_token: &str,
        ttl_seconds: i64,
    ) -> AppResult<BrowserContextRecord> {
        let id = id.to_string();
        let csrf_token = csrf_token.to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO browser_contexts (id, csrf_token, expires_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&csrf_token)
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(BrowserContextRecord {
                id,
                csrf_token,
                expires_at,
                created_at: now,
                updated_at: now,
            })
        })
    }

    pub async fn find_browser_context(&self, id: &str) -> AppResult<Option<BrowserContextRecord>> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, csrf_token, expires_at, created_at, updated_at FROM browser_contexts WHERE id = {} AND expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<BigInt, _>(now)
                .get_result::<BrowserContextRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_browser_context_accounts(
        &self,
        browser_context_id: &str,
    ) -> AppResult<Vec<BrowserContextAccountRecord>> {
        let browser_context_id = browser_context_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT browser_context_accounts.id, browser_context_accounts.browser_context_id, browser_context_accounts.user_id, browser_context_accounts.session_id, browser_context_accounts.added_at, browser_context_accounts.last_selected_at FROM browser_context_accounts INNER JOIN sessions ON sessions.id = browser_context_accounts.session_id WHERE browser_context_accounts.browser_context_id = {} AND sessions.expires_at >= {} ORDER BY sessions.created_at DESC, browser_context_accounts.added_at DESC, browser_context_accounts.id ASC",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(browser_context_id)
                .bind::<BigInt, _>(now)
                .load::<BrowserContextAccountRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_browser_context_account(
        &self,
        browser_context_id: &str,
        account_ref: &str,
    ) -> AppResult<Option<BrowserContextAccountRecord>> {
        let browser_context_id = browser_context_id.to_string();
        let account_ref = account_ref.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(browser_context_id)
                .bind::<Text, _>(account_ref)
                .get_result::<BrowserContextAccountRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_browser_context_account_by_session(
        &self,
        browser_context_id: &str,
        session_id: &str,
    ) -> AppResult<Option<BrowserContextAccountRecord>> {
        let browser_context_id = browser_context_id.to_string();
        let session_id = session_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND session_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(browser_context_id)
                .bind::<Text, _>(session_id)
                .get_result::<BrowserContextAccountRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn attach_browser_context_account(
        &self,
        browser_context_id: &str,
        user_id: &str,
        session_id: &str,
    ) -> AppResult<BrowserContextAccountRecord> {
        let browser_context_id = browser_context_id.to_string();
        let user_id = user_id.to_string();
        let session_id = session_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<BrowserContextAccountRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND user_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&user_id)
                    .get_result::<BrowserContextAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;

                let remove_other_mapping_sql = format!(
                    "DELETE FROM browser_context_accounts WHERE session_id = {} AND browser_context_id <> {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(remove_other_mapping_sql)
                    .bind::<Text, _>(&session_id)
                    .bind::<Text, _>(&browser_context_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let remove_other_credentials_sql = format!(
                    "DELETE FROM session_credentials WHERE session_id = {} AND browser_context_id <> {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(remove_other_credentials_sql)
                    .bind::<Text, _>(&session_id)
                    .bind::<Text, _>(&browser_context_id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                if let Some(existing) = existing {
                    if existing.session_id != session_id {
                        let delete_credentials_sql = format!(
                            "DELETE FROM session_credentials WHERE session_id = {}",
                            ph(kind, 1)
                        );
                        sql_query(delete_credentials_sql)
                            .bind::<Text, _>(&existing.session_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                        let delete_session_sql = format!(
                            "DELETE FROM sessions WHERE id = {}",
                            ph(kind, 1)
                        );
                        sql_query(delete_session_sql)
                            .bind::<Text, _>(&existing.session_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let update_sql = format!(
                        "UPDATE browser_context_accounts SET session_id = {}, last_selected_at = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    sql_query(update_sql)
                        .bind::<Text, _>(&session_id)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&existing.id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    return Ok(BrowserContextAccountRecord {
                        session_id,
                        last_selected_at: Some(now),
                        ..existing
                    });
                }

                let id = uuid::Uuid::new_v4().to_string();
                let insert_sql = format!(
                    "INSERT INTO browser_context_accounts (id, browser_context_id, user_id, session_id, added_at, last_selected_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&session_id)
                    .bind::<BigInt, _>(now)
                    .bind::<Nullable<BigInt>, _>(Some(now))
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(BrowserContextAccountRecord {
                    id,
                    browser_context_id,
                    user_id,
                    session_id,
                    added_at: now,
                    last_selected_at: Some(now),
                })
            })
        })
    }

    pub async fn mint_browser_account_session_credential(
        &self,
        browser_context_id: &str,
        account_ref: &str,
    ) -> AppResult<(SessionRecord, String)> {
        let browser_context_id = browser_context_id.to_string();
        let account_ref = account_ref.to_string();
        let (credential_id, cookie_value) = util::new_session_credentials();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<SessionRecord, AppError, _>(|conn| {
                let account_sql = format!(
                    "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let account = sql_query(account_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&account_ref)
                    .get_result::<BrowserContextAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                let session_sql = format!(
                    "SELECT id, user_id, csrf_token, ip_address, user_agent, login_method, expires_at, created_at FROM sessions WHERE id = {} AND user_id = {} AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let session = sql_query(session_sql)
                    .bind::<Text, _>(&account.session_id)
                    .bind::<Text, _>(&account.user_id)
                    .bind::<BigInt, _>(now)
                    .get_result::<SessionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                let delete_sql = format!(
                    "DELETE FROM session_credentials WHERE browser_context_id = {} AND session_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&session.id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let insert_sql = format!(
                    "INSERT INTO session_credentials (credential_id, session_id, browser_context_id, expires_at, created_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(credential_id)
                    .bind::<Text, _>(&session.id)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<BigInt, _>(session.expires_at)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let update_sql = format!(
                    "UPDATE browser_context_accounts SET last_selected_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(account.id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(session)
            })
        })
        .map(|session| (session, cookie_value))
    }

    pub async fn remove_browser_context_account(
        &self,
        browser_context_id: &str,
        account_ref: &str,
    ) -> AppResult<BrowserContextAccountRecord> {
        let browser_context_id = browser_context_id.to_string();
        let account_ref = account_ref.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<BrowserContextAccountRecord, AppError, _>(|conn| {
                let select_sql = format!(
                    "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let account = sql_query(select_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&account_ref)
                    .get_result::<BrowserContextAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                for (table, column) in [
                    ("session_credentials", "session_id"),
                    ("browser_context_accounts", "session_id"),
                ] {
                    let sql = format!("DELETE FROM {table} WHERE {column} = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&account.session_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let delete_session_sql =
                    format!("DELETE FROM sessions WHERE id = {}", ph(kind, 1));
                sql_query(delete_session_sql)
                    .bind::<Text, _>(&account.session_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(account)
            })
        })
    }

    pub async fn delete_browser_context(&self, browser_context_id: &str) -> AppResult<()> {
        let browser_context_id = browser_context_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let delete_credentials_sql = format!(
                    "DELETE FROM session_credentials WHERE browser_context_id = {} OR session_id IN (SELECT session_id FROM browser_context_accounts WHERE browser_context_id = {})",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(delete_credentials_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&browser_context_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let delete_sessions_sql = format!(
                    "DELETE FROM sessions WHERE id IN (SELECT session_id FROM browser_context_accounts WHERE browser_context_id = {})",
                    ph(kind, 1)
                );
                sql_query(delete_sessions_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for table in ["browser_context_accounts", "account_login_flows"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE browser_context_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&browser_context_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let delete_context_sql =
                    format!("DELETE FROM browser_contexts WHERE id = {}", ph(kind, 1));
                sql_query(delete_context_sql)
                    .bind::<Text, _>(browser_context_id)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_account_login_flow(
        &self,
        id_hash: &str,
        browser_context_id: &str,
        return_to: &str,
        expected_user_id: Option<&str>,
        ttl_seconds: i64,
    ) -> AppResult<AccountLoginFlowRecord> {
        let id_hash = id_hash.to_string();
        let browser_context_id = browser_context_id.to_string();
        let return_to = return_to.to_string();
        let expected_user_id = expected_user_id.map(ToOwned::to_owned);
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM account_login_flows WHERE expires_at < {} OR consumed_at IS NOT NULL",
                ph(kind, 1)
            );
            sql_query(cleanup_sql)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let insert_sql = format!(
                "INSERT INTO account_login_flows (id_hash, browser_context_id, return_to, expected_user_id, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(&id_hash)
                .bind::<Text, _>(&browser_context_id)
                .bind::<Text, _>(&return_to)
                .bind::<Nullable<Text>, _>(expected_user_id.as_deref())
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(AccountLoginFlowRecord {
                id_hash,
                browser_context_id,
                return_to,
                expected_user_id,
                expires_at,
                consumed_at: None,
                created_at: now,
            })
        })
    }

    pub async fn consume_account_login_flow(
        &self,
        id_hash: &str,
        browser_context_id: &str,
        authenticated_user_id: &str,
    ) -> AppResult<AccountLoginFlowRecord> {
        let id_hash = id_hash.to_string();
        let browser_context_id = browser_context_id.to_string();
        let authenticated_user_id = authenticated_user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<AccountLoginFlowRecord, AppError, _>(|conn| {
                let select_sql = format!(
                    "SELECT id_hash, browser_context_id, return_to, expected_user_id, expires_at, consumed_at, created_at FROM account_login_flows WHERE id_hash = {} AND browser_context_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let flow = sql_query(select_sql)
                    .bind::<Text, _>(&id_hash)
                    .bind::<Text, _>(&browser_context_id)
                    .get_result::<AccountLoginFlowRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if flow.consumed_at.is_some() || flow.expires_at < now {
                    return Err(AppError::Unauthorized);
                }
                if flow
                    .expected_user_id
                    .as_deref()
                    .is_some_and(|expected| expected != authenticated_user_id)
                {
                    return Err(AppError::Unauthorized);
                }
                let update_sql = format!(
                    "UPDATE account_login_flows SET consumed_at = {} WHERE id_hash = {} AND browser_context_id = {} AND consumed_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id_hash)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                Ok(AccountLoginFlowRecord {
                    consumed_at: Some(now),
                    ..flow
                })
            })
        })
    }

    pub async fn list_client_claim_mappers(
        &self,
        client_db_id: &str,
    ) -> AppResult<Vec<ClientClaimMapperRecord>> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE client_db_id = {} ORDER BY sort_order ASC, created_at ASC",
                select_client_claim_mapper_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .load::<ClientClaimMapperRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn replace_client_claim_mappers(
        &self,
        client_db_id: &str,
        mappers: Vec<NewClientClaimMapper>,
    ) -> AppResult<Vec<ClientClaimMapperRecord>> {
        let client_db_id = client_db_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM client_claim_mappers WHERE client_db_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&client_db_id)
                .execute(&mut conn)
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
                    .bind::<Text, _>(&client_db_id)
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
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }

            let sql = format!(
                "{} WHERE client_db_id = {} ORDER BY sort_order ASC, created_at ASC",
                select_client_claim_mapper_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .load::<ClientClaimMapperRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_client(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                // These tables refer to the public OIDC client_id rather than
                // the internal clients.id. Clear them before the client record
                // disappears so no live credential or authorization state can
                // outlast a deleted client.
                for (table, column) in [
                    ("authorization_codes", "client_id"),
                    ("refresh_tokens", "client_id"),
                    ("user_consents", "client_id"),
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
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                for table in ["client_registrations", "client_claim_mappers"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE client_db_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!("DELETE FROM clients WHERE id = {}", ph(kind, 1));
                let affected = sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::NotFound);
                }
                Ok(())
            })
        })
    }

    pub async fn upsert_client_registration(
        &self,
        client_db_id: &str,
        registration_access_token_hash: String,
    ) -> AppResult<ClientRegistrationRecord> {
        let client_db_id = client_db_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE client_registrations SET registration_access_token_hash = {}, updated_at = {} WHERE client_db_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            let changed = sql_query(update_sql)
                .bind::<Text, _>(&registration_access_token_hash)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&client_db_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO client_registrations (client_db_id, registration_access_token_hash, created_at, updated_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&client_db_id)
                    .bind::<Text, _>(&registration_access_token_hash)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!(
                "SELECT client_db_id, registration_access_token_hash, created_at, updated_at FROM client_registrations WHERE client_db_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .get_result::<ClientRegistrationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_client_registration(
        &self,
        client_db_id: &str,
    ) -> AppResult<Option<ClientRegistrationRecord>> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT client_db_id, registration_access_token_hash, created_at, updated_at FROM client_registrations WHERE client_db_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .get_result::<ClientRegistrationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_signing_keys(&self) -> AppResult<Vec<SigningKeyRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys ORDER BY is_active DESC, created_at DESC")
                .load::<SigningKeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_signing_key_seed(
        &self,
        settings: &Settings,
    ) -> AppResult<Vec<SigningKeyRecord>> {
        let existing = self.list_signing_keys().await?;
        if !existing.is_empty() {
            return Ok(existing);
        }
        let private_key_pem = if settings.security.rsa_private_key_pem.trim().is_empty() {
            util::generate_rsa_private_key_pem()?
        } else {
            settings.security.rsa_private_key_pem.clone()
        };
        self.insert_signing_key(NewSigningKey {
            kid: settings.security.key_id.clone(),
            private_key_pem,
            is_active: true,
        })
        .await?;
        self.list_signing_keys().await
    }

    pub async fn rotate_signing_key(&self, kid: Option<String>) -> AppResult<SigningKeyRecord> {
        let kid = kid
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("key-{}-{}", util::now_ts(), util::random_token(6)));
        if kid.len() > 128 {
            return Err(AppError::BadRequest(
                "signing key id must be 128 characters or fewer".to_string(),
            ));
        }
        let private_key_pem = util::generate_rsa_private_key_pem()?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<SigningKeyRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys WHERE kid = {}",
                    ph(kind, 1)
                );
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&kid)
                    .get_result::<SigningKeyRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                if existing.is_some() {
                    return Err(AppError::BadRequest(format!(
                        "signing key id already exists: {kid}"
                    )));
                }
                let retire_sql = format!(
                    "UPDATE signing_keys SET is_active = {}, retired_at = {} WHERE is_active = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(retire_sql)
                    .bind::<Integer, _>(0)
                    .bind::<BigInt, _>(now)
                    .bind::<Integer, _>(1)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let id = uuid::Uuid::new_v4().to_string();
                let insert_sql = format!(
                    "INSERT INTO signing_keys (id, kid, private_key_pem, is_active, created_at, activated_at, retired_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&kid)
                    .bind::<Text, _>(&private_key_pem)
                    .bind::<Integer, _>(1)
                    .bind::<BigInt, _>(now)
                    .bind::<Nullable<BigInt>, _>(Some(now))
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys WHERE id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<SigningKeyRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    async fn insert_signing_key(&self, key: NewSigningKey) -> AppResult<SigningKeyRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO signing_keys (id, kid, private_key_pem, is_active, created_at, activated_at, retired_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(key.kid)
                .bind::<Text, _>(key.private_key_pem)
                .bind::<Integer, _>(i32::from(key.is_active))
                .bind::<BigInt, _>(now)
                .bind::<Nullable<BigInt>, _>(key.is_active.then_some(now))
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<SigningKeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn create_mfa_totp_setup(
        &self,
        user_id: &str,
        secret: String,
        ttl_seconds: i64,
    ) -> AppResult<MfaTotpSetupRecord> {
        let id = util::random_token(24);
        let user_id = user_id.to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM mfa_totp_setups WHERE user_id = {} OR expires_at < {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(cleanup_sql)
                .bind::<Text, _>(&user_id)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "INSERT INTO mfa_totp_setups (id, user_id, secret, expires_at, created_at) VALUES ({}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&secret)
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(MfaTotpSetupRecord {
                id,
                user_id,
                secret,
                expires_at,
                created_at: now,
            })
        })
    }

    pub async fn find_mfa_totp_setup(&self, id: &str) -> AppResult<Option<MfaTotpSetupRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, secret, expires_at, created_at FROM mfa_totp_setups WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<MfaTotpSetupRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn delete_mfa_totp_setup(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("DELETE FROM mfa_totp_setups WHERE id = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn find_totp_method(&self, user_id: &str) -> AppResult<Option<MfaTotpMethodRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT user_id, secret, last_used_step, enabled_at, created_at, updated_at FROM mfa_totp_methods WHERE user_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .get_result::<MfaTotpMethodRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_totp_method(
        &self,
        user_id: &str,
        secret: String,
    ) -> AppResult<MfaTotpMethodRecord> {
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let select_sql = format!(
                "SELECT COUNT(*) AS count FROM mfa_totp_methods WHERE user_id = {}",
                ph(kind, 1)
            );
            let exists = sql_query(select_sql)
                .bind::<Text, _>(&user_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                > 0;
            if exists {
                let sql = format!(
                    "UPDATE mfa_totp_methods SET secret = {}, last_used_step = {}, enabled_at = {}, updated_at = {} WHERE user_id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(sql)
                    .bind::<Text, _>(&secret)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&user_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            } else {
                let sql = format!(
                    "INSERT INTO mfa_totp_methods (user_id, secret, last_used_step, enabled_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&secret)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!(
                "SELECT user_id, secret, last_used_step, enabled_at, created_at, updated_at FROM mfa_totp_methods WHERE user_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .get_result::<MfaTotpMethodRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn mark_totp_used(&self, user_id: &str, step: i64) -> AppResult<()> {
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE mfa_totp_methods SET last_used_step = {}, updated_at = {} WHERE user_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<BigInt, _>(step)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(user_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn replace_recovery_codes(
        &self,
        user_id: &str,
        code_hashes: Vec<String>,
    ) -> AppResult<()> {
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM mfa_recovery_codes WHERE user_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&user_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            for code_hash in code_hashes {
                let id = uuid::Uuid::new_v4().to_string();
                let sql = format!(
                    "INSERT INTO mfa_recovery_codes (id, user_id, code_hash, used_at, created_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(code_hash)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            Ok(())
        })
    }

    pub async fn list_recovery_codes(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<MfaRecoveryCodeRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, code_hash, used_at, created_at FROM mfa_recovery_codes WHERE user_id = {} ORDER BY created_at ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<MfaRecoveryCodeRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_unused_recovery_codes(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<MfaRecoveryCodeRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, code_hash, used_at, created_at FROM mfa_recovery_codes WHERE user_id = {} AND used_at IS NULL ORDER BY created_at ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<MfaRecoveryCodeRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn mark_recovery_code_used(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE mfa_recovery_codes SET used_at = {} WHERE id = {} AND used_at IS NULL",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_passkeys(&self, user_id: &str) -> AppResult<Vec<PasskeyRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE user_id = {} ORDER BY created_at DESC",
                select_passkey_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<PasskeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_passkey_by_id(&self, id: &str) -> AppResult<Option<PasskeyRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_passkey_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<PasskeyRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AppResult<Option<PasskeyRecord>> {
        let credential_id = credential_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE credential_id = {}",
                select_passkey_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(credential_id)
                .get_result::<PasskeyRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_passkey(
        &self,
        user_id: &str,
        credential_id: String,
        name: String,
        passkey_json: String,
    ) -> AppResult<PasskeyRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO passkeys (id, user_id, credential_id, name, passkey_json, last_used_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(credential_id)
                .bind::<Text, _>(name)
                .bind::<Text, _>(passkey_json)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_passkey_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<PasskeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_passkey_after_authentication(
        &self,
        id: &str,
        passkey_json: String,
    ) -> AppResult<PasskeyRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE passkeys SET passkey_json = {}, last_used_at = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(passkey_json)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            let sql = format!("{} WHERE id = {}", select_passkey_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<PasskeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_passkey(&self, user_id: &str, id: &str) -> AppResult<()> {
        let user_id = user_id.to_string();
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM passkeys WHERE id = {} AND user_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(user_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                Err(AppError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    pub async fn create_webauthn_challenge(
        &self,
        user_id: Option<&str>,
        purpose: &str,
        state_json: String,
        ttl_seconds: i64,
    ) -> AppResult<WebauthnChallengeRecord> {
        let id = util::random_token(24);
        let user_id = user_id.map(str::to_string);
        let purpose = purpose.to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM webauthn_challenges WHERE expires_at < {} OR ({} IS NOT NULL AND user_id = {} AND purpose = {} AND consumed_at IS NULL)",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(cleanup_sql)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(user_id.as_deref())
                .bind::<Nullable<Text>, _>(user_id.as_deref())
                .bind::<Text, _>(&purpose)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "INSERT INTO webauthn_challenges (id, user_id, purpose, state_json, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Nullable<Text>, _>(user_id.as_deref())
                .bind::<Text, _>(&purpose)
                .bind::<Text, _>(state_json)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE id = {}",
                select_webauthn_challenge_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<WebauthnChallengeRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_webauthn_challenge(
        &self,
        id: &str,
    ) -> AppResult<Option<WebauthnChallengeRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                select_webauthn_challenge_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<WebauthnChallengeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn consume_webauthn_challenge(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE webauthn_challenges SET consumed_at = {} WHERE id = {} AND consumed_at IS NULL",
                ph(kind, 1),
                ph(kind, 2)
            );
            let affected = sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                Err(AppError::Unauthorized)
            } else {
                Ok(())
            }
        })
    }

    pub async fn create_mfa_challenge(
        &self,
        user_id: &str,
        purpose: &str,
        return_to: Option<String>,
        ttl_seconds: i64,
    ) -> AppResult<MfaChallengeRecord> {
        let id = util::random_token(24);
        let user_id = user_id.to_string();
        let purpose = purpose.to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM mfa_challenges WHERE expires_at < {} OR (user_id = {} AND purpose = {} AND consumed_at IS NULL)",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(cleanup_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&purpose)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "INSERT INTO mfa_challenges (id, user_id, purpose, return_to, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&purpose)
                .bind::<Nullable<Text>, _>(&return_to)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(MfaChallengeRecord {
                id,
                user_id,
                purpose,
                return_to,
                expires_at,
                consumed_at: None,
                created_at: now,
            })
        })
    }

    pub async fn find_mfa_challenge(&self, id: &str) -> AppResult<Option<MfaChallengeRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, purpose, return_to, expires_at, consumed_at, created_at FROM mfa_challenges WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<MfaChallengeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn consume_mfa_challenge(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE mfa_challenges SET consumed_at = {} WHERE id = {} AND consumed_at IS NULL",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn delete_mfa_for_user(&self, user_id: &str) -> AppResult<()> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            for table in [
                "mfa_totp_methods",
                "mfa_totp_setups",
                "mfa_recovery_codes",
                "mfa_challenges",
                "passkeys",
                "webauthn_challenges",
            ] {
                let sql = format!("DELETE FROM {table} WHERE user_id = {}", ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(&user_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            Ok(())
        })
    }

    pub async fn find_oidc_login_grant(
        &self,
        credential_hash: &str,
        interaction_request_hash: &str,
    ) -> AppResult<Option<OidcLoginGrantRecord>> {
        let credential_hash = credential_hash.to_string();
        let interaction_request_hash = interaction_request_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE credential_hash = {} AND interaction_request_hash = {} AND consumed_at IS NULL AND expires_at >= {}",
                select_oidc_login_grant_sql(),
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(credential_hash)
                .bind::<Text, _>(interaction_request_hash)
                .bind::<BigInt, _>(now)
                .get_result::<OidcLoginGrantRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn consume_oidc_login_grant_and_insert_authorization_code(
        &self,
        credential_hash: &str,
        interaction_request_hash: &str,
        code: NewAuthorizationCode,
    ) -> AppResult<()> {
        if code.session_id.is_some() {
            return Err(AppError::Configuration(
                "OIDC login grant authorization code cannot have a session id".to_string(),
            ));
        }
        let credential_hash = credential_hash.to_string();
        let interaction_request_hash = interaction_request_hash.to_string();
        let expected_client_id = code.client_id.clone();
        let expected_user_id = code.user_id.clone();
        let amr = util::to_json(&code.amr)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE oidc_login_grants SET consumed_at = {} WHERE credential_hash = {} AND interaction_request_hash = {} AND client_id = {} AND user_id = {} AND consumed_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&credential_hash)
                    .bind::<Text, _>(&interaction_request_hash)
                    .bind::<Text, _>(&expected_client_id)
                    .bind::<Text, _>(&expected_user_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                let sql = format!(
                    "INSERT INTO authorization_codes (code, client_id, user_id, session_id, redirect_uri, scope, resource, authorization_details, nonce, code_challenge, code_challenge_method, auth_time, acr, amr, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 17)
                );
                sql_query(sql)
                    .bind::<Text, _>(code.code)
                    .bind::<Text, _>(code.client_id)
                    .bind::<Text, _>(code.user_id)
                    .bind::<Nullable<Text>, _>(code.session_id)
                    .bind::<Text, _>(code.redirect_uri)
                    .bind::<Text, _>(code.scope)
                    .bind::<Nullable<Text>, _>(code.resource)
                    .bind::<Nullable<Text>, _>(code.authorization_details)
                    .bind::<Nullable<Text>, _>(code.nonce)
                    .bind::<Nullable<Text>, _>(code.code_challenge)
                    .bind::<Nullable<Text>, _>(code.code_challenge_method)
                    .bind::<BigInt, _>(code.auth_time)
                    .bind::<Text, _>(code.acr)
                    .bind::<Text, _>(amr)
                    .bind::<BigInt, _>(code.expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_authorization_code(&self, code: NewAuthorizationCode) -> AppResult<()> {
        let now = util::now_ts();
        let amr = util::to_json(&code.amr)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO authorization_codes (code, client_id, user_id, session_id, redirect_uri, scope, resource, authorization_details, nonce, code_challenge, code_challenge_method, auth_time, acr, amr, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 17)
            );
            sql_query(sql)
                .bind::<Text, _>(code.code)
                .bind::<Text, _>(code.client_id)
                .bind::<Text, _>(code.user_id)
                .bind::<Nullable<Text>, _>(code.session_id)
                .bind::<Text, _>(code.redirect_uri)
                .bind::<Text, _>(code.scope)
                .bind::<Nullable<Text>, _>(code.resource)
                .bind::<Nullable<Text>, _>(code.authorization_details)
                .bind::<Nullable<Text>, _>(code.nonce)
                .bind::<Nullable<Text>, _>(code.code_challenge)
                .bind::<Nullable<Text>, _>(code.code_challenge_method)
                .bind::<BigInt, _>(code.auth_time)
                .bind::<Text, _>(code.acr)
                .bind::<Text, _>(amr)
                .bind::<BigInt, _>(code.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn consume_authorization_code(
        &self,
        code: &str,
    ) -> AppResult<AuthorizationCodeRecord> {
        let code = code.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let select_sql = format!(
                "SELECT code, client_id, user_id, session_id, redirect_uri, scope, resource, authorization_details, nonce, code_challenge, code_challenge_method, COALESCE(auth_time, created_at) AS auth_time, COALESCE(acr, '') AS acr, COALESCE(amr, '[]') AS amr, expires_at, consumed_at, created_at FROM authorization_codes WHERE code = {}",
                ph(kind, 1)
            );
            let record = sql_query(select_sql)
                .bind::<Text, _>(&code)
                .get_result::<AuthorizationCodeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or_else(|| AppError::Oidc("invalid authorization code".to_string()))?;
            if record.expires_at < now {
                return Err(AppError::Oidc("authorization code expired".to_string()));
            }
            if record.consumed_at.is_some() {
                return Err(AppError::Oidc(
                    "authorization code already consumed".to_string(),
                ));
            }
            let update_sql = format!(
                "UPDATE authorization_codes SET consumed_at = {} WHERE code = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(update_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(code)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(record)
        })
    }

    pub async fn insert_pushed_authorization_request(
        &self,
        request: NewPushedAuthorizationRequest,
    ) -> AppResult<PushedAuthorizationRequestRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO pushed_authorization_requests (request_uri_hash, client_id, request_json, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            sql_query(sql)
                .bind::<Text, _>(&request.request_uri_hash)
                .bind::<Text, _>(request.client_id)
                .bind::<Text, _>(request.request_json)
                .bind::<BigInt, _>(request.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE request_uri_hash = {}",
                select_pushed_authorization_request_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(request.request_uri_hash)
                .get_result::<PushedAuthorizationRequestRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_pushed_authorization_request(
        &self,
        request_uri_hash: &str,
    ) -> AppResult<Option<PushedAuthorizationRequestRecord>> {
        let request_uri_hash = request_uri_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE request_uri_hash = {}",
                select_pushed_authorization_request_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&request_uri_hash)
                .get_result::<PushedAuthorizationRequestRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn update_unconsumed_pushed_authorization_request(
        &self,
        request_uri_hash: &str,
        client_id: &str,
        expected_request_json: &str,
        request_json: &str,
    ) -> AppResult<PushedAuthorizationRequestRecord> {
        let request_uri_hash = request_uri_hash.to_string();
        let client_id = client_id.to_string();
        let expected_request_json = expected_request_json.to_string();
        let request_json = request_json.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PushedAuthorizationRequestRecord, AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE pushed_authorization_requests SET request_json = {} WHERE request_uri_hash = {} AND client_id = {} AND request_json = {} AND consumed_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                let affected = sql_query(update_sql)
                    .bind::<Text, _>(&request_json)
                    .bind::<Text, _>(&request_uri_hash)
                    .bind::<Text, _>(&client_id)
                    .bind::<Text, _>(&expected_request_json)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                let select_sql = format!(
                    "{} WHERE request_uri_hash = {}",
                    select_pushed_authorization_request_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(request_uri_hash)
                    .get_result::<PushedAuthorizationRequestRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn consume_pushed_authorization_request(
        &self,
        request_uri_hash: &str,
    ) -> AppResult<PushedAuthorizationRequestRecord> {
        let request_uri_hash = request_uri_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PushedAuthorizationRequestRecord, AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE pushed_authorization_requests SET consumed_at = {} WHERE request_uri_hash = {} AND consumed_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&request_uri_hash)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Oidc(
                        "request_uri is invalid, expired, or already consumed".to_string(),
                    ));
                }
                let select_sql = format!(
                    "{} WHERE request_uri_hash = {}",
                    select_pushed_authorization_request_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(request_uri_hash)
                    .get_result::<PushedAuthorizationRequestRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_device_authorization(
        &self,
        authorization: NewDeviceAuthorization,
    ) -> AppResult<DeviceAuthorizationRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO device_authorizations (device_code_hash, user_code_hash, user_code_display, client_id, scope, resource, authorization_details, expires_at, interval_seconds, authorized_user_id, authorized_at, denied_at, consumed_at, last_poll_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 15)
            );
            sql_query(sql)
                .bind::<Text, _>(&authorization.device_code_hash)
                .bind::<Text, _>(authorization.user_code_hash)
                .bind::<Text, _>(authorization.user_code_display)
                .bind::<Text, _>(authorization.client_id)
                .bind::<Text, _>(authorization.scope)
                .bind::<Nullable<Text>, _>(authorization.resource)
                .bind::<Nullable<Text>, _>(authorization.authorization_details)
                .bind::<BigInt, _>(authorization.expires_at)
                .bind::<Integer, _>(authorization.interval_seconds)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!(
                "{} WHERE device_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(authorization.device_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_device_authorization_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> AppResult<Option<DeviceAuthorizationRecord>> {
        let device_code_hash = device_code_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE device_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(device_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_device_authorization_by_user_code_hash(
        &self,
        user_code_hash: &str,
    ) -> AppResult<Option<DeviceAuthorizationRecord>> {
        let user_code_hash = user_code_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE user_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn mark_device_authorization_polled(
        &self,
        device_code_hash: &str,
        polled_at: i64,
    ) -> AppResult<()> {
        let device_code_hash = device_code_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE device_authorizations SET last_poll_at = {} WHERE device_code_hash = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(polled_at)
                .bind::<Text, _>(device_code_hash)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn authorize_device_authorization(
        &self,
        user_code_hash: &str,
        user_id: &str,
    ) -> AppResult<DeviceAuthorizationRecord> {
        let user_code_hash = user_code_hash.to_string();
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE device_authorizations SET authorized_user_id = {}, authorized_at = {} WHERE user_code_hash = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&user_code_hash)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE user_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn deny_device_authorization(
        &self,
        user_code_hash: &str,
    ) -> AppResult<DeviceAuthorizationRecord> {
        let user_code_hash = user_code_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE device_authorizations SET denied_at = {} WHERE user_code_hash = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&user_code_hash)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE user_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn consume_device_authorization(
        &self,
        device_code_hash: &str,
    ) -> AppResult<DeviceAuthorizationRecord> {
        let device_code_hash = device_code_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE device_authorizations SET consumed_at = {} WHERE device_code_hash = {} AND consumed_at IS NULL",
                ph(kind, 1),
                ph(kind, 2)
            );
            let changed = sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&device_code_hash)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                return Err(AppError::Oidc(
                    "device code has already been consumed".to_string(),
                ));
            }
            let sql = format!(
                "{} WHERE device_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(device_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_refresh_token(
        &self,
        client_id: String,
        token: RefreshTokenInput,
    ) -> AppResult<()> {
        let RefreshTokenInput {
            token_hash,
            user_id,
            scope,
            resource,
            authorization_details,
            dpop_jkt,
            expires_at,
        } = token;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, resource, authorization_details, dpop_jkt, expires_at, revoked_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9),
                ph(kind, 10)
            );
            sql_query(sql)
                .bind::<Text, _>(token_hash)
                .bind::<Text, _>(client_id)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(scope)
                .bind::<Nullable<Text>, _>(resource)
                .bind::<Nullable<Text>, _>(authorization_details)
                .bind::<Nullable<Text>, _>(dpop_jkt)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn find_refresh_token(
        &self,
        token_hash: &str,
    ) -> AppResult<Option<RefreshTokenRecord>> {
        let token_hash = token_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT token_hash, client_id, user_id, scope, resource, authorization_details, dpop_jkt, expires_at, revoked_at, created_at FROM refresh_tokens WHERE token_hash = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(token_hash)
                .get_result::<RefreshTokenRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn revoke_refresh_token(&self, token_hash: &str) -> AppResult<()> {
        let token_hash = token_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE refresh_tokens SET revoked_at = {} WHERE token_hash = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(token_hash)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn rotate_refresh_token(
        &self,
        token_hash: &str,
        client_id: &str,
        replacement: RefreshTokenInput,
    ) -> AppResult<bool> {
        let token_hash = token_hash.to_string();
        let client_id = client_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<bool, AppError, _>(|conn| {
                let revoke_sql = format!(
                    "UPDATE refresh_tokens SET revoked_at = {} WHERE token_hash = {} AND client_id = {} AND revoked_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let changed = sql_query(revoke_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&token_hash)
                    .bind::<Text, _>(&client_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if changed != 1 {
                    return Ok(false);
                }

                let insert_sql = format!(
                    "INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, resource, authorization_details, dpop_jkt, expires_at, revoked_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(replacement.token_hash)
                    .bind::<Text, _>(client_id)
                    .bind::<Text, _>(replacement.user_id)
                    .bind::<Text, _>(replacement.scope)
                    .bind::<Nullable<Text>, _>(replacement.resource)
                    .bind::<Nullable<Text>, _>(replacement.authorization_details)
                    .bind::<Nullable<Text>, _>(replacement.dpop_jkt)
                    .bind::<BigInt, _>(replacement.expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(true)
            })
        })
    }

    pub async fn find_user_consent(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> AppResult<Option<UserConsentRecord>> {
        let user_id = user_id.to_string();
        let client_id = client_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT user_id, client_id, granted_scopes, granted_at, updated_at, revoked_at FROM user_consents WHERE user_id = {} AND client_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(client_id)
                .get_result::<UserConsentRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_active_user_consents(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<UserConsentWithClientRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT user_consents.user_id, user_consents.client_id, clients.client_name, user_consents.granted_scopes, user_consents.granted_at, user_consents.updated_at, user_consents.revoked_at FROM user_consents LEFT JOIN clients ON clients.client_id = user_consents.client_id WHERE user_consents.user_id = {} AND user_consents.revoked_at IS NULL ORDER BY user_consents.updated_at DESC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<UserConsentWithClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_user_consent(
        &self,
        user_id: &str,
        client_id: &str,
        granted_scopes: String,
    ) -> AppResult<UserConsentRecord> {
        let user_id = user_id.to_string();
        let client_id = client_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE user_consents SET granted_scopes = {}, updated_at = {}, revoked_at = {} WHERE user_id = {} AND client_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            let changed = sql_query(update_sql)
                .bind::<Text, _>(&granted_scopes)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&client_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO user_consents (user_id, client_id, granted_scopes, granted_at, updated_at, revoked_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&client_id)
                    .bind::<Text, _>(&granted_scopes)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!(
                "SELECT user_id, client_id, granted_scopes, granted_at, updated_at, revoked_at FROM user_consents WHERE user_id = {} AND client_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(client_id)
                .get_result::<UserConsentRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn revoke_user_consent(&self, user_id: &str, client_id: &str) -> AppResult<bool> {
        let user_id = user_id.to_string();
        let client_id = client_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE user_consents SET revoked_at = {}, updated_at = {} WHERE user_id = {} AND client_id = {} AND revoked_at IS NULL",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(client_id)
                .execute(&mut conn)
                .map(|changed| changed > 0)
                .map_err(AppError::from)
        })
    }

    pub async fn registration_settings(&self) -> AppResult<RegistrationSettingsRecord> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, allow_password_registration, require_email_verification, require_phone_verification, allow_external_oidc_registration, require_invitation, first_user_direct_admin, default_user_active, updated_at FROM registration_settings WHERE id = 'default'")
                .get_result::<RegistrationSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_registration_settings(
        &self,
        settings: NewRegistrationSettings,
    ) -> AppResult<RegistrationSettingsRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE registration_settings SET allow_password_registration = {}, require_email_verification = {}, require_phone_verification = {}, allow_external_oidc_registration = {}, require_invitation = {}, first_user_direct_admin = {}, default_user_active = {}, updated_at = {} WHERE id = {}",
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
            let changed = sql_query(update_sql)
                .bind::<Integer, _>(i32::from(settings.allow_password_registration))
                .bind::<Integer, _>(i32::from(settings.require_email_verification))
                .bind::<Integer, _>(i32::from(settings.require_phone_verification))
                .bind::<Integer, _>(i32::from(settings.allow_external_oidc_registration))
                .bind::<Integer, _>(i32::from(settings.require_invitation))
                .bind::<Integer, _>(i32::from(FIRST_REGISTERED_USER_IS_ADMIN))
                .bind::<Integer, _>(i32::from(settings.default_user_active))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>("default")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO registration_settings (id, allow_password_registration, require_email_verification, require_phone_verification, allow_external_oidc_registration, require_invitation, first_user_direct_admin, default_user_active, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Integer, _>(i32::from(settings.allow_password_registration))
                    .bind::<Integer, _>(i32::from(settings.require_email_verification))
                    .bind::<Integer, _>(i32::from(settings.require_phone_verification))
                    .bind::<Integer, _>(i32::from(settings.allow_external_oidc_registration))
                    .bind::<Integer, _>(i32::from(settings.require_invitation))
                    .bind::<Integer, _>(i32::from(FIRST_REGISTERED_USER_IS_ADMIN))
                    .bind::<Integer, _>(i32::from(settings.default_user_active))
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            sql_query("SELECT id, allow_password_registration, require_email_verification, require_phone_verification, allow_external_oidc_registration, require_invitation, first_user_direct_admin, default_user_active, updated_at FROM registration_settings WHERE id = 'default'")
                .get_result::<RegistrationSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn security_policy(&self) -> AppResult<SecurityPolicyRecord> {
        with_conn!(self, |conn, _kind| {
            sql_query(format!(
                "{} WHERE id = 'default'",
                select_security_policy_sql()
            ))
            .get_result::<SecurityPolicyRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn ensure_security_policy(
        &self,
        settings: NewSecurityPolicy,
    ) -> AppResult<SecurityPolicyRecord> {
        let trusted_ip_cidrs = util::to_json(&settings.trusted_ip_cidrs)?;
        let allowed_ip_cidrs = util::to_json(&settings.allowed_ip_cidrs)?;
        let blocked_ip_cidrs = util::to_json(&settings.blocked_ip_cidrs)?;
        let allowed_email_domains = util::to_json(&settings.allowed_email_domains)?;
        let blocked_email_domains = util::to_json(&settings.blocked_email_domains)?;
        with_conn!(self, |conn, kind| {
            let existing = sql_query(format!(
                "{} WHERE id = 'default'",
                select_security_policy_sql()
            ))
            .get_result::<SecurityPolicyRecord>(&mut conn)
            .optional()
            .map_err(AppError::from)?;
            if let Some(existing) = existing {
                Ok(existing)
            } else {
                let now = util::now_ts();
                let insert_sql = format!(
                    "INSERT INTO security_policy (id, password_min_length, password_require_uppercase, password_require_lowercase, password_require_digit, password_require_symbol, password_reject_user_info, login_lockout_enabled, max_failed_login_attempts, failure_window_seconds, lockout_seconds, trusted_ip_cidrs, require_mfa_outside_trusted_networks, allowed_ip_cidrs, blocked_ip_cidrs, allowed_email_domains, blocked_email_domains, captcha_enabled, captcha_after_failed_attempts, captcha_ttl_seconds, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 21)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Integer, _>(settings.password_min_length)
                    .bind::<Integer, _>(i32::from(settings.password_require_uppercase))
                    .bind::<Integer, _>(i32::from(settings.password_require_lowercase))
                    .bind::<Integer, _>(i32::from(settings.password_require_digit))
                    .bind::<Integer, _>(i32::from(settings.password_require_symbol))
                    .bind::<Integer, _>(i32::from(settings.password_reject_user_info))
                    .bind::<Integer, _>(i32::from(settings.login_lockout_enabled))
                    .bind::<Integer, _>(settings.max_failed_login_attempts)
                    .bind::<BigInt, _>(settings.failure_window_seconds)
                    .bind::<BigInt, _>(settings.lockout_seconds)
                    .bind::<Text, _>(trusted_ip_cidrs)
                    .bind::<Integer, _>(i32::from(settings.require_mfa_outside_trusted_networks))
                    .bind::<Text, _>(allowed_ip_cidrs)
                    .bind::<Text, _>(blocked_ip_cidrs)
                    .bind::<Text, _>(allowed_email_domains)
                    .bind::<Text, _>(blocked_email_domains)
                    .bind::<Integer, _>(i32::from(settings.captcha_enabled))
                    .bind::<Integer, _>(settings.captcha_after_failed_attempts)
                    .bind::<BigInt, _>(settings.captcha_ttl_seconds)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
                sql_query(format!(
                    "{} WHERE id = 'default'",
                    select_security_policy_sql()
                ))
                .get_result::<SecurityPolicyRecord>(&mut conn)
                .map_err(AppError::from)
            }
        })
    }

    pub async fn upsert_security_policy(
        &self,
        settings: NewSecurityPolicy,
    ) -> AppResult<SecurityPolicyRecord> {
        let now = util::now_ts();
        let trusted_ip_cidrs = util::to_json(&settings.trusted_ip_cidrs)?;
        let allowed_ip_cidrs = util::to_json(&settings.allowed_ip_cidrs)?;
        let blocked_ip_cidrs = util::to_json(&settings.blocked_ip_cidrs)?;
        let allowed_email_domains = util::to_json(&settings.allowed_email_domains)?;
        let blocked_email_domains = util::to_json(&settings.blocked_email_domains)?;
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE security_policy SET password_min_length = {}, password_require_uppercase = {}, password_require_lowercase = {}, password_require_digit = {}, password_require_symbol = {}, password_reject_user_info = {}, login_lockout_enabled = {}, max_failed_login_attempts = {}, failure_window_seconds = {}, lockout_seconds = {}, trusted_ip_cidrs = {}, require_mfa_outside_trusted_networks = {}, allowed_ip_cidrs = {}, blocked_ip_cidrs = {}, allowed_email_domains = {}, blocked_email_domains = {}, captcha_enabled = {}, captcha_after_failed_attempts = {}, captcha_ttl_seconds = {}, updated_at = {} WHERE id = {}",
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
                ph(kind, 21)
            );
            let changed = sql_query(update_sql)
                .bind::<Integer, _>(settings.password_min_length)
                .bind::<Integer, _>(i32::from(settings.password_require_uppercase))
                .bind::<Integer, _>(i32::from(settings.password_require_lowercase))
                .bind::<Integer, _>(i32::from(settings.password_require_digit))
                .bind::<Integer, _>(i32::from(settings.password_require_symbol))
                .bind::<Integer, _>(i32::from(settings.password_reject_user_info))
                .bind::<Integer, _>(i32::from(settings.login_lockout_enabled))
                .bind::<Integer, _>(settings.max_failed_login_attempts)
                .bind::<BigInt, _>(settings.failure_window_seconds)
                .bind::<BigInt, _>(settings.lockout_seconds)
                .bind::<Text, _>(&trusted_ip_cidrs)
                .bind::<Integer, _>(i32::from(settings.require_mfa_outside_trusted_networks))
                .bind::<Text, _>(&allowed_ip_cidrs)
                .bind::<Text, _>(&blocked_ip_cidrs)
                .bind::<Text, _>(&allowed_email_domains)
                .bind::<Text, _>(&blocked_email_domains)
                .bind::<Integer, _>(i32::from(settings.captcha_enabled))
                .bind::<Integer, _>(settings.captcha_after_failed_attempts)
                .bind::<BigInt, _>(settings.captcha_ttl_seconds)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>("default")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO security_policy (id, password_min_length, password_require_uppercase, password_require_lowercase, password_require_digit, password_require_symbol, password_reject_user_info, login_lockout_enabled, max_failed_login_attempts, failure_window_seconds, lockout_seconds, trusted_ip_cidrs, require_mfa_outside_trusted_networks, allowed_ip_cidrs, blocked_ip_cidrs, allowed_email_domains, blocked_email_domains, captcha_enabled, captcha_after_failed_attempts, captcha_ttl_seconds, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 21)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Integer, _>(settings.password_min_length)
                    .bind::<Integer, _>(i32::from(settings.password_require_uppercase))
                    .bind::<Integer, _>(i32::from(settings.password_require_lowercase))
                    .bind::<Integer, _>(i32::from(settings.password_require_digit))
                    .bind::<Integer, _>(i32::from(settings.password_require_symbol))
                    .bind::<Integer, _>(i32::from(settings.password_reject_user_info))
                    .bind::<Integer, _>(i32::from(settings.login_lockout_enabled))
                    .bind::<Integer, _>(settings.max_failed_login_attempts)
                    .bind::<BigInt, _>(settings.failure_window_seconds)
                    .bind::<BigInt, _>(settings.lockout_seconds)
                    .bind::<Text, _>(trusted_ip_cidrs)
                    .bind::<Integer, _>(i32::from(settings.require_mfa_outside_trusted_networks))
                    .bind::<Text, _>(allowed_ip_cidrs)
                    .bind::<Text, _>(blocked_ip_cidrs)
                    .bind::<Text, _>(allowed_email_domains)
                    .bind::<Text, _>(blocked_email_domains)
                    .bind::<Integer, _>(i32::from(settings.captcha_enabled))
                    .bind::<Integer, _>(settings.captcha_after_failed_attempts)
                    .bind::<BigInt, _>(settings.captcha_ttl_seconds)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            sql_query(format!(
                "{} WHERE id = 'default'",
                select_security_policy_sql()
            ))
            .get_result::<SecurityPolicyRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn record_login_failure(
        &self,
        subject: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        reason: &str,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let subject = subject.to_string();
        let reason = reason.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO login_failures (id, subject, ip_address, user_agent, reason, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(subject)
                .bind::<Nullable<Text>, _>(ip_address)
                .bind::<Nullable<Text>, _>(user_agent)
                .bind::<Text, _>(reason)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn clear_login_failures(&self, subject: &str) -> AppResult<()> {
        let subject = subject.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("DELETE FROM login_failures WHERE subject = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(subject)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn login_failure_summary(
        &self,
        subject: &str,
        window_seconds: i64,
    ) -> AppResult<LoginFailureSummary> {
        let subject = subject.to_string();
        let since = util::now_ts() - window_seconds;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count, MAX(created_at) AS latest_at FROM login_failures WHERE subject = {} AND created_at >= {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(subject)
                .bind::<BigInt, _>(since)
                .get_result::<LoginFailureSummaryRow>(&mut conn)
                .map(|row| LoginFailureSummary {
                    count: row.count,
                    latest_at: row.latest_at,
                })
                .map_err(AppError::from)
        })
    }

    pub async fn create_captcha_challenge(
        &self,
        subject: &str,
        prompt: &str,
        answer: &str,
        ttl_seconds: i64,
    ) -> AppResult<CaptchaChallengeRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let subject = subject.to_string();
        let prompt = prompt.to_string();
        let answer_hash = util::hash_password(answer)?;
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM captcha_challenges WHERE expires_at < {} OR (subject = {} AND consumed_at IS NULL)",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(cleanup_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&subject)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let insert_sql = format!(
                "INSERT INTO captcha_challenges (id, subject, prompt, answer_hash, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&subject)
                .bind::<Text, _>(&prompt)
                .bind::<Text, _>(&answer_hash)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let select_sql = format!(
                "SELECT id, subject, prompt, answer_hash, expires_at, consumed_at, created_at FROM captcha_challenges WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(select_sql)
                .bind::<Text, _>(id)
                .get_result::<CaptchaChallengeRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn consume_captcha_challenge(
        &self,
        id: &str,
        subject: &str,
        answer: &str,
    ) -> AppResult<()> {
        let id = id.to_string();
        let subject = subject.to_string();
        let answer = answer.trim().to_string();
        let now = util::now_ts();
        let record = with_conn!(self, |conn, kind| {
            let select_sql = format!(
                "SELECT id, subject, prompt, answer_hash, expires_at, consumed_at, created_at FROM captcha_challenges WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(select_sql)
                .bind::<Text, _>(&id)
                .get_result::<CaptchaChallengeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })?
        .ok_or_else(|| AppError::BadRequest("captcha challenge is invalid".to_string()))?;
        if record.subject != subject || record.consumed_at.is_some() || record.expires_at < now {
            return Err(AppError::BadRequest(
                "captcha challenge is invalid".to_string(),
            ));
        }
        self.mark_captcha_challenge_consumed(&record.id, now)
            .await?;
        if util::verify_password(&record.answer_hash, &answer) {
            Ok(())
        } else {
            Err(AppError::BadRequest(
                "captcha answer is invalid".to_string(),
            ))
        }
    }

    async fn mark_captcha_challenge_consumed(&self, id: &str, now: i64) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE captcha_challenges SET consumed_at = {} WHERE id = {} AND consumed_at IS NULL",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn runtime_settings(&self) -> AppResult<RuntimeSettingsRecord> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, public_base_url, issuer, trust_proxy_headers, updated_at FROM runtime_settings WHERE id = 'default'")
                .get_result::<RuntimeSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_runtime_settings(
        &self,
        settings: NewRuntimeSettings,
    ) -> AppResult<RuntimeSettingsRecord> {
        with_conn!(self, |conn, kind| {
            let existing = sql_query("SELECT id, public_base_url, issuer, trust_proxy_headers, updated_at FROM runtime_settings WHERE id = 'default'")
                .get_result::<RuntimeSettingsRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?;
            if let Some(existing) = existing {
                return Ok(existing);
            }
            let now = util::now_ts();
            let insert_sql = format!(
                "INSERT INTO runtime_settings (id, public_base_url, issuer, trust_proxy_headers, updated_at) VALUES ({}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(insert_sql)
                .bind::<Text, _>("default")
                .bind::<Text, _>(settings.public_base_url)
                .bind::<Text, _>(settings.issuer)
                .bind::<Integer, _>(i32::from(settings.trust_proxy_headers))
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            sql_query("SELECT id, public_base_url, issuer, trust_proxy_headers, updated_at FROM runtime_settings WHERE id = 'default'")
                .get_result::<RuntimeSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_runtime_settings(
        &self,
        settings: NewRuntimeSettings,
    ) -> AppResult<RuntimeSettingsRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE runtime_settings SET public_base_url = {}, issuer = {}, trust_proxy_headers = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            let changed = sql_query(update_sql)
                .bind::<Text, _>(&settings.public_base_url)
                .bind::<Text, _>(&settings.issuer)
                .bind::<Integer, _>(i32::from(settings.trust_proxy_headers))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>("default")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO runtime_settings (id, public_base_url, issuer, trust_proxy_headers, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Text, _>(settings.public_base_url)
                    .bind::<Text, _>(settings.issuer)
                    .bind::<Integer, _>(i32::from(settings.trust_proxy_headers))
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            sql_query("SELECT id, public_base_url, issuer, trust_proxy_headers, updated_at FROM runtime_settings WHERE id = 'default'")
                .get_result::<RuntimeSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn login_settings(&self) -> AppResult<LoginSettingsRecord> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                .get_result::<LoginSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_login_settings(
        &self,
        settings: NewLoginSettings,
    ) -> AppResult<LoginSettingsRecord> {
        let NewLoginSettings {
            brand_logo_url,
            email_domains,
            quick_links,
        } = settings;
        let email_domains = util::to_json(&email_domains)?;
        let quick_links_json = util::to_json(&quick_links)?;
        with_conn!(self, |conn, kind| {
            let existing =
                sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                    .get_result::<LoginSettingsRecord>(&mut conn)
                    .optional()
                    .map_err(AppError::from)?;
            if let Some(existing) = existing {
                if let Some(quick_links) = merge_missing_quick_links(&existing, &quick_links)? {
                    let now = util::now_ts();
                    let update_sql = format!(
                        "UPDATE login_settings SET quick_links = {}, updated_at = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    sql_query(update_sql)
                        .bind::<Text, _>(quick_links)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>("default")
                        .execute(&mut conn)
                        .map_err(AppError::from)?;
                    return sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                        .get_result::<LoginSettingsRecord>(&mut conn)
                        .map_err(AppError::from);
                }
                return Ok(existing);
            }
            let now = util::now_ts();
            let insert_sql = format!(
                "INSERT INTO login_settings (id, brand_logo_url, email_domains, quick_links, updated_at) VALUES ({}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(insert_sql)
                .bind::<Text, _>("default")
                .bind::<Text, _>(brand_logo_url)
                .bind::<Text, _>(email_domains)
                .bind::<Text, _>(quick_links_json)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                .get_result::<LoginSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_login_settings(
        &self,
        settings: NewLoginSettings,
    ) -> AppResult<LoginSettingsRecord> {
        let now = util::now_ts();
        let NewLoginSettings {
            brand_logo_url,
            email_domains,
            quick_links,
        } = settings;
        let email_domains = util::to_json(&email_domains)?;
        let quick_links = util::to_json(&quick_links)?;
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE login_settings SET brand_logo_url = {}, email_domains = {}, quick_links = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            let changed = sql_query(update_sql)
                .bind::<Text, _>(&brand_logo_url)
                .bind::<Text, _>(&email_domains)
                .bind::<Text, _>(&quick_links)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>("default")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO login_settings (id, brand_logo_url, email_domains, quick_links, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Text, _>(&brand_logo_url)
                    .bind::<Text, _>(email_domains)
                    .bind::<Text, _>(quick_links)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                .get_result::<LoginSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_verification_code(
        &self,
        code: NewVerificationCode<'_>,
    ) -> AppResult<VerificationCodeRecord> {
        let NewVerificationCode {
            channel,
            target,
            purpose,
            code_hash,
            ttl_seconds,
            resend_interval_seconds,
            max_attempts,
        } = code;
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        let channel = channel.to_string();
        let target = target.to_string();
        let purpose = purpose.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<VerificationCodeRecord, AppError, _>(|conn| {
                let latest = sql_query(select_latest_verification_issue_sql(kind))
                    .bind::<Text, _>(&channel)
                    .bind::<Text, _>(&target)
                    .bind::<Text, _>(&purpose)
                    .get_result::<VerificationCodeRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                ensure_verification_resend_allowed(
                    latest.as_ref(),
                    now,
                    resend_interval_seconds,
                )?;

                let sql = format!(
                    "INSERT INTO verification_codes (id, channel, target, purpose, code_hash, attempts, max_attempts, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&channel)
                    .bind::<Text, _>(&target)
                    .bind::<Text, _>(&purpose)
                    .bind::<Text, _>(code_hash)
                    .bind::<Integer, _>(0)
                    .bind::<Integer, _>(max_attempts)
                    .bind::<BigInt, _>(expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = select_verification_code_by_id_sql(kind);
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<VerificationCodeRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_unconsumed_verification_code(&self, id: &str) -> AppResult<bool> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM verification_codes WHERE id = {} AND consumed_at IS NULL",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|affected| affected > 0)
                .map_err(AppError::from)
        })
    }

    async fn verify_verification_claims(
        &self,
        claims: Vec<VerificationCodeClaim>,
    ) -> AppResult<()> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            for claim in &claims {
                let code_hash = util::token_hash(&claim.code);
                let record =
                    latest_verification_code!(&mut conn, kind, claim).ok_or_else(|| {
                        AppError::BadRequest("verification code is missing".to_string())
                    })?;
                match record.verify_hash(&code_hash, now)? {
                    VerificationCodeDecision::Accepted(_) => {}
                    VerificationCodeDecision::RejectedAttempt(id) => {
                        increment_verification_attempts!(&mut conn, kind, &id);
                        return Err(AppError::BadRequest(
                            "verification code is invalid".to_string(),
                        ));
                    }
                }
            }
            Ok(())
        })
    }

    pub async fn consume_verification_code(
        &self,
        channel: &str,
        target: &str,
        purpose: &str,
        code: &str,
    ) -> AppResult<()> {
        let channel = channel.to_string();
        let target = target.to_string();
        let purpose = purpose.to_string();
        let code_hash = util::token_hash(code);
        let code = code.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let claim = VerificationCodeClaim {
                channel,
                target,
                purpose,
                code,
            };
            let record = latest_verification_code!(&mut conn, kind, &claim)
                .ok_or_else(|| AppError::BadRequest("verification code is missing".to_string()))?;
            let id = match record.verify_hash(&code_hash, now)? {
                VerificationCodeDecision::Accepted(id) => id,
                VerificationCodeDecision::RejectedAttempt(id) => {
                    increment_verification_attempts!(&mut conn, kind, &id);
                    return Err(AppError::BadRequest(
                        "verification code is invalid".to_string(),
                    ));
                }
            };
            let affected = mark_verification_code_consumed!(&mut conn, kind, now, &id);
            if affected == 0 {
                return Err(AppError::BadRequest(
                    "verification code is missing".to_string(),
                ));
            }
            Ok(())
        })
    }

    pub async fn list_invitations(&self) -> AppResult<Vec<InvitationRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!("{} ORDER BY created_at DESC", select_invitation_sql());
            sql_query(sql)
                .load::<InvitationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_invitation_by_id(&self, id: &str) -> AppResult<Option<InvitationRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_invitation_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<InvitationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_invitation_redemptions(&self) -> AppResult<Vec<InvitationRedemptionRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query(
                "SELECT invitation_redemptions.id, invitation_redemptions.invitation_id, invitation_redemptions.user_id, users.email AS user_email, users.username AS user_username, invitation_redemptions.redeemed_at FROM invitation_redemptions LEFT JOIN users ON users.id = invitation_redemptions.user_id ORDER BY invitation_redemptions.redeemed_at DESC",
            )
            .load::<InvitationRedemptionRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    /// Lists one bounded, keyset-paginated page of redemptions for a single
    /// authorization code.  Keeping this separate from `list_invitations`
    /// prevents a frequently-used code from making the management list grow
    /// without bound.
    pub async fn list_invitation_redemptions_for_invitation(
        &self,
        invitation_id: &str,
        before: Option<(i64, String)>,
        limit: i32,
    ) -> AppResult<Vec<InvitationRedemptionRecord>> {
        let invitation_id = invitation_id.to_string();
        with_conn!(self, |conn, kind| {
            if let Some((redeemed_at, redemption_id)) = before {
                let sql = format!(
                    "SELECT invitation_redemptions.id, invitation_redemptions.invitation_id, invitation_redemptions.user_id, users.email AS user_email, users.username AS user_username, invitation_redemptions.redeemed_at FROM invitation_redemptions LEFT JOIN users ON users.id = invitation_redemptions.user_id WHERE invitation_redemptions.invitation_id = {} AND (invitation_redemptions.redeemed_at < {} OR (invitation_redemptions.redeemed_at = {} AND invitation_redemptions.id < {})) ORDER BY invitation_redemptions.redeemed_at DESC, invitation_redemptions.id DESC LIMIT {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                );
                sql_query(sql)
                    .bind::<Text, _>(invitation_id)
                    .bind::<BigInt, _>(redeemed_at)
                    .bind::<BigInt, _>(redeemed_at)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Integer, _>(limit)
                    .load::<InvitationRedemptionRecord>(&mut conn)
                    .map_err(AppError::from)
            } else {
                let sql = format!(
                    "SELECT invitation_redemptions.id, invitation_redemptions.invitation_id, invitation_redemptions.user_id, users.email AS user_email, users.username AS user_username, invitation_redemptions.redeemed_at FROM invitation_redemptions LEFT JOIN users ON users.id = invitation_redemptions.user_id WHERE invitation_redemptions.invitation_id = {} ORDER BY invitation_redemptions.redeemed_at DESC, invitation_redemptions.id DESC LIMIT {}",
                    ph(kind, 1),
                    ph(kind, 2),
                );
                sql_query(sql)
                    .bind::<Text, _>(invitation_id)
                    .bind::<Integer, _>(limit)
                    .load::<InvitationRedemptionRecord>(&mut conn)
                    .map_err(AppError::from)
            }
        })
    }

    pub async fn insert_invitation(
        &self,
        invitation: NewInvitation,
    ) -> AppResult<(InvitationRecord, String)> {
        let code = format!(
            "{}-{}",
            match invitation.code_type {
                AuthorizationCodeType::Registration => "REG",
                AuthorizationCodeType::Login => "LOGIN",
            },
            util::random_token(18)
        );
        self.insert_invitation_with_secret(invitation, code, None, None)
            .await
    }

    /// Inserts a code whose complete value can later be revealed to an
    /// authorized manager.  The caller supplies an encrypted form produced by
    /// the server; neither the plaintext code nor its ciphertext is included
    /// in public invitation responses.
    pub async fn insert_invitation_with_reveal_secret(
        &self,
        invitation: NewInvitation,
        code: String,
        code_reveal_key_id: String,
        code_reveal_ciphertext: String,
    ) -> AppResult<(InvitationRecord, String)> {
        self.insert_invitation_with_secret(
            invitation,
            code,
            Some(code_reveal_key_id),
            Some(code_reveal_ciphertext),
        )
        .await
    }

    async fn insert_invitation_with_secret(
        &self,
        invitation: NewInvitation,
        code: String,
        code_reveal_key_id: Option<String>,
        code_reveal_ciphertext: Option<String>,
    ) -> AppResult<(InvitationRecord, String)> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let code_hash = util::token_hash(&code);
        let code_prefix = code.chars().take(12).collect::<String>();
        let allowed_client_ids = util::to_json(&invitation.allowed_client_ids)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO invitations (id, code_hash, code_prefix, code_reveal_key_id, code_reveal_ciphertext, code_type, login_code_level, allowed_client_ids, organization_id, organization_role, description, authorized_email, authorized_username, authorized_user_id, authorized_display_name, expires_at, max_uses, uses_count, is_active, created_by, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 22)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(code_hash)
                .bind::<Text, _>(code_prefix)
                .bind::<Nullable<Text>, _>(code_reveal_key_id)
                .bind::<Nullable<Text>, _>(code_reveal_ciphertext)
                .bind::<Text, _>(invitation.code_type.as_str())
                .bind::<Text, _>(invitation.login_code_level.as_str())
                .bind::<Nullable<Text>, _>(Some(allowed_client_ids))
                .bind::<Nullable<Text>, _>(invitation.organization_id)
                .bind::<Nullable<Text>, _>(invitation.organization_role)
                .bind::<Nullable<Text>, _>(invitation.description)
                .bind::<Nullable<Text>, _>(invitation.authorized_email)
                .bind::<Nullable<Text>, _>(invitation.authorized_username)
                .bind::<Nullable<Text>, _>(invitation.authorized_user_id)
                .bind::<Nullable<Text>, _>(invitation.authorized_display_name)
                .bind::<Nullable<BigInt>, _>(invitation.expires_at)
                .bind::<Nullable<Integer>, _>(invitation.max_uses)
                .bind::<Integer, _>(0)
                .bind::<Integer, _>(i32::from(invitation.is_active))
                .bind::<Nullable<Text>, _>(invitation.created_by)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_invitation_sql(), ph(kind, 1));
            let record = sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<InvitationRecord>(&mut conn)
                .map_err(AppError::from)?;
            Ok((record, code))
        })
    }

    pub async fn update_invitation(
        &self,
        update: InvitationUpdate<'_>,
    ) -> AppResult<InvitationRecord> {
        let InvitationUpdate {
            id,
            description,
            authorized_email,
            authorized_username,
            authorized_display_name,
            expires_at,
            max_uses,
            is_active,
        } = update;
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<InvitationRecord, AppError, _>(|conn| {
                let sql = format!(
                    "UPDATE invitations SET description = {}, authorized_email = {}, authorized_username = {}, authorized_display_name = {}, expires_at = {}, max_uses = {}, is_active = {}, updated_at = {} WHERE id = {}",
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
                    .bind::<Nullable<Text>, _>(description)
                    .bind::<Nullable<Text>, _>(authorized_email)
                    .bind::<Nullable<Text>, _>(authorized_username)
                    .bind::<Nullable<Text>, _>(authorized_display_name)
                    .bind::<Nullable<BigInt>, _>(expires_at)
                    .bind::<Nullable<Integer>, _>(max_uses)
                    .bind::<Integer, _>(i32::from(is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if !is_active {
                    let revoke_sql = format!(
                        "DELETE FROM oidc_login_grants WHERE invitation_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(revoke_sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    revoke_trial_enrollment_auth_state_for_invitation!(conn, kind, &id);
                    let revoke_trial_sql = format!(
                        "UPDATE trial_enrollments SET revoked_at = {} WHERE invitation_id = {} AND revoked_at IS NULL",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(revoke_trial_sql)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!("{} WHERE id = {}", select_invitation_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<InvitationRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_invitation(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let sql = format!(
                    "DELETE FROM oidc_login_grants WHERE invitation_id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                revoke_trial_enrollment_auth_state_for_invitation!(conn, kind, &id);
                let revoke_trial_sql = format!(
                    "UPDATE trial_enrollments SET revoked_at = {} WHERE invitation_id = {} AND revoked_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(revoke_trial_sql)
                    .bind::<BigInt, _>(util::now_ts())
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!("DELETE FROM invitations WHERE id = {}", ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn find_invitation_by_code(&self, code: &str) -> AppResult<InvitationRecord> {
        let code_hash = util::token_hash(code);
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE code_hash = {}",
                select_invitation_sql(),
                ph(kind, 1)
            );
            let record = sql_query(sql)
                .bind::<Text, _>(code_hash)
                .get_result::<InvitationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or_else(|| AppError::BadRequest("authorization code is invalid".to_string()))?;
            ensure_invitation_redeemable(&record, now)?;
            Ok(record)
        })
    }

    pub async fn redeem_registration_code_for_new_user(
        &self,
        code: &str,
        user: NewUser,
        verification_claims: Vec<VerificationCodeClaim>,
    ) -> AppResult<UserRecord> {
        if !verification_claims.is_empty() {
            self.verify_verification_claims(verification_claims.clone())
                .await?;
        }

        let user_id = uuid::Uuid::new_v4().to_string();
        let redemption_id = uuid::Uuid::new_v4().to_string();
        let code_hash = util::token_hash(code);
        let now = util::now_ts();
        let identity = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                let invitation_sql = format!(
                    "{} WHERE code_hash = {}",
                    select_invitation_sql(),
                    ph(kind, 1)
                );
                let invitation = sql_query(invitation_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<InvitationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or_else(|| {
                        AppError::BadRequest("registration authorization code is invalid".to_string())
                    })?;
                if invitation.authorization_code_type()?
                    != AuthorizationCodeType::Registration
                {
                    return Err(AppError::BadRequest(
                        "authorization code cannot be used for registration".to_string(),
                    ));
                }
                ensure_invitation_redeemable(&invitation, now)?;
                if invitation
                    .authorized_email
                    .as_deref()
                    .is_some_and(|value| value != user.email.as_str())
                    || invitation
                        .authorized_username
                        .as_deref()
                        .is_some_and(|value| value != user.username.as_str())
                {
                    return Err(AppError::BadRequest(
                        "registration details do not match the authorization code".to_string(),
                    ));
                }
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "registration authorization code cannot be used for an existing account"
                )?;

                let mut verification_code_ids = Vec::with_capacity(verification_claims.len());
                for claim in &verification_claims {
                    let verification_hash = util::token_hash(&claim.code);
                    let record = latest_verification_code!(conn, kind, claim).ok_or_else(|| {
                        AppError::BadRequest("verification code is missing".to_string())
                    })?;
                    match record.verify_hash(&verification_hash, now)? {
                        VerificationCodeDecision::Accepted(id) => verification_code_ids.push(id),
                        VerificationCodeDecision::RejectedAttempt(_) => {
                            return Err(AppError::BadRequest(
                                "verification code is invalid".to_string(),
                            ));
                        }
                    }
                }

                let update_sql = redeem_invitation_update_sql(kind);
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(AuthorizationCodeType::Registration.as_str())
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::BadRequest(
                        "registration authorization code is exhausted or no longer valid"
                            .to_string(),
                    ));
                }

                sql_query(insert_user_sql(
                    kind,
                    UserRegistrationSource::AuthorizationCode,
                ))
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&user.email)
                    .bind::<Text, _>(&user.username)
                    .bind::<Nullable<Text>, _>(user.display_name.clone())
                    .bind::<Nullable<Text>, _>(user.phone.clone())
                    .bind::<Text, _>(&user.password_hash)
                    .bind::<Nullable<BigInt>, _>(user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(user.phone_verified_at)
                    .bind::<Integer, _>(i32::from(user.is_admin))
                    .bind::<Integer, _>(i32::from(user.is_active))
                    .bind::<Nullable<BigInt>, _>(user.archived_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                for verification_code_id in &verification_code_ids {
                    let affected =
                        mark_verification_code_consumed!(conn, kind, now, verification_code_id);
                    if affected == 0 {
                        return Err(AppError::BadRequest(
                            "verification code is missing".to_string(),
                        ));
                    }
                }

                let select_user_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let user = sql_query(select_user_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)?;

                let insert_redemption_sql = format!(
                    "INSERT INTO invitation_redemptions (id, invitation_id, user_id, redeemed_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(insert_redemption_sql)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Text, _>(invitation.id)
                    .bind::<Text, _>(&user_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                Ok(user)
            })
        })
    }

    /// Atomically turns an active trial-enrollment code into one brand-new,
    /// restricted account.  Existing identities are never selected or reused:
    /// the code is an enrollment capability, not proof of ownership of an
    /// account name or email address.
    pub async fn redeem_trial_enrollment_code_for_new_user(
        &self,
        code: &str,
        user: NewTrialEnrollmentUser,
    ) -> AppResult<TrialEnrollmentCodeRedemption> {
        let user_id = uuid::Uuid::new_v4().to_string();
        let redemption_id = uuid::Uuid::new_v4().to_string();
        let code_hash = util::token_hash(code);
        let now = util::now_ts();
        let identity = UserIdentityCandidate {
            email: user.email.clone(),
            username: user.username.clone(),
            exclude_user_id: None,
        };
        with_conn!(self, |conn, kind| {
            conn.transaction::<TrialEnrollmentCodeRedemption, AppError, _>(|conn| {
                let invitation_sql = format!(
                    "{} WHERE code_hash = {}",
                    select_invitation_sql(),
                    ph(kind, 1)
                );
                let invitation = sql_query(invitation_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<InvitationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if invitation.authorization_code_type()? != AuthorizationCodeType::Login
                    || invitation.login_code_level()? != LoginCodeLevel::TrialEnrollment
                    || ensure_invitation_redeemable(&invitation, now).is_err()
                    || invitation.expires_at.is_some_and(|expires_at| expires_at <= now)
                {
                    return Err(AppError::Unauthorized);
                }

                let organization_id = invitation
                    .organization_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(AppError::Unauthorized)?
                    .to_string();
                let organization_role = invitation
                    .organization_role
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(AppError::Unauthorized)?;
                let organization_role = crate::organizations::normalize_role(organization_role)
                    .map_err(|_| AppError::Unauthorized)?;
                let allowed_client_ids = invitation.allowed_client_ids()?;
                if allowed_client_ids.is_empty() {
                    return Err(AppError::Unauthorized);
                }

                let organization_sql = format!(
                    "{} WHERE id = {}",
                    select_organization_sql(),
                    ph(kind, 1)
                );
                let organization = sql_query(organization_sql)
                    .bind::<Text, _>(&organization_id)
                    .get_result::<OrganizationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .filter(|organization| organization.is_active == 1)
                    .ok_or(AppError::Unauthorized)?;
                if !organization.allows_email(&user.email)? {
                    return Err(AppError::Unauthorized);
                }

                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "trial enrollment authorization code cannot be used for an existing account"
                )?;

                let affected = sql_query(redeem_trial_enrollment_invitation_update_sql(kind))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }

                sql_query(insert_user_sql(
                    kind,
                    UserRegistrationSource::AuthorizationCode,
                ))
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&user.email)
                    .bind::<Text, _>(&user.username)
                    .bind::<Nullable<Text>, _>(user.display_name.clone())
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&user.password_hash)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Integer, _>(0)
                    .bind::<Integer, _>(1)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let membership_sql = format!(
                    "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(membership_sql)
                    .bind::<Text, _>(&organization_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&organization_role)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let enrollment_sql = format!(
                    "INSERT INTO trial_enrollments (user_id, invitation_id, organization_id, organization_role, allowed_client_ids, expires_at, revoked_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8)
                );
                sql_query(enrollment_sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&organization_id)
                    .bind::<Text, _>(&organization_role)
                    .bind::<Text, _>(util::to_json(&allowed_client_ids)?)
                    .bind::<Nullable<BigInt>, _>(invitation.expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let redemption_sql = format!(
                    "INSERT INTO invitation_redemptions (id, invitation_id, user_id, redeemed_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(redemption_sql)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&user_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let user_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let user = sql_query(user_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)?;
                Ok(TrialEnrollmentCodeRedemption {
                    invitation_id: invitation.id,
                    user,
                    code_expires_at: invitation.expires_at,
                    organization_id,
                })
            })
        })
    }

    pub async fn find_trial_enrollment_for_user(
        &self,
        user_id: &str,
    ) -> AppResult<Option<TrialEnrollmentRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE user_id = {}",
                select_trial_enrollment_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .get_result::<TrialEnrollmentRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_active_trial_enrollment_for_user(
        &self,
        user_id: &str,
    ) -> AppResult<Option<TrialEnrollmentRecord>> {
        Ok(self
            .find_trial_enrollment_for_user(user_id)
            .await?
            .filter(|enrollment| enrollment.is_active_at(util::now_ts())))
    }

    pub async fn redeem_account_recovery_code(
        &self,
        code: &str,
        user_id: &str,
        email: &str,
    ) -> AppResult<AccountRecoveryCodeRedemption> {
        let code_hash = util::token_hash(code);
        let user_id = user_id.to_string();
        let email = email.to_string();
        let redemption_id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<AccountRecoveryCodeRedemption, AppError, _>(|conn| {
                let invitation_sql = format!(
                    "{} WHERE code_hash = {}",
                    select_invitation_sql(),
                    ph(kind, 1)
                );
                let invitation = sql_query(invitation_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<InvitationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if invitation.authorization_code_type()?
                    != AuthorizationCodeType::Login
                    || invitation.login_code_level()? != LoginCodeLevel::AccountRecovery
                    || ensure_invitation_redeemable(&invitation, now).is_err()
                {
                    return Err(AppError::Unauthorized);
                }
                let _bound_username = invitation
                    .authorized_username
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(AppError::Unauthorized)?;
                let authorized_user_id = invitation
                    .authorized_user_id
                    .as_deref()
                    .ok_or(AppError::Unauthorized)?;
                let user_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let user = sql_query(user_sql)
                    .bind::<Text, _>(authorized_user_id)
                    .get_result::<UserRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if user.id != user_id
                    || user.email != email
                    || user.is_active != 1
                    || user.archived_at.is_some()
                {
                    return Err(AppError::Unauthorized);
                }

                let affected = sql_query(redeem_account_recovery_invitation_update_sql(kind))
                    .bind::<Text, _>(&user.id)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::AccountRecovery.as_str())
                    .bind::<Text, _>(&user.id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::Unauthorized);
                }

                let insert_redemption_sql = format!(
                    "INSERT INTO invitation_redemptions (id, invitation_id, user_id, redeemed_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(insert_redemption_sql)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&user.id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                Ok(AccountRecoveryCodeRedemption {
                    invitation_id: invitation.id,
                    user,
                    code_expires_at: invitation.expires_at,
                })
            })
        })
    }

    pub(crate) async fn redeem_admin_login_code_for_oidc_grant(
        &self,
        input: AdminLoginCodeRedemptionInput<'_>,
    ) -> AppResult<OidcLoginGrantRedemption> {
        if input.ttl_seconds <= 0
            || input.trusted_client_id.trim().is_empty()
            || input.interaction_request_hash.trim().is_empty()
            || input.credential_hash.trim().is_empty()
        {
            return Err(AppError::Unauthorized);
        }
        let code_hash = util::token_hash(input.code);
        let user_id = input.user_id.to_string();
        let email = input.email.to_string();
        let trusted_client_id = input.trusted_client_id.to_string();
        let interaction_request_hash = input.interaction_request_hash.to_string();
        let credential_hash = input.credential_hash.to_string();
        let redemption_id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<OidcLoginGrantRedemption, AppError, _>(|conn| {
                let invitation_sql = format!(
                    "{} WHERE code_hash = {}",
                    select_invitation_sql(),
                    ph(kind, 1)
                );
                let invitation = sql_query(invitation_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<InvitationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if invitation.authorization_code_type()? != AuthorizationCodeType::Login
                    || invitation.login_code_level()? != LoginCodeLevel::AdminUniversal
                    || ensure_invitation_redeemable(&invitation, now).is_err()
                    || !invitation
                        .allowed_client_ids()?
                        .iter()
                        .any(|value| value == &trusted_client_id)
                {
                    return Err(AppError::Unauthorized);
                }

                let user_sql = format!(
                    "{} WHERE id = {}",
                    select_user_sql(),
                    ph(kind, 1)
                );
                let user = sql_query(user_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<UserRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .filter(|user| {
                        user.id == user_id
                            && user.email == email
                            && user.is_active == 1
                            && user.archived_at.is_none()
                    })
                    .ok_or(AppError::Unauthorized)?;

                let affected = sql_query(redeem_invitation_update_sql(kind))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }

                let insert_redemption_sql = format!(
                    "INSERT INTO invitation_redemptions (id, invitation_id, user_id, redeemed_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(insert_redemption_sql)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&user.id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let cleanup_sql = format!(
                    "DELETE FROM oidc_login_grants WHERE expires_at < {} OR consumed_at IS NOT NULL",
                    ph(kind, 1)
                );
                sql_query(cleanup_sql)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let expires_at = invitation
                    .expires_at
                    .unwrap_or(i64::MAX)
                    .min(now.saturating_add(input.ttl_seconds));
                if expires_at <= now {
                    return Err(AppError::Unauthorized);
                }
                let insert_grant_sql = format!(
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
                sql_query(insert_grant_sql)
                    .bind::<Text, _>(&credential_hash)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&user.id)
                    .bind::<Text, _>(&trusted_client_id)
                    .bind::<Text, _>(&interaction_request_hash)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(|_| AppError::Unauthorized)?;
                let grant = OidcLoginGrantRecord {
                    credential_hash,
                    invitation_id: invitation.id.clone(),
                    user_id: user.id.clone(),
                    client_id: trusted_client_id,
                    interaction_request_hash,
                    auth_time: now,
                    expires_at,
                    consumed_at: None,
                    created_at: now,
                };
                Ok(OidcLoginGrantRedemption {
                    invitation_id: invitation.id,
                    user,
                    grant,
                })
            })
        })
    }

    pub async fn user_has_invitation_redemption(&self, user_id: &str) -> AppResult<bool> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM invitation_redemptions INNER JOIN invitations ON invitations.id = invitation_redemptions.invitation_id WHERE invitation_redemptions.user_id = {} AND invitations.code_type = {} AND invitations.login_code_level = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                .bind::<Text, _>(LoginCodeLevel::AccountRecovery.as_str())
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count > 0)
                .map_err(AppError::from)
        })
    }

    pub async fn record_login_event(
        &self,
        user_id: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        method: &str,
        oidc_client_id: Option<String>,
        external_provider: Option<String>,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let user_id = user_id.to_string();
        let method = method.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let insert_sql = format!(
                "INSERT INTO login_events (id, user_id, login_at, ip_address, user_agent, method, oidc_client_id, external_provider) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(&user_id)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(&ip_address)
                .bind::<Nullable<Text>, _>(&user_agent)
                .bind::<Text, _>(&method)
                .bind::<Nullable<Text>, _>(&oidc_client_id)
                .bind::<Nullable<Text>, _>(&external_provider)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let update_sql = format!(
                "UPDATE users SET last_login_at = {}, last_login_ip = {}, last_oidc_client_id = {}, last_login_method = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            sql_query(update_sql)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(ip_address)
                .bind::<Nullable<Text>, _>(oidc_client_id)
                .bind::<Text, _>(method)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(user_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_login_events(
        &self,
        user_id: &str,
        limit: i64,
    ) -> AppResult<Vec<LoginEventRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, login_at, ip_address, user_agent, method, oidc_client_id, external_provider FROM login_events WHERE user_id = {} ORDER BY login_at DESC LIMIT {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<BigInt, _>(limit)
                .load::<LoginEventRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_audit_event(&self, event: crate::audit::AuditEvent) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let details = util::to_json(&event.details)?;
        let outcome = event.outcome.as_str().to_string();
        let record = AuditEventRecord {
            id,
            actor_user_id: event.actor_user_id,
            actor_client_id: event.actor_client_id,
            action: event.action,
            target_kind: event.target_kind,
            target_id: event.target_id,
            outcome,
            ip_address: event.ip_address,
            user_agent: event.user_agent,
            details,
            created_at: now,
        };
        let inserted = record.clone();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO audit_events (id, actor_user_id, actor_client_id, action, target_kind, target_id, outcome, ip_address, user_agent, details, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 11)
            );
            sql_query(sql)
                .bind::<Text, _>(record.id)
                .bind::<Nullable<Text>, _>(record.actor_user_id)
                .bind::<Nullable<Text>, _>(record.actor_client_id)
                .bind::<Text, _>(record.action)
                .bind::<Text, _>(record.target_kind)
                .bind::<Nullable<Text>, _>(record.target_id)
                .bind::<Text, _>(record.outcome)
                .bind::<Nullable<Text>, _>(record.ip_address)
                .bind::<Nullable<Text>, _>(record.user_agent)
                .bind::<Text, _>(record.details)
                .bind::<BigInt, _>(record.created_at)
                .execute(&mut conn)
                .map_err(AppError::from)
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(self.clone(), inserted);
        Ok(())
    }

    pub async fn list_audit_events(&self, limit: i64) -> AppResult<Vec<AuditEventRecord>> {
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, actor_user_id, actor_client_id, action, target_kind, target_id, outcome, ip_address, user_agent, details, created_at FROM audit_events ORDER BY created_at DESC LIMIT {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<BigInt, _>(limit.clamp(1, 500))
                .load::<AuditEventRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_audit_webhooks(&self) -> AppResult<Vec<AuditWebhookRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, name, url, secret, actions, is_active, timeout_seconds, last_delivered_at, last_status_code, last_error, created_at, updated_at FROM audit_webhooks ORDER BY created_at DESC")
                .load::<AuditWebhookRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_audit_webhook(&self, id: &str) -> AppResult<Option<AuditWebhookRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, name, url, secret, actions, is_active, timeout_seconds, last_delivered_at, last_status_code, last_error, created_at, updated_at FROM audit_webhooks WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<AuditWebhookRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_audit_webhook(
        &self,
        webhook: NewAuditWebhook,
    ) -> AppResult<AuditWebhookRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let actions = util::to_json(&webhook.actions)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO audit_webhooks (id, name, url, secret, actions, is_active, timeout_seconds, last_delivered_at, last_status_code, last_error, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                .bind::<Text, _>(&id)
                .bind::<Text, _>(webhook.name)
                .bind::<Text, _>(webhook.url)
                .bind::<Text, _>(webhook.secret)
                .bind::<Text, _>(actions)
                .bind::<Integer, _>(i32::from(webhook.is_active))
                .bind::<Integer, _>(webhook.timeout_seconds)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<Integer>, _>(None::<i32>)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "SELECT id, name, url, secret, actions, is_active, timeout_seconds, last_delivered_at, last_status_code, last_error, created_at, updated_at FROM audit_webhooks WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<AuditWebhookRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_audit_webhook(
        &self,
        id: &str,
        webhook: UpdateAuditWebhook,
    ) -> AppResult<AuditWebhookRecord> {
        let id = id.to_string();
        let actions = util::to_json(&webhook.actions)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let existing_sql = format!(
                "SELECT id, name, url, secret, actions, is_active, timeout_seconds, last_delivered_at, last_status_code, last_error, created_at, updated_at FROM audit_webhooks WHERE id = {}",
                ph(kind, 1)
            );
            let existing = sql_query(existing_sql)
                .bind::<Text, _>(&id)
                .get_result::<AuditWebhookRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or(AppError::NotFound)?;
            let secret = webhook.secret.unwrap_or(existing.secret);
            let sql = format!(
                "UPDATE audit_webhooks SET name = {}, url = {}, secret = {}, actions = {}, is_active = {}, timeout_seconds = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            sql_query(sql)
                .bind::<Text, _>(webhook.name)
                .bind::<Text, _>(webhook.url)
                .bind::<Text, _>(secret)
                .bind::<Text, _>(actions)
                .bind::<Integer, _>(i32::from(webhook.is_active))
                .bind::<Integer, _>(webhook.timeout_seconds)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "SELECT id, name, url, secret, actions, is_active, timeout_seconds, last_delivered_at, last_status_code, last_error, created_at, updated_at FROM audit_webhooks WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<AuditWebhookRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_audit_webhook(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("DELETE FROM audit_webhooks WHERE id = {}", ph(kind, 1));
            let affected = sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
    }

    pub async fn update_audit_webhook_delivery_status(
        &self,
        id: &str,
        status_code: Option<i32>,
        error: Option<String>,
    ) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE audit_webhooks SET last_delivered_at = {}, last_status_code = {}, last_error = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Integer>, _>(status_code)
                .bind::<Nullable<Text>, _>(error)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_system_roles(&self) -> AppResult<()> {
        let all_permissions = crate::access::Permission::ALL
            .iter()
            .map(|permission| permission.as_str().to_string())
            .collect::<Vec<_>>();
        self.upsert_system_role(
            "security-admin",
            Some("Full administrative access".to_string()),
            all_permissions,
        )
        .await?;
        self.upsert_system_role(
            "auditor",
            Some("Read-only audit access".to_string()),
            vec![crate::access::Permission::AuditRead.as_str().to_string()],
        )
        .await?;
        Ok(())
    }

    async fn upsert_system_role(
        &self,
        name: &str,
        description: Option<String>,
        permissions: Vec<String>,
    ) -> AppResult<()> {
        let name = name.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let select_sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE name = {}",
                ph(kind, 1)
            );
            let existing = sql_query(select_sql)
                .bind::<Text, _>(&name)
                .get_result::<RoleRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?;
            let role_id = if let Some(role) = existing {
                let update_sql = format!(
                    "UPDATE roles SET description = {}, is_system = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(update_sql)
                    .bind::<Nullable<Text>, _>(&description)
                    .bind::<Integer, _>(1)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&role.id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
                role.id
            } else {
                let id = uuid::Uuid::new_v4().to_string();
                let insert_sql = format!(
                    "INSERT INTO roles (id, name, description, is_system, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&name)
                    .bind::<Nullable<Text>, _>(&description)
                    .bind::<Integer, _>(1)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
                id
            };
            let delete_sql = format!(
                "DELETE FROM role_permissions WHERE role_id = {}",
                ph(kind, 1)
            );
            sql_query(delete_sql)
                .bind::<Text, _>(&role_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            for permission in permissions {
                let insert_sql = format!(
                    "INSERT INTO role_permissions (role_id, permission) VALUES ({}, {})",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&role_id)
                    .bind::<Text, _>(permission)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            Ok(())
        })
    }

    pub async fn list_roles(&self) -> AppResult<Vec<RoleRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, name, description, is_system, created_at, updated_at FROM roles ORDER BY name ASC")
                .load::<RoleRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_role_by_id(&self, id: &str) -> AppResult<Option<RoleRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<RoleRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_role(&self, role: NewRole) -> AppResult<RoleRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let name = role.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("role name is required".to_string()));
        }
        let description = role.description.map(|value| value.trim().to_string());
        let permissions = normalize_permission_keys(role.permissions)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO roles (id, name, description, is_system, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&name)
                .bind::<Nullable<Text>, _>(description)
                .bind::<Integer, _>(i32::from(role.is_system))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            for permission in permissions {
                let sql = format!(
                    "INSERT INTO role_permissions (role_id, permission) VALUES ({}, {})",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(permission)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }

            let sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<RoleRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_role(&self, id: &str, role: NewRole) -> AppResult<RoleRecord> {
        let id = id.to_string();
        let name = role.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("role name is required".to_string()));
        }
        let description = role.description.map(|value| value.trim().to_string());
        let permissions = normalize_permission_keys(role.permissions)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE id = {}",
                ph(kind, 1)
            );
            let existing = sql_query(sql)
                .bind::<Text, _>(&id)
                .get_result::<RoleRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or(AppError::NotFound)?;
            if existing.is_system != 0 {
                return Err(AppError::BadRequest(
                    "system roles cannot be updated".to_string(),
                ));
            }

            let sql = format!(
                "UPDATE roles SET name = {}, description = {}, is_system = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(sql)
                .bind::<Text, _>(name)
                .bind::<Nullable<Text>, _>(description)
                .bind::<Integer, _>(i32::from(role.is_system))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!(
                "DELETE FROM role_permissions WHERE role_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            for permission in permissions {
                let sql = format!(
                    "INSERT INTO role_permissions (role_id, permission) VALUES ({}, {})",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(permission)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }

            let sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<RoleRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_role(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE id = {}",
                ph(kind, 1)
            );
            let existing = sql_query(sql)
                .bind::<Text, _>(&id)
                .get_result::<RoleRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or(AppError::NotFound)?;
            if existing.is_system != 0 {
                return Err(AppError::BadRequest(
                    "system roles cannot be deleted".to_string(),
                ));
            }

            for table in ["role_permissions", "user_roles", "group_roles"] {
                let sql = format!("DELETE FROM {table} WHERE role_id = {}", ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!("DELETE FROM roles WHERE id = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_role_permissions(&self, role_id: &str) -> AppResult<Vec<String>> {
        let role_id = role_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT permission FROM role_permissions WHERE role_id = {} ORDER BY permission ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(role_id)
                .load::<PermissionRow>(&mut conn)
                .map(|rows| rows.into_iter().map(|row| row.permission).collect())
                .map_err(AppError::from)
        })
    }

    pub async fn list_groups(&self) -> AppResult<Vec<GroupRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, name, description, created_at, updated_at FROM access_groups ORDER BY name ASC")
                .load::<GroupRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_group_by_id(&self, id: &str) -> AppResult<Option<GroupRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, name, description, created_at, updated_at FROM access_groups WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<GroupRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_group(&self, group: NewGroup) -> AppResult<GroupRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let name = group.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("group name is required".to_string()));
        }
        let description = group.description.map(|value| value.trim().to_string());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO access_groups (id, name, description, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(name)
                .bind::<Nullable<Text>, _>(description)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!(
                "SELECT id, name, description, created_at, updated_at FROM access_groups WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<GroupRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_group(&self, id: &str, group: NewGroup) -> AppResult<GroupRecord> {
        let id = id.to_string();
        let name = group.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("group name is required".to_string()));
        }
        let description = group.description.map(|value| value.trim().to_string());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE access_groups SET name = {}, description = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(sql)
                .bind::<Text, _>(name)
                .bind::<Nullable<Text>, _>(description)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!(
                "SELECT id, name, description, created_at, updated_at FROM access_groups WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<GroupRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_group(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            for table in ["group_members", "group_roles"] {
                let sql = format!("DELETE FROM {table} WHERE group_id = {}", ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!("DELETE FROM access_groups WHERE id = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_user_roles(&self, user_id: &str) -> AppResult<Vec<RoleRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT roles.id, roles.name, roles.description, roles.is_system, roles.created_at, roles.updated_at FROM roles INNER JOIN user_roles ON roles.id = user_roles.role_id WHERE user_roles.user_id = {} ORDER BY roles.name ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<RoleRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_user_groups(&self, user_id: &str) -> AppResult<Vec<GroupRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at FROM access_groups INNER JOIN group_members ON access_groups.id = group_members.group_id WHERE group_members.user_id = {} ORDER BY access_groups.name ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<GroupRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn replace_user_roles(&self, user_id: &str, role_ids: Vec<String>) -> AppResult<()> {
        let user_id = user_id.to_string();
        let role_ids = dedupe_nonempty(role_ids);
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM users WHERE id = {}",
                ph(kind, 1)
            );
            let count = sql_query(sql)
                .bind::<Text, _>(&user_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count;
            if count == 0 {
                return Err(AppError::NotFound);
            }

            for role_id in &role_ids {
                let sql = format!(
                    "SELECT COUNT(*) AS count FROM roles WHERE id = {}",
                    ph(kind, 1)
                );
                let count = sql_query(sql)
                    .bind::<Text, _>(role_id)
                    .get_result::<CountRow>(&mut conn)
                    .map_err(AppError::from)?
                    .count;
                if count == 0 {
                    return Err(AppError::BadRequest(format!("unknown role: {role_id}")));
                }
            }

            let sql = format!("DELETE FROM user_roles WHERE user_id = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(&user_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            for role_id in role_ids {
                let sql = format!(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ({}, {})",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(role_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            Ok(())
        })
    }

    pub async fn list_group_roles(&self, group_id: &str) -> AppResult<Vec<RoleRecord>> {
        let group_id = group_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT roles.id, roles.name, roles.description, roles.is_system, roles.created_at, roles.updated_at FROM roles INNER JOIN group_roles ON roles.id = group_roles.role_id WHERE group_roles.group_id = {} ORDER BY roles.name ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(group_id)
                .load::<RoleRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn replace_group_roles(
        &self,
        group_id: &str,
        role_ids: Vec<String>,
    ) -> AppResult<()> {
        let group_id = group_id.to_string();
        let role_ids = dedupe_nonempty(role_ids);
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM access_groups WHERE id = {}",
                ph(kind, 1)
            );
            let count = sql_query(sql)
                .bind::<Text, _>(&group_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count;
            if count == 0 {
                return Err(AppError::NotFound);
            }

            for role_id in &role_ids {
                let sql = format!(
                    "SELECT COUNT(*) AS count FROM roles WHERE id = {}",
                    ph(kind, 1)
                );
                let count = sql_query(sql)
                    .bind::<Text, _>(role_id)
                    .get_result::<CountRow>(&mut conn)
                    .map_err(AppError::from)?
                    .count;
                if count == 0 {
                    return Err(AppError::BadRequest(format!("unknown role: {role_id}")));
                }
            }

            let sql = format!("DELETE FROM group_roles WHERE group_id = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(&group_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            for role_id in role_ids {
                let sql = format!(
                    "INSERT INTO group_roles (group_id, role_id) VALUES ({}, {})",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&group_id)
                    .bind::<Text, _>(role_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            Ok(())
        })
    }

    pub async fn list_group_members(&self, group_id: &str) -> AppResult<Vec<UserRecord>> {
        let group_id = group_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT users.id, users.email, users.username, users.display_name, users.phone, users.password_hash, users.email_verified_at, users.phone_verified_at, users.is_admin, users.is_active, users.archived_at, users.registration_source, users.last_login_at, users.last_login_ip, users.last_oidc_client_id, users.last_login_method, users.created_at, users.updated_at FROM users INNER JOIN group_members ON users.id = group_members.user_id WHERE group_members.group_id = {} ORDER BY users.email ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(group_id)
                .load::<UserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn replace_group_members(
        &self,
        group_id: &str,
        user_ids: Vec<String>,
    ) -> AppResult<()> {
        let group_id = group_id.to_string();
        let user_ids = dedupe_nonempty(user_ids);
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM access_groups WHERE id = {}",
                ph(kind, 1)
            );
            let count = sql_query(sql)
                .bind::<Text, _>(&group_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count;
            if count == 0 {
                return Err(AppError::NotFound);
            }

            for user_id in &user_ids {
                let sql = format!(
                    "SELECT COUNT(*) AS count FROM users WHERE id = {}",
                    ph(kind, 1)
                );
                let count = sql_query(sql)
                    .bind::<Text, _>(user_id)
                    .get_result::<CountRow>(&mut conn)
                    .map_err(AppError::from)?
                    .count;
                if count == 0 {
                    return Err(AppError::BadRequest(format!("unknown user: {user_id}")));
                }
            }

            let sql = format!("DELETE FROM group_members WHERE group_id = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(&group_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            for user_id in user_ids {
                let sql = format!(
                    "INSERT INTO group_members (group_id, user_id) VALUES ({}, {})",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&group_id)
                    .bind::<Text, _>(user_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            Ok(())
        })
    }

    pub async fn list_organizations(&self) -> AppResult<Vec<OrganizationRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!(
                "{} ORDER BY is_active DESC, slug ASC",
                select_organization_sql()
            );
            sql_query(sql)
                .load::<OrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_organization_member_counts(&self) -> AppResult<BTreeMap<String, i64>> {
        with_conn!(self, |conn, _kind| {
            sql_query(
                "SELECT organization_id, COUNT(*) AS member_count FROM organization_members GROUP BY organization_id",
            )
            .load::<OrganizationMemberCountRecord>(&mut conn)
            .map(|counts| {
                counts
                    .into_iter()
                    .map(|count| (count.organization_id, count.member_count))
                    .collect()
            })
            .map_err(AppError::from)
        })
    }

    pub async fn count_organization_members(&self, organization_id: &str) -> AppResult<i64> {
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM organization_members WHERE organization_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count)
                .map_err(AppError::from)
        })
    }

    pub async fn find_organization_by_id(&self, id: &str) -> AppResult<Option<OrganizationRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<OrganizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_organization(
        &self,
        organization: NewOrganization,
    ) -> AppResult<OrganizationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let allowed_email_domains = util::to_json(&organization.allowed_email_domains)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO organizations (id, slug, name, description, allowed_email_domains, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(organization.slug)
                .bind::<Text, _>(organization.name)
                .bind::<Nullable<Text>, _>(organization.description)
                .bind::<Text, _>(allowed_email_domains)
                .bind::<Integer, _>(i32::from(organization.is_active))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<OrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_organization(
        &self,
        id: &str,
        organization: NewOrganization,
    ) -> AppResult<OrganizationRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let allowed_email_domains = util::to_json(&organization.allowed_email_domains)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE organizations SET slug = {}, name = {}, description = {}, allowed_email_domains = {}, is_active = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(organization.slug)
                .bind::<Text, _>(organization.name)
                .bind::<Nullable<Text>, _>(organization.description)
                .bind::<Text, _>(allowed_email_domains)
                .bind::<Integer, _>(i32::from(organization.is_active))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<OrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_organization(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let sql = format!(
                    "UPDATE clients SET organization_id = NULL, updated_at = {} WHERE organization_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "UPDATE external_oidc_providers SET organization_id = NULL, updated_at = {} WHERE organization_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                // Trial-enrollment authorization codes cannot survive without
                // their one required organization.  Remove their outstanding
                // grants before deleting the codes, then revoke every trial
                // account that was created for this organization below.
                let sql = format!(
                    "DELETE FROM oidc_login_grants WHERE invitation_id IN (SELECT id FROM invitations WHERE organization_id = {} AND code_type = {} AND login_code_level = {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "DELETE FROM invitations WHERE organization_id = {} AND code_type = {} AND login_code_level = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                    .execute(conn)
                    .map_err(AppError::from)?;
                revoke_trial_enrollment_auth_state_for_organization!(conn, kind, &id);
                let sql = format!(
                    "UPDATE trial_enrollments SET revoked_at = {} WHERE organization_id = {} AND revoked_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                // The public API only permits an organization on trial
                // enrollment codes.  Clear it from any pre-existing legacy
                // or malformed records instead of deleting an otherwise
                // independent authorization code.
                let sql = format!(
                    "UPDATE invitations SET organization_id = NULL, organization_role = NULL, updated_at = {} WHERE organization_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "DELETE FROM organization_members WHERE organization_id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!("DELETE FROM organizations WHERE id = {}", ph(kind, 1));
                let affected = sql_query(sql)
                    .bind::<Text, _>(id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::NotFound);
                }
                Ok(())
            })
        })
    }

    pub async fn replace_organization_members(
        &self,
        organization_id: &str,
        members: Vec<OrganizationMemberInput>,
    ) -> AppResult<()> {
        let organization_id = organization_id.to_string();
        let members = dedupe_organization_members(members);
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let sql = format!(
                    "SELECT COUNT(*) AS count FROM organizations WHERE id = {}",
                    ph(kind, 1)
                );
                let count = sql_query(sql)
                    .bind::<Text, _>(&organization_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                if count == 0 {
                    return Err(AppError::NotFound);
                }

                for member in &members {
                    let sql = format!("SELECT COUNT(*) AS count FROM users WHERE id = {}", ph(kind, 1));
                    let count = sql_query(sql)
                        .bind::<Text, _>(&member.user_id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count;
                    if count == 0 {
                        return Err(AppError::BadRequest(format!(
                            "unknown user: {}",
                            member.user_id
                        )));
                    }
                }

                let sql = format!(
                    "DELETE FROM organization_members WHERE organization_id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&organization_id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                for member in members {
                    let sql = format!(
                        "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&organization_id)
                        .bind::<Text, _>(member.user_id)
                        .bind::<Text, _>(member.role)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    pub async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> AppResult<Vec<OrganizationMemberWithUserRecord>> {
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT organization_members.organization_id, organization_members.user_id, organization_members.role, organization_members.created_at AS membership_created_at, organization_members.updated_at AS membership_updated_at, users.email, users.username, users.display_name, users.is_active, users.archived_at FROM organization_members INNER JOIN users ON users.id = organization_members.user_id WHERE organization_members.organization_id = {} ORDER BY organization_members.role ASC, users.email ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .load::<OrganizationMemberWithUserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_user_organizations(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<UserOrganizationRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT organizations.id, organizations.slug, organizations.name, organizations.description, organizations.is_active, organization_members.role, organization_members.created_at AS membership_created_at, organization_members.updated_at AS membership_updated_at FROM organization_members INNER JOIN organizations ON organizations.id = organization_members.organization_id WHERE organization_members.user_id = {} ORDER BY organizations.is_active DESC, organizations.slug ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<UserOrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_effective_permissions(&self, user_id: &str) -> AppResult<Vec<String>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT DISTINCT permission FROM role_permissions WHERE role_id IN (SELECT role_id FROM user_roles WHERE user_id = {}) OR role_id IN (SELECT group_roles.role_id FROM group_roles INNER JOIN group_members ON group_roles.group_id = group_members.group_id WHERE group_members.user_id = {}) ORDER BY permission ASC",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&user_id)
                .load::<PermissionRow>(&mut conn)
                .map(|rows| rows.into_iter().map(|row| row.permission).collect())
                .map_err(AppError::from)
        })
    }

    pub async fn list_linked_identities(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<LinkedIdentityRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, provider_slug, external_subject, external_email, created_at, updated_at FROM linked_identities WHERE user_id = {} ORDER BY created_at DESC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<LinkedIdentityRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_user_ids_with_linked_identities(&self) -> AppResult<Vec<String>> {
        #[derive(diesel::QueryableByName)]
        struct UserIdRow {
            #[diesel(sql_type = Text)]
            user_id: String,
        }

        with_conn!(self, |conn, _kind| {
            sql_query("SELECT DISTINCT user_id FROM linked_identities")
                .load::<UserIdRow>(&mut conn)
                .map(|rows| rows.into_iter().map(|row| row.user_id).collect())
                .map_err(AppError::from)
        })
    }

    pub async fn find_linked_identity(
        &self,
        provider_slug: &str,
        external_subject: &str,
    ) -> AppResult<Option<LinkedIdentityRecord>> {
        let provider_slug = provider_slug.to_string();
        let external_subject = external_subject.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, provider_slug, external_subject, external_email, created_at, updated_at FROM linked_identities WHERE provider_slug = {} AND external_subject = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(provider_slug)
                .bind::<Text, _>(external_subject)
                .get_result::<LinkedIdentityRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_linked_identity(
        &self,
        user_id: &str,
        provider_slug: &str,
        external_subject: &str,
        external_email: Option<String>,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let user_id = user_id.to_string();
        let provider_slug = provider_slug.to_string();
        let external_subject = external_subject.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO linked_identities (id, user_id, provider_slug, external_subject, external_email, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(provider_slug)
                .bind::<Text, _>(external_subject)
                .bind::<Nullable<Text>, _>(external_email)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_external_oidc_providers(&self) -> AppResult<Vec<ExternalOidcProviderRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!(
                "{} ORDER BY display_name ASC",
                select_external_oidc_provider_sql()
            );
            sql_query(sql)
                .load::<ExternalOidcProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_external_oidc_provider(
        &self,
        slug: &str,
    ) -> AppResult<Option<ExternalOidcProviderRecord>> {
        let slug = slug.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE slug = {}",
                select_external_oidc_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(slug)
                .get_result::<ExternalOidcProviderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_external_oidc_provider_by_id(
        &self,
        id: &str,
    ) -> AppResult<Option<ExternalOidcProviderRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                select_external_oidc_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ExternalOidcProviderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_external_oidc_provider(
        &self,
        provider: NewExternalOidcProvider,
    ) -> AppResult<ExternalOidcProviderRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let scopes = util::to_json(&provider.scopes)?;
        let email_domains = util::to_json(&provider.email_domains)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO external_oidc_providers (id, slug, display_name, organization_id, issuer, client_id, client_secret, authorization_endpoint, token_endpoint, userinfo_endpoint, redirect_path, scopes, email_domains, is_active, allow_login, allow_registration, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 18)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(provider.slug)
                .bind::<Text, _>(provider.display_name)
                .bind::<Nullable<Text>, _>(provider.organization_id)
                .bind::<Text, _>(provider.issuer)
                .bind::<Text, _>(provider.client_id)
                .bind::<Text, _>(provider.client_secret)
                .bind::<Text, _>(provider.authorization_endpoint)
                .bind::<Text, _>(provider.token_endpoint)
                .bind::<Text, _>(provider.userinfo_endpoint)
                .bind::<Text, _>(provider.redirect_path)
                .bind::<Text, _>(scopes)
                .bind::<Text, _>(email_domains)
                .bind::<Integer, _>(i32::from(provider.is_active))
                .bind::<Integer, _>(i32::from(provider.allow_login))
                .bind::<Integer, _>(i32::from(provider.allow_registration))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE id = {}",
                select_external_oidc_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ExternalOidcProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_external_oidc_provider(
        &self,
        id: &str,
        provider: NewExternalOidcProvider,
    ) -> AppResult<ExternalOidcProviderRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let scopes = util::to_json(&provider.scopes)?;
        let email_domains = util::to_json(&provider.email_domains)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE external_oidc_providers SET slug = {}, display_name = {}, organization_id = {}, issuer = {}, client_id = {}, client_secret = {}, authorization_endpoint = {}, token_endpoint = {}, userinfo_endpoint = {}, redirect_path = {}, scopes = {}, email_domains = {}, is_active = {}, allow_login = {}, allow_registration = {}, updated_at = {} WHERE id = {}",
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
                ph(kind, 17)
            );
            sql_query(sql)
                .bind::<Text, _>(provider.slug)
                .bind::<Text, _>(provider.display_name)
                .bind::<Nullable<Text>, _>(provider.organization_id)
                .bind::<Text, _>(provider.issuer)
                .bind::<Text, _>(provider.client_id)
                .bind::<Text, _>(provider.client_secret)
                .bind::<Text, _>(provider.authorization_endpoint)
                .bind::<Text, _>(provider.token_endpoint)
                .bind::<Text, _>(provider.userinfo_endpoint)
                .bind::<Text, _>(provider.redirect_path)
                .bind::<Text, _>(scopes)
                .bind::<Text, _>(email_domains)
                .bind::<Integer, _>(i32::from(provider.is_active))
                .bind::<Integer, _>(i32::from(provider.allow_login))
                .bind::<Integer, _>(i32::from(provider.allow_registration))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE id = {}",
                select_external_oidc_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ExternalOidcProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_external_oidc_provider(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM external_oidc_providers WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_ldap_providers(&self) -> AppResult<Vec<LdapProviderRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query(format!(
                "{} ORDER BY display_name ASC",
                select_ldap_provider_sql()
            ))
            .load::<LdapProviderRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn find_ldap_provider(&self, slug: &str) -> AppResult<Option<LdapProviderRecord>> {
        let slug = slug.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE slug = {}",
                select_ldap_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(slug)
                .get_result::<LdapProviderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_ldap_provider(
        &self,
        provider: NewLdapProvider,
    ) -> AppResult<LdapProviderRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO ldap_providers (id, slug, display_name, url, starttls, bind_dn, bind_password, base_dn, user_filter, user_id_attribute, email_attribute, username_attribute, display_name_attribute, phone_attribute, is_active, allow_login, allow_registration, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 19)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(provider.slug)
                .bind::<Text, _>(provider.display_name)
                .bind::<Text, _>(provider.url)
                .bind::<Integer, _>(i32::from(provider.starttls))
                .bind::<Text, _>(provider.bind_dn)
                .bind::<Text, _>(provider.bind_password.unwrap_or_default())
                .bind::<Text, _>(provider.base_dn)
                .bind::<Text, _>(provider.user_filter)
                .bind::<Text, _>(provider.user_id_attribute)
                .bind::<Text, _>(provider.email_attribute)
                .bind::<Text, _>(provider.username_attribute)
                .bind::<Text, _>(provider.display_name_attribute)
                .bind::<Text, _>(provider.phone_attribute)
                .bind::<Integer, _>(i32::from(provider.is_active))
                .bind::<Integer, _>(i32::from(provider.allow_login))
                .bind::<Integer, _>(i32::from(provider.allow_registration))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_ldap_provider_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<LdapProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_ldap_provider(
        &self,
        id: &str,
        provider: NewLdapProvider,
    ) -> AppResult<LdapProviderRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let existing_sql = format!("{} WHERE id = {}", select_ldap_provider_sql(), ph(kind, 1));
            let existing = sql_query(existing_sql)
                .bind::<Text, _>(&id)
                .get_result::<LdapProviderRecord>(&mut conn)
                .map_err(AppError::from)?;
            let bind_password = provider.bind_password.unwrap_or(existing.bind_password);
            let sql = format!(
                "UPDATE ldap_providers SET slug = {}, display_name = {}, url = {}, starttls = {}, bind_dn = {}, bind_password = {}, base_dn = {}, user_filter = {}, user_id_attribute = {}, email_attribute = {}, username_attribute = {}, display_name_attribute = {}, phone_attribute = {}, is_active = {}, allow_login = {}, allow_registration = {}, updated_at = {} WHERE id = {}",
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
                ph(kind, 18)
            );
            sql_query(sql)
                .bind::<Text, _>(provider.slug)
                .bind::<Text, _>(provider.display_name)
                .bind::<Text, _>(provider.url)
                .bind::<Integer, _>(i32::from(provider.starttls))
                .bind::<Text, _>(provider.bind_dn)
                .bind::<Text, _>(bind_password)
                .bind::<Text, _>(provider.base_dn)
                .bind::<Text, _>(provider.user_filter)
                .bind::<Text, _>(provider.user_id_attribute)
                .bind::<Text, _>(provider.email_attribute)
                .bind::<Text, _>(provider.username_attribute)
                .bind::<Text, _>(provider.display_name_attribute)
                .bind::<Text, _>(provider.phone_attribute)
                .bind::<Integer, _>(i32::from(provider.is_active))
                .bind::<Integer, _>(i32::from(provider.allow_login))
                .bind::<Integer, _>(i32::from(provider.allow_registration))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_ldap_provider_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<LdapProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_ldap_provider(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("DELETE FROM ldap_providers WHERE id = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn insert_external_oidc_user(
        &self,
        user: NewUser,
        provider_slug: &str,
        external_subject: &str,
        external_email: Option<String>,
        organization_id: Option<String>,
        expected_first_user: bool,
    ) -> AppResult<UserRecord> {
        let user_id = uuid::Uuid::new_v4().to_string();
        let linked_identity_id = uuid::Uuid::new_v4().to_string();
        let provider_slug = provider_slug.to_string();
        let external_subject = external_subject.to_string();
        let organization_id = organization_id.map(|value| value.trim().to_string());
        let now = util::now_ts();
        let identity = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                ensure_first_user_registration_still_first!(conn, expected_first_user)?;
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "external OIDC email or username already belongs to an existing account"
                )?;

                let existing_identity_count = sql_query(count_linked_identity_sql(kind))
                    .bind::<Text, _>(&provider_slug)
                    .bind::<Text, _>(&external_subject)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                if existing_identity_count > 0 {
                    return Err(AppError::BadRequest(
                        "external OIDC identity is already linked".to_string(),
                    ));
                }

                sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&user.email)
                    .bind::<Text, _>(&user.username)
                    .bind::<Nullable<Text>, _>(user.display_name.clone())
                    .bind::<Nullable<Text>, _>(user.phone.clone())
                    .bind::<Text, _>(&user.password_hash)
                    .bind::<Nullable<BigInt>, _>(user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(user.phone_verified_at)
                    .bind::<Integer, _>(i32::from(user.is_admin))
                    .bind::<Integer, _>(i32::from(user.is_active))
                    .bind::<Nullable<BigInt>, _>(user.archived_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let linked_identity_sql = format!(
                    "INSERT INTO linked_identities (id, user_id, provider_slug, external_subject, external_email, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7)
                );
                sql_query(linked_identity_sql)
                    .bind::<Text, _>(linked_identity_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(provider_slug)
                    .bind::<Text, _>(external_subject)
                    .bind::<Nullable<Text>, _>(external_email)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                if let Some(organization_id) = organization_id.as_deref() {
                    let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
                    let organization = sql_query(sql)
                        .bind::<Text, _>(organization_id)
                        .get_result::<OrganizationRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?
                        .ok_or_else(|| {
                            AppError::BadRequest(
                            "external OIDC provider organization is missing".to_string(),
                            )
                        })?;
                    if !organization.allows_email(&user.email)? {
                        return Err(AppError::Forbidden);
                    }
                    let sql = format!(
                        "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(organization_id)
                        .bind::<Text, _>(&user_id)
                        .bind::<Text, _>(crate::organizations::ROLE_MEMBER)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(user_id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_external_oidc_state(
        &self,
        state: String,
        provider_slug: String,
        nonce: String,
        return_to: Option<String>,
        ttl_seconds: i64,
    ) -> AppResult<()> {
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO external_oidc_states (state, provider_slug, nonce, return_to, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(state)
                .bind::<Text, _>(provider_slug)
                .bind::<Text, _>(nonce)
                .bind::<Nullable<Text>, _>(return_to)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn consume_external_oidc_state(
        &self,
        state_value: &str,
    ) -> AppResult<ExternalOidcStateRecord> {
        let state_value = state_value.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT state, provider_slug, nonce, return_to, expires_at, consumed_at, created_at FROM external_oidc_states WHERE state = {}",
                ph(kind, 1)
            );
            let record = sql_query(sql)
                .bind::<Text, _>(&state_value)
                .get_result::<ExternalOidcStateRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or_else(|| AppError::BadRequest("OIDC state is invalid".to_string()))?;
            if record.expires_at < now || record.consumed_at.is_some() {
                return Err(AppError::BadRequest("OIDC state expired".to_string()));
            }
            let sql = format!(
                "UPDATE external_oidc_states SET consumed_at = {} WHERE state = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(state_value)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(record)
        })
    }
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
            let sql = count_linked_identity_sql(kind);
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
            assert!(select_sql.contains("ORDER BY created_at DESC LIMIT 1"));

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
    async fn deleting_an_organization_removes_members_and_cleans_authorization_codes() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "deleted-team".to_string(),
                name: "Deleted Team".to_string(),
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
    async fn iap_application_crud_normalizes_policy_fields() {
        let (db, path) = sqlite_test_db().await;
        let created = db
            .insert_iap_application(NewIapApplication {
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
    async fn external_oidc_user_creation_respects_provider_organization_email_policy() {
        let (db, path) = sqlite_test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "corp".to_string(),
                name: "Corp".to_string(),
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
}

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
    "CREATE TABLE IF NOT EXISTS dpop_proofs (
        jkt TEXT NOT NULL,
        jti TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (jkt, jti)
    )",
    "CREATE INDEX IF NOT EXISTS idx_dpop_proofs_expires ON dpop_proofs(expires_at)",
    "CREATE TABLE IF NOT EXISTS user_consents (
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        granted_scopes TEXT NOT NULL,
        granted_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        revoked_at INTEGER,
        PRIMARY KEY (user_id, client_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_user_consents_client ON user_consents(client_id, revoked_at)",
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
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS group_members (
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        PRIMARY KEY (group_id, user_id)
    )",
    "CREATE TABLE IF NOT EXISTS group_roles (
        group_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        PRIMARY KEY (group_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        allowed_email_domains TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "ALTER TABLE organizations ADD COLUMN allowed_email_domains TEXT NOT NULL DEFAULT '[]'",
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
    "CREATE TABLE IF NOT EXISTS ldap_providers (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
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
    "CREATE TABLE IF NOT EXISTS dpop_proofs (
        jkt TEXT NOT NULL,
        jti TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (jkt, jti)
    )",
    "CREATE INDEX IF NOT EXISTS idx_dpop_proofs_expires ON dpop_proofs(expires_at)",
    "CREATE TABLE IF NOT EXISTS user_consents (
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        granted_scopes TEXT NOT NULL,
        granted_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        revoked_at BIGINT,
        PRIMARY KEY (user_id, client_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_user_consents_client ON user_consents(client_id, revoked_at)",
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
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS group_members (
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        PRIMARY KEY (group_id, user_id)
    )",
    "CREATE TABLE IF NOT EXISTS group_roles (
        group_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        PRIMARY KEY (group_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        allowed_email_domains TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )",
    "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS allowed_email_domains TEXT NOT NULL DEFAULT '[]'",
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
    "CREATE TABLE IF NOT EXISTS ldap_providers (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
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
    "CREATE TABLE IF NOT EXISTS dpop_proofs (
        jkt VARCHAR(128) NOT NULL,
        jti VARCHAR(255) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (jkt, jti),
        INDEX idx_dpop_proofs_expires (expires_at)
    )",
    "CREATE TABLE IF NOT EXISTS user_consents (
        user_id VARCHAR(64) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        granted_scopes TEXT NOT NULL,
        granted_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        revoked_at BIGINT NULL,
        PRIMARY KEY (user_id, client_id),
        INDEX idx_user_consents_client (client_id, revoked_at)
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
        updated_at BIGINT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS group_members (
        group_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        PRIMARY KEY (group_id, user_id)
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
        description TEXT NULL,
        allowed_email_domains TEXT NOT NULL,
        is_active INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        INDEX idx_organizations_active_slug (is_active, slug)
    )",
    "ALTER TABLE organizations ADD COLUMN allowed_email_domains TEXT NULL",
    "CREATE TABLE IF NOT EXISTS organization_members (
        organization_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        role VARCHAR(32) NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (organization_id, user_id),
        INDEX idx_organization_members_user (user_id, organization_id)
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
    "CREATE TABLE IF NOT EXISTS ldap_providers (
        id VARCHAR(64) PRIMARY KEY,
        slug VARCHAR(255) NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
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
];
