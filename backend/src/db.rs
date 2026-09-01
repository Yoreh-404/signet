#[cfg(test)]
use crate::organizations::ORGANIZATION_KIND_TENANT;
use crate::{
    application_discovery_contract::{SOURCE_MODE_DISCOVERY, SOURCE_WEBSITE, SYNC_SYNCED},
    config::{BootstrapApplication, BootstrapClient, DatabaseKind, DatabaseSettings, Settings},
    error::{AppError, AppResult},
    organizations::{ORGANIZATION_KIND_SYSTEM, SIGNET_ORGANIZATION_ID, SIGNET_ORGANIZATION_SLUG},
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
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

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

#[cfg(feature = "mysql")]
use diesel::MysqlConnection;
#[cfg(feature = "postgres")]
use diesel::PgConnection;
#[macro_use]
mod auth_sql;
mod account_credentials;
mod application_auth_context_types;
mod application_authorization;
mod application_authorization_types;
mod application_discovery;
mod application_discovery_types;
#[macro_use]
mod application_write_sql;
#[macro_use]
mod application_graph_sql;
mod application_graph;
mod application_modules;
mod application_protocol_types;
mod application_sql;
pub(super) use application_sql::{
    select_application_authorization_profile_sql, select_application_cas_ticket_sql,
    select_application_client_binding_sql, select_application_discovery_sql,
    select_application_identity_binding_sql, select_application_jwt_client_sql,
    select_application_jwt_secret_sql, select_application_member_sql,
    select_application_module_sql, select_application_permission_definition_sql,
    select_application_profile_permission_override_sql, select_application_profile_role_sql,
    select_application_saml_interaction_sql, select_application_saml_session_sql,
    select_application_scim_token_sql, select_application_sql,
};
mod application_sso_cas;
mod application_sso_persistence;
mod application_sso_saml;
mod application_sso_scim;
mod application_types;
mod applications;
mod audit_persistence;
mod audit_types;
mod auth_challenges;
mod authorization;
mod authorization_bindings;
mod authorization_codes;
mod authorization_profiles;
mod authorization_transients;
mod billing;
mod billing_policy;
mod billing_reconciliation;
mod billing_sql;
mod billing_types;
mod browser_sessions;
mod client_applications;
mod client_registration;
mod client_security;
mod client_types;
mod database_bootstrap;
mod database_connection;
#[cfg(feature = "mysql")]
use database_connection::connect_mysql;
#[cfg(feature = "postgres")]
use database_connection::connect_postgres;
#[cfg(test)]
use database_connection::connect_sqlite;
mod database_lifecycle;
mod database_migrations;
mod directory_sync_types;
mod migration_sql;
#[cfg(test)]
pub(super) use migration_sql::{MYSQL_MIGRATIONS, POSTGRES_MIGRATIONS, SQLITE_MIGRATIONS};
pub(super) use migration_sql::{is_ignorable_migration_error, migration_sql};
mod query_types;
pub(super) use query_types::{
    ApplicationAuthorizationProfileCountRow, ApplicationDiscoveryMigrationRow,
    BrowserContextAccountOptionRow, CountRow, GroupMemberIdRow, GroupMemberLifecycleRow,
    PermissionRow, StringIdRow, TotalRow, UpdatedAtRow, UserEmailIdRow, UserIdentityConflictRow,
};
mod value_normalization;
use value_normalization::{
    application_slug_base, application_slug_collision_candidate, dedupe_nonempty,
    dedupe_organization_members, merge_missing_quick_links, normalize_application_entitlement_keys,
    normalize_permission_keys,
};
mod directory_sync;
mod directory_sync_sql;
mod external_identities;
mod external_identity_types;
mod iap_types;
mod invitation_persistence;
mod invitation_types;
mod mfa;
mod mfa_challenges;
mod mutation_receipts;
mod oauth_token_types;
mod organization_bootstrap;
mod organization_persistence;
mod organization_types;
mod organizations;
mod rbac;
mod rbac_types;
mod refresh_tokens;
mod registration_types;
mod scim;
mod scim_persistence;
mod scim_types;
mod security_policy_types;
mod session_types;
mod settings_persistence;
mod settings_types;
mod signing_key_types;
mod signing_keys;
mod sql;
mod user_cleanup;
mod user_directory;
mod user_lifecycle;
mod user_lifecycle_core;
mod user_persistence;
mod user_types;
mod webauthn;
mod website_discovery_sql;
pub(super) use website_discovery_sql::{WebsiteDiscoveryConnection, WebsiteDiscoveryProfileInput};

mod directory_sync_lifecycle;
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

use auth_challenges::VerificationCodeDecision;
pub(crate) use auth_challenges::VerificationCodeVerifier;
pub use auth_challenges::{
    CaptchaChallengeRecord, LoginFailureSummary, NewVerificationCode, VerificationCodeClaim,
    VerificationCodeRecord,
};
#[cfg(test)]
use auth_challenges::{
    consume_verification_code_sql, ensure_verification_resend_allowed,
    select_latest_verification_code_sql, select_verification_code_by_id_sql,
};
use sql::{bind_text_list, blocking, ph, placeholder_rows, placeholders};
use user_cleanup::{USER_AUTH_STATE_TABLES, USER_PERMANENT_DEPENDENT_TABLES};

pub(crate) use application_discovery::{
    ApplicationDiscoveryAuthorizationMappings, ApplicationDiscoveryGroupMapping,
    ApplicationDiscoveryManifest, ApplicationDiscoveryOrganizationRoleMapping,
    ApplicationDiscoveryPermission, ApplicationDiscoveryProfile, ApplicationDiscoveryRole,
};
pub use billing::{
    ApplicationBillingSettingsRecord, NewApplicationBillingSettings, NewPaymentOrder,
    NewWalletOperation, PaymentOrderLease, PaymentOrderRecord, PaymentRefundRecord,
    WalletAccountRecord, WalletAdjustment, WalletHoldRecord, WalletHoldReservation,
    WalletTransactionRecord, WalletTransfer,
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
pub use scim_types::{GroupPatchPlan, ScimGroupMemberRecord, ScimUserMutationPlan};

pub use mutation_receipts::{
    MutationReceiptClaim, MutationReceiptFinalization, MutationReceiptRecord,
};

pub use application_auth_context_types::{ApplicationAuthContextRecord, NewApplicationAuthContext};
pub use application_authorization_types::{
    ApplicationAuthorizationProfileRecord, ApplicationGraphRecordSet, ApplicationModuleRecord,
    ApplicationPermissionDefinitionRecord, ApplicationProfilePermissionOverrideRecord,
    ApplicationProfileRoleRecord, NewApplicationAuthorizationProfile,
    NewApplicationPermissionDefinition, NewApplicationProfileRole,
};
pub use application_discovery_types::{
    ApplicationDiscoveryIdempotencyClaim, ApplicationDiscoveryLease, ApplicationDiscoveryRecord,
    NewApplicationDiscovery,
};
pub(crate) use application_discovery_types::{
    ApplicationDiscoveryIdempotencyRecord, ApplicationDiscoveryJoinRecord,
};
pub use application_protocol_types::{
    ApplicationCasTicketRecord, ApplicationJwtClientRecord, ApplicationJwtClientSecretRecord,
    ApplicationJwtCodeRecord, ApplicationSamlInteractionRecord, ApplicationSamlSessionRecord,
    ApplicationScimTokenRecord, NewApplicationCasTicket, NewApplicationJwtClient,
    NewApplicationJwtCode, NewApplicationSamlInteraction, NewApplicationSamlSession,
    NewApplicationScimToken,
};
pub use application_types::{
    ApplicationAuthDomainRecord, ApplicationClientBindingRecord, ApplicationIdentityBindingRecord,
    ApplicationMemberRecord, ApplicationMemberWithUserRecord, ApplicationRecord, NewApplication,
    NewApplicationMember,
};
pub(crate) use audit_types::AuditWebhookOutboxRecord;
pub use audit_types::{
    AuditEventRecord, AuditWebhookRecord, LoginEventRecord, NewAuditWebhook, PublicAuditWebhook,
    UpdateAuditWebhook,
};
pub use authorization_bindings::{
    AuthorizationBindingPermissionOverride, AuthorizationBindingPermissionOverrideSnapshot,
    AuthorizationBindingsSnapshot, AuthorizationBindingsUpdate, AuthorizationUserBindingSnapshot,
};
pub use client_types::{
    ClientClaimMapperRecord, ClientRecord, ClientRegistrationRecord, NewClient,
    NewClientClaimMapper, PublicClient, PublicClientClaimMapper,
};
pub use directory_sync_types::{
    DirectorySyncCheckpointRecord, DirectorySyncGroupRecord, DirectorySyncMembershipRecord,
    DirectorySyncRunRecord, DirectorySyncRunUpdate,
};
pub use external_identity_types::{
    ExternalOidcProviderRecord, ExternalOidcStateRecord, LdapProviderRecord, LinkedIdentityRecord,
    NewExternalOidcProvider, NewLdapProvider, PublicExternalOidcProvider, PublicLdapProvider,
    ldap_provider_key,
};
pub use iap_types::{IapApplicationRecord, NewIapApplication, PublicIapApplication};
pub use invitation_types::{
    AccountRecoveryCodeRedemption, AuthorizationCodeType, InvitationRecord,
    InvitationRedemptionRecord, InvitationUpdate, LoginCodeLevel, NewInvitation,
    NewTrialEnrollmentUser, PublicInvitation, PublicInvitationRedemption,
    TrialEnrollmentCodeRedemption, TrialEnrollmentRecord,
};
pub(crate) use oauth_token_types::AdminLoginCodeRedemptionInput;
pub use oauth_token_types::{
    AuthorizationCodeRecord, ClientGrantRecord, ClientGrantWithClientRecord, NewAuthorizationCode,
    OidcLoginGrantRecord, OidcLoginGrantRedemption, RefreshTokenInput, RefreshTokenRecord,
};
pub use organization_types::{
    NewOrganization, OrganizationMemberCountRecord, OrganizationMemberInput,
    OrganizationMemberRecord, OrganizationMemberWithUserRecord, OrganizationRecord,
    UserOrganizationRecord,
};
use rbac_types::{GroupMemberPublicRow, GroupRoleJoinRow, RoleIdRow, RolePermissionJoinRow};
pub use rbac_types::{GroupRecord, NewGroup, NewRole, RoleRecord};
pub use registration_types::{
    FIRST_REGISTERED_USER_IS_ADMIN, NewRegistrationSettings, PublicRegistrationSettings,
    RegistrationSettingsRecord, registered_user_is_admin,
};
pub use security_policy_types::{NewSecurityPolicy, PublicSecurityPolicy, SecurityPolicyRecord};
pub use session_types::{
    AccountLoginFlowRecord, BrowserContextAccountOption, BrowserContextAccountRecord,
    BrowserContextRecord, MfaChallengeRecord, MfaRecoveryCodeRecord, MfaTotpMethodRecord,
    MfaTotpSetupRecord, PasskeyRecord, PublicPasskey, SessionMetadata, SessionRecord,
    WebauthnChallengeRecord,
};
pub use settings_types::{
    LoginSettingsRecord, NewLoginSettings, NewRuntimeSettings, PublicLoginSettings,
    PublicRuntimeSettings, QuickLink, RuntimeSettingsRecord,
};
pub use signing_key_types::{NewSigningKey, SigningKeyRecord};
pub use user_lifecycle::UserLifecycleBatchAction;
pub(crate) use user_types::UserRegistrationSource;
pub use user_types::{
    GroupListFilter, NewBulkProvisionedUser, NewUser, PublicUser, UserAssignmentStateRecord,
    UserDirectoryCursor, UserDirectoryCursorPage, UserListFilter, UserListFilters,
    UserListLinkedIdentityFilter, UserListLoginRegion, UserListPage, UserListRoleFilter,
    UserListScope, UserOptionRecord, UserRecord, UserUpdate,
};
/// Application identity bindings are leases over a user's currently verified
/// contacts, not historical account attributes.  A contact change releases
/// only that contact's leases; deactivation releases them all.

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
/// Makes the application-level authorization boundary explicit. Every
/// application has one physical `default` profile, including applications
/// that do not yet expose a client-bound protocol. Runtime adapters resolve
/// this row instead of falling back to a second application-wide role graph.
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

fn select_group_sql() -> &'static str {
    "SELECT id, name, description, created_at, updated_at, version FROM access_groups"
}

/// The application aggregate write primitives below intentionally accept an
/// existing connection.  The public one-operation methods use them directly,
/// while audited mutation methods compose them with the audit insert inside
/// one transaction.
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

fn select_security_policy_sql() -> &'static str {
    "SELECT id, password_min_length, password_require_uppercase, password_require_lowercase, password_require_digit, password_require_symbol, password_reject_user_info, login_lockout_enabled, max_failed_login_attempts, failure_window_seconds, lockout_seconds, COALESCE(trusted_ip_cidrs, '[]') AS trusted_ip_cidrs, COALESCE(require_mfa_outside_trusted_networks, 0) AS require_mfa_outside_trusted_networks, COALESCE(allowed_ip_cidrs, '[]') AS allowed_ip_cidrs, COALESCE(blocked_ip_cidrs, '[]') AS blocked_ip_cidrs, COALESCE(allowed_email_domains, '[]') AS allowed_email_domains, COALESCE(blocked_email_domains, '[]') AS blocked_email_domains, COALESCE(captcha_enabled, 0) AS captcha_enabled, COALESCE(captcha_after_failed_attempts, 3) AS captcha_after_failed_attempts, COALESCE(captcha_ttl_seconds, 300) AS captcha_ttl_seconds, updated_at FROM security_policy"
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
        db.finish_directory_sync_run(DirectorySyncRunUpdate {
            run_id: &reclaimed.id,
            status: "succeeded",
            total_seen: 0,
            created_count: 0,
            updated_count: 0,
            disabled_count: 0,
            error: None,
            cursor: None,
        })
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
            db.finalize_mutation_receipt(MutationReceiptFinalization {
                id: &first.id,
                owner_token: first.owner_token.as_deref().unwrap(),
                status: "committed",
                response_status: 200,
                response_body: Some(r#"{"id":"application-1"}"#.to_string()),
                response_content_type: Some("application/json".to_string()),
                error_code: None,
            })
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
            .claim_mutation_receipt_with_owner(MutationReceiptClaim {
                dedupe_hash: "reclaim-receipt-test",
                scope_key: "session:test",
                method: "POST",
                path: "/api/admin/applications",
                idempotency_key: "key-1",
                request_hash: "request-a",
                owner_token: "owner-a",
            })
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
            .claim_mutation_receipt_with_owner(MutationReceiptClaim {
                dedupe_hash: "reclaim-receipt-test",
                scope_key: "session:test",
                method: "POST",
                path: "/api/admin/applications",
                idempotency_key: "key-1",
                request_hash: "request-a",
                owner_token: "owner-b",
            })
            .await
            .unwrap();
        assert_eq!(reclaimed.id, first.id);
        assert_eq!(reclaimed.owner_token.as_deref(), Some("owner-b"));
        assert!(reclaimed.lease_expires_at.unwrap() > util::now_ts());

        assert!(
            !db.finalize_mutation_receipt(MutationReceiptFinalization {
                id: &first.id,
                owner_token: "owner-a",
                status: "committed",
                response_status: 200,
                response_body: Some("old".to_string()),
                response_content_type: None,
                error_code: None,
            })
            .await
            .unwrap()
        );
        assert!(
            db.finalize_mutation_receipt(MutationReceiptFinalization {
                id: &first.id,
                owner_token: "owner-b",
                status: "committed",
                response_status: 200,
                response_body: Some("new".to_string()),
                response_content_type: None,
                error_code: None,
            })
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

        db.adjust_wallet(WalletAdjustment {
            wallet_id: &global.id,
            user_id: Some(&user.id),
            application_id: None,
            currency: "CNY",
            amount_delta_minor: 10_000,
            idempotency_key: "seed-balance",
            metadata: serde_json::json!({"test": true}),
        })
        .await
        .unwrap();

        let hold = db
            .reserve_wallet_hold(WalletHoldReservation {
                wallet_id: &global.id,
                user_id: &user.id,
                application_id,
                currency: "CNY",
                amount_minor: 4_000,
                reference: "charge-1",
                idempotency_key: "reserve-1",
                expires_at: util::now_ts() + 900,
            })
            .await
            .unwrap();
        let duplicate_hold = db
            .reserve_wallet_hold(WalletHoldReservation {
                wallet_id: &global.id,
                user_id: &user.id,
                application_id,
                currency: "CNY",
                amount_minor: 4_000,
                reference: "charge-1",
                idempotency_key: "reserve-1",
                expires_at: util::now_ts() + 900,
            })
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
            .transfer_wallets(WalletTransfer {
                user_id: &user.id,
                source_wallet_id: &global.id,
                destination_wallet_id: &application_wallet.id,
                currency: "CNY",
                amount_minor: 2_000,
                application_id: Some(application_id),
                idempotency_key: "transfer-1",
            })
            .await
            .unwrap();
        let duplicate_transfer = db
            .transfer_wallets(WalletTransfer {
                user_id: &user.id,
                source_wallet_id: &global.id,
                destination_wallet_id: &application_wallet.id,
                currency: "CNY",
                amount_minor: 2_000,
                application_id: Some(application_id),
                idempotency_key: "transfer-1",
            })
            .await
            .unwrap();
        assert_eq!(transferred.id, duplicate_transfer.id);
        assert!(
            db.transfer_wallets(WalletTransfer {
                user_id: &user.id,
                source_wallet_id: &global.id,
                destination_wallet_id: &application_wallet.id,
                currency: "CNY",
                amount_minor: 9_000,
                application_id: Some(application_id),
                idempotency_key: "transfer-too-much",
            })
            .await
            .is_err()
        );
        db.transfer_wallets(WalletTransfer {
            user_id: &user.id,
            source_wallet_id: &application_wallet.id,
            destination_wallet_id: &global.id,
            currency: "CNY",
            amount_minor: 2_000,
            application_id: Some(application_id),
            idempotency_key: "transfer-2",
        })
        .await
        .unwrap();

        let release_hold = db
            .reserve_wallet_hold(WalletHoldReservation {
                wallet_id: &global.id,
                user_id: &user.id,
                application_id,
                currency: "CNY",
                amount_minor: 500,
                reference: "release-1",
                idempotency_key: "reserve-2",
                expires_at: util::now_ts() + 900,
            })
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
        assert_eq!(
            db.list_application_saml_sessions_by_indexes(
                &["session-index-a".to_string(), "missing".to_string()],
                "application-a",
            )
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
            management_mode: crate::application_discovery_contract::MANAGEMENT_MODE_WEBSITE
                .to_string(),
            website_url: "https://website.example".to_string(),
            fetch_secret_ciphertext: "encrypted-fetch-secret".to_string(),
            signing_public_jwks: "{}".to_string(),
            last_verified_revision: None,
            last_verified_version: None,
            last_verified_digest: None,
            last_verified_expires_at: None,
            sync_status: crate::application_discovery_contract::SYNC_PENDING.to_string(),
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
        let profile = ApplicationDiscoveryProfile {
            permissions: vec![ApplicationDiscoveryPermission {
                key: "website.read".to_string(),
                label: "Website read".to_string(),
                description: None,
            }],
            roles: vec![ApplicationDiscoveryRole {
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
            ApplicationDiscoveryManifest {
                revision: 1,
                version: "v1".to_string(),
                digest: "digest-1".to_string(),
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
            ApplicationDiscoveryProfile {
                permissions: vec![ApplicationDiscoveryPermission {
                    key: "website.read".to_string(),
                    label: "Website read".to_string(),
                    description: None,
                }],
                roles: vec![ApplicationDiscoveryRole {
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
            ApplicationDiscoveryManifest {
                revision: 2,
                version: "v2".to_string(),
                digest: "digest-2".to_string(),
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
