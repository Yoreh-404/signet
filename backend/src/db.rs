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
mod application_discovery_read;
mod application_discovery_types;
#[macro_use]
mod application_write_sql;
#[macro_use]
mod application_graph_sql;
mod application_graph;
mod application_graph_read;
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
mod authorization_binding_policy;
mod authorization_bindings;
mod authorization_codes;
mod authorization_policy;
mod authorization_profiles;
mod authorization_transients;
mod billing;
mod billing_ledger;
mod billing_policy;
mod billing_read;
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
    ApplicationDiscoveryMigrationRow, BrowserContextAccountOptionRow, CountRow, GroupMemberIdRow,
    GroupMemberLifecycleRow, PermissionRow, StringIdRow, TotalRow, UpdatedAtRow, UserEmailIdRow,
    UserIdentityConflictRow,
};
mod value_normalization;
use value_normalization::{
    application_slug_base, application_slug_collision_candidate, dedupe_nonempty,
    dedupe_organization_members, merge_missing_quick_links, normalize_application_entitlement_keys,
    normalize_permission_keys,
};
#[macro_use]
mod directory_sync_read;
mod directory_sync;
mod directory_sync_group_mapping;
mod directory_sync_membership;
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
mod rbac_directory_read;
mod rbac_group_read;
mod rbac_read;
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
    ApplicationMemberRecord, ApplicationMemberWithUserRecord, ApplicationOidcClientRecord,
    ApplicationRecord, NewApplication, NewApplicationMember,
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
    UserSessionSummary, WebauthnChallengeRecord,
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

    #[path = "db_session_revocation_tests.rs"]
    mod session_revocation_tests;

    #[path = "device_authorization.rs"]
    mod device_authorization;

    #[path = "authorization_transient.rs"]
    mod authorization_transient;

    #[path = "refresh_tokens.rs"]
    mod refresh_tokens;

    #[path = "saml_interactions.rs"]
    mod saml_interactions;

    #[path = "invitation_authorization.rs"]
    mod invitation_authorization;

    #[path = "user_lifecycle.rs"]
    mod user_lifecycle;

    #[path = "captcha_challenges.rs"]
    mod captcha_challenges;

    #[path = "group_lifecycle.rs"]
    mod group_lifecycle;

    #[path = "verification_delivery.rs"]
    mod verification_delivery;

    #[path = "identity_provider_lifecycle.rs"]
    mod identity_provider_lifecycle;

    #[path = "application_lifecycle.rs"]
    mod application_lifecycle;

    #[path = "organization_account_lifecycle.rs"]
    mod organization_account_lifecycle;

    #[path = "application_enrollment.rs"]
    mod application_enrollment;

    #[path = "application_authorization_lifecycle.rs"]
    mod application_authorization_lifecycle;

    #[path = "application_provisioning.rs"]
    mod application_provisioning;

    #[path = "protocol_security_lifecycle.rs"]
    mod protocol_security_lifecycle;

    #[path = "bootstrap_organization_lifecycle.rs"]
    mod bootstrap_organization_lifecycle;

    #[path = "application_modules.rs"]
    mod application_modules;

    #[path = "security_mutation_lifecycle.rs"]
    mod security_mutation_lifecycle;

    #[path = "mutation_discovery_billing.rs"]
    mod mutation_discovery_billing;

    #[path = "core_db_tests.rs"]
    mod core_db_tests;

    #[cfg(feature = "sqlite")]
    pub(super) use protocol_security_lifecycle::{
        bootstrap_client, test_application, test_client, test_external_oidc_provider,
        test_ldap_provider, test_organization,
    };

    #[cfg(feature = "sqlite")]
    pub(super) use core_db_tests::{
        assert_user_auth_state_count, default_authorization_profile, insert_user_auth_state,
        load_verification_code, refresh_token_replacement, replace_test_authorization_bindings,
        session_link_count, sqlite_test_db, sqlite_test_db_with_pool_size, test_bulk_user,
        test_invitation, test_user,
    };
}
