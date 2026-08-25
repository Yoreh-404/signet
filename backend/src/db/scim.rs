//! Read-side repositories for the SCIM application boundary.
//!
//! SCIM authentication is an application capability, not a generic client or
//! user permission.  These repository methods keep the client, binding,
//! application, lifecycle, and directory module reads together so protocol
//! handlers do not reopen the same application context one row at a time.

use super::{
    ApplicationClientBindingRecord, ApplicationModuleRecord, ApplicationRecord,
    ApplicationScimTokenRecord, DatabaseKind, Db, blocking, ph,
};
use crate::error::{AppError, AppResult};
use diesel::{
    Connection, OptionalExtension, QueryableByName, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

/// Scope captured by a SCIM mutation and rechecked in the same write
/// transaction. Handler-level authorization is only a fast 404 check; this
/// value prevents an organization/application membership change between that
/// check and the user update from escaping its directory boundary.
#[derive(Debug, Clone, Default)]
pub struct ScimUserMutationScope {
    pub application_id: Option<String>,
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScimApplicationContext {
    pub application: ApplicationRecord,
    pub module: ApplicationModuleRecord,
    pub organization_active: bool,
    pub discovery: Option<ScimDiscoveryState>,
}

impl ScimApplicationContext {
    pub fn runtime_active(&self) -> bool {
        self.application.is_active == 1
            && self.organization_active
            && self.discovery.as_ref().is_none_or(|discovery| {
                crate::application_discovery::website_discovery_runtime_active(
                    &discovery.management_mode,
                    discovery.operator_disabled,
                    discovery.last_verified_revision,
                    discovery.last_verified_expires_at,
                    discovery.has_snapshot,
                    crate::util::now_ts(),
                )
            })
    }
}

#[derive(Debug, Clone)]
pub struct ScimDiscoveryState {
    pub management_mode: String,
    pub operator_disabled: bool,
    pub last_verified_revision: Option<i64>,
    pub last_verified_expires_at: Option<i64>,
    pub has_snapshot: bool,
}

#[derive(Debug, Clone)]
pub struct ScimApplicationTokenContext {
    pub token: ApplicationScimTokenRecord,
    pub application: ScimApplicationContext,
}

#[derive(Debug, Clone)]
pub struct ScimServiceAccountContext {
    pub client_db_id: String,
    pub client_id: String,
    pub client_active: bool,
    pub service_account_enabled: bool,
    pub service_account_permissions: String,
    pub binding: ApplicationClientBindingRecord,
    pub application: ScimApplicationContext,
}

#[derive(Debug, Clone, QueryableByName)]
struct ScimApplicationContextRow {
    #[diesel(sql_type = Text)]
    application_id: String,
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
    application_is_active: i32,
    #[diesel(sql_type = BigInt)]
    application_created_at: i64,
    #[diesel(sql_type = BigInt)]
    application_updated_at: i64,
    #[diesel(sql_type = Text)]
    module_application_id: String,
    #[diesel(sql_type = Text)]
    module_key: String,
    #[diesel(sql_type = Text)]
    module_config_json: String,
    #[diesel(sql_type = Integer)]
    module_is_enabled: i32,
    #[diesel(sql_type = BigInt)]
    module_created_at: i64,
    #[diesel(sql_type = BigInt)]
    module_updated_at: i64,
    #[diesel(sql_type = Integer)]
    organization_is_active: i32,
    #[diesel(sql_type = Nullable<Text>)]
    discovery_management_mode: Option<String>,
    #[diesel(sql_type = Nullable<Integer>)]
    discovery_operator_disabled: Option<i32>,
    #[diesel(sql_type = Nullable<BigInt>)]
    discovery_last_verified_revision: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    discovery_last_verified_expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    discovery_snapshot_json: Option<String>,
}

#[derive(Debug, Clone, QueryableByName)]
struct ScimClientContextRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    client_id: String,
    #[diesel(sql_type = Integer)]
    is_active: i32,
    #[diesel(sql_type = Integer)]
    service_account_enabled: i32,
    #[diesel(sql_type = Text)]
    service_account_permissions: String,
}

#[derive(Debug, Clone, QueryableByName)]
struct ScimTokenRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    application_id: String,
    #[diesel(sql_type = Text)]
    token_prefix: String,
    #[diesel(sql_type = Text)]
    token_hash: String,
    #[diesel(sql_type = Text)]
    scopes: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    revoked_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_used_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
}

impl ScimTokenRow {
    fn record(self) -> ApplicationScimTokenRecord {
        ApplicationScimTokenRecord {
            id: self.id,
            application_id: self.application_id,
            token_prefix: self.token_prefix,
            token_hash: self.token_hash,
            scopes: self.scopes,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
            last_used_at: self.last_used_at,
            created_at: self.created_at,
        }
    }
}

fn application_context_from_row(row: ScimApplicationContextRow) -> ScimApplicationContext {
    let ScimApplicationContextRow {
        application_id,
        organization_id,
        slug,
        name,
        description,
        access_mode,
        registration_mode,
        account_selection_mode,
        unique_identity_factors,
        application_is_active,
        application_created_at,
        application_updated_at,
        module_application_id,
        module_key,
        module_config_json,
        module_is_enabled,
        module_created_at,
        module_updated_at,
        organization_is_active,
        discovery_management_mode,
        discovery_operator_disabled,
        discovery_last_verified_revision,
        discovery_last_verified_expires_at,
        discovery_snapshot_json,
    } = row;
    let discovery = discovery_management_mode.map(|management_mode| ScimDiscoveryState {
        management_mode,
        operator_disabled: discovery_operator_disabled.unwrap_or_default() != 0,
        last_verified_revision: discovery_last_verified_revision,
        last_verified_expires_at: discovery_last_verified_expires_at,
        has_snapshot: discovery_snapshot_json.is_some(),
    });
    ScimApplicationContext {
        application: ApplicationRecord {
            id: application_id,
            organization_id,
            slug,
            name,
            description,
            access_mode,
            registration_mode,
            account_selection_mode,
            unique_identity_factors,
            is_active: application_is_active,
            created_at: application_created_at,
            updated_at: application_updated_at,
        },
        module: ApplicationModuleRecord {
            application_id: module_application_id,
            module_key,
            config_json: module_config_json,
            is_enabled: module_is_enabled,
            created_at: module_created_at,
            updated_at: module_updated_at,
        },
        organization_active: organization_is_active == 1,
        discovery,
    }
}

macro_rules! load_application_context_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr $(,)?) => {{
        let sql = format!(
            "SELECT applications.id AS application_id, applications.organization_id, applications.slug, applications.name, applications.description, applications.access_mode, applications.registration_mode, applications.account_selection_mode, COALESCE(applications.unique_identity_factors, '[]') AS unique_identity_factors, applications.is_active AS application_is_active, applications.created_at AS application_created_at, applications.updated_at AS application_updated_at, application_modules.application_id AS module_application_id, application_modules.module_key, application_modules.config_json AS module_config_json, application_modules.is_enabled AS module_is_enabled, application_modules.created_at AS module_created_at, application_modules.updated_at AS module_updated_at, organizations.is_active AS organization_is_active, application_discovery.management_mode AS discovery_management_mode, application_discovery.operator_disabled AS discovery_operator_disabled, application_discovery.last_verified_revision AS discovery_last_verified_revision, application_discovery.last_verified_expires_at AS discovery_last_verified_expires_at, application_discovery.snapshot_json AS discovery_snapshot_json FROM applications INNER JOIN organizations ON organizations.id = applications.organization_id INNER JOIN application_modules ON application_modules.application_id = applications.id AND application_modules.module_key = 'directory_sync' LEFT JOIN application_discovery ON application_discovery.application_id = applications.id WHERE applications.id = {}",
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>($application_id.to_string())
            .get_result::<ScimApplicationContextRow>($conn)
            .optional()
            .map(|row| row.map(application_context_from_row))
            .map_err(AppError::from)?
    }};
}

impl Db {
    /// Resolves the application-owned opaque SCIM credential and its complete
    /// runtime boundary without reopening the application or module through
    /// separate handler-level reads.
    pub async fn find_scim_application_token_context(
        &self,
        token_hash: &str,
    ) -> AppResult<Option<ScimApplicationTokenContext>> {
        let token_hash = token_hash.to_string();
        let now = crate::util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<Option<ScimApplicationTokenContext>, AppError, _>(|conn| {
                let sql = format!(
                    "SELECT id, application_id, token_prefix, token_hash, scopes, expires_at, revoked_at, last_used_at, created_at FROM application_scim_tokens WHERE token_hash = {} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > {})",
                    ph(kind, 1),
                    ph(kind, 2),
                );
                let Some(token) = sql_query(sql)
                    .bind::<Text, _>(&token_hash)
                    .bind::<BigInt, _>(now)
                    .get_result::<ScimTokenRow>(conn)
                    .optional()
                    .map_err(AppError::from)?
                else {
                    return Ok(None);
                };
                let Some(application) = load_application_context_on_conn!(
                    conn,
                    kind,
                    &token.application_id,
                ) else {
                    return Ok(None);
                };
                Ok(Some(ScimApplicationTokenContext {
                    token: token.record(),
                    application,
                }))
            })
        })
    }

    /// Resolves an OAuth client-credentials SCIM boundary in one repository
    /// operation. The active OIDC binding is required before the directory
    /// module is considered, preserving the client/application boundary.
    pub async fn find_scim_service_account_context(
        &self,
        client_id: &str,
    ) -> AppResult<Option<ScimServiceAccountContext>> {
        let client_id = client_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<Option<ScimServiceAccountContext>, AppError, _>(|conn| {
                let client_sql = format!(
                    "SELECT id, client_id, is_active, COALESCE(service_account_enabled, 0) AS service_account_enabled, COALESCE(service_account_permissions, '[]') AS service_account_permissions FROM clients WHERE client_id = {}",
                    ph(kind, 1)
                );
                let Some(client) = sql_query(client_sql)
                    .bind::<Text, _>(&client_id)
                    .get_result::<ScimClientContextRow>(conn)
                    .optional()
                    .map_err(AppError::from)?
                else {
                    return Ok(None);
                };
                let binding_sql = format!(
                    "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE client_db_id = {} AND is_active = 1",
                    ph(kind, 1)
                );
                let Some(binding) = sql_query(binding_sql)
                    .bind::<Text, _>(&client.id)
                    .get_result::<ApplicationClientBindingRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                else {
                    return Ok(None);
                };
                let Some(application) = load_application_context_on_conn!(
                    conn,
                    kind,
                    &binding.application_id,
                ) else {
                    return Ok(None);
                };
                Ok(Some(ScimServiceAccountContext {
                    client_db_id: client.id,
                    client_id: client.client_id,
                    client_active: client.is_active == 1,
                    service_account_enabled: client.service_account_enabled == 1,
                    service_account_permissions: client.service_account_permissions,
                    binding,
                    application,
                }))
            })
        })
    }
}
