//! Transaction-scoped reads for subject authorization policy.
//!
//! The authorization resolver must not assemble a policy by borrowing the
//! connection pool one relation at a time.  This module owns the read side of
//! that aggregate: every row which can affect one application/profile + user
//! decision is copied while one connection is inside one read transaction.

use super::{
    ApplicationAuthorizationProfileRecord, ApplicationClientBindingRecord, ApplicationModuleRecord,
    ApplicationProfilePermissionOverrideRecord, ApplicationProfileRoleRecord, ApplicationRecord,
    ClientClaimMapperRecord, CountRow, Db, GroupRecord, RoleRecord, UserOrganizationRecord,
    bind_text_list, blocking, ph, placeholders, select_application_authorization_profile_sql,
    select_application_profile_permission_override_sql, select_application_profile_role_sql,
    select_application_sql, select_client_claim_mapper_sql,
};
use super::{normalize_application_entitlement_keys, select_application_module_sql};
use crate::application_discovery_contract::{
    SOURCE_MODE_MANUAL, SYNC_STATUS_MANUAL, website_discovery_runtime_active,
};
use crate::config::DatabaseKind;
use crate::error::{AppError, AppResult};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl,
    connection::SimpleConnection,
    sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Legacy application-wide role rows are read only during the one-way
/// migration into the physical `default` profile.  Keeping this shape inside
/// the migration module prevents the removed authorization model from
/// leaking back into the runtime database facade.
#[derive(Debug, Clone, diesel::QueryableByName)]
struct LegacyApplicationRoleRecord {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Nullable<Text>)]
    description: Option<String>,
    #[diesel(sql_type = Text)]
    permissions: String,
    #[diesel(sql_type = Integer)]
    is_default: i32,
    #[diesel(sql_type = Integer)]
    is_active: i32,
}

impl LegacyApplicationRoleRecord {
    fn permission_keys(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.permissions)
    }
}

fn select_application_role_sql() -> &'static str {
    "SELECT id, name, description, permissions, is_default, is_active FROM application_roles"
}

#[derive(Debug, Clone)]
enum PolicyBoundary {
    Application {
        application_id: String,
    },
    Client {
        client_db_id: String,
        required_protocol: Option<String>,
    },
    Profile {
        application_id: String,
        profile_id: String,
    },
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct UserActivityRow {
    #[diesel(sql_type = Integer)]
    is_active: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    archived_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ClientActivityRow {
    #[diesel(sql_type = Nullable<Text>)]
    organization_id: Option<String>,
    #[diesel(sql_type = Integer)]
    is_active: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ClientBindingBoundaryRow {
    #[diesel(sql_type = Nullable<Text>)]
    organization_id: Option<String>,
    #[diesel(sql_type = Integer)]
    client_is_active: i32,
    #[diesel(sql_type = Nullable<Text>)]
    binding_application_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    binding_client_db_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    binding_protocol: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    binding_authorization_profile_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    binding_auth_domain_id: Option<String>,
    #[diesel(sql_type = Nullable<Integer>)]
    binding_is_active: Option<i32>,
    #[diesel(sql_type = Nullable<BigInt>)]
    binding_created_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    binding_updated_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct OrganizationActivityRow {
    #[diesel(sql_type = Integer)]
    is_active: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct PolicyOrganizationMembershipRow {
    #[diesel(sql_type = Integer)]
    organization_is_active: i32,
    #[diesel(sql_type = Nullable<Text>)]
    membership_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    membership_slug: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    membership_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    membership_kind: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    membership_description: Option<String>,
    #[diesel(sql_type = Nullable<Integer>)]
    membership_is_active: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    membership_role: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    membership_created_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    membership_updated_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct DiscoveryRuntimeRow {
    #[diesel(sql_type = Text)]
    management_mode: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_verified_revision: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_verified_expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    snapshot_json: Option<String>,
    #[diesel(sql_type = Integer)]
    operator_disabled: i32,
}

fn discovery_runtime_is_active(discovery: Option<DiscoveryRuntimeRow>, now: i64) -> bool {
    discovery.is_none_or(|discovery| {
        website_discovery_runtime_active(
            &discovery.management_mode,
            discovery.operator_disabled != 0,
            discovery.last_verified_revision,
            discovery.last_verified_expires_at,
            discovery.snapshot_json.is_some(),
            now,
        )
    })
}

fn initialize_consistent_read<C: SimpleConnection>(
    conn: &mut C,
    kind: DatabaseKind,
) -> AppResult<()> {
    if matches!(kind, DatabaseKind::Postgres) {
        conn.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .map_err(AppError::from)?;
    }
    Ok(())
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct GroupRoleSnapshotRow {
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
struct RolePermissionSnapshotRow {
    #[diesel(sql_type = Text)]
    role_id: String,
    #[diesel(sql_type = Text)]
    permission: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ProfileRoleIdRow {
    #[diesel(sql_type = Text)]
    id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct LegacyApplicationRoleAssignmentRow {
    #[diesel(sql_type = Text)]
    subject_id: String,
    #[diesel(sql_type = Text)]
    application_role_id: String,
    #[diesel(sql_type = Integer)]
    is_active: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct LegacyApplicationOrganizationRoleAssignmentRow {
    #[diesel(sql_type = Text)]
    organization_role: String,
    #[diesel(sql_type = Text)]
    application_role_id: String,
    #[diesel(sql_type = Integer)]
    is_active: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct LegacyApplicationOverrideRow {
    #[diesel(sql_type = Text)]
    user_id: String,
    #[diesel(sql_type = Text)]
    permission: String,
    #[diesel(sql_type = Text)]
    effect: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationOrganizationRoleAssignmentRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub organization_role: String,
    #[diesel(sql_type = Text)]
    pub application_role_id: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationProfileRoleAssignmentRecord {
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = Text)]
    pub subject_id: String,
    #[diesel(sql_type = Text)]
    pub role_id: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationProfileOrganizationRoleAssignmentRecord {
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = Text)]
    pub organization_role: String,
    #[diesel(sql_type = Text)]
    pub role_id: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
}

/// The complete request-local authorization input graph.
///
/// This is deliberately a data value, not a database handle.  Once returned,
/// authorization code may only inspect these fields.  The optional binding is
/// every authorizable boundary carries one. The physical `default` profile is
/// the application-level policy; a client binding may point at another
/// profile, but no request is resolved from an application-wide role graph.
#[derive(Debug, Clone)]
pub struct AuthorizationPolicySnapshot {
    pub application: Option<ApplicationRecord>,
    pub binding: Option<ApplicationClientBindingRecord>,
    pub profile: Option<ApplicationAuthorizationProfileRecord>,
    pub user_id: String,
    pub user_active: bool,
    pub client_id: Option<String>,
    pub client_active: bool,
    pub client_organization_id: Option<String>,
    pub organization_active: bool,
    pub membership: Option<UserOrganizationRecord>,
    pub groups: Vec<GroupRecord>,
    pub enterprise_roles: Vec<RoleRecord>,
    pub enterprise_group_roles: BTreeMap<String, Vec<RoleRecord>>,
    pub enterprise_role_permissions: BTreeMap<String, Vec<String>>,
    pub authorization_config: Map<String, Value>,
    pub application_runtime_active: bool,
    pub protocol_enabled: bool,
    pub profile_roles: Vec<ApplicationProfileRoleRecord>,
    pub profile_user_assignments: Vec<ApplicationProfileRoleAssignmentRecord>,
    pub profile_group_assignments: Vec<ApplicationProfileRoleAssignmentRecord>,
    pub profile_organization_assignments: Vec<ApplicationProfileOrganizationRoleAssignmentRecord>,
    pub profile_permission_overrides: Vec<ApplicationProfilePermissionOverrideRecord>,
    pub claim_mappers: Vec<ClientClaimMapperRecord>,
    pub is_authorizable: bool,
}

impl AuthorizationPolicySnapshot {
    /// Returns the application/client boundary decision without consulting a
    /// user or opening another database connection.  This is the machine
    /// boundary used by client credentials; it intentionally excludes the
    /// interactive OIDC protocol flag.
    pub fn is_application_client_runtime_active(&self) -> bool {
        self.client_id
            .as_deref()
            .is_some_and(|client_id| self.has_client_application_boundary(client_id))
            && self.client_active
            && self.organization_active
            && self
                .application
                .as_ref()
                .is_some_and(|application| application.is_active == 1)
            && self.application_runtime_active
            && self
                .binding
                .as_ref()
                .is_some_and(|binding| binding.is_active == 1)
    }

    /// Returns the complete interactive OIDC application/client boundary.
    /// User activity and the authorization policy are checked separately by
    /// `is_authorizable`; this method is safe for pre-login runtime checks.
    pub fn is_interactive_client_runtime_active(&self) -> bool {
        self.is_application_client_runtime_active() && self.protocol_enabled
    }

    pub fn has_client_application_boundary(&self, client_id: &str) -> bool {
        let Some(application) = self.application.as_ref() else {
            return false;
        };
        let Some(binding) = self.binding.as_ref() else {
            return false;
        };
        self.client_id.as_deref() == Some(client_id)
            && binding.client_db_id == client_id
            && binding.application_id == application.id
            && self
                .client_organization_id
                .as_deref()
                .is_some_and(|organization_id| organization_id == application.organization_id)
    }

    pub fn has_profile_application_boundary(&self) -> bool {
        self.profile.as_ref().is_none_or(|profile| {
            self.application
                .as_ref()
                .is_some_and(|application| profile.application_id == application.id)
        })
    }
}

/// Lightweight application admission snapshot. Login admission must not
/// hydrate roles, groups, assignments, or overrides when it only needs the
/// active account/application boundary and the policy version.
#[derive(Debug, Clone)]
pub struct ApplicationAccessSnapshot {
    pub application: Option<ApplicationRecord>,
    pub user_id: String,
    pub user_active: bool,
    pub organization_active: bool,
    pub application_runtime_active: bool,
    pub authorization_config: Map<String, Value>,
    pub is_authorizable: bool,
}

macro_rules! load_group_roles {
    ($conn:expr, $kind:expr, $group_ids:expr) => {{
        let group_ids = $group_ids;
        if group_ids.is_empty() {
            Ok::<BTreeMap<String, Vec<RoleRecord>>, AppError>(BTreeMap::new())
        } else {
            let sql = format!(
                "SELECT group_roles.group_id, roles.id, roles.name, roles.description, roles.is_system, roles.created_at, roles.updated_at FROM roles INNER JOIN group_roles ON roles.id = group_roles.role_id WHERE group_roles.group_id IN ({}) ORDER BY group_roles.group_id ASC, roles.name ASC, roles.id ASC",
                placeholders($kind, 1, group_ids.len())
            );
            let rows = bind_text_list($conn, sql_query(sql), group_ids)
                .load::<GroupRoleSnapshotRow>($conn)
                .map_err(AppError::from)?;
            let mut grouped: BTreeMap<String, Vec<RoleRecord>> = BTreeMap::new();
            for row in rows {
                grouped
                    .entry(row.group_id)
                    .or_insert_with(Vec::new)
                    .push(RoleRecord {
                        id: row.id,
                        name: row.name,
                        description: row.description,
                        is_system: row.is_system,
                        created_at: row.created_at,
                        updated_at: row.updated_at,
                    });
            }
            Ok::<BTreeMap<String, Vec<RoleRecord>>, AppError>(grouped)
        }
    }};
}

macro_rules! load_role_permissions {
    ($conn:expr, $kind:expr, $role_ids:expr) => {{
        let role_ids = $role_ids.iter().cloned().collect::<Vec<_>>();
        if role_ids.is_empty() {
            Ok::<BTreeMap<String, Vec<String>>, AppError>(BTreeMap::new())
        } else {
            let sql = format!(
                "SELECT role_id, permission FROM role_permissions WHERE role_id IN ({}) ORDER BY role_id ASC, permission ASC",
                placeholders($kind, 1, role_ids.len())
            );
            let rows = bind_text_list($conn, sql_query(sql), &role_ids)
                .load::<RolePermissionSnapshotRow>($conn)
                .map_err(AppError::from)?;
            let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for row in rows {
                grouped
                    .entry(row.role_id)
                    .or_insert_with(Vec::new)
                    .push(row.permission);
            }
            Ok::<BTreeMap<String, Vec<String>>, AppError>(grouped)
        }
    }};
}

macro_rules! load_profile_group_assignments {
    ($conn:expr, $kind:expr, $profile_id:expr, $group_ids:expr) => {{
        let group_ids = $group_ids;
        if group_ids.is_empty() {
            Ok(Vec::new())
        } else {
            let mut values = vec![$profile_id.to_string()];
            values.extend(group_ids.iter().cloned());
            let sql = format!(
                "SELECT profile_id, group_id AS subject_id, role_id, is_active FROM application_profile_group_roles WHERE profile_id = {} AND group_id IN ({}) ORDER BY group_id ASC, role_id ASC",
                ph($kind, 1),
                placeholders($kind, 2, values.len() - 1)
            );
            bind_text_list($conn, sql_query(sql), &values)
                .load::<ApplicationProfileRoleAssignmentRecord>($conn)
                .map_err(AppError::from)
        }
    }};
}

/// Materializes one role from the removed application-wide catalog into the
/// owning profile. The operation is idempotent by `(profile_id, role_key)` and
/// keeps the legacy id when it is globally available so old edge rows can be
/// migrated without an intermediate mapping table.
macro_rules! materialize_migrated_profile_role {
    (
        $conn:expr,
        $kind:expr,
        $profile_id:expr,
        $legacy_id:expr,
        $role_key:expr,
        $name:expr,
        $description:expr,
        $permissions:expr,
        $source:expr,
        $is_default:expr,
        $is_active:expr,
        $now:expr $(,)?
    ) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let profile_id = $profile_id;
        let legacy_id = $legacy_id;
        let role_key = $role_key;
        let name = $name;
        let description = $description;
        let permissions = $permissions;
        let source = $source;
        let is_default = $is_default;
        let is_active = $is_active;
        let should_be_default = is_default && is_active;
        let now = $now;
        let existing_sql = format!(
            "{} WHERE profile_id = {} AND role_key = {}",
            select_application_profile_role_sql(),
            ph(kind, 1),
            ph(kind, 2)
        );
        if let Some(existing) = sql_query(existing_sql)
            .bind::<Text, _>(profile_id.to_string())
            .bind::<Text, _>(role_key.to_string())
            .get_result::<ApplicationProfileRoleRecord>(conn)
            .optional()
            .map_err(AppError::from)?
        {
            if should_be_default && existing.is_default != 1 {
                // A legacy catalog could contain multiple rows marked as
                // default. The profile invariant is stricter: at most one
                // default role. Apply the same repair as the normal profile
                // upsert before promoting an existing role.
                let clear_sql = format!(
                    "UPDATE application_profile_roles SET is_default = 0, updated_at = {} WHERE profile_id = {} AND id <> {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(clear_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(profile_id.to_string())
                    .bind::<Text, _>(existing.id.clone())
                    .execute(conn)
                    .map_err(AppError::from)?;
                let update_sql = format!(
                    "UPDATE application_profile_roles SET is_default = 1, updated_at = {} WHERE profile_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(profile_id.to_string())
                    .bind::<Text, _>(existing.id.clone())
                    .execute(conn)
                    .map_err(AppError::from)?;
            } else if !is_active
                && existing.is_default == 1
                && existing.source == source
            {
                let update_sql = format!(
                    "UPDATE application_profile_roles SET is_default = 0, updated_at = {} WHERE profile_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(profile_id.to_string())
                    .bind::<Text, _>(existing.id.clone())
                    .execute(conn)
                    .map_err(AppError::from)?;
            }
            existing.id
        } else {
            let candidate = legacy_id.to_string();
            let id = if candidate.is_empty()
                || sql_query(format!(
                    "SELECT id FROM application_profile_roles WHERE id = {}",
                    ph(kind, 1)
                ))
                .bind::<Text, _>(candidate.clone())
                .get_result::<ProfileRoleIdRow>(conn)
                .optional()
                .map_err(AppError::from)?
                .map(|row| !row.id.is_empty())
                .unwrap_or(false)
            {
                uuid::Uuid::new_v4().to_string()
            } else {
                candidate
            };
            if should_be_default {
                let clear_sql = format!(
                    "UPDATE application_profile_roles SET is_default = 0, updated_at = {} WHERE profile_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(clear_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(profile_id.to_string())
                    .execute(conn)
                    .map_err(AppError::from)?;
            }
            let insert_sql = format!(
                "INSERT INTO application_profile_roles (id, profile_id, role_key, name, description, permissions, source, is_default, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
            sql_query(insert_sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(profile_id.to_string())
                .bind::<Text, _>(role_key.to_string())
                .bind::<Text, _>(name.to_string())
                .bind::<Nullable<Text>, _>(description)
                .bind::<Text, _>(permissions.to_string())
                .bind::<Text, _>(source.to_string())
                .bind::<Integer, _>(i32::from(should_be_default))
                .bind::<Integer, _>(i32::from(is_active))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(conn)
                .map_err(AppError::from)?;
            id
        }
    }};
}

macro_rules! insert_migrated_profile_edge {
    (
        $conn:expr,
        $kind:expr,
        $table:literal,
        $subject_column:literal,
        $profile_id:expr,
        $subject_id:expr,
        $role_id:expr,
        $is_active:expr,
        $now:expr $(,)?
    ) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let insert_sql = match kind {
            DatabaseKind::Mysql => format!(
                "INSERT INTO {} (profile_id, {}, role_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}) ON DUPLICATE KEY UPDATE is_active = VALUES(is_active), updated_at = VALUES(updated_at)",
                $table,
                $subject_column,
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
            ),
            DatabaseKind::Sqlite | DatabaseKind::Postgres => format!(
                "INSERT INTO {} (profile_id, {}, role_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}) ON CONFLICT DO NOTHING",
                $table,
                $subject_column,
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
            ),
        };
        sql_query(insert_sql)
            .bind::<Text, _>($profile_id.to_string())
            .bind::<Text, _>($subject_id.to_string())
            .bind::<Text, _>($role_id.to_string())
            .bind::<Integer, _>($is_active)
            .bind::<BigInt, _>($now)
            .bind::<BigInt, _>($now)
            .execute(conn)
            .map_err(AppError::from)?;
    }};
}

impl Db {
    /// Reads only the live admission boundary in one transaction. Full
    /// entitlement graphs are deliberately not loaded for login checks.
    pub async fn load_application_access_snapshot(
        &self,
        application_id: &str,
        user_id: &str,
    ) -> AppResult<ApplicationAccessSnapshot> {
        let application_id = application_id.to_string();
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationAccessSnapshot, AppError, _>(|conn| {
                // The admission decision combines application, user,
                // organization, discovery, and module rows. Keep all of
                // those reads on one PostgreSQL MVCC revision as well; a
                // policy snapshot that is consistent only after login is
                // still enough to admit a stale or disabled boundary.
                initialize_consistent_read(conn, kind)?;
                let application = sql_query(format!(
                    "{} WHERE id = {}",
                    select_application_sql(),
                    ph(kind, 1)
                ))
                .bind::<Text, _>(&application_id)
                .get_result::<ApplicationRecord>(conn)
                .optional()
                .map_err(AppError::from)?;

                let user_active = sql_query(format!(
                    "SELECT is_active, archived_at FROM users WHERE id = {}",
                    ph(kind, 1)
                ))
                .bind::<Text, _>(&user_id)
                .get_result::<UserActivityRow>(conn)
                .optional()
                .map_err(AppError::from)?
                .is_some_and(|user| user.is_active == 1 && user.archived_at.is_none());

                let (organization_active, application_runtime_active, authorization_config) =
                    if let Some(application) = application.as_ref() {
                        let organization_active = sql_query(format!(
                            "SELECT is_active FROM organizations WHERE id = {}",
                            ph(kind, 1)
                        ))
                        .bind::<Text, _>(&application.organization_id)
                        .get_result::<OrganizationActivityRow>(conn)
                        .optional()
                        .map_err(AppError::from)?
                        .is_some_and(|organization| organization.is_active == 1);

                        let discovery = sql_query(format!(
                            "SELECT management_mode, last_verified_revision, last_verified_expires_at, snapshot_json, operator_disabled FROM application_discovery WHERE application_id = {}",
                            ph(kind, 1)
                        ))
                        .bind::<Text, _>(&application.id)
                        .get_result::<DiscoveryRuntimeRow>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                        let now = crate::util::now_ts();
                        let discovery_runtime_active = discovery_runtime_is_active(discovery, now);
                        let module = sql_query(format!(
                            "SELECT application_id, module_key, config_json, is_enabled, created_at, updated_at FROM application_modules WHERE application_id = {} AND module_key = {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        ))
                        .bind::<Text, _>(&application.id)
                        .bind::<Text, _>("authorization")
                        .get_result::<ApplicationModuleRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                        (
                            organization_active,
                            application_runtime_active(
                                application,
                                organization_active,
                                discovery_runtime_active,
                            ),
                            authorization_config(module)?,
                        )
                    } else {
                        (false, false, Map::new())
                    };

                let is_authorizable = application.as_ref().is_some_and(|application| {
                    application.is_active == 1
                        && application_runtime_active
                        && organization_active
                        && user_active
                });
                Ok(ApplicationAccessSnapshot {
                    application,
                    user_id,
                    user_active,
                    organization_active,
                    application_runtime_active,
                    authorization_config,
                    is_authorizable,
                })
            })
        })
    }

    /// Migrates the removed application-wide authorization graph into each
    /// application's physical `default` profile. This is intentionally a
    /// startup data migration rather than a runtime fallback: after it runs,
    /// the resolver has one source of truth and old rows cannot silently alter
    /// a request.
    pub async fn migrate_legacy_application_authorization(&self) -> AppResult<()> {
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let applications = sql_query(select_application_sql())
                    .load::<ApplicationRecord>(conn)
                    .map_err(AppError::from)?;
                let now = crate::util::now_ts();
                for application in applications {
                    // Startup can race when two application instances begin
                    // against the same database. Reuse the application-row
                    // write lock used by profile mutations before the
                    // check-then-insert migration steps below.
                    let lock_sql = format!(
                        "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                        ph(kind, 1)
                    );
                    if sql_query(lock_sql)
                        .bind::<Text, _>(&application.id)
                        .execute(conn)
                        .map_err(AppError::from)?
                        == 0
                    {
                        return Err(AppError::NotFound);
                    }
                    let marker_sql = format!(
                        "SELECT COUNT(*) AS count FROM application_authorization_migration_state WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    if sql_query(marker_sql)
                        .bind::<Text, _>(&application.id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        > 0
                    {
                        continue;
                    }
                    let default_profile_sql = format!(
                        "{} WHERE application_id = {} AND profile_key = {}",
                        select_application_authorization_profile_sql(),
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    let default_profile = if let Some(profile) = sql_query(default_profile_sql)
                        .bind::<Text, _>(&application.id)
                        .bind::<Text, _>("default")
                        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?
                    {
                        profile
                    } else {
                        let profile_id =
                            format!("application-default-profile:{}", application.id);
                        let insert_profile_sql = format!(
                            "INSERT INTO application_authorization_profiles (id, application_id, profile_key, connection_kind, connection_id, source_mode, sync_status, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                        sql_query(insert_profile_sql)
                            .bind::<Text, _>(&profile_id)
                            .bind::<Text, _>(&application.id)
                            .bind::<Text, _>("default")
                            .bind::<Text, _>("application")
                            .bind::<Nullable<Text>, _>(None::<String>)
                            .bind::<Text, _>(SOURCE_MODE_MANUAL)
                            .bind::<Text, _>(SYNC_STATUS_MANUAL)
                            .bind::<BigInt, _>(now)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                        sql_query(format!(
                            "{} WHERE id = {} AND application_id = {}",
                            select_application_authorization_profile_sql(),
                            ph(kind, 1),
                            ph(kind, 2)
                        ))
                        .bind::<Text, _>(&profile_id)
                        .bind::<Text, _>(&application.id)
                        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
                        .map_err(AppError::from)?
                    };

                    let legacy_roles_sql = format!(
                        "{} WHERE application_id = {} ORDER BY created_at ASC, id ASC",
                        select_application_role_sql(),
                        ph(kind, 1)
                    );
                    let legacy_roles = sql_query(legacy_roles_sql)
                        .bind::<Text, _>(&application.id)
                        .load::<LegacyApplicationRoleRecord>(conn)
                        .map_err(AppError::from)?;
                    let mut role_ids = BTreeMap::new();
                    let mut config_role_ids = BTreeMap::new();
                    for role in &legacy_roles {
                        let role_key = role.name.trim();
                        if role_key.is_empty() {
                            continue;
                        }
                        let permissions = normalize_application_entitlement_keys(
                            role.permission_keys()?,
                        )?;
                        let permissions = util::to_json(&permissions)?;
                        let migrated_id = materialize_migrated_profile_role!(
                            conn,
                            kind,
                            &default_profile.id,
                            &role.id,
                            role_key,
                            role_key,
                            role.description.clone(),
                            permissions,
                            "migrated",
                            role.is_default == 1,
                            role.is_active == 1,
                            now,
                        );
                        role_ids.insert(role.id.clone(), migrated_id.clone());
                        config_role_ids.insert(role_key.to_string(), migrated_id);
                    }

                    let module_sql = format!(
                        "{} WHERE application_id = {} AND module_key = {}",
                        select_application_module_sql(),
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    let module = sql_query(module_sql)
                        .bind::<Text, _>(&application.id)
                        .bind::<Text, _>("authorization")
                        .get_result::<ApplicationModuleRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                    let mut authorization_config = module
                        .as_ref()
                        .map(|module| {
                            serde_json::from_str::<Value>(&module.config_json).map_err(|error| {
                                AppError::Database(format!(
                                    "legacy authorization config is invalid: {error}"
                                ))
                            })
                        })
                        .transpose()?
                        .and_then(|value| value.as_object().cloned())
                        .unwrap_or_default();
                    let has_legacy_config = [
                        "default_role",
                        "custom_roles",
                        "group_mappings",
                        "organization_role_mappings",
                    ]
                    .iter()
                    .any(|key| authorization_config.contains_key(*key));
                    if has_legacy_config {
                        if let Some(custom_roles) = authorization_config
                            .get("custom_roles")
                            .and_then(Value::as_array)
                        {
                            for custom_role in custom_roles {
                                let Some(custom_role) = custom_role.as_object() else {
                                    continue;
                                };
                                let Some(name) = custom_role
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .map(str::trim)
                                    .filter(|value| !value.is_empty())
                                else {
                                    continue;
                                };
                                let permissions = custom_role
                                    .get("permissions")
                                    .and_then(Value::as_array)
                                    .into_iter()
                                    .flatten()
                                    .filter_map(Value::as_str)
                                    .map(ToOwned::to_owned)
                                    .collect::<Vec<_>>();
                                let permissions = normalize_application_entitlement_keys(permissions)?;
                                let permissions = util::to_json(&permissions)?;
                                let is_default = authorization_config
                                    .get("default_role")
                                    .and_then(Value::as_str)
                                    .is_some_and(|default_role| default_role.trim() == name);
                                let role_id = materialize_migrated_profile_role!(
                                    conn,
                                    kind,
                                    &default_profile.id,
                                    "",
                                    name,
                                    name,
                                    None::<String>,
                                    permissions,
                                    "migrated",
                                    is_default,
                                    true,
                                    now,
                                );
                                config_role_ids.insert(name.to_string(), role_id);
                            }
                        }
                        if let Some(default_role) = authorization_config
                            .get("default_role")
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            && !config_role_ids.contains_key(default_role)
                        {
                            let role_id = materialize_migrated_profile_role!(
                                conn,
                                kind,
                                &default_profile.id,
                                "",
                                default_role,
                                default_role,
                                None::<String>,
                                "[]",
                                "migrated",
                                true,
                                true,
                                now,
                            );
                            config_role_ids.insert(default_role.to_string(), role_id);
                        }
                    }

                    if let Some(module) = module.as_ref()
                        && has_legacy_config
                    {
                        let role_ids_for_config = &config_role_ids;
                        if let Some(group_mappings) = authorization_config
                            .get("group_mappings")
                            .and_then(Value::as_array)
                        {
                            for mapping in group_mappings {
                                let Some(mapping) = mapping.as_object() else {
                                    continue;
                                };
                                let Some(group_name) = mapping
                                    .get("group")
                                    .and_then(Value::as_str)
                                    .map(str::trim)
                                    .filter(|value| !value.is_empty())
                                else {
                                    continue;
                                };
                                let Some(role_name) = mapping
                                    .get("role")
                                    .and_then(Value::as_str)
                                    .map(str::trim)
                                    .filter(|value| !value.is_empty())
                                else {
                                    continue;
                                };
                                let Some(role_id) = role_ids_for_config.get(role_name) else {
                                    continue;
                                };
                                #[derive(Debug, diesel::QueryableByName)]
                                struct GroupIdRow {
                                    #[diesel(sql_type = Text)]
                                    id: String,
                                }
                                let group_sql = format!(
                                    "SELECT id FROM access_groups WHERE id = {} OR name = {}",
                                    ph(kind, 1),
                                    ph(kind, 2)
                                );
                                let Some(group) = sql_query(group_sql)
                                    .bind::<Text, _>(group_name)
                                    .bind::<Text, _>(group_name)
                                    .get_result::<GroupIdRow>(conn)
                                    .optional()
                                    .map_err(AppError::from)?
                                else {
                                    continue;
                                };
                                insert_migrated_profile_edge!(
                                    conn,
                                    kind,
                                    "application_profile_group_roles",
                                    "group_id",
                                    &default_profile.id,
                                    group.id,
                                    role_id,
                                    1,
                                    now,
                                );
                            }
                        }
                        if let Some(organization_mappings) = authorization_config
                            .get("organization_role_mappings")
                            .and_then(Value::as_object)
                        {
                            for (organization_role, role_name) in organization_mappings {
                                let Some(role_name) = role_name.as_str().map(str::trim) else {
                                    continue;
                                };
                                let Some(role_id) = role_ids_for_config.get(role_name) else {
                                    continue;
                                };
                                insert_migrated_profile_edge!(
                                    conn,
                                    kind,
                                    "application_profile_organization_roles",
                                    "organization_role",
                                    &default_profile.id,
                                    organization_role,
                                    role_id,
                                    1,
                                    now,
                                );
                            }
                        }
                        for key in [
                            "default_role",
                            "custom_roles",
                            "group_mappings",
                            "organization_role_mappings",
                        ] {
                            authorization_config.remove(key);
                        }
                        let config_json = util::to_json(&Value::Object(authorization_config))?;
                        let update_sql = format!(
                            "UPDATE application_modules SET config_json = {}, updated_at = {} WHERE application_id = {} AND module_key = {}",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3),
                            ph(kind, 4)
                        );
                        sql_query(update_sql)
                            .bind::<Text, _>(config_json)
                            .bind::<BigInt, _>(now)
                            .bind::<Text, _>(&application.id)
                            .bind::<Text, _>(&module.module_key)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }

                    let user_sql = format!(
                        "SELECT user_id AS subject_id, application_role_id, is_active FROM application_user_roles WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    let user_assignments = sql_query(user_sql)
                        .bind::<Text, _>(&application.id)
                        .load::<LegacyApplicationRoleAssignmentRow>(conn)
                        .map_err(AppError::from)?;
                    for assignment in user_assignments {
                        if let Some(role_id) = role_ids.get(&assignment.application_role_id) {
                            insert_migrated_profile_edge!(
                                conn,
                                kind,
                                "application_profile_user_roles",
                                "user_id",
                                &default_profile.id,
                                assignment.subject_id,
                                role_id,
                                assignment.is_active,
                                now,
                            );
                        }
                    }
                    let group_sql = format!(
                        "SELECT group_id AS subject_id, application_role_id, is_active FROM application_group_roles WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    let group_assignments = sql_query(group_sql)
                        .bind::<Text, _>(&application.id)
                        .load::<LegacyApplicationRoleAssignmentRow>(conn)
                        .map_err(AppError::from)?;
                    for assignment in group_assignments {
                        if let Some(role_id) = role_ids.get(&assignment.application_role_id) {
                            insert_migrated_profile_edge!(
                                conn,
                                kind,
                                "application_profile_group_roles",
                                "group_id",
                                &default_profile.id,
                                assignment.subject_id,
                                role_id,
                                assignment.is_active,
                                now,
                            );
                        }
                    }
                    let organization_sql = format!(
                        "SELECT organization_role, application_role_id, is_active FROM application_organization_role_mappings WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    let organization_assignments = sql_query(organization_sql)
                        .bind::<Text, _>(&application.id)
                        .load::<LegacyApplicationOrganizationRoleAssignmentRow>(conn)
                        .map_err(AppError::from)?;
                    for assignment in organization_assignments {
                        if let Some(role_id) = role_ids.get(&assignment.application_role_id) {
                            insert_migrated_profile_edge!(
                                conn,
                                kind,
                                "application_profile_organization_roles",
                                "organization_role",
                                &default_profile.id,
                                assignment.organization_role,
                                role_id,
                                assignment.is_active,
                                now,
                            );
                        }
                    }
                    let override_sql = format!(
                        "SELECT user_id, permission, effect FROM application_user_permission_overrides WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    let overrides = sql_query(override_sql)
                        .bind::<Text, _>(&application.id)
                        .load::<LegacyApplicationOverrideRow>(conn)
                        .map_err(AppError::from)?;
                    for override_record in overrides {
                        let insert_sql = match kind {
                            DatabaseKind::Mysql => format!(
                                "INSERT INTO application_profile_permission_overrides (profile_id, user_id, permission, effect, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}) ON DUPLICATE KEY UPDATE effect = VALUES(effect), updated_at = VALUES(updated_at)",
                                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                            ),
                            DatabaseKind::Sqlite | DatabaseKind::Postgres => format!(
                                "INSERT INTO application_profile_permission_overrides (profile_id, user_id, permission, effect, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}) ON CONFLICT DO NOTHING",
                                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                            ),
                        };
                        sql_query(insert_sql)
                            .bind::<Text, _>(&default_profile.id)
                            .bind::<Text, _>(override_record.user_id)
                            .bind::<Text, _>(override_record.permission)
                            .bind::<Text, _>(override_record.effect)
                            .bind::<BigInt, _>(now)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }

                    let binding_sql = format!(
                        "UPDATE application_client_bindings SET authorization_profile_id = {}, updated_at = {} WHERE application_id = {} AND authorization_profile_id = {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
                    );
                    sql_query(binding_sql)
                        .bind::<Text, _>(&default_profile.id)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&application.id)
                        .bind::<Text, _>("default")
                        .execute(conn)
                        .map_err(AppError::from)?;
                    let marker_insert = match kind {
                        DatabaseKind::Mysql => format!(
                            "INSERT IGNORE INTO application_authorization_migration_state (application_id, migrated_at) VALUES ({}, {})",
                            ph(kind, 1),
                            ph(kind, 2)
                        ),
                        DatabaseKind::Sqlite | DatabaseKind::Postgres => format!(
                            "INSERT INTO application_authorization_migration_state (application_id, migrated_at) VALUES ({}, {}) ON CONFLICT DO NOTHING",
                            ph(kind, 1),
                            ph(kind, 2)
                        ),
                    };
                    sql_query(marker_insert)
                        .bind::<Text, _>(&application.id)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    /// Reads the application boundary through its physical `default` profile.
    /// Application-level adapters (CAS, SAML, JWT, and management previews)
    /// therefore use the same policy graph as client-bound protocols.
    pub async fn load_application_policy_snapshot(
        &self,
        application_id: &str,
        user_id: &str,
    ) -> AppResult<AuthorizationPolicySnapshot> {
        self.load_policy_snapshot(
            PolicyBoundary::Application {
                application_id: application_id.to_string(),
            },
            user_id,
        )
        .await
    }

    /// Reads a client binding, its application/profile policy, and the user
    /// subject graph in one transaction. This is the OIDC/runtime entrypoint.
    pub async fn load_client_policy_snapshot(
        &self,
        client_db_id: &str,
        user_id: &str,
    ) -> AppResult<AuthorizationPolicySnapshot> {
        self.load_policy_snapshot(
            PolicyBoundary::Client {
                client_db_id: client_db_id.to_string(),
                required_protocol: None,
            },
            user_id,
        )
        .await
    }

    /// Reads a client-bound policy snapshot while requiring one protocol
    /// binding.  OIDC uses this entrypoint so a SAML/CAS binding or a disabled
    /// `oauth2_oidc` module cannot share the user authorization path.
    pub async fn load_client_policy_snapshot_for_protocol(
        &self,
        client_db_id: &str,
        user_id: &str,
        protocol: &str,
    ) -> AppResult<AuthorizationPolicySnapshot> {
        self.load_policy_snapshot(
            PolicyBoundary::Client {
                client_db_id: client_db_id.to_string(),
                required_protocol: Some(protocol.to_string()),
            },
            user_id,
        )
        .await
    }

    /// Reads the application/client runtime boundary in one transaction.
    /// The empty subject is deliberate: this method is for pre-login and
    /// service-account decisions, never for user authorization.  Callers must
    /// use `load_client_policy_snapshot_for_protocol` when a user is present.
    pub async fn load_client_runtime_snapshot(
        &self,
        client_db_id: &str,
        protocol: Option<&str>,
    ) -> AppResult<AuthorizationPolicySnapshot> {
        self.load_policy_snapshot(
            PolicyBoundary::Client {
                client_db_id: client_db_id.to_string(),
                required_protocol: protocol.map(ToOwned::to_owned),
            },
            "",
        )
        .await
    }

    /// Reads a profile-scoped policy for management previews and non-OIDC
    /// adapters which already have an application/profile edge.
    pub async fn load_profile_policy_snapshot(
        &self,
        application_id: &str,
        profile_id: &str,
        user_id: &str,
    ) -> AppResult<AuthorizationPolicySnapshot> {
        self.load_policy_snapshot(
            PolicyBoundary::Profile {
                application_id: application_id.to_string(),
                profile_id: profile_id.to_string(),
            },
            user_id,
        )
        .await
    }

    async fn load_policy_snapshot(
        &self,
        boundary: PolicyBoundary,
        user_id: &str,
    ) -> AppResult<AuthorizationPolicySnapshot> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<AuthorizationPolicySnapshot, AppError, _>(|conn| {
                // PostgreSQL READ COMMITTED assigns a fresh snapshot to each
                // SELECT. Authorization is a graph decision, so role,
                // membership, and assignment reads must observe one MVCC
                // point rather than a mixture of revisions.
                initialize_consistent_read(conn, kind)?;
                let (client_id, requested_application_id, requested_profile_id) =
                    match &boundary {
                        PolicyBoundary::Application { application_id } => {
                            (
                                None,
                                Some(application_id.clone()),
                                Some("default".to_string()),
                            )
                        }
                        PolicyBoundary::Client { client_db_id, .. } => {
                            (Some(client_db_id.clone()), None, None)
                        }
                        PolicyBoundary::Profile {
                            application_id,
                            profile_id,
                        } => (
                            None,
                            Some(application_id.clone()),
                            Some(profile_id.clone()),
                        ),
                    };

                let client_boundary = if let Some(client_id) = client_id.as_ref() {
                    let sql = format!(
                        "SELECT clients.organization_id,
                                clients.is_active AS client_is_active,
                                application_client_bindings.application_id AS binding_application_id,
                                application_client_bindings.client_db_id AS binding_client_db_id,
                                application_client_bindings.protocol AS binding_protocol,
                                application_client_bindings.authorization_profile_id AS binding_authorization_profile_id,
                                application_client_bindings.auth_domain_id AS binding_auth_domain_id,
                                application_client_bindings.is_active AS binding_is_active,
                                application_client_bindings.created_at AS binding_created_at,
                                application_client_bindings.updated_at AS binding_updated_at
                         FROM clients
                         LEFT JOIN application_client_bindings
                           ON application_client_bindings.client_db_id = clients.id
                         WHERE clients.id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(client_id)
                        .get_result::<ClientBindingBoundaryRow>(conn)
                        .optional()
                        .map_err(AppError::from)?
                } else {
                    None
                };
                let client_state = client_boundary.as_ref().map(|boundary| ClientActivityRow {
                    organization_id: boundary.organization_id.clone(),
                    is_active: boundary.client_is_active,
                });
                let binding = client_boundary.as_ref().and_then(|boundary| {
                    Some(ApplicationClientBindingRecord {
                        application_id: boundary.binding_application_id.clone()?,
                        client_db_id: boundary.binding_client_db_id.clone()?,
                        protocol: boundary.binding_protocol.clone()?,
                        authorization_profile_id: boundary
                            .binding_authorization_profile_id
                            .clone()?,
                        auth_domain_id: boundary.binding_auth_domain_id.clone()?,
                        is_active: boundary.binding_is_active?,
                        created_at: boundary.binding_created_at?,
                        updated_at: boundary.binding_updated_at?,
                    })
                });

                let application_id = requested_application_id
                    .as_deref()
                    .or_else(|| binding.as_ref().map(|value| value.application_id.as_str()));
                let application = if let Some(application_id) = application_id {
                    let sql = format!(
                        "{} WHERE id = {}",
                        select_application_sql(),
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(application_id)
                        .get_result::<ApplicationRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?
                } else {
                    None
                };

                let profile_selector = requested_profile_id.or_else(|| {
                    binding
                        .as_ref()
                        .map(|value| value.authorization_profile_id.clone())
                });
                let profile = match (application.as_ref(), profile_selector.as_deref()) {
                    (Some(application), Some("default")) => {
                        let sql = format!(
                            "{} WHERE application_id = {} AND profile_key = {}",
                            select_application_authorization_profile_sql(),
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        sql_query(sql)
                            .bind::<Text, _>(&application.id)
                            .bind::<Text, _>("default")
                            .get_result::<ApplicationAuthorizationProfileRecord>(conn)
                            .optional()
                            .map_err(AppError::from)?
                    }
                    (Some(application), Some(profile_id)) => {
                        let sql = format!(
                            "{} WHERE id = {} AND application_id = {}",
                            select_application_authorization_profile_sql(),
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        sql_query(sql)
                            .bind::<Text, _>(profile_id)
                            .bind::<Text, _>(&application.id)
                            .get_result::<ApplicationAuthorizationProfileRecord>(conn)
                            .optional()
                            .map_err(AppError::from)?
                    }
                    _ => None,
                };

                let user_active = {
                    let sql = format!(
                        "SELECT is_active, archived_at FROM users WHERE id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&user_id)
                        .get_result::<UserActivityRow>(conn)
                        .optional()
                        .map_err(AppError::from)?
                        .is_some_and(|user| user.is_active == 1 && user.archived_at.is_none())
                };

                let (organization_active, membership, runtime_active) =
                    if let Some(application) = application.as_ref() {
                        let membership_sql = format!(
                            "SELECT organizations.is_active AS organization_is_active,
                                    organizations.id AS membership_id,
                                    organizations.slug AS membership_slug,
                                    organizations.name AS membership_name,
                                    COALESCE(organizations.kind, 'tenant') AS membership_kind,
                                    organizations.description AS membership_description,
                                    organizations.is_active AS membership_is_active,
                                    organization_members.role AS membership_role,
                                    organization_members.created_at AS membership_created_at,
                                    organization_members.updated_at AS membership_updated_at
                             FROM organizations
                             LEFT JOIN organization_members
                               ON organization_members.organization_id = organizations.id
                              AND organization_members.user_id = {}
                             WHERE organizations.id = {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        let organization_membership = sql_query(membership_sql)
                            .bind::<Text, _>(&user_id)
                            .bind::<Text, _>(&application.organization_id)
                            .get_result::<PolicyOrganizationMembershipRow>(conn)
                            .optional()
                            .map_err(AppError::from)?;
                        let organization_active = organization_membership
                            .as_ref()
                            .is_some_and(|organization| organization.organization_is_active == 1);
                        let membership = organization_membership.and_then(|row| {
                            Some(UserOrganizationRecord {
                                id: row.membership_id?,
                                slug: row.membership_slug?,
                                name: row.membership_name?,
                                kind: row.membership_kind?,
                                description: row.membership_description,
                                is_active: row.membership_is_active?,
                                role: row.membership_role?,
                                membership_created_at: row.membership_created_at?,
                                membership_updated_at: row.membership_updated_at?,
                            })
                        });
                        let discovery_sql = format!(
                            "SELECT management_mode, last_verified_revision, last_verified_expires_at, snapshot_json, operator_disabled FROM application_discovery WHERE application_id = {}",
                            ph(kind, 1)
                        );
                        let discovery = sql_query(discovery_sql)
                            .bind::<Text, _>(&application.id)
                            .get_result::<DiscoveryRuntimeRow>(conn)
                            .optional()
                            .map_err(AppError::from)?;
                        let now = crate::util::now_ts();
                        let runtime_active = discovery_runtime_is_active(discovery, now);
                        (organization_active, membership, runtime_active)
                    } else {
                        (false, None, false)
                    };

                let application_modules = if let Some(application) = application.as_ref() {
                    let module_sql = format!(
                        "SELECT application_id, module_key, config_json, is_enabled, created_at, updated_at FROM application_modules WHERE application_id = {} AND module_key IN ({}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    let modules = sql_query(module_sql)
                        .bind::<Text, _>(&application.id)
                        .bind::<Text, _>("authorization")
                        .bind::<Text, _>("protocols")
                        .load::<ApplicationModuleRecord>(conn)
                        .map_err(AppError::from)?;
                    let mut modules_by_key = BTreeMap::new();
                    for module in modules {
                        if modules_by_key
                            .insert(module.module_key.clone(), module)
                            .is_some()
                        {
                            return Err(AppError::Internal(
                                "duplicate application module key".to_string(),
                            ));
                        }
                    }
                    modules_by_key
                } else {
                    BTreeMap::new()
                };

                let authorization_config = authorization_config(
                    application_modules.get("authorization").cloned(),
                )?;
                let required_protocol = match &boundary {
                    PolicyBoundary::Client {
                        required_protocol, ..
                    } => required_protocol.as_deref(),
                    _ => None,
                };
                let protocol_enabled = if client_id.is_some() {
                    let protocol = required_protocol.or_else(|| {
                        binding
                            .as_ref()
                            .map(|value| value.protocol.as_str())
                    });
                    if let Some(_application) = application.as_ref() {
                        protocol_module_enabled(
                            application_modules.get("protocols").cloned(),
                            protocol,
                        )?
                    } else {
                        false
                    }
                } else {
                    true
                };
                let binding_protocol_matches = required_protocol.is_none_or(|required| {
                    binding.as_ref().is_some_and(|binding| {
                        protocol_key(&binding.protocol) == protocol_key(required)
                    })
                });
                let inherit_enterprise = authorization_config
                    .get("inherit_enterprise_roles")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let scoped_subject = user_active
                    && organization_active
                    && membership.as_ref().is_some_and(|value| value.is_active == 1);

                let groups = if scoped_subject {
                    let sql = format!(
                        "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at, access_groups.version FROM access_groups INNER JOIN group_members ON access_groups.id = group_members.group_id WHERE group_members.user_id = {} ORDER BY access_groups.name ASC, access_groups.id ASC",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&user_id)
                        .load::<GroupRecord>(conn)
                        .map_err(AppError::from)?
                } else {
                    Vec::new()
                };
                let group_ids = groups
                    .iter()
                    .map(|group| group.id.clone())
                    .collect::<Vec<_>>();

                let enterprise_roles = if scoped_subject && inherit_enterprise {
                    let sql = format!(
                        "SELECT roles.id, roles.name, roles.description, roles.is_system, roles.created_at, roles.updated_at FROM roles INNER JOIN user_roles ON roles.id = user_roles.role_id WHERE user_roles.user_id = {} ORDER BY roles.name ASC, roles.id ASC",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&user_id)
                        .load::<RoleRecord>(conn)
                        .map_err(AppError::from)?
                } else {
                    Vec::new()
                };

                let enterprise_group_roles = if scoped_subject && inherit_enterprise {
                    load_group_roles!(conn, kind, &group_ids)?
                } else {
                    BTreeMap::new()
                };
                let mut enterprise_role_ids = BTreeSet::new();
                enterprise_role_ids.extend(enterprise_roles.iter().map(|role| role.id.clone()));
                for roles in enterprise_group_roles.values() {
                    enterprise_role_ids.extend(roles.iter().map(|role| role.id.clone()));
                }
                let enterprise_role_permissions =
                    load_role_permissions!(conn, kind, &enterprise_role_ids)?;

                let profile_roles = if let Some(profile) = profile.as_ref() {
                    let sql = format!(
                        "{} WHERE profile_id = {} ORDER BY is_active DESC, name ASC, id ASC",
                        select_application_profile_role_sql(),
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&profile.id)
                        .load::<ApplicationProfileRoleRecord>(conn)
                        .map_err(AppError::from)?
                } else {
                    Vec::new()
                };
                let profile_user_assignments = if let Some(profile) = profile.as_ref() {
                    let sql = format!(
                        "SELECT profile_id, user_id AS subject_id, role_id, is_active FROM application_profile_user_roles WHERE profile_id = {} AND user_id = {} ORDER BY role_id ASC",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&profile.id)
                        .bind::<Text, _>(&user_id)
                        .load::<ApplicationProfileRoleAssignmentRecord>(conn)
                        .map_err(AppError::from)?
                } else {
                    Vec::new()
                };
                let profile_group_assignments = if let Some(profile) = profile.as_ref() {
                    load_profile_group_assignments!(conn, kind, &profile.id, &group_ids)?
                } else {
                    Vec::new()
                };
                let profile_organization_assignments = if let Some(profile) = profile.as_ref() {
                    let sql = format!(
                        "SELECT profile_id, organization_role, role_id, is_active FROM application_profile_organization_roles WHERE profile_id = {} ORDER BY organization_role ASC, role_id ASC",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&profile.id)
                        .load::<ApplicationProfileOrganizationRoleAssignmentRecord>(conn)
                        .map_err(AppError::from)?
                } else {
                    Vec::new()
                };
                let profile_permission_overrides = if let Some(profile) = profile.as_ref() {
                    let sql = format!(
                        "{} WHERE profile_id = {} AND user_id = {} ORDER BY permission ASC",
                        select_application_profile_permission_override_sql(),
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&profile.id)
                        .bind::<Text, _>(&user_id)
                        .load::<ApplicationProfilePermissionOverrideRecord>(conn)
                        .map_err(AppError::from)?
                } else {
                    Vec::new()
                };

                let claim_mappers = if let Some(client_id) = client_id.as_ref() {
                    let sql = format!(
                        "{} WHERE client_db_id = {} ORDER BY sort_order ASC, created_at ASC",
                        select_client_claim_mapper_sql(),
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(client_id)
                        .load::<ClientClaimMapperRecord>(conn)
                        .map_err(AppError::from)?
                } else {
                    Vec::new()
                };
                let application_matches_client = match (application.as_ref(), client_state.as_ref()) {
                    (Some(application), Some(client)) => client.organization_id.as_deref()
                        == Some(application.organization_id.as_str()),
                    (None, _) => false,
                    (_, None) if client_id.is_some() => false,
                    (_, None) => true,
                };
                let binding_active = client_id.as_ref().is_none_or(|client_id| {
                    binding.as_ref().is_some_and(|binding| {
                        binding.client_db_id == *client_id
                            && binding.is_active == 1
                            && application
                                .as_ref()
                                .is_some_and(|application| binding.application_id == application.id)
                    })
                });
                let profile_active = profile.as_ref().is_some_and(|profile| {
                    application
                        .as_ref()
                        .is_some_and(|application| profile.application_id == application.id)
                });
                let client_active = client_id.as_ref().is_none_or(|_| {
                    client_state.as_ref().is_some_and(|client| client.is_active == 1)
                });
                let is_authorizable = application.as_ref().is_some_and(|application| {
                    application.is_active == 1
                        && application_runtime_active(
                            application,
                            organization_active,
                            runtime_active,
                        )
                }) && user_active
                    && application_matches_client
                    && client_active
                    && binding_active
                    && protocol_enabled
                    && binding_protocol_matches
                    && profile_active;

                Ok(AuthorizationPolicySnapshot {
                    application,
                    binding,
                    profile,
                    user_id,
                    user_active,
                    client_id,
                    client_active,
                    client_organization_id: client_state
                        .as_ref()
                        .and_then(|client| client.organization_id.clone()),
                    organization_active,
                    membership,
                    groups,
                    enterprise_roles,
                    enterprise_group_roles,
                    enterprise_role_permissions,
                    authorization_config,
                    application_runtime_active: runtime_active,
                    protocol_enabled,
                    profile_roles,
                    profile_user_assignments,
                    profile_group_assignments,
                    profile_organization_assignments,
                    profile_permission_overrides,
                    claim_mappers,
                    is_authorizable,
                })
            })
        })
    }
}

fn authorization_config(module: Option<ApplicationModuleRecord>) -> AppResult<Map<String, Value>> {
    let Some(module) = module.filter(|module| module.is_enabled == 1) else {
        return Ok(Map::new());
    };
    let value = serde_json::from_str::<Value>(&module.config_json).map_err(|err| {
        AppError::Internal(format!("application module config is invalid: {err}"))
    })?;
    let normalized = crate::applications::normalize_module_config("authorization", value)?;
    normalized
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::Internal("application module config is not an object".to_string()))
}

fn protocol_key(protocol: &str) -> &str {
    match protocol {
        "oidc" | "oauth2_oidc" => "oauth2_oidc",
        "saml" | "saml2" => "saml2",
        other => other,
    }
}

fn protocol_module_enabled(
    module: Option<ApplicationModuleRecord>,
    protocol: Option<&str>,
) -> AppResult<bool> {
    let Some(protocol) = protocol else {
        return Ok(false);
    };
    let Some(module) = module else {
        // Applications created before protocol modules existed retain the
        // historical compatibility behavior.
        return Ok(true);
    };
    if module.is_enabled != 1 {
        return Ok(false);
    }
    let value = serde_json::from_str::<Value>(&module.config_json).map_err(|err| {
        AppError::Internal(format!("application module config is invalid: {err}"))
    })?;
    let normalized = crate::applications::normalize_module_config("protocols", value)?;
    let Some(protocol_config) = normalized
        .get(protocol_key(protocol))
        .and_then(Value::as_object)
    else {
        return Ok(false);
    };
    Ok(protocol_config
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true))
}

fn application_runtime_active(
    application: &ApplicationRecord,
    organization_active: bool,
    discovery_runtime_active: bool,
) -> bool {
    application.is_active == 1 && organization_active && discovery_runtime_active
}
