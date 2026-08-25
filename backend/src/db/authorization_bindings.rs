//! Atomic persistence for profile-scoped authorization bindings.
//!
//! The legacy admin API exposes one endpoint per edge table.  This module
//! owns the aggregate command used by the profile-scoped endpoint so that a
//! user role set, user overrides, group role set, and organization-role map
//! cannot be observed or committed independently.

use super::{
    AuditEventRecord, CountRow, DatabaseKind, Db, bind_text_list, blocking, dedupe_nonempty,
    normalize_application_entitlement_keys, ph,
};
use crate::{
    audit::AuditEvent,
    error::{AppError, AppResult},
    organizations, util,
};
use diesel::{
    Connection, OptionalExtension, RunQueryDsl,
    connection::SimpleConnection,
    sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_ROLE_IDS: usize = 900;
const MAX_PERMISSION_OVERRIDES: usize = 900;
const MAX_ORGANIZATION_BINDINGS: usize = 900;
const WRITE_BATCH_SIZE: usize = 200;

#[derive(Debug, Clone)]
pub struct AuthorizationBindingPermissionOverride {
    pub permission: String,
    pub effect: String,
}

#[derive(Debug, Clone)]
pub struct AuthorizationBindingsUpdate {
    pub user_id: Option<String>,
    pub group_id: Option<String>,
    pub user_role_ids: Vec<String>,
    pub user_permission_overrides: Vec<AuthorizationBindingPermissionOverride>,
    pub group_role_ids: Vec<String>,
    pub organization_role_bindings: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthorizationBindingPermissionOverrideSnapshot {
    pub permission: String,
    pub effect: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthorizationUserBindingSnapshot {
    pub user_role_ids: Vec<String>,
    pub user_permission_overrides: Vec<AuthorizationBindingPermissionOverrideSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthorizationBindingsSnapshot {
    pub application_id: String,
    pub profile_id: String,
    pub user_bindings: BTreeMap<String, AuthorizationUserBindingSnapshot>,
    pub group_bindings: BTreeMap<String, Vec<String>>,
    pub organization_role_bindings: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct NormalizedAuthorizationBindingsUpdate {
    user_id: Option<String>,
    group_id: Option<String>,
    user_role_ids: Vec<String>,
    user_permission_overrides: Vec<AuthorizationBindingPermissionOverride>,
    group_role_ids: Vec<String>,
    organization_role_bindings: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ApplicationOrganizationRow {
    #[diesel(sql_type = Text)]
    organization_id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ProfileApplicationRow {
    #[diesel(sql_type = Text)]
    application_id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ProfileRoleIdRow {
    #[diesel(sql_type = Text)]
    id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct UserRoleBindingRow {
    #[diesel(sql_type = Text)]
    user_id: String,
    #[diesel(sql_type = Text)]
    role_id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct UserPermissionOverrideRow {
    #[diesel(sql_type = Text)]
    user_id: String,
    #[diesel(sql_type = Text)]
    permission: String,
    #[diesel(sql_type = Text)]
    effect: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct GroupRoleBindingRow {
    #[diesel(sql_type = Text)]
    group_id: String,
    #[diesel(sql_type = Text)]
    role_id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct OrganizationRoleBindingRow {
    #[diesel(sql_type = Text)]
    organization_role: String,
    #[diesel(sql_type = Text)]
    role_id: String,
}

fn normalize_subject_id(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_role_ids(values: Vec<String>, field: &str) -> AppResult<Vec<String>> {
    if values.len() > MAX_ROLE_IDS {
        return Err(AppError::BadRequest(format!(
            "{field} contains too many role ids"
        )));
    }
    Ok(dedupe_nonempty(values))
}

fn normalize_permission_overrides(
    values: Vec<AuthorizationBindingPermissionOverride>,
) -> AppResult<Vec<AuthorizationBindingPermissionOverride>> {
    if values.len() > MAX_PERMISSION_OVERRIDES {
        return Err(AppError::BadRequest(
            "user_permission_overrides contains too many entries".to_string(),
        ));
    }
    let mut normalized = BTreeMap::new();
    for value in values {
        let permission = normalize_application_entitlement_keys(vec![value.permission])?
            .into_iter()
            .next()
            .ok_or_else(|| AppError::BadRequest("permission is required".to_string()))?;
        let effect = value.effect.trim().to_ascii_lowercase();
        if effect != "allow" && effect != "deny" {
            return Err(AppError::BadRequest(
                "permission effect must be allow or deny".to_string(),
            ));
        }
        // A permission is a primary key in the storage table.  Last-write
        // semantics are deterministic because the request order is retained
        // until this map is folded.
        normalized.insert(permission, effect);
    }
    Ok(normalized
        .into_iter()
        .map(|(permission, effect)| AuthorizationBindingPermissionOverride { permission, effect })
        .collect())
}

fn normalize_organization_role_bindings(
    values: BTreeMap<String, Vec<String>>,
) -> AppResult<BTreeMap<String, Vec<String>>> {
    let mut normalized = BTreeMap::new();
    let mut raw_count = 0usize;
    for (organization_role, role_ids) in values {
        let organization_role = organizations::normalize_role(&organization_role)?;
        raw_count = raw_count.saturating_add(role_ids.len());
        if raw_count > MAX_ORGANIZATION_BINDINGS {
            return Err(AppError::BadRequest(
                "organization_role_bindings contains too many entries".to_string(),
            ));
        }
        normalized.insert(organization_role, dedupe_nonempty(role_ids));
    }
    Ok(normalized)
}

fn normalize_update(
    update: AuthorizationBindingsUpdate,
) -> AppResult<NormalizedAuthorizationBindingsUpdate> {
    let user_id = normalize_subject_id(update.user_id);
    let group_id = normalize_subject_id(update.group_id);
    let user_role_ids = normalize_role_ids(update.user_role_ids, "user_role_ids")?;
    let group_role_ids = normalize_role_ids(update.group_role_ids, "group_role_ids")?;
    let user_permission_overrides =
        normalize_permission_overrides(update.user_permission_overrides)?;
    let organization_role_bindings =
        normalize_organization_role_bindings(update.organization_role_bindings)?;

    if user_id.is_none() && (!user_role_ids.is_empty() || !user_permission_overrides.is_empty()) {
        return Err(AppError::BadRequest(
            "user_id is required when user bindings are supplied".to_string(),
        ));
    }
    if group_id.is_none() && !group_role_ids.is_empty() {
        return Err(AppError::BadRequest(
            "group_id is required when group bindings are supplied".to_string(),
        ));
    }

    let mut distinct_role_ids = BTreeSet::new();
    distinct_role_ids.extend(user_role_ids.iter().cloned());
    distinct_role_ids.extend(group_role_ids.iter().cloned());
    distinct_role_ids.extend(
        organization_role_bindings
            .values()
            .flat_map(|role_ids| role_ids.iter().cloned()),
    );
    if distinct_role_ids.len() > MAX_ROLE_IDS {
        return Err(AppError::BadRequest(
            "authorization bindings contain too many distinct role ids".to_string(),
        ));
    }

    Ok(NormalizedAuthorizationBindingsUpdate {
        user_id,
        group_id,
        user_role_ids,
        user_permission_overrides,
        group_role_ids,
        organization_role_bindings,
    })
}

/// Loads all four edge sets using the connection currently held by the caller.
/// The macro form keeps the Diesel backend generic without opening another
/// pooled connection for each subject or organization role.
macro_rules! load_authorization_bindings_snapshot {
    ($conn:expr, $kind:expr, $application_id:expr, $profile_id:expr) => {{
        let user_role_sql = format!(
            "SELECT user_id, role_id FROM application_profile_user_roles WHERE profile_id = {} AND is_active = 1 ORDER BY user_id ASC, role_id ASC",
            ph($kind, 1)
        );
        let user_role_rows = sql_query(user_role_sql)
            .bind::<Text, _>($profile_id)
            .load::<UserRoleBindingRow>($conn)
            .map_err(AppError::from)?;

        let user_override_sql = format!(
            "SELECT user_id, permission, effect FROM application_profile_permission_overrides WHERE profile_id = {} ORDER BY user_id ASC, permission ASC",
            ph($kind, 1)
        );
        let user_override_rows = sql_query(user_override_sql)
            .bind::<Text, _>($profile_id)
            .load::<UserPermissionOverrideRow>($conn)
            .map_err(AppError::from)?;

        let group_role_sql = format!(
            "SELECT group_id, role_id FROM application_profile_group_roles WHERE profile_id = {} AND is_active = 1 ORDER BY group_id ASC, role_id ASC",
            ph($kind, 1)
        );
        let group_role_rows = sql_query(group_role_sql)
            .bind::<Text, _>($profile_id)
            .load::<GroupRoleBindingRow>($conn)
            .map_err(AppError::from)?;

        let organization_role_sql = format!(
            "SELECT organization_role, role_id FROM application_profile_organization_roles WHERE profile_id = {} AND is_active = 1 ORDER BY organization_role ASC, role_id ASC",
            ph($kind, 1)
        );
        let organization_role_rows = sql_query(organization_role_sql)
            .bind::<Text, _>($profile_id)
            .load::<OrganizationRoleBindingRow>($conn)
            .map_err(AppError::from)?;

        let mut user_bindings = BTreeMap::new();
        for row in user_role_rows {
            user_bindings
                .entry(row.user_id)
                .or_insert_with(|| AuthorizationUserBindingSnapshot {
                    user_role_ids: Vec::new(),
                    user_permission_overrides: Vec::new(),
                })
                .user_role_ids
                .push(row.role_id);
        }
        for row in user_override_rows {
            user_bindings
                .entry(row.user_id)
                .or_insert_with(|| AuthorizationUserBindingSnapshot {
                    user_role_ids: Vec::new(),
                    user_permission_overrides: Vec::new(),
                })
                .user_permission_overrides
                .push(AuthorizationBindingPermissionOverrideSnapshot {
                    permission: row.permission,
                    effect: row.effect,
                });
        }

        let mut group_bindings = BTreeMap::new();
        for row in group_role_rows {
            group_bindings
                .entry(row.group_id)
                .or_insert_with(Vec::new)
                .push(row.role_id);
        }

        let mut organization_role_bindings = BTreeMap::new();
        for row in organization_role_rows {
            organization_role_bindings
                .entry(row.organization_role)
                .or_insert_with(Vec::new)
                .push(row.role_id);
        }

        Ok::<AuthorizationBindingsSnapshot, AppError>(AuthorizationBindingsSnapshot {
            application_id: ($application_id).to_string(),
            profile_id: ($profile_id).to_string(),
            user_bindings,
            group_bindings,
            organization_role_bindings,
        })
    }};
}

macro_rules! insert_profile_role_edges {
    ($conn:expr, $kind:expr, $table:literal, $subject_column:literal, $profile_id:expr, $subject_id:expr, $role_ids:expr) => {{
        for chunk in ($role_ids).chunks(WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let placeholders = (1..=chunk.len() * 3)
                .map(|index| ph($kind, index))
                .collect::<Vec<_>>();
            let values_sql = placeholders
                .chunks(3)
                .map(|row| format!("({}, {}, {}, 1, {}, {})", row[0], row[1], row[2], util::now_ts(), util::now_ts()))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO {} (profile_id, {}, role_id, is_active, created_at, updated_at) VALUES {}",
                $table, $subject_column, values_sql
            );
            let mut values = Vec::with_capacity(chunk.len() * 3);
            for role_id in chunk {
                values.push(($profile_id).to_string());
                values.push(($subject_id).to_string());
                values.push(role_id.clone());
            }
            bind_text_list($conn, sql_query(sql), &values)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

impl Db {
    /// Reads the complete profile binding graph in one read transaction.
    pub async fn read_application_authorization_bindings(
        &self,
        application_id: &str,
        profile_id: &str,
    ) -> AppResult<AuthorizationBindingsSnapshot> {
        let application_id = application_id.to_string();
        let profile_id = profile_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<AuthorizationBindingsSnapshot, AppError, _>(|conn| {
                // PostgreSQL READ COMMITTED assigns a fresh MVCC snapshot to
                // each SELECT. The response combines four edge tables, so a
                // single repeatable snapshot is required to avoid returning
                // a graph assembled from different revisions.
                if matches!(kind, DatabaseKind::Postgres) {
                    conn.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                        .map_err(AppError::from)?;
                }
                let application_sql = format!(
                    "SELECT organization_id FROM applications WHERE id = {}",
                    ph(kind, 1)
                );
                sql_query(application_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<ApplicationOrganizationRow>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;

                let profile_sql = format!(
                    "SELECT application_id FROM application_authorization_profiles WHERE id = {}",
                    ph(kind, 1)
                );
                let profile = sql_query(profile_sql)
                    .bind::<Text, _>(&profile_id)
                    .get_result::<ProfileApplicationRow>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                if profile.application_id != application_id {
                    return Err(AppError::BadRequest(
                        "authorization profile must belong to the application".to_string(),
                    ));
                }

                load_authorization_bindings_snapshot!(conn, kind, &application_id, &profile_id)
            })
        })
    }

    /// Replaces all requested profile binding sets atomically and records the
    /// audit event before commit.  Optional subjects scope the two subject
    /// edge sets: omitting a subject leaves that subject set unchanged, while
    /// supplying a subject with an empty list clears it.  The organization map
    /// is always a complete replacement for the profile.
    pub async fn replace_application_authorization_bindings_with_audit(
        &self,
        application_id: &str,
        profile_id: &str,
        update: AuthorizationBindingsUpdate,
        mut event: AuditEvent,
    ) -> AppResult<AuthorizationBindingsSnapshot> {
        let normalized = normalize_update(update)?;
        let application_id = application_id.to_string();
        let profile_id = profile_id.to_string();
        if event.target_id.is_none() {
            event.target_id = Some(profile_id.clone());
        }
        let webhook_db = self.clone();
        let (snapshot, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(AuthorizationBindingsSnapshot, AuditEventRecord), AppError, _>(
                |conn| {
                    // Role catalog mutations use the same application row as
                    // their serialization point. Lock it before validating
                    // role ids so a successful replacement cannot race a
                    // role delete/deactivation and leave a stale edge graph.
                    let lock_sql = format!(
                        "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                        ph(kind, 1)
                    );
                    if sql_query(lock_sql)
                        .bind::<Text, _>(&application_id)
                        .execute(conn)
                        .map_err(AppError::from)?
                        == 0
                    {
                        return Err(AppError::NotFound);
                    }
                    let application_sql = format!(
                        "SELECT organization_id FROM applications WHERE id = {}",
                        ph(kind, 1)
                    );
                    let application = sql_query(application_sql)
                        .bind::<Text, _>(&application_id)
                        .get_result::<ApplicationOrganizationRow>(conn)
                        .optional()
                        .map_err(AppError::from)?
                        .ok_or(AppError::NotFound)?;

                    let profile_sql = format!(
                        "SELECT application_id FROM application_authorization_profiles WHERE id = {}",
                        ph(kind, 1)
                    );
                    let profile = sql_query(profile_sql)
                        .bind::<Text, _>(&profile_id)
                        .get_result::<ProfileApplicationRow>(conn)
                        .optional()
                        .map_err(AppError::from)?
                        .ok_or(AppError::NotFound)?;
                    if profile.application_id != application_id {
                        return Err(AppError::BadRequest(
                            "authorization profile must belong to the application".to_string(),
                        ));
                    }

                    if let Some(user_id) = normalized.user_id.as_deref() {
                        let user_sql = format!(
                            "SELECT COUNT(*) AS count FROM users INNER JOIN organization_members ON organization_members.user_id = users.id WHERE users.id = {} AND organization_members.organization_id = {} AND users.is_active = 1 AND users.archived_at IS NULL",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        if sql_query(user_sql)
                            .bind::<Text, _>(user_id)
                            .bind::<Text, _>(&application.organization_id)
                            .get_result::<CountRow>(conn)
                            .map_err(AppError::from)?
                            .count
                            == 0
                        {
                            return Err(AppError::BadRequest(
                                "user must belong to the application's organization and be active"
                                    .to_string(),
                            ));
                        }
                    }

                    if let Some(group_id) = normalized.group_id.as_deref() {
                        let group_sql = format!(
                            "SELECT COUNT(*) AS count FROM access_groups WHERE access_groups.id = {} AND EXISTS (SELECT 1 FROM group_members INNER JOIN users ON users.id = group_members.user_id INNER JOIN organization_members ON organization_members.user_id = users.id WHERE group_members.group_id = access_groups.id AND organization_members.organization_id = {} AND users.is_active = 1 AND users.archived_at IS NULL)",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        if sql_query(group_sql)
                            .bind::<Text, _>(group_id)
                            .bind::<Text, _>(&application.organization_id)
                            .get_result::<CountRow>(conn)
                            .map_err(AppError::from)?
                            .count
                            == 0
                        {
                            return Err(AppError::BadRequest(
                                "group must belong to the application's organization and have an active, non-archived member"
                                    .to_string(),
                            ));
                        }
                    }

                    let mut role_ids = BTreeSet::new();
                    role_ids.extend(normalized.user_role_ids.iter().cloned());
                    role_ids.extend(normalized.group_role_ids.iter().cloned());
                    role_ids.extend(
                        normalized
                            .organization_role_bindings
                            .values()
                            .flat_map(|values| values.iter().cloned()),
                    );
                    if !role_ids.is_empty() {
                        let role_ids = role_ids.into_iter().collect::<Vec<_>>();
                        let placeholders = (2..=role_ids.len() + 1)
                            .map(|index| ph(kind, index))
                            .collect::<Vec<_>>()
                            .join(", ");
                        let role_sql = format!(
                            "SELECT id FROM application_profile_roles WHERE profile_id = {} AND is_active = 1 AND id IN ({placeholders})",
                            ph(kind, 1)
                        );
                        let mut values = Vec::with_capacity(role_ids.len() + 1);
                        values.push(profile_id.clone());
                        values.extend(role_ids.iter().cloned());
                        let valid = bind_text_list(conn, sql_query(role_sql), &values)
                            .load::<ProfileRoleIdRow>(conn)
                            .map_err(AppError::from)?
                            .into_iter()
                            .map(|row| row.id)
                            .collect::<BTreeSet<_>>();
                        if let Some(missing) = role_ids.iter().find(|role_id| !valid.contains(*role_id))
                        {
                            return Err(AppError::BadRequest(format!(
                                "unknown or inactive application profile role: {missing}"
                            )));
                        }
                    }

                    if let Some(user_id) = normalized.user_id.as_deref() {
                        let delete_user_roles = format!(
                            "DELETE FROM application_profile_user_roles WHERE profile_id = {} AND user_id = {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        sql_query(delete_user_roles)
                            .bind::<Text, _>(&profile_id)
                            .bind::<Text, _>(user_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                        insert_profile_role_edges!(
                            conn,
                            kind,
                            "application_profile_user_roles",
                            "user_id",
                            &profile_id,
                            user_id,
                            &normalized.user_role_ids
                        )?;

                        let delete_user_overrides = format!(
                            "DELETE FROM application_profile_permission_overrides WHERE profile_id = {} AND user_id = {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        sql_query(delete_user_overrides)
                            .bind::<Text, _>(&profile_id)
                            .bind::<Text, _>(user_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                        for chunk in normalized
                            .user_permission_overrides
                            .chunks(WRITE_BATCH_SIZE)
                        {
                            if chunk.is_empty() {
                                continue;
                            }
                            let placeholders = (1..=chunk.len() * 4)
                                .map(|index| ph(kind, index))
                                .collect::<Vec<_>>();
                            let values_sql = placeholders
                                .chunks(4)
                                .map(|row| {
                                    format!(
                                        "({}, {}, {}, {}, {}, {})",
                                        row[0],
                                        row[1],
                                        row[2],
                                        row[3],
                                        util::now_ts(),
                                        util::now_ts()
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(", ");
                            let sql = format!(
                                "INSERT INTO application_profile_permission_overrides (profile_id, user_id, permission, effect, created_at, updated_at) VALUES {values_sql}"
                            );
                            let mut values = Vec::with_capacity(chunk.len() * 4);
                            for value in chunk {
                                values.push(profile_id.clone());
                                values.push(user_id.to_string());
                                values.push(value.permission.clone());
                                values.push(value.effect.clone());
                            }
                            bind_text_list(conn, sql_query(sql), &values)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        }
                    }

                    if let Some(group_id) = normalized.group_id.as_deref() {
                        let delete_group_roles = format!(
                            "DELETE FROM application_profile_group_roles WHERE profile_id = {} AND group_id = {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        sql_query(delete_group_roles)
                            .bind::<Text, _>(&profile_id)
                            .bind::<Text, _>(group_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                        insert_profile_role_edges!(
                            conn,
                            kind,
                            "application_profile_group_roles",
                            "group_id",
                            &profile_id,
                            group_id,
                            &normalized.group_role_ids
                        )?;
                    }

                    let delete_organization_roles = format!(
                        "DELETE FROM application_profile_organization_roles WHERE profile_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(delete_organization_roles)
                        .bind::<Text, _>(&profile_id)
                        .execute(conn)
                        .map_err(AppError::from)?;

                    let organization_edges = normalized
                        .organization_role_bindings
                        .iter()
                        .flat_map(|(organization_role, role_ids)| {
                            role_ids
                                .iter()
                                .map(|role_id| (organization_role.clone(), role_id.clone()))
                        })
                        .collect::<Vec<_>>();
                    for chunk in organization_edges.chunks(WRITE_BATCH_SIZE) {
                        if chunk.is_empty() {
                            continue;
                        }
                        let placeholders = (1..=chunk.len() * 3)
                            .map(|index| ph(kind, index))
                            .collect::<Vec<_>>();
                        let values_sql = placeholders
                            .chunks(3)
                            .map(|row| {
                                format!(
                                    "({}, {}, {}, 1, {}, {})",
                                    row[0],
                                    row[1],
                                    row[2],
                                    util::now_ts(),
                                    util::now_ts()
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        let sql = format!(
                            "INSERT INTO application_profile_organization_roles (profile_id, organization_role, role_id, is_active, created_at, updated_at) VALUES {values_sql}"
                        );
                        let mut values = Vec::with_capacity(chunk.len() * 3);
                        for (organization_role, role_id) in chunk {
                            values.push(profile_id.clone());
                            values.push(organization_role.clone());
                            values.push(role_id.clone());
                        }
                        bind_text_list(conn, sql_query(sql), &values)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }

                    let snapshot = load_authorization_bindings_snapshot!(
                        conn,
                        kind,
                        &application_id,
                        &profile_id
                    )?;
                    let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                    Ok((snapshot, audit_event))
                },
            )
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(snapshot)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::config::{DatabaseKind, DatabaseSettings};
    use crate::db::{
        ApplicationAuthorizationProfileRecord, NewApplication, NewApplicationAuthorizationProfile,
        NewApplicationProfileRole, NewGroup, NewOrganization, NewUser, OrganizationMemberInput,
    };
    use diesel::connection::SimpleConnection;

    async fn test_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "signet-authorization-bindings-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let db = super::super::connect_sqlite(&DatabaseSettings {
            kind: DatabaseKind::Sqlite,
            url: path.to_string_lossy().into_owned(),
            pool_size: 2,
            run_migrations: true,
        })
        .unwrap();
        db.migrate().await.unwrap();
        (db, path)
    }

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

    async fn fixture() -> (
        Db,
        std::path::PathBuf,
        crate::db::OrganizationRecord,
        crate::db::ApplicationRecord,
        ApplicationAuthorizationProfileRecord,
        crate::db::UserRecord,
        crate::db::GroupRecord,
        crate::db::ApplicationProfileRoleRecord,
        crate::db::ApplicationProfileRoleRecord,
    ) {
        let (db, path) = test_db().await;
        let organization = db
            .insert_organization(NewOrganization {
                slug: "bindings-tenant".to_string(),
                name: "Bindings Tenant".to_string(),
                kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application = db
            .insert_application(NewApplication {
                organization_id: organization.id.clone(),
                slug: "bindings-app".to_string(),
                name: "Bindings App".to_string(),
                description: None,
                access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
                registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
                account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
                unique_identity_factors: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let profile = db
            .upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
                id: "bindings-profile".to_string(),
                application_id: application.id.clone(),
                profile_key: "bindings".to_string(),
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
        let user = db
            .insert_user(test_user("bindings@example.test", "bindings-user"))
            .await
            .unwrap();
        db.replace_organization_members(
            &organization.id,
            vec![OrganizationMemberInput {
                user_id: user.id.clone(),
                role: organizations::ROLE_MEMBER.to_string(),
            }],
        )
        .await
        .unwrap();
        let group = db
            .insert_group(NewGroup {
                name: "Bindings Group".to_string(),
                description: None,
            })
            .await
            .unwrap();
        db.replace_group_members(&group.id, vec![user.id.clone()])
            .await
            .unwrap();
        let role_a = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("bindings-role-a".to_string()),
                profile_id: profile.id.clone(),
                role_key: "read".to_string(),
                name: "Read".to_string(),
                description: None,
                permissions: vec!["application.read".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        let role_b = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("bindings-role-b".to_string()),
                profile_id: profile.id.clone(),
                role_key: "write".to_string(),
                name: "Write".to_string(),
                description: None,
                permissions: vec!["application.write".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        (
            db,
            path,
            organization,
            application,
            profile,
            user,
            group,
            role_a,
            role_b,
        )
    }

    fn audit_event() -> AuditEvent {
        crate::audit::management_event(
            "bindings-test-actor",
            "application.authorization_profile.bindings.update",
            "application_authorization_profile",
            Some("bindings-profile".to_string()),
            serde_json::json!({}),
        )
    }

    #[tokio::test]
    async fn rejects_cross_tenant_subjects_inside_the_write_transaction() {
        let (db, path, organization, application, profile, _user, _group, role_a, _role_b) =
            fixture().await;
        let foreign_organization = db
            .insert_organization(NewOrganization {
                slug: "foreign-bindings-tenant".to_string(),
                name: "Foreign Bindings Tenant".to_string(),
                kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let foreign_user = db
            .insert_user(test_user(
                "foreign-bindings@example.test",
                "foreign-bindings",
            ))
            .await
            .unwrap();
        db.replace_organization_members(
            &foreign_organization.id,
            vec![OrganizationMemberInput {
                user_id: foreign_user.id.clone(),
                role: organizations::ROLE_MEMBER.to_string(),
            }],
        )
        .await
        .unwrap();
        let result = db
            .replace_application_authorization_bindings_with_audit(
                &application.id,
                &profile.id,
                AuthorizationBindingsUpdate {
                    user_id: Some(foreign_user.id),
                    group_id: None,
                    user_role_ids: vec![role_a.id],
                    user_permission_overrides: Vec::new(),
                    group_role_ids: Vec::new(),
                    organization_role_bindings: BTreeMap::new(),
                },
                audit_event(),
            )
            .await;
        assert!(
            matches!(result, Err(AppError::BadRequest(message)) if message.contains("application's organization"))
        );
        assert!(
            db.read_application_authorization_bindings(&application.id, &profile.id)
                .await
                .unwrap()
                .user_bindings
                .is_empty()
        );
        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = organization;
    }

    #[tokio::test]
    async fn rejects_unknown_or_inactive_profile_roles() {
        let (db, path, _organization, application, profile, user, _group, _role_a, _role_b) =
            fixture().await;
        let result = db
            .replace_application_authorization_bindings_with_audit(
                &application.id,
                &profile.id,
                AuthorizationBindingsUpdate {
                    user_id: Some(user.id),
                    group_id: None,
                    user_role_ids: vec!["role-from-another-profile".to_string()],
                    user_permission_overrides: Vec::new(),
                    group_role_ids: Vec::new(),
                    organization_role_bindings: BTreeMap::new(),
                },
                audit_event(),
            )
            .await;
        assert!(
            matches!(result, Err(AppError::BadRequest(message)) if message.contains("unknown or inactive"))
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn audit_failure_rolls_back_all_four_binding_sets() {
        let (db, path, _organization, application, profile, user, group, role_a, role_b) =
            fixture().await;
        let initial = db
            .replace_application_authorization_bindings_with_audit(
                &application.id,
                &profile.id,
                AuthorizationBindingsUpdate {
                    user_id: Some(user.id.clone()),
                    group_id: Some(group.id.clone()),
                    user_role_ids: vec![role_a.id.clone()],
                    user_permission_overrides: vec![AuthorizationBindingPermissionOverride {
                        permission: "application.read".to_string(),
                        effect: "allow".to_string(),
                    }],
                    group_role_ids: vec![role_a.id.clone()],
                    organization_role_bindings: BTreeMap::from([(
                        "member".to_string(),
                        vec![role_a.id.clone()],
                    )]),
                },
                audit_event(),
            )
            .await
            .unwrap();
        with_conn!(db.clone(), |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_authorization_bindings_audit BEFORE INSERT ON audit_webhook_outbox BEGIN SELECT RAISE(ABORT, 'forced authorization bindings audit failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();
        let result = db
            .replace_application_authorization_bindings_with_audit(
                &application.id,
                &profile.id,
                AuthorizationBindingsUpdate {
                    user_id: Some(user.id.clone()),
                    group_id: Some(group.id.clone()),
                    user_role_ids: vec![role_b.id.clone()],
                    user_permission_overrides: vec![AuthorizationBindingPermissionOverride {
                        permission: "application.write".to_string(),
                        effect: "deny".to_string(),
                    }],
                    group_role_ids: vec![role_b.id.clone()],
                    organization_role_bindings: BTreeMap::from([(
                        "ADMIN".to_string(),
                        vec![role_b.id.clone()],
                    )]),
                },
                audit_event(),
            )
            .await;
        assert!(
            matches!(result, Err(AppError::Database(message)) if message.contains("forced authorization bindings audit failure"))
        );
        with_conn!(db.clone(), |conn, _kind| {
            conn.batch_execute("DROP TRIGGER fail_authorization_bindings_audit")
                .map_err(AppError::from)
        })
        .unwrap();
        let after = db
            .read_application_authorization_bindings(&application.id, &profile.id)
            .await
            .unwrap();
        assert_eq!(after, initial);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn successful_update_returns_a_normalized_consistent_snapshot() {
        let (db, path, _organization, application, profile, user, group, role_a, role_b) =
            fixture().await;
        let snapshot = db
            .replace_application_authorization_bindings_with_audit(
                &application.id,
                &profile.id,
                AuthorizationBindingsUpdate {
                    user_id: Some(format!(" {} ", user.id)),
                    group_id: Some(format!(" {} ", group.id)),
                    user_role_ids: vec![
                        format!(" {} ", role_b.id),
                        role_a.id.clone(),
                        role_a.id.clone(),
                    ],
                    user_permission_overrides: vec![AuthorizationBindingPermissionOverride {
                        permission: " application.read ".to_string(),
                        effect: " DENY ".to_string(),
                    }],
                    group_role_ids: vec![role_b.id.clone()],
                    organization_role_bindings: BTreeMap::from([(
                        " OWNER ".to_string(),
                        vec![format!(" {} ", role_a.id)],
                    )]),
                },
                audit_event(),
            )
            .await
            .unwrap();
        assert_eq!(snapshot.application_id, application.id);
        assert_eq!(snapshot.profile_id, profile.id);
        assert_eq!(
            snapshot.user_bindings[&user.id].user_role_ids,
            vec![role_a.id.clone(), role_b.id.clone()]
        );
        assert_eq!(
            snapshot.user_bindings[&user.id].user_permission_overrides,
            vec![AuthorizationBindingPermissionOverrideSnapshot {
                permission: "application.read".to_string(),
                effect: "deny".to_string(),
            }]
        );
        assert_eq!(snapshot.group_bindings[&group.id], vec![role_b.id]);
        assert_eq!(
            snapshot.organization_role_bindings["owner"],
            vec![role_a.id]
        );
        assert_eq!(
            db.read_application_authorization_bindings(&application.id, &profile.id)
                .await
                .unwrap(),
            snapshot
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn concurrent_profile_default_role_writes_keep_one_default() {
        let (db, path, _organization, application, profile, _user, _group, _role_a, _role_b) =
            fixture().await;
        let first_db = db.clone();
        let first_profile_id = profile.id.clone();
        let second_profile_id = profile.id.clone();
        let (first, second) = tokio::join!(
            first_db.upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: first_profile_id,
                role_key: "concurrent-reader".to_string(),
                name: "Concurrent Reader".to_string(),
                description: None,
                permissions: vec!["application.read".to_string()],
                source: "manual".to_string(),
                is_default: true,
                is_active: true,
            }),
            db.upsert_application_profile_role(NewApplicationProfileRole {
                id: None,
                profile_id: second_profile_id,
                role_key: "concurrent-writer".to_string(),
                name: "Concurrent Writer".to_string(),
                description: None,
                permissions: vec!["application.write".to_string()],
                source: "manual".to_string(),
                is_default: true,
                is_active: true,
            })
        );
        assert!(
            first.is_ok(),
            "first concurrent role write failed: {first:?}"
        );
        assert!(
            second.is_ok(),
            "second concurrent role write failed: {second:?}"
        );
        let defaults = db
            .list_application_profile_roles(&profile.id)
            .await
            .unwrap()
            .into_iter()
            .filter(|role| role.is_default == 1)
            .count();
        assert_eq!(defaults, 1, "application: {}", application.id);
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
