use super::{
    AuditEventRecord, CountRow, Db, GroupMemberLifecycleRow, GroupMemberPublicRow, GroupPatchPlan,
    GroupRecord, GroupRoleJoinRow, NewGroup, NewRole, PublicUser, RoleIdRow, RoleRecord,
    bind_text_list, blocking, dedupe_nonempty, normalize_application_entitlement_keys,
    optimistic_concurrency_conflict, ph, placeholder_rows, placeholders, select_group_sql,
};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    util,
};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};
use std::collections::{BTreeMap, BTreeSet};

const ROLE_PERMISSION_BATCH_SIZE: usize = 100;

macro_rules! insert_role_permissions_on_conn {
    ($conn:expr, $kind:expr, $role_id:expr, $permissions:expr) => {{
        for chunk in $permissions.chunks(ROLE_PERMISSION_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let placeholders = placeholder_rows($kind, 1, chunk.len(), 2);
            let sql = format!(
                "INSERT INTO role_permissions (role_id, permission) VALUES {}",
                placeholders
            );
            let mut values = Vec::with_capacity(chunk.len() * 2);
            for permission in chunk {
                values.push($role_id.to_string());
                values.push(permission.clone());
            }
            bind_text_list($conn, sql_query(sql), &values)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

impl Db {
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

    pub async fn insert_role(&self, role: NewRole) -> AppResult<RoleRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let name = role.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("role name is required".to_string()));
        }
        let description = role.description.map(|value| value.trim().to_string());
        // Enterprise roles can carry application-defined entitlement keys
        // (for example `docs.read`) in addition to Signet's platform
        // permissions.  Keep the key-shape validation, but do not route this
        // aggregate through the platform-only Permission enum; platform
        // authorization still validates its own enum at the call boundary.
        let permissions = normalize_application_entitlement_keys(role.permissions)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<_, AppError, _>(|conn| {
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
                .execute(conn)
                .map_err(AppError::from)?;

            insert_role_permissions_on_conn!(conn, kind, &id, &permissions)?;

            let sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<RoleRecord>(conn)
                .map_err(AppError::from)
            })
        })
    }

    pub async fn update_role(&self, id: &str, role: NewRole) -> AppResult<RoleRecord> {
        let id = id.to_string();
        let name = role.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("role name is required".to_string()));
        }
        let description = role.description.map(|value| value.trim().to_string());
        // Global enterprise roles are also a source for application claims,
        // so their permission namespace must remain extensible.  Unknown
        // platform permissions are harmless here because `has_permission`
        // only checks the typed platform enum, while application entitlement
        // resolution intentionally preserves custom keys.
        let permissions = normalize_application_entitlement_keys(role.permissions)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<_, AppError, _>(|conn| {
            let sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE id = {}",
                ph(kind, 1)
            );
            let existing = sql_query(sql)
                .bind::<Text, _>(&id)
                .get_result::<RoleRecord>(conn)
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
                .execute(conn)
                .map_err(AppError::from)?;

            let sql = format!(
                "DELETE FROM role_permissions WHERE role_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .execute(conn)
                .map_err(AppError::from)?;

            insert_role_permissions_on_conn!(conn, kind, &id, &permissions)?;

            let sql = format!(
                "SELECT id, name, description, is_system, created_at, updated_at FROM roles WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<RoleRecord>(conn)
                .map_err(AppError::from)
            })
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

    /// Loads the complete role-permission read model in one query.  Management
    /// endpoints can join it with `list_roles` in memory instead of resolving
    /// permissions once per role.
    pub async fn list_role_permissions_by_role(&self) -> AppResult<BTreeMap<String, Vec<String>>> {
        #[derive(Debug, diesel::QueryableByName)]
        struct RolePermissionRow {
            #[diesel(sql_type = Text)]
            role_id: String,
            #[diesel(sql_type = Text)]
            permission: String,
        }
        with_conn!(self, |conn, _kind| {
            let rows = sql_query(
                "SELECT role_id, permission FROM role_permissions ORDER BY role_id ASC, permission ASC",
            )
            .load::<RolePermissionRow>(&mut conn)
            .map_err(AppError::from)?;
            let mut permissions = BTreeMap::new();
            for row in rows {
                permissions
                    .entry(row.role_id)
                    .or_insert_with(Vec::new)
                    .push(row.permission);
            }
            Ok(permissions)
        })
    }

    /// Loads all group-to-role edges in one query for the security management
    /// read model.  The response layer performs the final grouping.
    pub async fn list_group_roles_by_group(&self) -> AppResult<BTreeMap<String, Vec<RoleRecord>>> {
        with_conn!(self, |conn, _kind| {
            let rows = sql_query(
                "SELECT group_roles.group_id, roles.id, roles.name, roles.description, roles.is_system, roles.created_at, roles.updated_at FROM group_roles INNER JOIN roles ON roles.id = group_roles.role_id ORDER BY group_roles.group_id ASC, roles.name ASC, roles.id ASC",
            )
            .load::<GroupRoleJoinRow>(&mut conn)
            .map_err(AppError::from)?;
            let mut grouped = BTreeMap::new();
            for row in rows {
                let group_id = row.group_id.clone();
                grouped
                    .entry(group_id)
                    .or_insert_with(Vec::new)
                    .push(row.role());
            }
            Ok(grouped)
        })
    }

    /// Loads public group members in one narrow query.  Unlike
    /// `list_group_members`, this read model never selects password hashes or
    /// login-security fields that the management response cannot expose.
    pub async fn list_group_members_public_by_group(
        &self,
    ) -> AppResult<BTreeMap<String, Vec<PublicUser>>> {
        with_conn!(self, |conn, _kind| {
            let rows = sql_query(
                "SELECT group_members.group_id, users.id, users.email, users.username, users.display_name, users.phone, users.email_verified_at, users.phone_verified_at, users.is_admin, users.is_active, users.archived_at, users.registration_source, users.last_login_at, users.last_login_ip, users.last_oidc_client_id, users.last_login_method, users.created_at, users.updated_at FROM group_members INNER JOIN users ON users.id = group_members.user_id ORDER BY group_members.group_id ASC, users.email ASC, users.id ASC",
            )
            .load::<GroupMemberPublicRow>(&mut conn)
            .map_err(AppError::from)?;
            let mut grouped = BTreeMap::new();
            for row in rows {
                let group_id = row.group_id.clone();
                grouped
                    .entry(group_id)
                    .or_insert_with(Vec::new)
                    .push(row.public());
            }
            Ok(grouped)
        })
    }

    pub async fn insert_group(&self, group: NewGroup) -> AppResult<GroupRecord> {
        self.insert_group_mutation(group, None).await
    }

    pub async fn insert_group_with_audit(
        &self,
        group: NewGroup,
        event: crate::audit::AuditEvent,
    ) -> AppResult<GroupRecord> {
        self.insert_group_mutation(group, Some(event)).await
    }

    async fn insert_group_mutation(
        &self,
        group: NewGroup,
        mut audit: Option<crate::audit::AuditEvent>,
    ) -> AppResult<GroupRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let name = group.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("group name is required".to_string()));
        }
        let description = group.description.map(|value| value.trim().to_string());
        let now = util::now_ts();
        if let Some(event) = audit.as_mut()
            && event.target_id.is_none()
        {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let (group, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(GroupRecord, Option<AuditEventRecord>), AppError, _>(|conn| {
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
                    .bind::<Text, _>(&name)
                    .bind::<Nullable<Text>, _>(&description)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let sql = format!(
                    "SELECT id, name, description, created_at, updated_at, version FROM access_groups WHERE id = {}",
                    ph(kind, 1)
                );
                let group = sql_query(sql)
                    .bind::<Text, _>(&id)
                    .get_result::<GroupRecord>(conn)
                    .map_err(AppError::from)?;
                let audit_event = audit
                    .take()
                    .map(|event| insert_audit_event_on_conn!(conn, kind, event))
                    .transpose()?;
                Ok((group, audit_event))
            })
        })?;
        if let Some(audit_event) = audit_event {
            crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        }
        Ok(group)
    }

    pub async fn update_group(&self, id: &str, group: NewGroup) -> AppResult<GroupRecord> {
        self.update_group_mutation(id, group, None).await
    }

    pub async fn update_group_with_audit(
        &self,
        id: &str,
        group: NewGroup,
        event: crate::audit::AuditEvent,
    ) -> AppResult<GroupRecord> {
        self.update_group_mutation(id, group, Some(event)).await
    }

    async fn update_group_mutation(
        &self,
        id: &str,
        group: NewGroup,
        mut audit: Option<crate::audit::AuditEvent>,
    ) -> AppResult<GroupRecord> {
        let id = id.to_string();
        let name = group.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("group name is required".to_string()));
        }
        let description = group.description.map(|value| value.trim().to_string());
        let now = util::now_ts();
        if let Some(event) = audit.as_mut()
            && event.target_id.is_none()
        {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        with_conn!(self, |conn, kind| {
            let (group, audit_event) = conn.transaction::<
                (GroupRecord, Option<AuditEventRecord>),
                AppError,
                _,
            >(|conn| {
                let sql = format!(
                    "UPDATE access_groups SET name = {}, description = {}, updated_at = {}, version = version + 1 WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let affected = sql_query(sql)
                    .bind::<Text, _>(&name)
                    .bind::<Nullable<Text>, _>(&description)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::NotFound);
                }

                let sql = format!(
                    "SELECT id, name, description, created_at, updated_at, version FROM access_groups WHERE id = {}",
                    ph(kind, 1)
                );
                let group = sql_query(sql)
                    .bind::<Text, _>(&id)
                    .get_result::<GroupRecord>(conn)
                    .map_err(AppError::from)?;
                let audit_event = audit
                    .take()
                    .map(|event| insert_audit_event_on_conn!(conn, kind, event))
                    .transpose()?;
                Ok((group, audit_event))
            })?;
            if let Some(audit_event) = audit_event {
                crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
            }
            Ok(group)
        })
    }

    /// Applies a fully folded SCIM group mutation atomically. The application
    /// variant changes only the members visible through that application's
    /// organization; shared group membership outside that boundary is left
    /// untouched.
    pub async fn apply_group_patch_plan(&self, plan: GroupPatchPlan) -> AppResult<GroupRecord> {
        let application_id = plan.application_id;
        let group_id = plan.group_id;
        let name = plan.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("group name is required".to_string()));
        }
        let description = plan.description.map(|value| value.trim().to_string());
        let create = plan.create;
        let expected_version = plan.expected_version;
        let user_ids = dedupe_nonempty(plan.member_ids);
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<GroupRecord, AppError, _>(|conn| {
                if create {
                    let insert_group = format!(
                        "INSERT INTO access_groups (id, name, description, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5)
                    );
                    sql_query(insert_group)
                        .bind::<Text, _>(&group_id)
                        .bind::<Text, _>(&name)
                        .bind::<Nullable<Text>, _>(&description)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;

                    if let Some(application_id) = application_id.as_deref() {
                        let app_sql = format!(
                            "SELECT COUNT(*) AS count FROM applications WHERE id = {}",
                            ph(kind, 1)
                        );
                        if sql_query(app_sql)
                            .bind::<Text, _>(application_id)
                            .get_result::<CountRow>(conn)
                            .map_err(AppError::from)?
                            .count
                            == 0
                        {
                            return Err(AppError::NotFound);
                        }
                        let binding_sql = format!(
                            "INSERT INTO application_scim_groups (application_id, group_id, created_at) VALUES ({}, {}, {})",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3)
                        );
                        sql_query(binding_sql)
                            .bind::<Text, _>(application_id)
                            .bind::<Text, _>(&group_id)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                }
                let group_sql = if application_id.is_some() {
                    format!(
                        "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at, access_groups.version FROM access_groups INNER JOIN application_scim_groups ON application_scim_groups.group_id = access_groups.id WHERE application_scim_groups.application_id = {} AND access_groups.id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    )
                } else {
                    format!(
                        "SELECT id, name, description, created_at, updated_at, version FROM access_groups WHERE id = {}",
                        ph(kind, 1)
                    )
                };
                let existing_group = if let Some(application_id) = application_id.as_deref() {
                    sql_query(group_sql)
                        .bind::<Text, _>(application_id)
                        .bind::<Text, _>(&group_id)
                        .get_result::<GroupRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?
                } else {
                    sql_query(group_sql)
                        .bind::<Text, _>(&group_id)
                        .get_result::<GroupRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?
                };
                let Some(existing_group) = existing_group else {
                    return Err(AppError::NotFound);
                };
                if let Some(expected_version) = expected_version
                    && existing_group.version != expected_version
                {
                    return Err(optimistic_concurrency_conflict(
                        "SCIM group changed while the request was in flight",
                    ));
                }
                let metadata_changed = existing_group.name != name
                    || existing_group.description != description;

                let existing_member_sql = if application_id.is_some() {
                    format!(
                        "SELECT users.id AS user_id, users.archived_at FROM users INNER JOIN group_members ON group_members.user_id = users.id INNER JOIN organization_members ON organization_members.user_id = users.id INNER JOIN applications ON applications.id = {} AND applications.organization_id = organization_members.organization_id INNER JOIN application_scim_groups ON application_scim_groups.application_id = applications.id AND application_scim_groups.group_id = group_members.group_id WHERE application_scim_groups.application_id = {} AND group_members.group_id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    )
                } else {
                    format!(
                        "SELECT users.id AS user_id, users.archived_at FROM users INNER JOIN group_members ON group_members.user_id = users.id WHERE group_members.group_id = {}",
                        ph(kind, 1)
                    )
                };
                let existing_members = if let Some(application_id) = application_id.as_deref() {
                    sql_query(existing_member_sql)
                        .bind::<Text, _>(application_id)
                        .bind::<Text, _>(application_id)
                        .bind::<Text, _>(&group_id)
                        .load::<GroupMemberLifecycleRow>(conn)
                        .map_err(AppError::from)?
                } else {
                    sql_query(existing_member_sql)
                        .bind::<Text, _>(&group_id)
                        .load::<GroupMemberLifecycleRow>(conn)
                        .map_err(AppError::from)?
                };
                let existing_ids = existing_members
                    .iter()
                    .map(|member| member.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let archived_existing_ids = existing_members
                    .iter()
                    .filter(|member| member.archived_at.is_some())
                    .map(|member| member.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let requested_ids = user_ids.iter().cloned().collect::<BTreeSet<_>>();
                if let Some(archived_id) = archived_existing_ids
                    .iter()
                    .find(|user_id| !requested_ids.contains(*user_id))
                {
                    return Err(AppError::BadRequest(format!(
                        "archived group member cannot be removed: {archived_id}"
                    )));
                }

                let valid_members = if user_ids.is_empty() {
                    Vec::new()
                } else {
                    let user_placeholders = placeholders(kind, 1, user_ids.len());
                    let sql = if application_id.is_some() {
                        let application_param = ph(kind, user_ids.len() + 1);
                        format!(
                            "SELECT users.id AS user_id, users.archived_at FROM users INNER JOIN organization_members ON organization_members.user_id = users.id INNER JOIN applications ON applications.id = {application_param} AND applications.organization_id = organization_members.organization_id INNER JOIN application_scim_groups ON application_scim_groups.application_id = applications.id AND application_scim_groups.group_id = {} WHERE application_scim_groups.application_id = {} AND users.id IN ({user_placeholders})",
                            ph(kind, user_ids.len() + 2),
                            ph(kind, user_ids.len() + 3),
                        )
                    } else {
                        format!(
                            "SELECT users.id AS user_id, users.archived_at FROM users WHERE users.id IN ({user_placeholders})"
                        )
                    };
                    if let Some(application_id) = application_id.as_deref() {
                        // PostgreSQL binds `$n` by its explicit index, while
                        // SQLite/MySQL bind `?` by lexical occurrence. The
                        // SQL keeps the user IDs numbered first for the
                        // former, so construct the latter's occurrence order
                        // explicitly instead of silently validating zero
                        // members on SQLite.
                        let values = match kind {
                            DatabaseKind::Postgres => {
                                let mut values = user_ids.clone();
                                values.push(application_id.to_string());
                                values.push(group_id.clone());
                                values.push(application_id.to_string());
                                values
                            }
                            DatabaseKind::Sqlite | DatabaseKind::Mysql => {
                                let mut values = vec![
                                    application_id.to_string(),
                                    group_id.clone(),
                                    application_id.to_string(),
                                ];
                                values.extend(user_ids.clone());
                                values
                            }
                        };
                        bind_text_list(conn, sql_query(sql), &values)
                            .load::<GroupMemberLifecycleRow>(conn)
                            .map_err(AppError::from)?
                    } else {
                        bind_text_list(conn, sql_query(sql), &user_ids)
                            .load::<GroupMemberLifecycleRow>(conn)
                            .map_err(AppError::from)?
                    }
                };
                let valid_by_id = valid_members
                    .iter()
                    .map(|member| (member.user_id.clone(), member))
                    .collect::<BTreeMap<_, _>>();
                if let Some(missing_id) = user_ids
                    .iter()
                    .find(|user_id| !valid_by_id.contains_key(*user_id))
                {
                    if application_id.is_some() {
                        return Err(AppError::BadRequest(
                            "SCIM group members must belong to the application's organization"
                                .to_string(),
                        ));
                    }
                    return Err(AppError::BadRequest(format!(
                        "unknown user: {missing_id}"
                    )));
                }
                if let Some(archived_id) = valid_members.iter().find_map(|member| {
                    (member.archived_at.is_some()
                        && !archived_existing_ids.contains(&member.user_id))
                    .then_some(member.user_id.as_str())
                }) {
                    return Err(AppError::BadRequest(format!(
                        "archived users cannot be assigned to SCIM groups: {archived_id}"
                    )));
                }

                let removed = existing_ids
                    .difference(&requested_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                let added = requested_ids
                    .difference(&existing_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                if !removed.is_empty() {
                    let placeholders = placeholders(kind, 2, removed.len());
                    let sql = format!(
                        "DELETE FROM group_members WHERE group_id = {} AND user_id IN ({placeholders})",
                        ph(kind, 1)
                    );
                    let mut values = vec![group_id.clone()];
                    values.extend(removed.iter().cloned());
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                if !added.is_empty() {
                    let placeholders = placeholder_rows(kind, 1, added.len(), 2);
                    let sql = format!(
                        "INSERT INTO group_members (group_id, user_id) VALUES {}",
                        placeholders
                    );
                    let mut values = Vec::with_capacity(added.len() * 2);
                    for user_id in added.iter().cloned() {
                        values.push(group_id.clone());
                        values.push(user_id);
                    }
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                if metadata_changed || !removed.is_empty() || !added.is_empty() {
                    let version_guard = expected_version
                        .map(|_| format!(" AND version = {}", ph(kind, 5)))
                        .unwrap_or_default();
                    let update_sql = format!(
                        "UPDATE access_groups SET name = {}, description = {}, updated_at = {}, version = version + 1 WHERE id = {}{version_guard}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4)
                    );
                    let affected = if let Some(expected_version) = expected_version {
                        sql_query(update_sql)
                            .bind::<Text, _>(&name)
                            .bind::<Nullable<Text>, _>(&description)
                            .bind::<BigInt, _>(now)
                            .bind::<Text, _>(&group_id)
                            .bind::<BigInt, _>(expected_version)
                            .execute(conn)
                            .map_err(AppError::from)?
                    } else {
                        sql_query(update_sql)
                            .bind::<Text, _>(&name)
                            .bind::<Nullable<Text>, _>(&description)
                            .bind::<BigInt, _>(now)
                            .bind::<Text, _>(&group_id)
                            .execute(conn)
                            .map_err(AppError::from)?
                    };
                    if affected == 0 {
                        return Err(optimistic_concurrency_conflict(
                            "SCIM group changed while the request was being committed",
                        ));
                    }
                }

                let select_sql = format!(
                    "{} WHERE id = {}",
                    select_group_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(existing_group.id)
                    .get_result::<GroupRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_group(&self, id: &str) -> AppResult<()> {
        self.delete_group_mutation(id, None).await
    }

    pub async fn delete_group_with_audit(
        &self,
        id: &str,
        event: crate::audit::AuditEvent,
    ) -> AppResult<()> {
        self.delete_group_mutation(id, Some(event)).await
    }

    async fn delete_group_mutation(
        &self,
        id: &str,
        mut audit: Option<crate::audit::AuditEvent>,
    ) -> AppResult<()> {
        let id = id.to_string();
        if let Some(event) = audit.as_mut()
            && event.target_id.is_none()
        {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        with_conn!(self, |conn, kind| {
            let audit_event =
                conn.transaction::<Option<AuditEventRecord>, AppError, _>(|conn| {
                    let exists_sql = format!(
                        "SELECT COUNT(*) AS count FROM access_groups WHERE id = {}",
                        ph(kind, 1)
                    );
                    if sql_query(exists_sql)
                        .bind::<Text, _>(&id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        == 0
                    {
                        return Err(AppError::NotFound);
                    }

                    // A group is shared by enterprise authorization and several
                    // application protocol projections. Remove every edge before
                    // deleting the aggregate root so no stale subject can survive
                    // in a profile or SCIM binding.
                    for table in [
                        "application_profile_group_roles",
                        "application_scim_groups",
                        "group_members",
                        "group_roles",
                    ] {
                        let sql = format!("DELETE FROM {table} WHERE group_id = {}", ph(kind, 1));
                        sql_query(sql)
                            .bind::<Text, _>(&id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let sql = format!("DELETE FROM access_groups WHERE id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    audit
                        .take()
                        .map(|event| insert_audit_event_on_conn!(conn, kind, event))
                        .transpose()
                })?;
            if let Some(audit_event) = audit_event {
                crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
            }
            Ok(())
        })
    }

    pub async fn replace_user_roles(&self, user_id: &str, role_ids: Vec<String>) -> AppResult<()> {
        let user_id = user_id.to_string();
        let role_ids = dedupe_nonempty(role_ids);
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let sql = format!(
                    "SELECT COUNT(*) AS count FROM users WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::NotFound);
                }

                let requested = role_ids.iter().cloned().collect::<BTreeSet<_>>();
                let valid = if role_ids.is_empty() {
                    BTreeSet::new()
                } else {
                    let placeholders = placeholders(kind, 1, role_ids.len());
                    let sql = format!("SELECT id FROM roles WHERE id IN ({placeholders})");
                    bind_text_list(conn, sql_query(sql), &role_ids)
                        .load::<RoleIdRow>(conn)
                        .map_err(AppError::from)?
                        .into_iter()
                        .map(|row| row.id)
                        .collect::<BTreeSet<_>>()
                };
                if let Some(missing_id) = role_ids.iter().find(|role_id| !valid.contains(*role_id))
                {
                    return Err(AppError::BadRequest(format!("unknown role: {missing_id}")));
                }

                let existing_sql = format!(
                    "SELECT role_id AS id FROM user_roles WHERE user_id = {}",
                    ph(kind, 1)
                );
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&user_id)
                    .load::<RoleIdRow>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|row| row.id)
                    .collect::<BTreeSet<_>>();
                let removed = existing.difference(&requested).cloned().collect::<Vec<_>>();
                for chunk in removed.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = placeholders(kind, 2, chunk.len());
                    let sql = format!(
                        "DELETE FROM user_roles WHERE user_id = {} AND role_id IN ({placeholders})",
                        ph(kind, 1)
                    );
                    let mut values = vec![user_id.clone()];
                    values.extend(chunk.iter().cloned());
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let added = requested.difference(&existing).cloned().collect::<Vec<_>>();
                for chunk in added.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = placeholder_rows(kind, 1, chunk.len(), 2);
                    let sql = format!(
                        "INSERT INTO user_roles (user_id, role_id) VALUES {}",
                        placeholders
                    );
                    let mut values = Vec::with_capacity(chunk.len() * 2);
                    for role_id in chunk {
                        values.push(user_id.clone());
                        values.push(role_id.clone());
                    }
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    pub async fn replace_group_roles(
        &self,
        group_id: &str,
        role_ids: Vec<String>,
    ) -> AppResult<()> {
        self.replace_group_roles_mutation(group_id, role_ids, None)
            .await
    }

    pub async fn replace_group_roles_with_audit(
        &self,
        group_id: &str,
        role_ids: Vec<String>,
        event: crate::audit::AuditEvent,
    ) -> AppResult<()> {
        self.replace_group_roles_mutation(group_id, role_ids, Some(event))
            .await
    }

    async fn replace_group_roles_mutation(
        &self,
        group_id: &str,
        role_ids: Vec<String>,
        mut audit: Option<crate::audit::AuditEvent>,
    ) -> AppResult<()> {
        let group_id = group_id.to_string();
        let role_ids = dedupe_nonempty(role_ids);
        if let Some(event) = audit.as_mut()
            && event.target_id.is_none()
        {
            event.target_id = Some(group_id.clone());
        }
        let webhook_db = self.clone();
        with_conn!(self, |conn, kind| {
            let audit_event = conn.transaction::<Option<AuditEventRecord>, AppError, _>(|conn| {
                let sql = format!(
                    "SELECT COUNT(*) AS count FROM access_groups WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(sql)
                    .bind::<Text, _>(&group_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::NotFound);
                }

                let requested = role_ids.iter().cloned().collect::<BTreeSet<_>>();
                let valid = if role_ids.is_empty() {
                    BTreeSet::new()
                } else {
                    let placeholders = placeholders(kind, 1, role_ids.len());
                    let sql = format!("SELECT id FROM roles WHERE id IN ({placeholders})");
                    bind_text_list(conn, sql_query(sql), &role_ids)
                        .load::<RoleIdRow>(conn)
                        .map_err(AppError::from)?
                        .into_iter()
                        .map(|row| row.id)
                        .collect::<BTreeSet<_>>()
                };
                if let Some(missing_id) = role_ids.iter().find(|role_id| !valid.contains(*role_id))
                {
                    return Err(AppError::BadRequest(format!("unknown role: {missing_id}")));
                }

                let existing_sql = format!(
                    "SELECT role_id AS id FROM group_roles WHERE group_id = {}",
                    ph(kind, 1)
                );
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&group_id)
                    .load::<RoleIdRow>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|row| row.id)
                    .collect::<BTreeSet<_>>();
                let removed = existing
                    .difference(&requested)
                    .cloned()
                    .collect::<Vec<_>>();
                for chunk in removed.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = placeholders(kind, 2, chunk.len());
                    let sql = format!(
                        "DELETE FROM group_roles WHERE group_id = {} AND role_id IN ({placeholders})",
                        ph(kind, 1)
                    );
                    let mut values = vec![group_id.clone()];
                    values.extend(chunk.iter().cloned());
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let added = requested
                    .difference(&existing)
                    .cloned()
                    .collect::<Vec<_>>();
                for chunk in added.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = placeholder_rows(kind, 1, chunk.len(), 2);
                    let sql = format!(
                        "INSERT INTO group_roles (group_id, role_id) VALUES {}",
                        placeholders
                    );
                    let mut values = Vec::with_capacity(chunk.len() * 2);
                    for role_id in chunk {
                        values.push(group_id.clone());
                        values.push(role_id.clone());
                    }
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                audit
                    .take()
                    .map(|event| insert_audit_event_on_conn!(conn, kind, event))
                    .transpose()
            })?;
            if let Some(audit_event) = audit_event {
                crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
            }
            Ok(())
        })
    }

    pub async fn replace_group_members(
        &self,
        group_id: &str,
        user_ids: Vec<String>,
    ) -> AppResult<()> {
        self.replace_group_members_mutation(group_id, user_ids, None)
            .await
    }

    pub async fn replace_group_members_with_audit(
        &self,
        group_id: &str,
        user_ids: Vec<String>,
        event: crate::audit::AuditEvent,
    ) -> AppResult<()> {
        self.replace_group_members_mutation(group_id, user_ids, Some(event))
            .await
    }

    async fn replace_group_members_mutation(
        &self,
        group_id: &str,
        user_ids: Vec<String>,
        mut audit: Option<crate::audit::AuditEvent>,
    ) -> AppResult<()> {
        let group_id = group_id.to_string();
        let user_ids = dedupe_nonempty(user_ids);
        let now = util::now_ts();
        if let Some(event) = audit.as_mut()
            && event.target_id.is_none()
        {
            event.target_id = Some(group_id.clone());
        }
        let webhook_db = self.clone();
        with_conn!(self, |conn, kind| {
            let audit_event = conn.transaction::<Option<AuditEventRecord>, AppError, _>(|conn| {
                let sql = format!(
                    "SELECT COUNT(*) AS count FROM access_groups WHERE id = {}",
                    ph(kind, 1)
                );
                let count = sql_query(sql)
                    .bind::<Text, _>(&group_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                if count == 0 {
                    return Err(AppError::NotFound);
                }

                let existing_sql = format!(
                    "SELECT group_members.user_id, users.archived_at FROM group_members INNER JOIN users ON users.id = group_members.user_id WHERE group_members.group_id = {}",
                    ph(kind, 1)
                );
                let existing_members = sql_query(existing_sql)
                    .bind::<Text, _>(&group_id)
                    .load::<GroupMemberLifecycleRow>(conn)
                    .map_err(AppError::from)?
                    ;
                let existing_ids = existing_members
                    .iter()
                    .map(|row| row.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let requested_ids = user_ids.iter().cloned().collect::<BTreeSet<_>>();
                if let Some(archived_id) = existing_members.iter().find_map(|row| {
                    (row.archived_at.is_some() && !requested_ids.contains(&row.user_id))
                        .then_some(row.user_id.as_str())
                }) {
                    return Err(AppError::BadRequest(format!(
                        "archived group member cannot be removed: {archived_id}"
                    )));
                }

                if !user_ids.is_empty() {
                    let placeholders = placeholders(kind, 1, user_ids.len());
                    let sql = format!(
                        "SELECT id AS user_id, archived_at FROM users WHERE id IN ({placeholders})"
                    );
                    let valid_members = bind_text_list(conn, sql_query(sql), &user_ids)
                        .load::<GroupMemberLifecycleRow>(conn)
                        .map_err(AppError::from)?
                        ;
                    let valid_ids = valid_members
                        .iter()
                        .map(|row| row.user_id.clone())
                        .collect::<BTreeSet<_>>();
                    if let Some(missing_id) = user_ids
                        .iter()
                        .find(|user_id| !valid_ids.contains(*user_id))
                    {
                        return Err(AppError::BadRequest(format!("unknown user: {missing_id}")));
                    }
                }

                let removed = existing_ids
                    .difference(&requested_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                if !removed.is_empty() {
                    let placeholders = placeholders(kind, 2, removed.len());
                    let sql = format!(
                        "DELETE FROM group_members WHERE group_id = {} AND user_id IN ({placeholders})",
                        ph(kind, 1)
                    );
                    let mut values = vec![group_id.clone()];
                    values.extend(removed.iter().cloned());
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                let added = requested_ids
                    .difference(&existing_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                if !added.is_empty() {
                    let placeholders = placeholder_rows(kind, 1, added.len(), 2);
                    let sql = format!(
                        "INSERT INTO group_members (group_id, user_id) VALUES {}",
                        placeholders
                    );
                    let mut values = Vec::with_capacity(added.len() * 2);
                    for user_id in added.iter().cloned() {
                        values.push(group_id.clone());
                        values.push(user_id);
                    }
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                if !removed.is_empty() || !added.is_empty() {
                    let sql = format!(
                        "UPDATE access_groups SET updated_at = {}, version = version + 1 WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(sql)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&group_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                audit
                    .take()
                    .map(|event| insert_audit_event_on_conn!(conn, kind, event))
                    .transpose()
            })?;
            if let Some(audit_event) = audit_event {
                crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
            }
            Ok(())
        })
    }
}
