//! Application-scoped authorization catalog and directory persistence.

use super::{
    ApplicationAuthorizationProfileCountRow, ApplicationAuthorizationProfileRecord,
    ApplicationPermissionDefinitionRecord, CountRow, DatabaseKind, Db, GroupPatchPlan, GroupRecord,
    NewApplicationAuthorizationProfile, NewApplicationPermissionDefinition, NewGroup, UserRecord,
    bind_text_list, blocking, normalize_application_entitlement_keys, ph,
    select_application_authorization_profile_sql, select_application_permission_definition_sql,
    select_user_sql,
};
use crate::error::{AppError, AppResult};
use crate::util;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};
use std::collections::BTreeMap;

impl Db {
    pub async fn list_application_authorization_groups(
        &self,
        organization_id: &str,
    ) -> AppResult<Vec<GroupRecord>> {
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at, access_groups.version FROM access_groups WHERE EXISTS (SELECT 1 FROM group_members INNER JOIN organization_members ON organization_members.user_id = group_members.user_id INNER JOIN users ON users.id = group_members.user_id WHERE group_members.group_id = access_groups.id AND organization_members.organization_id = {} AND users.is_active = 1 AND users.archived_at IS NULL) ORDER BY access_groups.name ASC, access_groups.id ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .load::<GroupRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_authorization_user(
        &self,
        application_id: &str,
        user_id: &str,
    ) -> AppResult<Option<UserRecord>> {
        let application_id = application_id.to_string();
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} INNER JOIN organization_members ON organization_members.user_id = users.id INNER JOIN applications ON applications.organization_id = organization_members.organization_id WHERE applications.id = {} AND users.id = {} AND users.is_active = 1 AND users.archived_at IS NULL",
                select_user_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(user_id)
                .get_result::<UserRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_authorization_group(
        &self,
        application_id: &str,
        group_id: &str,
    ) -> AppResult<Option<GroupRecord>> {
        let application_id = application_id.to_string();
        let group_id = group_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at, access_groups.version FROM access_groups WHERE access_groups.id = {} AND EXISTS (SELECT 1 FROM group_members INNER JOIN users ON users.id = group_members.user_id INNER JOIN organization_members ON organization_members.user_id = users.id INNER JOIN applications ON applications.organization_id = organization_members.organization_id WHERE applications.id = {} AND group_members.group_id = access_groups.id AND users.is_active = 1 AND users.archived_at IS NULL)",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(group_id)
                .bind::<Text, _>(application_id)
                .get_result::<GroupRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_scim_groups(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<GroupRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at, access_groups.version FROM access_groups INNER JOIN application_scim_groups ON application_scim_groups.group_id = access_groups.id WHERE application_scim_groups.application_id = {} ORDER BY access_groups.name ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<GroupRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_scim_group(
        &self,
        application_id: &str,
        group_id: &str,
    ) -> AppResult<Option<GroupRecord>> {
        let application_id = application_id.to_string();
        let group_id = group_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at, access_groups.version FROM access_groups INNER JOIN application_scim_groups ON application_scim_groups.group_id = access_groups.id WHERE application_scim_groups.application_id = {} AND access_groups.id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(group_id)
                .get_result::<GroupRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    /// Creates the global authorization group and its application SCIM
    /// binding atomically. The group remains compatible with the existing
    /// application-group-role mapping tables, while its SCIM visibility is
    /// strictly limited to this application.
    pub async fn insert_application_scim_group(
        &self,
        application_id: &str,
        group: NewGroup,
    ) -> AppResult<GroupRecord> {
        let application_id = application_id.to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let name = group.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("group name is required".to_string()));
        }
        let description = group.description.map(|value| value.trim().to_string());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<GroupRecord, AppError, _>(|conn| {
                let app_sql = format!(
                    "SELECT COUNT(*) AS count FROM applications WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(app_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::NotFound);
                }

                let insert_group = format!(
                    "INSERT INTO access_groups (id, name, description, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(insert_group)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&name)
                    .bind::<Nullable<Text>, _>(&description)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let binding_sql = format!(
                    "INSERT INTO application_scim_groups (application_id, group_id, created_at) VALUES ({}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(binding_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let select_sql = format!(
                    "SELECT id, name, description, created_at, updated_at, version FROM access_groups WHERE id = {}",
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<GroupRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_application_scim_group(
        &self,
        application_id: &str,
        group_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let group_id = group_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let binding_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_scim_groups WHERE application_id = {} AND group_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if sql_query(binding_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&group_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::NotFound);
                }

                // Remove only this application's role mapping.  Group
                // membership and the global group/role rows are shared by
                // other applications and by the admin security domain.
                let role_sql = format!(
                    "DELETE FROM application_profile_group_roles WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE application_id = {}) AND group_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(role_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&group_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let unbind_sql = format!(
                    "DELETE FROM application_scim_groups WHERE application_id = {} AND group_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(unbind_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&group_id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let scim_reference_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_scim_groups WHERE group_id = {}",
                    ph(kind, 1)
                );
                let scim_references = sql_query(scim_reference_sql)
                    .bind::<Text, _>(&group_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                let profile_role_reference_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_profile_group_roles WHERE group_id = {}",
                    ph(kind, 1)
                );
                let profile_role_references = sql_query(profile_role_reference_sql)
                    .bind::<Text, _>(&group_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                let directory_reference_sql = format!(
                    "SELECT COUNT(*) AS count FROM directory_sync_groups WHERE group_id = {}",
                    ph(kind, 1)
                );
                let directory_references = sql_query(directory_reference_sql)
                    .bind::<Text, _>(&group_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                if scim_references == 0
                    && profile_role_references == 0
                    && directory_references == 0
                {
                    for table in ["group_members", "group_roles"] {
                        let sql = format!(
                            "DELETE FROM {table} WHERE group_id = {}",
                            ph(kind, 1)
                        );
                        sql_query(sql)
                            .bind::<Text, _>(&group_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let delete_sql = format!(
                        "DELETE FROM access_groups WHERE id = {}",
                        ph(kind, 1)
                    );
                    sql_query(delete_sql)
                        .bind::<Text, _>(&group_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    pub async fn list_application_scim_group_members(
        &self,
        application_id: &str,
        group_id: &str,
    ) -> AppResult<Vec<UserRecord>> {
        let application_id = application_id.to_string();
        let group_id = group_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} INNER JOIN group_members ON users.id = group_members.user_id INNER JOIN application_scim_groups ON application_scim_groups.group_id = group_members.group_id INNER JOIN applications ON applications.id = application_scim_groups.application_id INNER JOIN organization_members ON organization_members.organization_id = applications.organization_id AND organization_members.user_id = users.id WHERE application_scim_groups.application_id = {} AND application_scim_groups.group_id = {} ORDER BY users.email ASC",
                select_user_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(group_id)
                .load::<UserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Replaces members only after verifying that the group is bound to this
    /// application and every requested user belongs to the application's
    /// organization. This database-side check is the final boundary even if
    /// a caller races with another membership update.
    pub async fn replace_application_scim_group_members(
        &self,
        application_id: &str,
        group_id: &str,
        user_ids: Vec<String>,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let group_id = group_id.to_string();
        let group = self
            .find_application_scim_group(&application_id, &group_id)
            .await?
            .ok_or(AppError::NotFound)?;
        self.apply_group_patch_plan(GroupPatchPlan {
            application_id: Some(application_id),
            group_id,
            name: group.name,
            description: group.description,
            member_ids: user_ids,
            create: false,
            expected_version: Some(group.version),
        })
        .await
        .map(|_| ())
    }

    pub async fn list_application_authorization_profiles(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationAuthorizationProfileRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} ORDER BY profile_key ASC",
                select_application_authorization_profile_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationAuthorizationProfileRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_authorization_profile_counts(
        &self,
        profile_ids: &[String],
    ) -> AppResult<BTreeMap<String, (i64, i64)>> {
        if profile_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let profile_ids = profile_ids.to_vec();
        with_conn!(self, |conn, kind| {
            let placeholders = (1..=profile_ids.len())
                .map(|index| ph(kind, index))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT profiles.id AS profile_id, (SELECT COUNT(*) FROM application_permission_definitions WHERE profile_id = profiles.id AND is_active = 1) AS permission_count, (SELECT COUNT(*) FROM application_profile_roles WHERE profile_id = profiles.id AND is_active = 1) AS role_count FROM application_authorization_profiles AS profiles WHERE profiles.id IN ({placeholders})"
            );
            let rows = bind_text_list(&mut conn, sql_query(sql), &profile_ids)
                .load::<ApplicationAuthorizationProfileCountRow>(&mut conn)
                .map_err(AppError::from)?;
            Ok(rows
                .into_iter()
                .map(|row| (row.profile_id, (row.permission_count, row.role_count)))
                .collect())
        })
    }

    pub async fn find_application_authorization_profile(
        &self,
        application_id: &str,
        profile_key: &str,
    ) -> AppResult<Option<ApplicationAuthorizationProfileRecord>> {
        let application_id = application_id.to_string();
        let profile_key = profile_key.trim().to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} AND profile_key = {}",
                select_application_authorization_profile_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(profile_key)
                .get_result::<ApplicationAuthorizationProfileRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_authorization_profile_by_id(
        &self,
        profile_id: &str,
    ) -> AppResult<Option<ApplicationAuthorizationProfileRecord>> {
        let profile_id = profile_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                select_application_authorization_profile_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(profile_id)
                .get_result::<ApplicationAuthorizationProfileRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_application_authorization_profile(
        &self,
        profile: NewApplicationAuthorizationProfile,
    ) -> AppResult<ApplicationAuthorizationProfileRecord> {
        let profile_key = profile.profile_key.trim().to_string();
        if profile_key.is_empty()
            || profile_key.len() > 255
            || profile_key.chars().any(|ch| ch.is_control())
        {
            return Err(AppError::BadRequest(
                "authorization profile key is invalid".to_string(),
            ));
        }
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let existing_sql = format!(
                "{} WHERE application_id = {} AND profile_key = {}",
                select_application_authorization_profile_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            let existing = sql_query(existing_sql)
                .bind::<Text, _>(&profile.application_id)
                .bind::<Text, _>(&profile_key)
                .get_result::<ApplicationAuthorizationProfileRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?;
            let id = existing
                .as_ref()
                .map(|value| value.id.clone())
                .unwrap_or(profile.id);
            if existing.is_some() {
                let sql = format!(
                    "UPDATE application_authorization_profiles SET connection_kind = {}, connection_id = {}, source_mode = {}, remote_version = {}, remote_digest = {}, sync_status = {}, last_synced_at = {}, last_error = {}, updated_at = {} WHERE id = {}",
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
                    .bind::<Text, _>(&profile.connection_kind)
                    .bind::<Nullable<Text>, _>(&profile.connection_id)
                    .bind::<Text, _>(&profile.source_mode)
                    .bind::<Nullable<Text>, _>(&profile.remote_version)
                    .bind::<Nullable<Text>, _>(&profile.remote_digest)
                    .bind::<Text, _>(&profile.sync_status)
                    .bind::<Nullable<BigInt>, _>(&profile.last_synced_at)
                    .bind::<Nullable<Text>, _>(&profile.last_error)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(&mut conn)
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
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&profile.application_id)
                    .bind::<Text, _>(&profile_key)
                    .bind::<Text, _>(&profile.connection_kind)
                    .bind::<Nullable<Text>, _>(&profile.connection_id)
                    .bind::<Text, _>(&profile.source_mode)
                    .bind::<Nullable<Text>, _>(&profile.remote_version)
                    .bind::<Nullable<Text>, _>(&profile.remote_digest)
                    .bind::<Text, _>(&profile.sync_status)
                    .bind::<Nullable<BigInt>, _>(&profile.last_synced_at)
                    .bind::<Nullable<Text>, _>(&profile.last_error)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!(
                "{} WHERE id = {}",
                select_application_authorization_profile_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ApplicationAuthorizationProfileRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_permission_definitions(
        &self,
        profile_id: &str,
    ) -> AppResult<Vec<ApplicationPermissionDefinitionRecord>> {
        let profile_id = profile_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE profile_id = {} ORDER BY permission_key ASC",
                select_application_permission_definition_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(profile_id)
                .load::<ApplicationPermissionDefinitionRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn replace_application_permission_definitions(
        &self,
        profile_id: &str,
        definitions: Vec<NewApplicationPermissionDefinition>,
    ) -> AppResult<()> {
        let profile_id = profile_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let delete_sql = format!(
                    "DELETE FROM application_permission_definitions WHERE profile_id = {}",
                    ph(kind, 1)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&profile_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let now = util::now_ts();
                for definition in definitions {
                    let key = normalize_application_entitlement_keys(vec![definition.permission_key])?
                        .into_iter()
                        .next()
                        .ok_or_else(|| AppError::BadRequest("permission key is required".to_string()))?;
                    let label = definition.label.trim().to_string();
                    if label.is_empty() || label.len() > 160 {
                        return Err(AppError::BadRequest("permission label is invalid".to_string()));
                    }
                    let sql = format!(
                        "INSERT INTO application_permission_definitions (profile_id, permission_key, label, description, source, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&profile_id)
                        .bind::<Text, _>(&key)
                        .bind::<Text, _>(&label)
                        .bind::<Nullable<Text>, _>(&definition.description)
                        .bind::<Text, _>(&definition.source)
                        .bind::<Integer, _>(i32::from(definition.is_active))
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }
}
