use super::{
    Db, PermissionRow, RolePermissionJoinRow, RoleRecord, bind_text_list, blocking, ph,
    placeholders,
};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
};
use diesel::{OptionalExtension, RunQueryDsl, sql_query, sql_types::Text};
use std::collections::BTreeMap;

#[derive(Debug, diesel::QueryableByName)]
struct PermissionPresenceRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    present: i32,
}

impl Db {
    pub async fn has_any_effective_permission(
        &self,
        user_id: &str,
        permissions: &[&str],
    ) -> AppResult<bool> {
        if permissions.is_empty() {
            return Ok(false);
        }
        let user_id = user_id.to_string();
        let permission_values = permissions
            .iter()
            .map(|permission| (*permission).to_string())
            .collect::<Vec<_>>();
        let permission_count = permission_values.len();
        let mut values = permission_values;
        values.push(user_id.clone());
        values.push(user_id);
        with_conn!(self, |conn, kind| {
            let permission_placeholders = placeholders(kind, 1, permission_count);
            let user_placeholder = ph(kind, permission_count + 1);
            let group_user_placeholder = ph(kind, permission_count + 2);
            let sql = format!(
                "SELECT CASE WHEN EXISTS (SELECT 1 FROM role_permissions WHERE permission IN ({permission_placeholders}) AND (role_id IN (SELECT role_id FROM user_roles WHERE user_id = {user_placeholder}) OR role_id IN (SELECT group_roles.role_id FROM group_roles INNER JOIN group_members ON group_roles.group_id = group_members.group_id WHERE group_members.user_id = {group_user_placeholder}))) THEN 1 ELSE 0 END AS present"
            );
            bind_text_list(&mut conn, sql_query(sql), &values)
                .get_result::<PermissionPresenceRow>(&mut conn)
                .map(|row| row.present != 0)
                .map_err(AppError::from)
        })
    }

    pub async fn has_effective_permission(
        &self,
        user_id: &str,
        permission: &str,
    ) -> AppResult<bool> {
        let user_id = user_id.to_string();
        let permission = permission.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT CASE WHEN EXISTS (SELECT 1 FROM role_permissions WHERE permission = {} AND (role_id IN (SELECT role_id FROM user_roles WHERE user_id = {}) OR role_id IN (SELECT group_roles.role_id FROM group_roles INNER JOIN group_members ON group_roles.group_id = group_members.group_id WHERE group_members.user_id = {}))) THEN 1 ELSE 0 END AS present",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(&permission)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&user_id)
                .get_result::<PermissionPresenceRow>(&mut conn)
                .map(|row| row.present != 0)
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

    pub async fn list_role_permissions_by_role_ids(
        &self,
        role_ids: &[String],
    ) -> AppResult<BTreeMap<String, Vec<String>>> {
        if role_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let role_ids = role_ids.to_vec();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT role_id, permission FROM role_permissions WHERE role_id IN ({}) ORDER BY role_id ASC, permission ASC",
                placeholders(kind, 1, role_ids.len())
            );
            let rows = bind_text_list(&mut conn, sql_query(sql), &role_ids)
                .load::<RolePermissionJoinRow>(&mut conn)
                .map_err(AppError::from)?;
            let mut grouped = BTreeMap::new();
            for row in rows {
                grouped
                    .entry(row.role_id)
                    .or_insert_with(Vec::new)
                    .push(row.permission);
            }
            Ok(grouped)
        })
    }
}
