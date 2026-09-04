use super::{
    Db, GroupRecord, GroupRoleJoinRow, RoleRecord, UserRecord, bind_text_list, blocking, ph,
    placeholders,
};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
};
use diesel::{RunQueryDsl, sql_query, sql_types::Text};
use std::collections::BTreeMap;

impl Db {
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
                "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at, access_groups.version FROM access_groups INNER JOIN group_members ON access_groups.id = group_members.group_id WHERE group_members.user_id = {} ORDER BY access_groups.name ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<GroupRecord>(&mut conn)
                .map_err(AppError::from)
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

    pub async fn list_group_roles_by_group_ids(
        &self,
        group_ids: &[String],
    ) -> AppResult<BTreeMap<String, Vec<RoleRecord>>> {
        if group_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let group_ids = group_ids.to_vec();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT group_roles.group_id, roles.id, roles.name, roles.description, roles.is_system, roles.created_at, roles.updated_at FROM roles INNER JOIN group_roles ON roles.id = group_roles.role_id WHERE group_roles.group_id IN ({}) ORDER BY group_roles.group_id ASC, roles.name ASC, roles.id ASC",
                placeholders(kind, 1, group_ids.len())
            );
            let rows = bind_text_list(&mut conn, sql_query(sql), &group_ids)
                .load::<GroupRoleJoinRow>(&mut conn)
                .map_err(AppError::from)?;
            let mut grouped = BTreeMap::new();
            for row in rows {
                grouped
                    .entry(row.group_id.clone())
                    .or_insert_with(Vec::new)
                    .push(row.role());
            }
            Ok(grouped)
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
}
