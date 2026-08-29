//! Profile role catalog persistence.
//!
//! Profile roles are the catalog consumed by the authorization binding
//! aggregate. Keeping their lifecycle separate from the general Db facade
//! makes catalog mutations and edge mutations share a domain boundary without
//! making every database operation depend on the monolithic db module.

use super::{
    ApplicationProfileRoleRecord, DatabaseKind, Db, NewApplicationProfileRole, blocking,
    normalize_application_entitlement_keys, ph, select_application_profile_role_sql,
};
use crate::error::{AppError, AppResult};
use crate::util;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};

fn list_application_profile_roles_sql(kind: DatabaseKind) -> String {
    format!(
        "{} WHERE profile_id = {} ORDER BY is_active DESC, name ASC, id ASC",
        select_application_profile_role_sql(),
        ph(kind, 1)
    )
}

impl Db {
    pub async fn list_application_profile_roles(
        &self,
        profile_id: &str,
    ) -> AppResult<Vec<ApplicationProfileRoleRecord>> {
        let profile_id = profile_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = list_application_profile_roles_sql(kind);
            sql_query(sql)
                .bind::<Text, _>(profile_id)
                .load::<ApplicationProfileRoleRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_application_profile_role(
        &self,
        role: NewApplicationProfileRole,
    ) -> AppResult<ApplicationProfileRoleRecord> {
        let role_key = role.role_key.trim().to_string();
        let name = role.name.trim().to_string();
        if role_key.is_empty() || role_key.len() > 128 || role_key.chars().any(|ch| ch.is_control())
        {
            return Err(AppError::BadRequest(
                "application role key is invalid".to_string(),
            ));
        }
        if name.is_empty() || name.len() > 160 || name.chars().any(|ch| ch.is_control()) {
            return Err(AppError::BadRequest(
                "application role name is invalid".to_string(),
            ));
        }
        if role.is_default && !role.is_active {
            return Err(AppError::BadRequest(
                "an inactive application role cannot be the default role".to_string(),
            ));
        }
        let permissions =
            util::to_json(&normalize_application_entitlement_keys(role.permissions)?)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationProfileRoleRecord, AppError, _>(|conn| {
                // Serialize every profile-role mutation through the owning
                // application row.  A transaction alone is insufficient on
                // PostgreSQL READ COMMITTED: two writers can both observe an
                // empty/default-free profile before either inserts its role.
                // The parent-row update is a portable row lock for SQLite,
                // PostgreSQL, and MySQL, and also makes discovery reconciliation
                // use the same scope lock.
                let lock_sql = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id IN (SELECT application_id FROM application_authorization_profiles WHERE id = {})",
                    ph(kind, 1)
                );
                if sql_query(lock_sql)
                    .bind::<Text, _>(&role.profile_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let existing_sql = format!(
                    "{} WHERE profile_id = {} AND role_key = {}",
                    select_application_profile_role_sql(),
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let existing_by_key = sql_query(existing_sql)
                    .bind::<Text, _>(&role.profile_id)
                    .bind::<Text, _>(&role_key)
                    .get_result::<ApplicationProfileRoleRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                if let Some(requested_id) = role.id.as_ref()
                    && existing_by_key
                        .as_ref()
                        .is_some_and(|existing| existing.id != *requested_id)
                {
                    return Err(AppError::BadRequest(
                        "application profile role key is already used by another role".to_string(),
                    ));
                }
                let existing = if existing_by_key.is_some() {
                    existing_by_key
                } else if let Some(role_id) = role.id.as_ref() {
                    let existing_id_sql = format!(
                        "{} WHERE profile_id = {} AND id = {}",
                        select_application_profile_role_sql(),
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(existing_id_sql)
                        .bind::<Text, _>(&role.profile_id)
                        .bind::<Text, _>(role_id)
                        .get_result::<ApplicationProfileRoleRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?
                } else {
                    None
                };
                let id = existing
                    .as_ref()
                    .map(|value| value.id.clone())
                    .or(role.id)
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                if role.is_default {
                    let clear_sql = format!(
                        "UPDATE application_profile_roles SET is_default = 0, updated_at = {} WHERE profile_id = {} AND id <> {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3)
                    );
                    sql_query(clear_sql)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&role.profile_id)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                if existing.is_some() {
                    let sql = format!(
                        "UPDATE application_profile_roles SET role_key = {}, name = {}, description = {}, permissions = {}, source = {}, is_default = {}, is_active = {}, updated_at = {} WHERE profile_id = {} AND id = {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&role_key)
                        .bind::<Text, _>(&name)
                        .bind::<Nullable<Text>, _>(&role.description)
                        .bind::<Text, _>(&permissions)
                        .bind::<Text, _>(&role.source)
                        .bind::<Integer, _>(i32::from(role.is_default))
                        .bind::<Integer, _>(i32::from(role.is_active))
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&role.profile_id)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                } else {
                    let sql = format!(
                        "INSERT INTO application_profile_roles (id, profile_id, role_key, name, description, permissions, source, is_default, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .bind::<Text, _>(&role.profile_id)
                        .bind::<Text, _>(&role_key)
                        .bind::<Text, _>(&name)
                        .bind::<Nullable<Text>, _>(&role.description)
                        .bind::<Text, _>(&permissions)
                        .bind::<Text, _>(&role.source)
                        .bind::<Integer, _>(i32::from(role.is_default))
                        .bind::<Integer, _>(i32::from(role.is_active))
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "{} WHERE profile_id = {} AND id = {}",
                    select_application_profile_role_sql(),
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&role.profile_id)
                    .bind::<Text, _>(&id)
                    .get_result::<ApplicationProfileRoleRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_application_profile_role(
        &self,
        profile_id: &str,
        role_id: &str,
    ) -> AppResult<()> {
        let profile_id = profile_id.to_string();
        let role_id = role_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let lock_sql = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id IN (SELECT application_id FROM application_authorization_profiles WHERE id = {})",
                    ph(kind, 1)
                );
                if sql_query(lock_sql)
                    .bind::<Text, _>(&profile_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let role_sql = format!(
                    "{} WHERE profile_id = {} AND id = {}",
                    select_application_profile_role_sql(),
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let role = sql_query(role_sql)
                    .bind::<Text, _>(&profile_id)
                    .bind::<Text, _>(&role_id)
                    .get_result::<ApplicationProfileRoleRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                if role.is_default == 1 {
                    return Err(AppError::BadRequest(
                        "set another application role as default before deleting this role"
                            .to_string(),
                    ));
                }
                for table in [
                    "application_profile_user_roles",
                    "application_profile_group_roles",
                    "application_profile_organization_roles",
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE profile_id = {} AND role_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&profile_id)
                        .bind::<Text, _>(&role_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "DELETE FROM application_profile_roles WHERE profile_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&profile_id)
                    .bind::<Text, _>(&role_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(())
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::list_application_profile_roles_sql;
    use crate::config::DatabaseKind;

    #[test]
    fn list_application_profile_roles_sql_is_stably_ordered() {
        assert_eq!(
            list_application_profile_roles_sql(DatabaseKind::Sqlite),
            "SELECT id, profile_id, role_key, name, description, permissions, source, is_default, is_active, created_at, updated_at FROM application_profile_roles WHERE profile_id = ? ORDER BY is_active DESC, name ASC, id ASC"
        );
        assert_eq!(
            list_application_profile_roles_sql(DatabaseKind::Postgres),
            "SELECT id, profile_id, role_key, name, description, permissions, source, is_default, is_active, created_at, updated_at FROM application_profile_roles WHERE profile_id = $1 ORDER BY is_active DESC, name ASC, id ASC"
        );
    }
}
