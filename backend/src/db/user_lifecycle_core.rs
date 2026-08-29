use super::{
    AuthorizationCodeType, DatabaseKind, Db, LoginCodeLevel, ScimUserMutationScope,
    USER_AUTH_STATE_TABLES, USER_PERMANENT_DEPENDENT_TABLES, blocking, ph,
};
use crate::{
    error::{AppError, AppResult},
    util,
};
use diesel::{
    Connection, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

impl Db {
    pub async fn set_user_password(&self, id: &str, password_hash: String) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE users SET password_hash = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(password_hash)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn clear_user_auth_state(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            clear_user_auth_state_for_conn!(&mut conn, kind, &id)
        })
    }

    pub async fn enable_user(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE users SET is_active = {}, archived_at = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(sql)
                .bind::<Integer, _>(1)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn disable_user(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                clear_user_auth_state_for_conn!(conn, kind, &id)?;
                clear_user_application_identity_bindings_for_conn!(conn, kind, &id)?;
                let sql = format!(
                    "UPDATE users SET is_active = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(sql)
                    .bind::<Integer, _>(0)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    /// Disables a user only while the SCIM application/organization scope is
    /// still true. The scope predicates are part of the conditional update,
    /// not a handler-side preflight, so removing a user from an organization
    /// cannot be followed by a global account disable from an in-flight SCIM
    /// request.
    pub async fn disable_scim_user(&self, id: &str, scope: ScimUserMutationScope) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let mut next_scope_param = 4;
                let mut scope_guard = String::new();
                if scope.organization_id.is_some() {
                    let index = next_scope_param;
                    next_scope_param += 1;
                    scope_guard.push_str(&format!(
                        " AND EXISTS (SELECT 1 FROM organization_members WHERE organization_members.user_id = users.id AND organization_members.organization_id = {})",
                        ph(kind, index)
                    ));
                }
                if scope.application_id.is_some() {
                    let index = next_scope_param;
                    scope_guard.push_str(&format!(
                        " AND EXISTS (SELECT 1 FROM applications INNER JOIN organization_members ON organization_members.organization_id = applications.organization_id WHERE applications.id = {} AND applications.is_active = 1 AND organization_members.user_id = users.id)",
                        ph(kind, index)
                    ));
                }
                let sql = format!(
                    "UPDATE users SET is_active = {}, updated_at = {} WHERE id = {} AND archived_at IS NULL{scope_guard}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let mut query = sql_query(sql)
                    .into_boxed::<_>()
                    .bind::<Integer, _>(0)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id);
                if let Some(organization_id) = scope.organization_id.as_ref() {
                    query = query.bind::<Text, _>(organization_id);
                }
                if let Some(application_id) = scope.application_id.as_ref() {
                    query = query.bind::<Text, _>(application_id);
                }
                if query.execute(conn).map_err(AppError::from)? == 0 {
                    return Err(AppError::NotFound);
                }
                clear_user_auth_state_for_conn!(conn, kind, &id)?;
                clear_user_application_identity_bindings_for_conn!(conn, kind, &id)?;
                Ok(())
            })
        })
    }

    pub async fn archive_user(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                clear_user_auth_state_for_conn!(conn, kind, &id)?;
                clear_user_application_identity_bindings_for_conn!(conn, kind, &id)?;
                let sql = format!(
                    "UPDATE users SET is_active = {}, archived_at = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(sql)
                    .bind::<Integer, _>(0)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn permanently_delete_user(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                clear_user_auth_state_for_conn!(conn, kind, &id)?;
                for table in USER_PERMANENT_DEPENDENT_TABLES {
                    let sql = format!("DELETE FROM {table} WHERE user_id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let invalidate_recovery_codes_sql = format!(
                    "UPDATE invitations SET is_active = 0, updated_at = {} WHERE authorized_user_id = {} AND code_type = {} AND login_code_level = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(invalidate_recovery_codes_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::AccountRecovery.as_str())
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!("DELETE FROM users WHERE id = {}", ph(kind, 1));
                let affected = sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::NotFound);
                }
                Ok(())
            })
        })
    }
}
