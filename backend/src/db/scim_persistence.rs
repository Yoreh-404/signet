use super::*;

use super::{
    AppError, AppResult, Db, ScimUserMutationPlan, UserIdentityCandidate, UserRecord,
    optimistic_concurrency_conflict, ph, select_user_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

impl Db {
    pub async fn apply_scim_user_mutation(
        &self,
        plan: ScimUserMutationPlan,
    ) -> AppResult<UserRecord> {
        let ScimUserMutationPlan {
            id,
            expected_version,
            email,
            username,
            display_name,
            phone,
            is_admin,
            is_active,
            password_hash,
            scope,
        } = plan;
        let scope = scope.unwrap_or_default();
        let now = util::now_ts();
        let identity = UserIdentityCandidate::update(&id, email.clone(), username.clone());
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                let current_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let current = sql_query(current_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<UserRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                if current.scim_concurrency_version() != expected_version {
                    return Err(optimistic_concurrency_conflict(
                        "SCIM user changed while the request was in flight",
                    ));
                }
                if current.archived_at.is_some() {
                    return Err(AppError::BadRequest(
                        "archived users cannot be changed through SCIM".to_string(),
                    ));
                }
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "user email or username already exists"
                )?;

                let email_changed = current.email != email;
                let phone_changed = current.phone != phone;
                if !is_active || password_hash.is_some() {
                    clear_user_auth_state_for_conn!(conn, kind, &id)?;
                }
                if !is_active {
                    clear_user_application_identity_bindings_for_conn!(conn, kind, &id)?;
                } else {
                    if email_changed {
                        clear_user_application_identity_factor_bindings_for_conn!(
                            conn,
                            kind,
                            &id,
                            crate::applications::FACTOR_EMAIL
                        )?;
                    }
                    if phone_changed {
                        clear_user_application_identity_factor_bindings_for_conn!(
                            conn,
                            kind,
                            &id,
                            crate::applications::FACTOR_PHONE
                        )?;
                    }
                }

                let next_email_verified_at =
                    (!email_changed).then_some(current.email_verified_at).flatten();
                let next_phone_verified_at =
                    (!phone_changed).then_some(current.phone_verified_at).flatten();
                let mut next_scope_param = 24;
                let password_guard = if password_hash.is_some() {
                    let index = next_scope_param;
                    next_scope_param += 1;
                    format!(" AND password_hash = {}", ph(kind, index))
                } else {
                    String::new()
                };
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
                let update_sql = format!(
                    "UPDATE users SET email = {}, username = {}, display_name = {}, phone = {}, email_verified_at = {}, phone_verified_at = {}, is_admin = {}, is_active = {}, updated_at = {} WHERE id = {} AND archived_at IS NULL AND updated_at = {} AND email = {} AND username = {} AND ((display_name = {}) OR (display_name IS NULL AND {} IS NULL)) AND ((phone = {}) OR (phone IS NULL AND {} IS NULL)) AND ((email_verified_at = {}) OR (email_verified_at IS NULL AND {} IS NULL)) AND ((phone_verified_at = {}) OR (phone_verified_at IS NULL AND {} IS NULL)) AND is_admin = {} AND is_active = {}{password_guard}{scope_guard}",
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
                    ph(kind, 18),
                    ph(kind, 19),
                    ph(kind, 20),
                    ph(kind, 21),
                    ph(kind, 22),
                    ph(kind, 23)
                );
                let mut update_query = sql_query(update_sql)
                    .into_boxed::<_>()
                    .bind::<Text, _>(&email)
                    .bind::<Text, _>(&username)
                    .bind::<Nullable<Text>, _>(&display_name)
                    .bind::<Nullable<Text>, _>(&phone)
                    .bind::<Nullable<BigInt>, _>(next_email_verified_at)
                    .bind::<Nullable<BigInt>, _>(next_phone_verified_at)
                    .bind::<Integer, _>(i32::from(is_admin))
                    .bind::<Integer, _>(i32::from(is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .bind::<BigInt, _>(current.updated_at)
                    .bind::<Text, _>(&current.email)
                    .bind::<Text, _>(&current.username)
                    .bind::<Nullable<Text>, _>(&current.display_name)
                    .bind::<Nullable<Text>, _>(&current.display_name)
                    .bind::<Nullable<Text>, _>(&current.phone)
                    .bind::<Nullable<Text>, _>(&current.phone)
                    .bind::<Nullable<BigInt>, _>(current.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(current.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(current.phone_verified_at)
                    .bind::<Nullable<BigInt>, _>(current.phone_verified_at)
                    .bind::<Integer, _>(current.is_admin)
                    .bind::<Integer, _>(current.is_active);
                if let Some(password_hash) = password_hash.as_ref() {
                    update_query = update_query.bind::<Text, _>(password_hash);
                }
                if let Some(organization_id) = scope.organization_id.as_ref() {
                    update_query = update_query.bind::<Text, _>(organization_id);
                }
                if let Some(application_id) = scope.application_id.as_ref() {
                    update_query = update_query.bind::<Text, _>(application_id);
                }
                let affected = update_query.execute(conn).map_err(AppError::from)?;
                if affected == 0 {
                    return Err(optimistic_concurrency_conflict(
                        "SCIM user changed while the request was being committed",
                    ));
                }

                if let Some(password_hash) = password_hash {
                    let password_sql = format!(
                        "UPDATE users SET password_hash = {}, updated_at = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    sql_query(password_sql)
                        .bind::<Text, _>(password_hash)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)
                        .and_then(|affected| {
                            (affected > 0).then_some(()).ok_or_else(|| {
                                optimistic_concurrency_conflict(
                                    "SCIM user changed while the password was being committed",
                                )
                            })
                        })?;
                }

                let select_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }
}
