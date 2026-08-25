//! Atomic account credential mutations.
//!
//! Replacing a password is an authentication-state transition, not a plain
//! profile update.  The database transaction in this module deliberately
//! owns both sides of that transition: old authentication artifacts are
//! revoked before the new hash becomes visible, and the audit row is part of
//! the same commit.  Webhook delivery starts only after the transaction has
//! committed.

use super::{
    AppError, AuditEventRecord, CountRow, DatabaseKind, Db, USER_AUTH_STATE_TABLES,
    UserIdentityCandidate, UserRecord, UserUpdate, blocking, count_user_identity_conflicts_sql, ph,
    select_user_sql,
};
use crate::audit::AuditEvent;
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

impl Db {
    /// Replaces an existing account password and revokes every authentication
    /// artifact that could have been minted with the previous credential.
    ///
    /// The caller is responsible for policy validation and password hashing;
    /// this method is the persistence boundary and never accepts plaintext.
    pub async fn replace_user_password_with_audit(
        &self,
        user_id: &str,
        password_hash: String,
        event: AuditEvent,
    ) -> crate::error::AppResult<UserRecord> {
        let user_id = user_id.to_string();
        let now = crate::util::now_ts();
        let webhook_db = self.clone();
        let (user, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(UserRecord, AuditEventRecord), AppError, _>(|conn| {
                clear_user_auth_state_for_conn!(conn, kind, &user_id)?;

                let update_sql = format!(
                    "UPDATE users SET password_hash = {}, updated_at = {} WHERE id = {} AND archived_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                );
                let affected = sql_query(update_sql)
                    .bind::<Text, _>(&password_hash)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&user_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::NotFound);
                }

                let select_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let user = sql_query(select_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((user, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(user)
    }

    /// Atomically updates profile metadata and a replacement password.
    ///
    /// This is intentionally separate from `update_user`: callers that do not
    /// change credentials retain the cheaper metadata-only path, while every
    /// password-bearing request gets one identity check, one auth-state
    /// revocation, one user update, and one audit commit.
    pub async fn update_user_with_password_and_audit(
        &self,
        update: UserUpdate<'_>,
        password_hash: String,
        event: AuditEvent,
    ) -> crate::error::AppResult<UserRecord> {
        let UserUpdate {
            id,
            email,
            username,
            display_name,
            phone,
            is_admin,
            is_active,
        } = update;
        let id = id.to_string();
        let now = crate::util::now_ts();
        let identity = UserIdentityCandidate::update(&id, email.clone(), username.clone());
        let webhook_db = self.clone();
        let (user, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(UserRecord, AuditEventRecord), AppError, _>(|conn| {
                let current_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let current = sql_query(current_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<UserRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "user email or username already exists"
                )?;

                // A password replacement and a deactivation both invalidate
                // all login state.  Contact changes only release the factor
                // leases tied to the changed contact.
                clear_user_auth_state_for_conn!(conn, kind, &id)?;
                if !is_active {
                    clear_user_application_identity_bindings_for_conn!(conn, kind, &id)?;
                } else {
                    if current.email != email {
                        clear_user_application_identity_factor_bindings_for_conn!(
                            conn,
                            kind,
                            &id,
                            crate::applications::FACTOR_EMAIL
                        )?;
                    }
                    if current.phone != phone {
                        clear_user_application_identity_factor_bindings_for_conn!(
                            conn,
                            kind,
                            &id,
                            crate::applications::FACTOR_PHONE
                        )?;
                    }
                }

                let email_changed = current.email != email;
                let phone_changed = current.phone != phone;
                let update_sql = format!(
                    "UPDATE users SET email = {}, username = {}, display_name = {}, phone = {}, password_hash = {}, email_verified_at = {}, phone_verified_at = {}, is_admin = {}, is_active = {}, updated_at = {} WHERE id = {} AND archived_at IS NULL",
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
                );
                let affected = sql_query(update_sql)
                    .bind::<Text, _>(&email)
                    .bind::<Text, _>(&username)
                    .bind::<Nullable<Text>, _>(&display_name)
                    .bind::<Nullable<Text>, _>(&phone)
                    .bind::<Text, _>(&password_hash)
                    .bind::<Nullable<BigInt>, _>(
                        (!email_changed).then_some(current.email_verified_at).flatten(),
                    )
                    .bind::<Nullable<BigInt>, _>(
                        (!phone_changed).then_some(current.phone_verified_at).flatten(),
                    )
                    .bind::<Integer, _>(i32::from(is_admin))
                    .bind::<Integer, _>(i32::from(is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::NotFound);
                }

                let select_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let user = sql_query(select_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((user, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(user)
    }
}
