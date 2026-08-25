//! Atomic MFA aggregate mutations.
//!
//! MFA setup, recovery codes, passkeys, and challenges form one account
//! security boundary. The HTTP layer may verify a TOTP code before calling
//! these methods, but the final setup ownership/expiry check and the audit
//! write must share the same database transaction as the state transition.

use super::{
    AppError, AuditEventRecord, CountRow, DatabaseKind, Db, MfaTotpMethodRecord, blocking, ph,
};
use crate::audit::AuditEvent;
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

impl Db {
    /// Consumes a live setup owned by `user_id`, enables/replaces the TOTP
    /// method, replaces recovery codes, and records one audit event.
    pub async fn confirm_totp_setup_with_audit(
        &self,
        user_id: &str,
        setup_id: &str,
        recovery_code_hashes: Vec<String>,
        event: AuditEvent,
    ) -> crate::error::AppResult<MfaTotpMethodRecord> {
        let user_id = user_id.to_string();
        let setup_id = setup_id.to_string();
        let now = crate::util::now_ts();
        let webhook_db = self.clone();
        let (method, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(MfaTotpMethodRecord, AuditEventRecord), AppError, _>(|conn| {
                let setup_sql = format!(
                    "SELECT id, user_id, secret, expires_at, created_at FROM mfa_totp_setups WHERE id = {} AND user_id = {} AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                );
                let setup = sql_query(setup_sql)
                    .bind::<Text, _>(&setup_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<BigInt, _>(now)
                    .get_result::<super::MfaTotpSetupRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;

                let exists_sql = format!(
                    "SELECT COUNT(*) AS count FROM mfa_totp_methods WHERE user_id = {}",
                    ph(kind, 1)
                );
                let exists = sql_query(exists_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    > 0;
                if exists {
                    let update_sql = format!(
                        "UPDATE mfa_totp_methods SET secret = {}, last_used_step = {}, enabled_at = {}, updated_at = {} WHERE user_id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                    );
                    sql_query(update_sql)
                        .bind::<Text, _>(&setup.secret)
                        .bind::<Nullable<BigInt>, _>(None::<i64>)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&user_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                } else {
                    let insert_sql = format!(
                        "INSERT INTO mfa_totp_methods (user_id, secret, last_used_step, enabled_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6),
                    );
                    sql_query(insert_sql)
                        .bind::<Text, _>(&user_id)
                        .bind::<Text, _>(&setup.secret)
                        .bind::<Nullable<BigInt>, _>(None::<i64>)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                let delete_setup_sql = format!(
                    "DELETE FROM mfa_totp_setups WHERE id = {} AND user_id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                );
                let deleted = sql_query(delete_setup_sql)
                    .bind::<Text, _>(&setup_id)
                    .bind::<Text, _>(&user_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if deleted != 1 {
                    return Err(AppError::Unauthorized);
                }

                let delete_codes_sql = format!(
                    "DELETE FROM mfa_recovery_codes WHERE user_id = {}",
                    ph(kind, 1)
                );
                sql_query(delete_codes_sql)
                    .bind::<Text, _>(&user_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for code_hash in recovery_code_hashes {
                    let insert_code_sql = format!(
                        "INSERT INTO mfa_recovery_codes (id, user_id, code_hash, used_at, created_at) VALUES ({}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                    );
                    sql_query(insert_code_sql)
                        .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                        .bind::<Text, _>(&user_id)
                        .bind::<Text, _>(code_hash)
                        .bind::<Nullable<BigInt>, _>(None::<i64>)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                let method_sql = format!(
                    "SELECT user_id, secret, last_used_step, enabled_at, created_at, updated_at FROM mfa_totp_methods WHERE user_id = {}",
                    ph(kind, 1)
                );
                let method = sql_query(method_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<MfaTotpMethodRecord>(conn)
                    .map_err(AppError::from)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((method, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(method)
    }

    /// Replaces recovery codes only while TOTP remains enabled and records the
    /// rotation in the same transaction.
    pub async fn replace_recovery_codes_with_audit(
        &self,
        user_id: &str,
        code_hashes: Vec<String>,
        event: AuditEvent,
    ) -> crate::error::AppResult<()> {
        let user_id = user_id.to_string();
        let now = crate::util::now_ts();
        let webhook_db = self.clone();
        let audit_event = with_conn!(self, |conn, kind| {
            conn.transaction::<AuditEventRecord, AppError, _>(|conn| {
                let enabled_sql = format!(
                    "SELECT COUNT(*) AS count FROM mfa_totp_methods WHERE user_id = {}",
                    ph(kind, 1)
                );
                if sql_query(enabled_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::BadRequest("MFA is not enabled".to_string()));
                }
                let delete_sql = format!(
                    "DELETE FROM mfa_recovery_codes WHERE user_id = {}",
                    ph(kind, 1)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&user_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for code_hash in code_hashes {
                    let insert_sql = format!(
                        "INSERT INTO mfa_recovery_codes (id, user_id, code_hash, used_at, created_at) VALUES ({}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                    );
                    sql_query(insert_sql)
                        .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                        .bind::<Text, _>(&user_id)
                        .bind::<Text, _>(code_hash)
                        .bind::<Nullable<BigInt>, _>(None::<i64>)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                insert_audit_event_on_conn!(conn, kind, event)
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(())
    }

    /// Removes all MFA factors and pending challenges atomically with its
    /// audit event. This is used by both self-service disable and admin reset.
    pub async fn delete_mfa_for_user_with_audit(
        &self,
        user_id: &str,
        event: AuditEvent,
    ) -> crate::error::AppResult<()> {
        let user_id = user_id.to_string();
        let webhook_db = self.clone();
        let audit_event = with_conn!(self, |conn, kind| {
            conn.transaction::<AuditEventRecord, AppError, _>(|conn| {
                for table in [
                    "mfa_totp_methods",
                    "mfa_totp_setups",
                    "mfa_recovery_codes",
                    "mfa_challenges",
                    "passkeys",
                    "webauthn_challenges",
                ] {
                    let sql = format!("DELETE FROM {table} WHERE user_id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&user_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                insert_audit_event_on_conn!(conn, kind, event)
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(())
    }
}
