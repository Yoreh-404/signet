//! MFA challenge persistence.
//!
//! This module owns the short-lived MFA challenge lifecycle. Challenge
//! consumption remains an atomic conditional update so a challenge can only
//! be consumed once.

use super::*;

use super::{AppError, AppResult, Db, MfaChallengeRecord, ph};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};

impl Db {
    pub async fn create_mfa_challenge(
        &self,
        user_id: &str,
        purpose: &str,
        return_to: Option<String>,
        ttl_seconds: i64,
    ) -> AppResult<MfaChallengeRecord> {
        let id = util::random_token(24);
        let user_id = user_id.to_string();
        let purpose = purpose.to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM mfa_challenges WHERE expires_at < {} OR (user_id = {} AND purpose = {} AND consumed_at IS NULL)",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(cleanup_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&purpose)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "INSERT INTO mfa_challenges (id, user_id, purpose, return_to, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&purpose)
                .bind::<Nullable<Text>, _>(&return_to)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(MfaChallengeRecord {
                id,
                user_id,
                purpose,
                return_to,
                expires_at,
                consumed_at: None,
                created_at: now,
            })
        })
    }

    pub async fn find_mfa_challenge(&self, id: &str) -> AppResult<Option<MfaChallengeRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, purpose, return_to, expires_at, consumed_at, created_at FROM mfa_challenges WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<MfaChallengeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn consume_mfa_challenge(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE mfa_challenges SET consumed_at = {} WHERE id = {} AND consumed_at IS NULL",
                ph(kind, 1),
                ph(kind, 2)
            );
            let affected = sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                Err(AppError::Unauthorized)
            } else {
                Ok(())
            }
        })
    }

    pub async fn complete_mfa_challenge_with_totp(
        &self,
        challenge_id: &str,
        user_id: &str,
        step: i64,
    ) -> AppResult<()> {
        let challenge_id = challenge_id.to_string();
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let challenge_sql = format!(
                    "UPDATE mfa_challenges SET consumed_at = {} WHERE id = {} AND user_id = {} AND expires_at >= {} AND consumed_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let challenge_affected = sql_query(challenge_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&challenge_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if challenge_affected == 0 {
                    return Err(AppError::Unauthorized);
                }

                let totp_sql = format!(
                    "UPDATE mfa_totp_methods SET last_used_step = {}, updated_at = {} WHERE user_id = {} AND (last_used_step IS NULL OR last_used_step < {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let totp_affected = sql_query(totp_sql)
                    .bind::<BigInt, _>(step)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&user_id)
                    .bind::<BigInt, _>(step)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if totp_affected == 0 {
                    Err(AppError::Unauthorized)
                } else {
                    Ok(())
                }
            })
        })
    }

    pub async fn complete_mfa_challenge_with_recovery_code(
        &self,
        challenge_id: &str,
        user_id: &str,
        recovery_code_id: &str,
    ) -> AppResult<()> {
        let challenge_id = challenge_id.to_string();
        let user_id = user_id.to_string();
        let recovery_code_id = recovery_code_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let challenge_sql = format!(
                    "UPDATE mfa_challenges SET consumed_at = {} WHERE id = {} AND user_id = {} AND expires_at >= {} AND consumed_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let challenge_affected = sql_query(challenge_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&challenge_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if challenge_affected == 0 {
                    return Err(AppError::Unauthorized);
                }

                let recovery_code_sql = format!(
                    "UPDATE mfa_recovery_codes SET used_at = {} WHERE id = {} AND user_id = {} AND used_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let recovery_code_affected = sql_query(recovery_code_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&recovery_code_id)
                    .bind::<Text, _>(&user_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if recovery_code_affected == 0 {
                    Err(AppError::Unauthorized)
                } else {
                    Ok(())
                }
            })
        })
    }

    pub async fn delete_mfa_for_user(&self, user_id: &str) -> AppResult<()> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
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
                Ok(())
            })
        })
    }
}
