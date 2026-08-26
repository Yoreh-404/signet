//! Passkey and WebAuthn challenge persistence.
//!
//! This module owns the WebAuthn credential and challenge lifecycle. The
//! public `Db` methods remain unchanged so callers retain the same account
//! ownership, single-use, and connection semantics.

use super::*;

use super::{AppError, AppResult, Db, PasskeyRecord, WebauthnChallengeRecord, ph};
use crate::util;
use diesel::{
    OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};

fn select_passkey_sql() -> &'static str {
    "SELECT id, user_id, credential_id, name, passkey_json, last_used_at, created_at, updated_at FROM passkeys"
}

fn select_webauthn_challenge_sql() -> &'static str {
    "SELECT id, user_id, challenge, kind, expires_at, created_at FROM webauthn_challenges"
}

impl Db {
    pub async fn list_passkeys(&self, user_id: &str) -> AppResult<Vec<PasskeyRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE user_id = {} ORDER BY created_at DESC",
                select_passkey_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<PasskeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_passkey_by_id(&self, id: &str) -> AppResult<Option<PasskeyRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_passkey_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<PasskeyRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AppResult<Option<PasskeyRecord>> {
        let credential_id = credential_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE credential_id = {}",
                select_passkey_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(credential_id)
                .get_result::<PasskeyRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_passkey(
        &self,
        user_id: &str,
        credential_id: String,
        name: String,
        passkey_json: String,
    ) -> AppResult<PasskeyRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO passkeys (id, user_id, credential_id, name, passkey_json, last_used_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(credential_id)
                .bind::<Text, _>(name)
                .bind::<Text, _>(passkey_json)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_passkey_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<PasskeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_passkey_after_authentication(
        &self,
        id: &str,
        passkey_json: String,
    ) -> AppResult<PasskeyRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE passkeys SET passkey_json = {}, last_used_at = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(passkey_json)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            let sql = format!("{} WHERE id = {}", select_passkey_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<PasskeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_passkey(&self, user_id: &str, id: &str) -> AppResult<()> {
        let user_id = user_id.to_string();
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM passkeys WHERE id = {} AND user_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(user_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                Err(AppError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    pub async fn create_webauthn_challenge(
        &self,
        user_id: Option<&str>,
        purpose: &str,
        state_json: String,
        ttl_seconds: i64,
    ) -> AppResult<WebauthnChallengeRecord> {
        let id = util::random_token(24);
        let user_id = user_id.map(str::to_string);
        let purpose = purpose.to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM webauthn_challenges WHERE expires_at < {} OR ({} IS NOT NULL AND user_id = {} AND purpose = {} AND consumed_at IS NULL)",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(cleanup_sql)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(user_id.as_deref())
                .bind::<Nullable<Text>, _>(user_id.as_deref())
                .bind::<Text, _>(&purpose)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "INSERT INTO webauthn_challenges (id, user_id, purpose, state_json, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
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
                .bind::<Nullable<Text>, _>(user_id.as_deref())
                .bind::<Text, _>(&purpose)
                .bind::<Text, _>(state_json)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE id = {}",
                select_webauthn_challenge_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<WebauthnChallengeRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_webauthn_challenge(
        &self,
        id: &str,
    ) -> AppResult<Option<WebauthnChallengeRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                select_webauthn_challenge_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<WebauthnChallengeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn consume_webauthn_challenge(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE webauthn_challenges SET consumed_at = {} WHERE id = {} AND consumed_at IS NULL",
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
}
