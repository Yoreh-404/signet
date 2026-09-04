use super::{AppError, AppResult, DatabaseKind, Db, NewSigningKey, SigningKeyRecord, blocking, ph};
use crate::{config::Settings, util};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};

impl Db {
    pub async fn list_signing_keys(&self) -> AppResult<Vec<SigningKeyRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys ORDER BY is_active DESC, created_at DESC")
                .load::<SigningKeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_signing_key_by_kid(&self, kid: &str) -> AppResult<Option<SigningKeyRecord>> {
        let kid = kid.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys WHERE kid = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(kid)
                .get_result::<SigningKeyRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_active_signing_key(&self) -> AppResult<Option<SigningKeyRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1")
                .get_result::<SigningKeyRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_signing_key_seed(
        &self,
        settings: &Settings,
    ) -> AppResult<Vec<SigningKeyRecord>> {
        let existing = self.list_signing_keys().await?;
        if !existing.is_empty() {
            return Ok(existing);
        }
        let private_key_pem = if settings.security.rsa_private_key_pem.trim().is_empty() {
            util::generate_rsa_private_key_pem()?
        } else {
            settings.security.rsa_private_key_pem.clone()
        };
        self.insert_signing_key(NewSigningKey {
            kid: settings.security.key_id.clone(),
            private_key_pem,
            is_active: true,
        })
        .await?;
        self.list_signing_keys().await
    }

    pub async fn rotate_signing_key(&self, kid: Option<String>) -> AppResult<SigningKeyRecord> {
        let kid = kid
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("key-{}-{}", util::now_ts(), util::random_token(6)));
        if kid.is_empty() || kid.len() > 128 || kid.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(AppError::BadRequest(
                "signing key id must be 1-128 printable characters".to_string(),
            ));
        }
        let private_key_pem = util::generate_rsa_private_key_pem()?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<SigningKeyRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys WHERE kid = {}",
                    ph(kind, 1)
                );
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&kid)
                    .get_result::<SigningKeyRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                if existing.is_some() {
                    return Err(AppError::BadRequest(format!(
                        "signing key id already exists: {kid}"
                    )));
                }
                let retire_sql = format!(
                    "UPDATE signing_keys SET is_active = {}, retired_at = {} WHERE is_active = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(retire_sql)
                    .bind::<Integer, _>(0)
                    .bind::<BigInt, _>(now)
                    .bind::<Integer, _>(1)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let id = uuid::Uuid::new_v4().to_string();
                let insert_sql = format!(
                    "INSERT INTO signing_keys (id, kid, private_key_pem, is_active, created_at, activated_at, retired_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&kid)
                    .bind::<Text, _>(&private_key_pem)
                    .bind::<Integer, _>(1)
                    .bind::<BigInt, _>(now)
                    .bind::<Nullable<BigInt>, _>(Some(now))
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys WHERE id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<SigningKeyRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    async fn insert_signing_key(&self, key: NewSigningKey) -> AppResult<SigningKeyRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO signing_keys (id, kid, private_key_pem, is_active, created_at, activated_at, retired_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
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
                .bind::<Text, _>(key.kid)
                .bind::<Text, _>(key.private_key_pem)
                .bind::<Integer, _>(i32::from(key.is_active))
                .bind::<BigInt, _>(now)
                .bind::<Nullable<BigInt>, _>(key.is_active.then_some(now))
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "SELECT id, kid, private_key_pem, is_active, created_at, activated_at, retired_at FROM signing_keys WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<SigningKeyRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }
}
