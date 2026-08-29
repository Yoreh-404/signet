//! Persistence for application-owned JWT, SAML, CAS, and SCIM protocol state.
//! The public methods remain inherent on Db; this module only owns their
//! physical implementation so callers and transaction semantics are unchanged.

use super::{
    AppError, AppResult, ApplicationJwtClientRecord, ApplicationJwtClientSecretRecord,
    ApplicationJwtCodeRecord, AuditEventRecord, DatabaseKind, Db, NewApplicationJwtClient,
    NewApplicationJwtCode, blocking, ph, select_application_jwt_client_sql,
    select_application_jwt_secret_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

impl Db {
    pub async fn find_application_jwt_client(
        &self,
        application_id: &str,
        client_id: &str,
    ) -> AppResult<Option<ApplicationJwtClientRecord>> {
        let application_id = application_id.to_string();
        let client_id = client_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} AND client_id = {}",
                select_application_jwt_client_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&client_id)
                .get_result::<ApplicationJwtClientRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_application_jwt_client(
        &self,
        application_id: &str,
        client: NewApplicationJwtClient,
    ) -> AppResult<ApplicationJwtClientRecord> {
        let application_id = application_id.to_string();
        let client_id = client.client_id.trim().to_string();
        let client_type = client.client_type.trim().to_ascii_lowercase();
        if client_id.is_empty()
            || client_id.len() > 255
            || client_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(AppError::BadRequest(
                "application JWT client_id is invalid".to_string(),
            ));
        }
        if !matches!(client_type.as_str(), "public" | "confidential") {
            return Err(AppError::BadRequest(
                "application JWT client_type must be public or confidential".to_string(),
            ));
        }
        let is_active = client.is_active;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationJwtClientRecord, AppError, _>(|conn| {
                let find_sql = format!(
                    "{} WHERE application_id = {} AND client_id = {}",
                    select_application_jwt_client_sql(),
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let existing = sql_query(find_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&client_id)
                    .get_result::<ApplicationJwtClientRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                if let Some(existing) = existing {
                    let update_sql = format!(
                        "UPDATE application_jwt_clients SET client_type = {}, is_active = {}, updated_at = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4)
                    );
                    sql_query(update_sql)
                        .bind::<Text, _>(&client_type)
                        .bind::<Integer, _>(i32::from(is_active))
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&existing.id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    if client_type == "public" || !is_active {
                        let revoke_sql = format!(
                            "UPDATE application_jwt_client_secrets SET revoked_at = {} WHERE jwt_client_id = {} AND revoked_at IS NULL",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        sql_query(revoke_sql)
                            .bind::<BigInt, _>(now)
                            .bind::<Text, _>(&existing.id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let select_sql = format!(
                        "{} WHERE id = {}",
                        select_application_jwt_client_sql(),
                        ph(kind, 1)
                    );
                    return sql_query(select_sql)
                        .bind::<Text, _>(&existing.id)
                        .get_result::<ApplicationJwtClientRecord>(conn)
                        .map_err(AppError::from);
                }

                let id = uuid::Uuid::new_v4().to_string();
                let insert_sql = format!(
                    "INSERT INTO application_jwt_clients (id, application_id, client_id, client_type, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
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
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&client_id)
                    .bind::<Text, _>(&client_type)
                    .bind::<Integer, _>(i32::from(is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!(
                    "{} WHERE id = {}",
                    select_application_jwt_client_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<ApplicationJwtClientRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn list_application_jwt_secrets(
        &self,
        application_id: &str,
        client_id: &str,
    ) -> AppResult<Vec<ApplicationJwtClientSecretRecord>> {
        let Some(client) = self
            .find_application_jwt_client(application_id, client_id)
            .await?
        else {
            return Ok(Vec::new());
        };
        let client_id = client.id;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE jwt_client_id = {} ORDER BY created_at DESC",
                select_application_jwt_secret_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&client_id)
                .load::<ApplicationJwtClientSecretRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Inserts a new secret and keeps the previous secret usable for the
    /// requested grace period. Hashes are the only secret material persisted.
    pub async fn rotate_application_jwt_secret(
        &self,
        application_id: &str,
        client_id: &str,
        secret_hash: &str,
        grace_seconds: i64,
    ) -> AppResult<ApplicationJwtClientSecretRecord> {
        if secret_hash.trim().is_empty() || secret_hash.len() > 512 {
            return Err(AppError::BadRequest(
                "application JWT secret hash is invalid".to_string(),
            ));
        }
        let grace_seconds = grace_seconds.clamp(0, 86_400);
        let application_id = application_id.to_string();
        let client_id = client_id.to_string();
        let secret_hash = secret_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationJwtClientSecretRecord, AppError, _>(|conn| {
                rotate_application_jwt_secret_on_conn!(
                    conn,
                    kind,
                    &application_id,
                    &client_id,
                    &secret_hash,
                    grace_seconds,
                    now,
                )
            })
        })
    }

    /// Rotates an application JWT secret and records the management audit in
    /// the same transaction.  The raw secret is never passed to the database
    /// or the audit event; only the generated secret response remains in the
    /// handler's in-memory scope.
    pub async fn rotate_application_jwt_secret_with_audit(
        &self,
        application_id: &str,
        client_id: &str,
        secret_hash: &str,
        grace_seconds: i64,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationJwtClientSecretRecord> {
        let application_id = application_id.to_string();
        let client_id = client_id.to_string();
        let secret_hash = secret_hash.to_string();
        let grace_seconds = grace_seconds.clamp(0, 86_400);
        let now = util::now_ts();
        let webhook_db = self.clone();
        let (secret, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationJwtClientSecretRecord, AuditEventRecord), AppError, _>(
                |conn| {
                    let secret = rotate_application_jwt_secret_on_conn!(
                        conn,
                        kind,
                        &application_id,
                        &client_id,
                        &secret_hash,
                        grace_seconds,
                        now,
                    )?;
                    let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                    Ok((secret, audit_event))
                },
            )
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(secret)
    }

    pub async fn verify_application_jwt_secret(
        &self,
        application_id: &str,
        client_id: &str,
        secret: &str,
    ) -> AppResult<bool> {
        if secret.is_empty() || secret.len() > 512 {
            return Ok(false);
        }
        let Some(client) = self
            .find_application_jwt_client(application_id, client_id)
            .await?
        else {
            return Ok(false);
        };
        if client.is_active != 1 || client.client_type != "confidential" {
            return Ok(false);
        }
        let secrets = self
            .list_application_jwt_secrets(application_id, client_id)
            .await?;
        let now = util::now_ts();
        Ok(secrets.into_iter().any(|record| {
            record.revoked_at.is_none()
                && record.expires_at.is_none_or(|expires_at| expires_at > now)
                && util::verify_password(&record.secret_hash, secret)
        }))
    }

    pub async fn revoke_application_jwt_secrets(
        &self,
        application_id: &str,
        client_id: &str,
    ) -> AppResult<()> {
        let Some(client) = self
            .find_application_jwt_client(application_id, client_id)
            .await?
        else {
            return Ok(());
        };
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_jwt_client_secrets SET revoked_at = {} WHERE jwt_client_id = {} AND revoked_at IS NULL",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&client.id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn insert_application_jwt_code(&self, code: NewApplicationJwtCode) -> AppResult<()> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO application_jwt_codes (code_hash, application_id, client_id, redirect_uri, user_id, nonce, code_challenge, code_challenge_method, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
            sql_query(sql)
                .bind::<Text, _>(code.code_hash)
                .bind::<Text, _>(code.application_id)
                .bind::<Text, _>(code.client_id)
                .bind::<Text, _>(code.redirect_uri)
                .bind::<Text, _>(code.user_id)
                .bind::<Nullable<Text>, _>(code.nonce)
                .bind::<Nullable<Text>, _>(code.code_challenge)
                .bind::<Nullable<Text>, _>(code.code_challenge_method)
                .bind::<BigInt, _>(code.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn consume_application_jwt_code(
        &self,
        code_hash: &str,
        application_id: &str,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        code_challenge_method: &str,
    ) -> AppResult<ApplicationJwtCodeRecord> {
        let code_hash = code_hash.to_string();
        let application_id = application_id.to_string();
        let client_id = client_id.to_string();
        let redirect_uri = redirect_uri.to_string();
        let code_challenge = code_challenge.to_string();
        let code_challenge_method = code_challenge_method.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationJwtCodeRecord, AppError, _>(|conn| {
                let select_sql = format!(
                    "SELECT code_hash, application_id, client_id, redirect_uri, user_id, nonce, code_challenge, code_challenge_method, expires_at, consumed_at, created_at FROM application_jwt_codes WHERE code_hash = {}",
                    ph(kind, 1)
                );
                let record = sql_query(select_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<ApplicationJwtCodeRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if record.expires_at < now
                    || record.consumed_at.is_some()
                    || record.application_id != application_id
                    || record.client_id != client_id
                    || record.redirect_uri != redirect_uri
                    || record.code_challenge.as_deref() != Some(code_challenge.as_str())
                    || record.code_challenge_method.as_deref() != Some(code_challenge_method.as_str())
                {
                    return Err(AppError::Unauthorized);
                }
                let update_sql = format!(
                    "UPDATE application_jwt_codes SET consumed_at = {} WHERE code_hash = {} AND consumed_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&code_hash)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                Ok(record)
            })
        })
    }
}
