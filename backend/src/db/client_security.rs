use super::*;

use super::{
    AppError, AppResult, ClientClaimMapperRecord, ClientRecord, CountRow, Db, NewClientClaimMapper,
    SessionMetadata, SessionRecord, bind_text_list, ph,
};
use crate::util;
use diesel::{
    OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};
use std::collections::BTreeMap;

impl Db {
    pub async fn list_backchannel_logout_clients_for_user(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<ClientRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE is_active = 1 AND COALESCE(backchannel_logout_uri, '') <> '' AND client_id IN (SELECT DISTINCT oidc_client_id FROM login_events WHERE user_id = {} AND oidc_client_id IS NOT NULL) ORDER BY updated_at DESC",
                super::select_client_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_frontchannel_logout_clients_for_user(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<ClientRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE is_active = 1 AND COALESCE(frontchannel_logout_uri, '') <> '' AND client_id IN (SELECT DISTINCT oidc_client_id FROM login_events WHERE user_id = {} AND oidc_client_id IS NOT NULL) ORDER BY updated_at DESC",
                super::select_client_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_client_assertion_jti(
        &self,
        client_id: &str,
        jti: &str,
        expires_at: i64,
    ) -> AppResult<()> {
        let client_id = client_id.to_string();
        let jti = jti.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let delete_sql = format!(
                "DELETE FROM client_assertion_jtis WHERE expires_at < {}",
                ph(kind, 1)
            );
            sql_query(delete_sql)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let insert_sql = format!(
                "INSERT INTO client_assertion_jtis (client_id, jti, expires_at, created_at) VALUES ({}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(client_id)
                .bind::<Text, _>(jti)
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn insert_dpop_proof_jti(
        &self,
        jkt: &str,
        jti: &str,
        expires_at: i64,
    ) -> AppResult<()> {
        let jkt = jkt.to_string();
        let jti = jti.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let delete_sql = format!("DELETE FROM dpop_proofs WHERE expires_at < {}", ph(kind, 1));
            sql_query(delete_sql)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let insert_sql = format!(
                "INSERT INTO dpop_proofs (jkt, jti, expires_at, created_at) VALUES ({}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(jkt)
                .bind::<Text, _>(jti)
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn insert_session(
        &self,
        user_id: &str,
        ttl_seconds: i64,
        metadata: SessionMetadata,
    ) -> AppResult<(SessionRecord, String)> {
        let (id, cookie_value) = util::new_session_credentials();
        let csrf_token = util::random_token(32);
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO sessions (id, user_id, csrf_token, ip_address, user_agent, login_method, expires_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
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
                .bind::<Text, _>(&csrf_token)
                .bind::<Nullable<Text>, _>(metadata.ip_address.as_deref())
                .bind::<Nullable<Text>, _>(metadata.user_agent.as_deref())
                .bind::<Nullable<Text>, _>(metadata.login_method.as_deref())
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok((
                SessionRecord {
                    id,
                    user_id,
                    csrf_token,
                    ip_address: metadata.ip_address,
                    user_agent: metadata.user_agent,
                    login_method: metadata.login_method,
                    expires_at,
                    created_at: now,
                },
                cookie_value,
            ))
        })
    }

    pub async fn find_session(&self, id: &str) -> AppResult<Option<SessionRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, csrf_token, ip_address, user_agent, login_method, expires_at, created_at FROM sessions WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<SessionRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_session_by_credential(
        &self,
        credential_id: &str,
    ) -> AppResult<Option<SessionRecord>> {
        let credential_id = credential_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT sessions.id, sessions.user_id, sessions.csrf_token, sessions.ip_address, sessions.user_agent, sessions.login_method, sessions.expires_at, sessions.created_at FROM session_credentials INNER JOIN sessions ON sessions.id = session_credentials.session_id WHERE session_credentials.credential_id = {} AND session_credentials.expires_at >= {} AND sessions.expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(credential_id)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .get_result::<SessionRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_user_sessions(&self, user_id: &str) -> AppResult<Vec<SessionRecord>> {
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, csrf_token, ip_address, user_agent, login_method, expires_at, created_at FROM sessions WHERE user_id = {} AND expires_at >= {} ORDER BY created_at DESC",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<BigInt, _>(now)
                .load::<SessionRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_session(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                for (table, column) in [
                    ("session_credentials", "session_id"),
                    ("browser_context_accounts", "session_id"),
                    ("application_saml_sessions", "signet_session_id"),
                ] {
                    let sql = format!("DELETE FROM {table} WHERE {column} = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!("DELETE FROM sessions WHERE id = {}", ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_user_session(&self, user_id: &str, session_id: &str) -> AppResult<bool> {
        let user_id = user_id.to_string();
        let session_id = session_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<bool, AppError, _>(|conn| {
                let exists_sql = format!(
                    "SELECT COUNT(*) AS count FROM sessions WHERE user_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let exists = sql_query(exists_sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&session_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    > 0;
                if !exists {
                    return Ok(false);
                }
                for (table, column) in [
                    ("session_credentials", "session_id"),
                    ("browser_context_accounts", "session_id"),
                    ("application_saml_sessions", "signet_session_id"),
                ] {
                    let sql = format!("DELETE FROM {table} WHERE {column} = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&session_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "DELETE FROM sessions WHERE user_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(user_id)
                    .bind::<Text, _>(session_id)
                    .execute(conn)
                    .map(|affected| affected > 0)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn list_client_claim_mappers(
        &self,
        client_db_id: &str,
    ) -> AppResult<Vec<ClientClaimMapperRecord>> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE client_db_id = {} ORDER BY sort_order ASC, created_at ASC",
                select_client_claim_mapper_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .load::<ClientClaimMapperRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_client_claim_mappers_by_client_ids(
        &self,
        client_db_ids: &[String],
    ) -> AppResult<BTreeMap<String, Vec<ClientClaimMapperRecord>>> {
        if client_db_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let client_db_ids = client_db_ids.to_vec();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE client_db_id IN ({}) ORDER BY client_db_id ASC, sort_order ASC, created_at ASC",
                select_client_claim_mapper_sql(),
                (1..=client_db_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let rows = bind_text_list(&mut conn, sql_query(sql), &client_db_ids)
                .load::<ClientClaimMapperRecord>(&mut conn)
                .map_err(AppError::from)?;
            let mut grouped = BTreeMap::new();
            for mapper in rows {
                grouped
                    .entry(mapper.client_db_id.clone())
                    .or_insert_with(Vec::new)
                    .push(mapper);
            }
            Ok(grouped)
        })
    }

    pub async fn replace_client_claim_mappers(
        &self,
        client_db_id: &str,
        mappers: Vec<NewClientClaimMapper>,
    ) -> AppResult<Vec<ClientClaimMapperRecord>> {
        let client_db_id = client_db_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM client_claim_mappers WHERE client_db_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&client_db_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            for mapper in mappers {
                let sql = format!(
                    "INSERT INTO client_claim_mappers (id, client_db_id, claim_name, source, source_value, value_type, include_in_id_token, include_in_access_token, include_in_userinfo, is_active, sort_order, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 13)
                );
                sql_query(sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&client_db_id)
                    .bind::<Text, _>(mapper.claim_name)
                    .bind::<Text, _>(mapper.source)
                    .bind::<Text, _>(mapper.source_value)
                    .bind::<Text, _>(mapper.value_type)
                    .bind::<Integer, _>(i32::from(mapper.include_in_id_token))
                    .bind::<Integer, _>(i32::from(mapper.include_in_access_token))
                    .bind::<Integer, _>(i32::from(mapper.include_in_userinfo))
                    .bind::<Integer, _>(i32::from(mapper.is_active))
                    .bind::<Integer, _>(mapper.sort_order)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }

            let sql = format!(
                "{} WHERE client_db_id = {} ORDER BY sort_order ASC, created_at ASC",
                select_client_claim_mapper_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .load::<ClientClaimMapperRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }
}
