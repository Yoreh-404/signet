use super::*;

use super::{
    AppError, AppResult, ClientGrantRecord, ClientGrantWithClientRecord, Db, RefreshTokenInput,
    RefreshTokenRecord, ph,
};
use crate::util;
use diesel::{
    OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};

impl Db {
    pub async fn insert_refresh_token(
        &self,
        client_id: String,
        token: RefreshTokenInput,
    ) -> AppResult<()> {
        let RefreshTokenInput {
            token_hash,
            user_id,
            scope,
            resource,
            authorization_details,
            dpop_jkt,
            auth_context_id,
            expires_at,
        } = token;
        let binding = self
            .find_application_client_binding_by_public_client_id(&client_id)
            .await?;
        let application_id = binding.as_ref().map(|value| value.application_id.clone());
        let authorization_profile_id = binding
            .as_ref()
            .map(|value| value.authorization_profile_id.clone());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO refresh_tokens (token_hash, client_id, application_id, authorization_profile_id, auth_context_id, user_id, scope, resource, authorization_details, dpop_jkt, expires_at, revoked_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                .bind::<Text, _>(token_hash)
                .bind::<Text, _>(client_id)
                .bind::<Nullable<Text>, _>(application_id)
                .bind::<Nullable<Text>, _>(authorization_profile_id)
                .bind::<Nullable<Text>, _>(auth_context_id)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(scope)
                .bind::<Nullable<Text>, _>(resource)
                .bind::<Nullable<Text>, _>(authorization_details)
                .bind::<Nullable<Text>, _>(dpop_jkt)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn find_refresh_token(
        &self,
        token_hash: &str,
    ) -> AppResult<Option<RefreshTokenRecord>> {
        let token_hash = token_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT token_hash, client_id, application_id, authorization_profile_id, auth_context_id, user_id, scope, resource, authorization_details, dpop_jkt, expires_at, revoked_at, created_at FROM refresh_tokens WHERE token_hash = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(token_hash)
                .get_result::<RefreshTokenRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn revoke_refresh_token(&self, token_hash: &str) -> AppResult<()> {
        let token_hash = token_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE refresh_tokens SET revoked_at = {} WHERE token_hash = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(token_hash)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn rotate_refresh_token(
        &self,
        token_hash: &str,
        client_id: &str,
        replacement: RefreshTokenInput,
    ) -> AppResult<bool> {
        let token_hash = token_hash.to_string();
        let client_id = client_id.to_string();
        let previous = self.find_refresh_token(&token_hash).await?;
        let application_id = previous
            .as_ref()
            .and_then(|value| value.application_id.clone());
        let authorization_profile_id = previous
            .as_ref()
            .and_then(|value| value.authorization_profile_id.clone());
        let auth_context_id = previous
            .as_ref()
            .and_then(|value| value.auth_context_id.clone());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<bool, AppError, _>(|conn| {
                let revoke_sql = format!(
                    "UPDATE refresh_tokens SET revoked_at = {} WHERE token_hash = {} AND client_id = {} AND revoked_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let changed = sql_query(revoke_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&token_hash)
                    .bind::<Text, _>(&client_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if changed != 1 {
                    return Ok(false);
                }

                let insert_sql = format!(
                    "INSERT INTO refresh_tokens (token_hash, client_id, application_id, authorization_profile_id, auth_context_id, user_id, scope, resource, authorization_details, dpop_jkt, expires_at, revoked_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                sql_query(insert_sql)
                    .bind::<Text, _>(replacement.token_hash)
                    .bind::<Text, _>(client_id)
                    .bind::<Nullable<Text>, _>(application_id)
                    .bind::<Nullable<Text>, _>(authorization_profile_id)
                    .bind::<Nullable<Text>, _>(auth_context_id)
                    .bind::<Text, _>(replacement.user_id)
                    .bind::<Text, _>(replacement.scope)
                    .bind::<Nullable<Text>, _>(replacement.resource)
                    .bind::<Nullable<Text>, _>(replacement.authorization_details)
                    .bind::<Nullable<Text>, _>(replacement.dpop_jkt)
                    .bind::<BigInt, _>(replacement.expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(true)
            })
        })
    }

    pub async fn find_client_grant(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> AppResult<Option<ClientGrantRecord>> {
        let user_id = user_id.to_string();
        let client_id = client_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT user_id, client_id, granted_scopes, granted_at, updated_at, revoked_at FROM client_grants WHERE user_id = {} AND client_id = {} AND authorization_profile_id = 'default'",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(client_id)
                .get_result::<ClientGrantRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_active_client_grants(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<ClientGrantWithClientRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT client_grants.user_id, client_grants.client_id, clients.client_name, client_grants.granted_scopes, client_grants.granted_at, client_grants.updated_at, client_grants.revoked_at FROM client_grants LEFT JOIN clients ON clients.client_id = client_grants.client_id WHERE client_grants.user_id = {} AND client_grants.revoked_at IS NULL ORDER BY client_grants.updated_at DESC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<ClientGrantWithClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_client_grant(
        &self,
        user_id: &str,
        client_id: &str,
        granted_scopes: String,
    ) -> AppResult<ClientGrantRecord> {
        let user_id = user_id.to_string();
        let client_id = client_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE client_grants SET granted_scopes = {}, updated_at = {}, revoked_at = {} WHERE user_id = {} AND client_id = {} AND authorization_profile_id = 'default'",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            let changed = sql_query(update_sql)
                .bind::<Text, _>(&granted_scopes)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&client_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO client_grants (user_id, client_id, authorization_profile_id, granted_scopes, granted_at, updated_at, revoked_at) VALUES ({}, {}, 'default', {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&client_id)
                    .bind::<Text, _>(&granted_scopes)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!(
                "SELECT user_id, client_id, granted_scopes, granted_at, updated_at, revoked_at FROM client_grants WHERE user_id = {} AND client_id = {} AND authorization_profile_id = 'default'",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(client_id)
                .get_result::<ClientGrantRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn revoke_client_grant(&self, user_id: &str, client_id: &str) -> AppResult<bool> {
        let user_id = user_id.to_string();
        let client_id = client_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE client_grants SET revoked_at = {}, updated_at = {} WHERE user_id = {} AND client_id = {} AND authorization_profile_id = 'default' AND revoked_at IS NULL",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(client_id)
                .execute(&mut conn)
                .map(|changed| changed > 0)
                .map_err(AppError::from)
        })
    }
}
