use super::{
    AppError, AppResult, AuthorizationCodeRecord, DatabaseKind, Db, NewAuthorizationCode,
    OidcLoginGrantRecord, blocking, ph, select_oidc_login_grant_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};

impl Db {
    pub async fn find_oidc_login_grant(
        &self,
        credential_hash: &str,
        interaction_request_hash: &str,
    ) -> AppResult<Option<OidcLoginGrantRecord>> {
        let credential_hash = credential_hash.to_string();
        let interaction_request_hash = interaction_request_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE credential_hash = {} AND interaction_request_hash = {} AND consumed_at IS NULL AND expires_at >= {}",
                select_oidc_login_grant_sql(),
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(credential_hash)
                .bind::<Text, _>(interaction_request_hash)
                .bind::<BigInt, _>(now)
                .get_result::<OidcLoginGrantRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn consume_oidc_login_grant_and_insert_authorization_code(
        &self,
        credential_hash: &str,
        interaction_request_hash: &str,
        code: NewAuthorizationCode,
    ) -> AppResult<()> {
        if code.session_id.is_some() {
            return Err(AppError::Configuration(
                "OIDC login grant authorization code cannot have a session id".to_string(),
            ));
        }
        let credential_hash = credential_hash.to_string();
        let interaction_request_hash = interaction_request_hash.to_string();
        let expected_client_id = code.client_id.clone();
        let expected_user_id = code.user_id.clone();
        let amr = util::to_json(&code.amr)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE oidc_login_grants SET consumed_at = {} WHERE credential_hash = {} AND interaction_request_hash = {} AND client_id = {} AND user_id = {} AND consumed_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&credential_hash)
                    .bind::<Text, _>(&interaction_request_hash)
                    .bind::<Text, _>(&expected_client_id)
                    .bind::<Text, _>(&expected_user_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                let sql = format!(
                    "INSERT INTO authorization_codes (code, client_id, user_id, application_id, authorization_profile_id, auth_context_id, session_id, redirect_uri, scope, resource, authorization_details, nonce, code_challenge, code_challenge_method, auth_time, acr, amr, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5),
                    ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10),
                    ph(kind, 11), ph(kind, 12), ph(kind, 13), ph(kind, 14), ph(kind, 15),
                    ph(kind, 16), ph(kind, 17), ph(kind, 18), ph(kind, 19), ph(kind, 20)
                );
                sql_query(sql)
                    .bind::<Text, _>(code.code)
                    .bind::<Text, _>(code.client_id)
                    .bind::<Text, _>(code.user_id)
                    .bind::<Nullable<Text>, _>(code.application_id)
                    .bind::<Nullable<Text>, _>(code.authorization_profile_id)
                    .bind::<Nullable<Text>, _>(code.auth_context_id)
                    .bind::<Nullable<Text>, _>(code.session_id)
                    .bind::<Text, _>(code.redirect_uri)
                    .bind::<Text, _>(code.scope)
                    .bind::<Nullable<Text>, _>(code.resource)
                    .bind::<Nullable<Text>, _>(code.authorization_details)
                    .bind::<Nullable<Text>, _>(code.nonce)
                    .bind::<Nullable<Text>, _>(code.code_challenge)
                    .bind::<Nullable<Text>, _>(code.code_challenge_method)
                    .bind::<BigInt, _>(code.auth_time)
                    .bind::<Text, _>(code.acr)
                    .bind::<Text, _>(amr)
                    .bind::<BigInt, _>(code.expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_authorization_code(&self, code: NewAuthorizationCode) -> AppResult<()> {
        let now = util::now_ts();
        let amr = util::to_json(&code.amr)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO authorization_codes (code, client_id, user_id, application_id, authorization_profile_id, auth_context_id, session_id, redirect_uri, scope, resource, authorization_details, nonce, code_challenge, code_challenge_method, auth_time, acr, amr, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 20)
            );
            sql_query(sql)
                .bind::<Text, _>(code.code)
                .bind::<Text, _>(code.client_id)
                .bind::<Text, _>(code.user_id)
                .bind::<Nullable<Text>, _>(code.application_id)
                .bind::<Nullable<Text>, _>(code.authorization_profile_id)
                .bind::<Nullable<Text>, _>(code.auth_context_id)
                .bind::<Nullable<Text>, _>(code.session_id)
                .bind::<Text, _>(code.redirect_uri)
                .bind::<Text, _>(code.scope)
                .bind::<Nullable<Text>, _>(code.resource)
                .bind::<Nullable<Text>, _>(code.authorization_details)
                .bind::<Nullable<Text>, _>(code.nonce)
                .bind::<Nullable<Text>, _>(code.code_challenge)
                .bind::<Nullable<Text>, _>(code.code_challenge_method)
                .bind::<BigInt, _>(code.auth_time)
                .bind::<Text, _>(code.acr)
                .bind::<Text, _>(amr)
                .bind::<BigInt, _>(code.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn consume_authorization_code(
        &self,
        code: &str,
    ) -> AppResult<AuthorizationCodeRecord> {
        let code = code.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let select_sql = format!(
                "SELECT code, client_id, user_id, application_id, authorization_profile_id, auth_context_id, session_id, redirect_uri, scope, resource, authorization_details, nonce, code_challenge, code_challenge_method, COALESCE(auth_time, created_at) AS auth_time, COALESCE(acr, '') AS acr, COALESCE(amr, '[]') AS amr, expires_at, consumed_at, created_at FROM authorization_codes WHERE code = {}",
                ph(kind, 1)
            );
            let record = sql_query(select_sql)
                .bind::<Text, _>(&code)
                .get_result::<AuthorizationCodeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or_else(|| AppError::Oidc("invalid authorization code".to_string()))?;
            if record.expires_at < now {
                return Err(AppError::Oidc("authorization code expired".to_string()));
            }
            if record.consumed_at.is_some() {
                return Err(AppError::Oidc(
                    "authorization code already consumed".to_string(),
                ));
            }
            let update_sql = format!(
                "UPDATE authorization_codes SET consumed_at = {} WHERE code = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(update_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(code)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(record)
        })
    }

    /// Atomically validates the OAuth authorization-code binding and consumes
    /// the code in the same transaction. A token endpoint must not consume a
    /// code merely because an attacker supplied the right opaque value with a
    /// wrong client, redirect URI, or PKCE verifier: doing so would turn a
    /// failed exchange into a denial-of-service against the legitimate client.
    pub async fn consume_authorization_code_for_client(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
        require_pkce: bool,
        require_s256_pkce: bool,
    ) -> AppResult<AuthorizationCodeRecord> {
        let code = code.to_string();
        let client_id = client_id.to_string();
        let redirect_uri = redirect_uri.map(ToOwned::to_owned);
        let code_verifier = code_verifier.map(ToOwned::to_owned);
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<AuthorizationCodeRecord, AppError, _>(|conn| {
                let select_sql = format!(
                    "SELECT code, client_id, user_id, application_id, authorization_profile_id, auth_context_id, session_id, redirect_uri, scope, resource, authorization_details, nonce, code_challenge, code_challenge_method, COALESCE(auth_time, created_at) AS auth_time, COALESCE(acr, '') AS acr, COALESCE(amr, '[]') AS amr, expires_at, consumed_at, created_at FROM authorization_codes WHERE code = {}",
                    ph(kind, 1)
                );
                let record = sql_query(select_sql)
                    .bind::<Text, _>(&code)
                    .get_result::<AuthorizationCodeRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or_else(|| AppError::Oidc("invalid authorization code".to_string()))?;
                if record.expires_at < now {
                    return Err(AppError::Oidc("authorization code expired".to_string()));
                }
                if record.consumed_at.is_some() {
                    return Err(AppError::Oidc(
                        "authorization code already consumed".to_string(),
                    ));
                }
                if record.client_id != client_id {
                    return Err(AppError::Oidc(
                        "authorization code was issued to a different client".to_string(),
                    ));
                }
                if redirect_uri
                    .as_deref()
                    .is_some_and(|uri| uri != record.redirect_uri)
                {
                    return Err(AppError::Oidc("redirect_uri mismatch".to_string()));
                }
                util::check_pkce(
                    record.code_challenge.as_deref(),
                    record.code_challenge_method.as_deref(),
                    code_verifier.as_deref(),
                    require_pkce,
                    require_s256_pkce,
                )?;
                let update_sql = format!(
                    "UPDATE authorization_codes SET consumed_at = {} WHERE code = {} AND consumed_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&code)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Oidc(
                        "authorization code already consumed".to_string(),
                    ));
                }
                Ok(record)
            })
        })
    }
}
