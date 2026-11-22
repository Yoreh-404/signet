use super::{
    AppError, AppResult, ClientRegistrationRecord, DatabaseKind, Db, bind_text_list, blocking, ph,
    placeholders,
};
use crate::util;
use diesel::{
    OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Text},
};

#[derive(diesel::QueryableByName)]
pub(crate) struct RegisteredPeer {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub redirect_uris: String,
}

impl Db {
    pub(crate) async fn registered_peers(&self, ids: &[String]) -> AppResult<Vec<RegisteredPeer>> {
        let ids = ids.to_vec();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT c.id, c.client_id, c.redirect_uris FROM clients c
                 JOIN client_registrations r ON r.client_db_id = c.id
                 WHERE c.is_active = 1 AND c.client_id IN ({})",
                placeholders(kind, 1, ids.len()),
            );
            bind_text_list(&mut conn, sql_query(sql), &ids)
                .load::<RegisteredPeer>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_client_registration(
        &self,
        client_db_id: &str,
        registration_access_token_hash: String,
    ) -> AppResult<ClientRegistrationRecord> {
        let client_db_id = client_db_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE client_registrations SET registration_access_token_hash = {}, updated_at = {} WHERE client_db_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            let changed = sql_query(update_sql)
                .bind::<Text, _>(&registration_access_token_hash)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&client_db_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO client_registrations (client_db_id, registration_access_token_hash, created_at, updated_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&client_db_id)
                    .bind::<Text, _>(&registration_access_token_hash)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!(
                "SELECT client_db_id, registration_access_token_hash, created_at, updated_at FROM client_registrations WHERE client_db_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .get_result::<ClientRegistrationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_client_registration(
        &self,
        client_db_id: &str,
    ) -> AppResult<Option<ClientRegistrationRecord>> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT client_db_id, registration_access_token_hash, created_at, updated_at FROM client_registrations WHERE client_db_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .get_result::<ClientRegistrationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }
}
