use super::{CountRow, Db, DirectorySyncMembershipRecord, blocking, ph};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    util,
};
use diesel::{
    RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Text},
};

impl Db {
    pub async fn upsert_directory_sync_membership(
        &self,
        application_id: &str,
        provider_id: &str,
        user_id: &str,
        managed: bool,
        last_seen_at: i64,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let provider_id = provider_id.to_string();
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let exists_sql = format!(
                "SELECT COUNT(*) AS count FROM directory_sync_memberships WHERE application_id = {} AND provider_id = {} AND user_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            let exists = sql_query(exists_sql)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&provider_id)
                .bind::<Text, _>(&user_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                > 0;
            if exists {
                let update_sql = format!(
                    "UPDATE directory_sync_memberships SET last_seen_at = {}, updated_at = {} WHERE application_id = {} AND provider_id = {} AND user_id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(update_sql)
                    .bind::<BigInt, _>(last_seen_at)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<Text, _>(&user_id)
                    .execute(&mut conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            } else {
                let insert_sql = format!(
                    "INSERT INTO directory_sync_memberships (application_id, provider_id, user_id, managed, last_seen_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Integer, _>(i32::from(managed))
                    .bind::<BigInt, _>(last_seen_at)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            }
        })
    }

    pub async fn list_directory_sync_memberships(
        &self,
        application_id: &str,
        provider_id: &str,
    ) -> AppResult<Vec<DirectorySyncMembershipRecord>> {
        let application_id = application_id.to_string();
        let provider_id = provider_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT application_id, provider_id, user_id, managed, last_seen_at, created_at, updated_at FROM directory_sync_memberships WHERE application_id = {} AND provider_id = {} ORDER BY user_id ASC",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(provider_id)
                .load::<DirectorySyncMembershipRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_directory_sync_membership(
        &self,
        application_id: &str,
        provider_id: &str,
        user_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let provider_id = provider_id.to_string();
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM directory_sync_memberships WHERE application_id = {} AND provider_id = {} AND user_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(provider_id)
                .bind::<Text, _>(user_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }
}
