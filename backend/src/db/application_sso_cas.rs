//! Persistence for application-scoped CAS tickets.

use super::{
    AppError, AppResult, ApplicationCasTicketRecord, DatabaseKind, Db, NewApplicationCasTicket,
    blocking, ph, select_application_cas_ticket_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};

impl Db {
    pub async fn insert_application_cas_ticket(
        &self,
        ticket: NewApplicationCasTicket,
    ) -> AppResult<()> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO application_cas_tickets (ticket_hash, application_id, ticket_type, service, user_id, parent_ticket_hash, pgt_iou, expires_at, consumed_at, revoked_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                .bind::<Text, _>(ticket.ticket_hash)
                .bind::<Text, _>(ticket.application_id)
                .bind::<Text, _>(ticket.ticket_type)
                .bind::<Text, _>(ticket.service)
                .bind::<Text, _>(ticket.user_id)
                .bind::<Nullable<Text>, _>(ticket.parent_ticket_hash)
                .bind::<Nullable<Text>, _>(ticket.pgt_iou)
                .bind::<BigInt, _>(ticket.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_cas_ticket(
        &self,
        ticket_hash: &str,
        application_id: &str,
        ticket_type: &str,
    ) -> AppResult<Option<ApplicationCasTicketRecord>> {
        let ticket_hash = ticket_hash.to_string();
        let application_id = application_id.to_string();
        let ticket_type = ticket_type.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE ticket_hash = {} AND application_id = {} AND ticket_type = {} AND expires_at > {} AND revoked_at IS NULL",
                select_application_cas_ticket_sql(),
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
            );
            sql_query(sql)
                .bind::<Text, _>(&ticket_hash)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&ticket_type)
                .bind::<BigInt, _>(now)
                .get_result::<ApplicationCasTicketRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    /// Atomically consumes a CAS service/proxy ticket after checking its
    /// application and exact service binding.  The accepted types are kept
    /// explicit at the caller so `serviceValidate` cannot accidentally accept
    /// a proxy-granting ticket.
    pub async fn consume_application_cas_ticket(
        &self,
        ticket_hash: &str,
        application_id: &str,
        service: &str,
        accepted_types: &[&str],
    ) -> AppResult<ApplicationCasTicketRecord> {
        let ticket_hash = ticket_hash.to_string();
        let application_id = application_id.to_string();
        let service = service.to_string();
        let accepted_types = accepted_types
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationCasTicketRecord, AppError, _>(|conn| {
                let sql = format!(
                    "{} WHERE ticket_hash = {}",
                    select_application_cas_ticket_sql(),
                    ph(kind, 1),
                );
                let record = sql_query(sql)
                    .bind::<Text, _>(&ticket_hash)
                    .get_result::<ApplicationCasTicketRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if record.application_id != application_id
                    || record.service != service
                    || record.expires_at <= now
                    || record.consumed_at.is_some()
                    || record.revoked_at.is_some()
                    || !accepted_types
                        .iter()
                        .any(|ticket_type| ticket_type == &record.ticket_type)
                {
                    return Err(AppError::Unauthorized);
                }
                let update_sql = format!(
                    "UPDATE application_cas_tickets SET consumed_at = {} WHERE ticket_hash = {} AND consumed_at IS NULL AND revoked_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2),
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&ticket_hash)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                Ok(record)
            })
        })
    }

    pub async fn revoke_application_cas_tickets_for_user(
        &self,
        application_id: &str,
        user_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_cas_tickets SET revoked_at = {} WHERE application_id = {} AND user_id = {} AND revoked_at IS NULL",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&user_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn revoke_application_cas_ticket(&self, ticket_hash: &str) -> AppResult<()> {
        let ticket_hash = ticket_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_cas_tickets SET revoked_at = {} WHERE ticket_hash = {} AND revoked_at IS NULL",
                ph(kind, 1),
                ph(kind, 2),
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&ticket_hash)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }
}
