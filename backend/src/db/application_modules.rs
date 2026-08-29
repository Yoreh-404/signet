//! Persistence for application module configuration.

use super::{
    AppError, AppResult, ApplicationModuleRecord, AuditEventRecord, CountRow, DatabaseKind, Db,
    blocking, ph, select_application_module_sql,
};
use crate::util;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};

impl Db {
    pub async fn list_application_modules(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationModuleRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} ORDER BY module_key ASC",
                select_application_module_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationModuleRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_module(
        &self,
        application_id: &str,
        module_key: &str,
    ) -> AppResult<Option<ApplicationModuleRecord>> {
        let application_id = application_id.to_string();
        let module_key = module_key.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} AND module_key = {}",
                select_application_module_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(module_key)
                .get_result::<ApplicationModuleRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_application_module(
        &self,
        application_id: &str,
        module_key: &str,
        config_json: &str,
        is_enabled: bool,
    ) -> AppResult<ApplicationModuleRecord> {
        let application_id = application_id.to_string();
        let module_key = module_key.to_string();
        let config_json = config_json.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            upsert_application_module_on_conn!(
                conn,
                kind,
                &application_id,
                &module_key,
                &config_json,
                is_enabled,
                now,
            )
        })
    }

    /// Upserts one application module and its audit record atomically.
    pub async fn upsert_application_module_with_audit(
        &self,
        application_id: &str,
        module_key: &str,
        config_json: &str,
        is_enabled: bool,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationModuleRecord> {
        let application_id = application_id.to_string();
        let module_key = module_key.to_string();
        let config_json = config_json.to_string();
        let now = util::now_ts();
        let webhook_db = self.clone();
        let (module, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationModuleRecord, AuditEventRecord), AppError, _>(|conn| {
                let module = upsert_application_module_on_conn!(
                    conn,
                    kind,
                    &application_id,
                    &module_key,
                    &config_json,
                    is_enabled,
                    now,
                )?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((module, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(module)
    }

    pub async fn delete_application_module(
        &self,
        application_id: &str,
        module_key: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let module_key = module_key.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let lock_sql = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(lock_sql)
                    .bind::<Text, _>(&application_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let sql = format!(
                    "DELETE FROM application_modules WHERE application_id = {} AND module_key = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&module_key)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }
}
