use super::{
    AuthorizationCodeType, DatabaseKind, Db, LoginCodeLevel, UserRegistrationSource,
    authorization_code_registration_source_backfill_sql, blocking, is_ignorable_migration_error,
    migration_sql,
};
use crate::error::{AppError, AppResult};
use diesel::{RunQueryDsl, connection::SimpleConnection, sql_query, sql_types::Text};

impl Db {
    pub async fn migrate(&self) -> AppResult<()> {
        with_conn!(self, |conn, kind| {
            for statement in migration_sql(kind) {
                if let Err(err) = conn.batch_execute(statement) {
                    let message = err.to_string();
                    if !is_ignorable_migration_error(statement, &message) {
                        return Err(AppError::Database(message));
                    }
                }
            }
            Ok(())
        })?;
        self.remove_legacy_phone_uniqueness().await?;
        self.migrate_tenant_application_model().await?;
        with_conn!(self, |conn, kind| {
            sql_query(authorization_code_registration_source_backfill_sql(kind))
                .bind::<Text, _>(UserRegistrationSource::AuthorizationCode.as_str())
                .bind::<Text, _>(UserRegistrationSource::Local.as_str())
                .bind::<Text, _>(AuthorizationCodeType::Registration.as_str())
                .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(())
        })?;
        Ok(())
    }
}
