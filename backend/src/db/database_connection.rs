//! Database connection construction and health checks.

use super::{
    AppError, AppResult, DatabaseKind, Db, Settings, blocking, connect_mysql, connect_postgres,
    connect_sqlite,
};
use diesel::connection::SimpleConnection;
use std::time::Duration;
use tracing::warn;

impl Db {
    pub fn connect(settings: &Settings) -> AppResult<Self> {
        match settings.database.kind {
            DatabaseKind::Sqlite => connect_sqlite(&settings.database),
            DatabaseKind::Postgres => connect_postgres(&settings.database),
            DatabaseKind::Mysql => connect_mysql(&settings.database),
        }
    }

    pub async fn connect_with_retry(settings: &Settings) -> AppResult<Self> {
        let mut retry_delay = Duration::from_secs(1);
        loop {
            match Self::connect(settings) {
                Ok(db) => match db.ping().await {
                    Ok(()) => return Ok(db),
                    Err(error) => {
                        warn!(
                            error = %error,
                            retry_in_seconds = retry_delay.as_secs(),
                            "Signet database is unavailable; retrying"
                        );
                    }
                },
                Err(error @ AppError::Configuration(_)) => return Err(error),
                Err(error) => {
                    warn!(
                        error = %error,
                        retry_in_seconds = retry_delay.as_secs(),
                        "Signet database pool could not be created; retrying"
                    );
                }
            }
            tokio::time::sleep(retry_delay).await;
            retry_delay = std::cmp::min(retry_delay + retry_delay, Duration::from_secs(30));
        }
    }

    pub async fn ping(&self) -> AppResult<()> {
        with_conn!(self, |conn, _kind| {
            conn.batch_execute("SELECT 1")
                .map_err(|err| AppError::Database(err.to_string()))
        })
    }
}
