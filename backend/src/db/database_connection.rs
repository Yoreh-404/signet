//! Database connection construction and health checks.

#[cfg(feature = "mysql")]
use super::MysqlConnection;
#[cfg(feature = "postgres")]
use super::PgConnection;
use super::{AppError, AppResult, DatabaseKind, DatabaseSettings, Db, Settings, blocking};
#[cfg(feature = "sqlite")]
use super::{SqliteConnection, SqliteConnectionCustomizer};
use diesel::{
    connection::SimpleConnection,
    r2d2::{ConnectionManager, Pool},
};
use std::time::Duration;
use tracing::warn;

#[cfg(feature = "sqlite")]
pub(super) fn connect_sqlite(settings: &DatabaseSettings) -> AppResult<Db> {
    if let Some(parent) = std::path::Path::new(&settings.url).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| AppError::Database(format!("failed to create sqlite dir: {err}")))?;
    }
    let manager = ConnectionManager::<SqliteConnection>::new(settings.url.clone());
    let pool = Pool::builder()
        .max_size(settings.pool_size)
        .connection_customizer(Box::new(SqliteConnectionCustomizer))
        .build(manager)
        .map_err(|err| AppError::Database(err.to_string()))?;
    Ok(Db::Sqlite(pool))
}

#[cfg(not(feature = "sqlite"))]
pub(super) fn connect_sqlite(_settings: &DatabaseSettings) -> AppResult<Db> {
    Err(AppError::Configuration(
        "database.kind=sqlite requires cargo feature `sqlite`".to_string(),
    ))
}

#[cfg(feature = "postgres")]
pub(super) fn connect_postgres(settings: &DatabaseSettings) -> AppResult<Db> {
    let manager = ConnectionManager::<PgConnection>::new(settings.url.clone());
    let pool = Pool::builder()
        .max_size(settings.pool_size)
        .build(manager)
        .map_err(|err| AppError::Database(err.to_string()))?;
    Ok(Db::Postgres(pool))
}

#[cfg(not(feature = "postgres"))]
pub(super) fn connect_postgres(_settings: &DatabaseSettings) -> AppResult<Db> {
    Err(AppError::Configuration(
        "database.kind=postgres requires cargo feature `postgres`".to_string(),
    ))
}

#[cfg(feature = "mysql")]
pub(super) fn connect_mysql(settings: &DatabaseSettings) -> AppResult<Db> {
    let manager = ConnectionManager::<MysqlConnection>::new(settings.url.clone());
    let pool = Pool::builder()
        .max_size(settings.pool_size)
        .build(manager)
        .map_err(|err| AppError::Database(err.to_string()))?;
    Ok(Db::Mysql(pool))
}

#[cfg(not(feature = "mysql"))]
pub(super) fn connect_mysql(_settings: &DatabaseSettings) -> AppResult<Db> {
    Err(AppError::Configuration(
        "database.kind=mysql requires cargo feature `mysql`".to_string(),
    ))
}

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
