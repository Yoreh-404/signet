use super::{AppError, AppResult, DatabaseKind, Db, blocking, ph};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct PushedAuthorizationRequestRecord {
    #[diesel(sql_type = Text)]
    pub request_uri_hash: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub request_json: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewPushedAuthorizationRequest {
    pub request_uri_hash: String,
    pub client_id: String,
    pub request_json: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct DeviceAuthorizationRecord {
    #[diesel(sql_type = Text)]
    pub device_code_hash: String,
    #[diesel(sql_type = Text)]
    pub user_code_hash: String,
    #[diesel(sql_type = Text)]
    pub user_code_display: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub scope: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub resource: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorization_details: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Integer)]
    pub interval_seconds: i32,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorized_user_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub authorized_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub denied_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub last_poll_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewDeviceAuthorization {
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub user_code_display: String,
    pub client_id: String,
    pub scope: String,
    pub resource: Option<String>,
    pub authorization_details: Option<String>,
    pub expires_at: i64,
    pub interval_seconds: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthorizationStatus {
    Pending,
    Authorized,
    Denied,
    Consumed,
    Expired,
    SlowDown,
}

#[derive(Debug, Clone)]
pub struct DeviceAuthorizationTransition {
    pub status: DeviceAuthorizationStatus,
    pub changed: bool,
    pub record: DeviceAuthorizationRecord,
}

impl Db {
    pub async fn insert_pushed_authorization_request(
        &self,
        request: NewPushedAuthorizationRequest,
    ) -> AppResult<PushedAuthorizationRequestRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO pushed_authorization_requests (request_uri_hash, client_id, request_json, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            sql_query(sql)
                .bind::<Text, _>(&request.request_uri_hash)
                .bind::<Text, _>(request.client_id)
                .bind::<Text, _>(request.request_json)
                .bind::<BigInt, _>(request.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE request_uri_hash = {}",
                select_pushed_authorization_request_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(request.request_uri_hash)
                .get_result::<PushedAuthorizationRequestRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_pushed_authorization_request(
        &self,
        request_uri_hash: &str,
    ) -> AppResult<Option<PushedAuthorizationRequestRecord>> {
        let request_uri_hash = request_uri_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE request_uri_hash = {}",
                select_pushed_authorization_request_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&request_uri_hash)
                .get_result::<PushedAuthorizationRequestRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn update_unconsumed_pushed_authorization_request(
        &self,
        request_uri_hash: &str,
        client_id: &str,
        expected_request_json: &str,
        request_json: &str,
    ) -> AppResult<PushedAuthorizationRequestRecord> {
        let request_uri_hash = request_uri_hash.to_string();
        let client_id = client_id.to_string();
        let expected_request_json = expected_request_json.to_string();
        let request_json = request_json.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PushedAuthorizationRequestRecord, AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE pushed_authorization_requests SET request_json = {} WHERE request_uri_hash = {} AND client_id = {} AND request_json = {} AND consumed_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                let affected = sql_query(update_sql)
                    .bind::<Text, _>(&request_json)
                    .bind::<Text, _>(&request_uri_hash)
                    .bind::<Text, _>(&client_id)
                    .bind::<Text, _>(&expected_request_json)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                let select_sql = format!(
                    "{} WHERE request_uri_hash = {}",
                    select_pushed_authorization_request_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(request_uri_hash)
                    .get_result::<PushedAuthorizationRequestRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn consume_pushed_authorization_request(
        &self,
        request_uri_hash: &str,
    ) -> AppResult<PushedAuthorizationRequestRecord> {
        let request_uri_hash = request_uri_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PushedAuthorizationRequestRecord, AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE pushed_authorization_requests SET consumed_at = {} WHERE request_uri_hash = {} AND consumed_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&request_uri_hash)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Oidc(
                        "request_uri is invalid, expired, or already consumed".to_string(),
                    ));
                }
                let select_sql = format!(
                    "{} WHERE request_uri_hash = {}",
                    select_pushed_authorization_request_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(request_uri_hash)
                    .get_result::<PushedAuthorizationRequestRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_device_authorization(
        &self,
        authorization: NewDeviceAuthorization,
    ) -> AppResult<DeviceAuthorizationRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO device_authorizations (device_code_hash, user_code_hash, user_code_display, client_id, scope, resource, authorization_details, expires_at, interval_seconds, authorized_user_id, authorized_at, denied_at, consumed_at, last_poll_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 15)
            );
            sql_query(sql)
                .bind::<Text, _>(&authorization.device_code_hash)
                .bind::<Text, _>(authorization.user_code_hash)
                .bind::<Text, _>(authorization.user_code_display)
                .bind::<Text, _>(authorization.client_id)
                .bind::<Text, _>(authorization.scope)
                .bind::<Nullable<Text>, _>(authorization.resource)
                .bind::<Nullable<Text>, _>(authorization.authorization_details)
                .bind::<BigInt, _>(authorization.expires_at)
                .bind::<Integer, _>(authorization.interval_seconds)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!(
                "{} WHERE device_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(authorization.device_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_device_authorization_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> AppResult<Option<DeviceAuthorizationRecord>> {
        let device_code_hash = device_code_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE device_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(device_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_device_authorization_by_user_code_hash(
        &self,
        user_code_hash: &str,
    ) -> AppResult<Option<DeviceAuthorizationRecord>> {
        let user_code_hash = user_code_hash.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE user_code_hash = {}",
                select_device_authorization_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_code_hash)
                .get_result::<DeviceAuthorizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    /// Atomically records a device-code poll.  The interval check belongs in
    /// the UPDATE predicate so concurrent token requests cannot both pass the
    /// same polling window.
    pub async fn poll_device_authorization(
        &self,
        device_code_hash: &str,
        polled_at: i64,
    ) -> AppResult<DeviceAuthorizationTransition> {
        let device_code_hash = device_code_hash.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<DeviceAuthorizationTransition, AppError, _>(|conn| {
                let select_sql = format!(
                    "{} WHERE device_code_hash = {}",
                    select_device_authorization_sql(),
                    ph(kind, 1)
                );
                let record = sql_query(select_sql)
                    .bind::<Text, _>(&device_code_hash)
                    .get_result::<DeviceAuthorizationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                let status = device_authorization_status(&record, polled_at);
                if status != DeviceAuthorizationStatus::Pending {
                    return Ok(DeviceAuthorizationTransition {
                        status,
                        changed: false,
                        record,
                    });
                }

                let update_sql = format!(
                    "UPDATE device_authorizations SET last_poll_at = {} WHERE device_code_hash = {} AND authorized_user_id IS NULL AND denied_at IS NULL AND consumed_at IS NULL AND expires_at > {} AND (last_poll_at IS NULL OR last_poll_at + interval_seconds <= {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(polled_at)
                    .bind::<Text, _>(&device_code_hash)
                    .bind::<BigInt, _>(polled_at)
                    .bind::<BigInt, _>(polled_at)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let select_sql = format!(
                    "{} WHERE device_code_hash = {}",
                    select_device_authorization_sql(),
                    ph(kind, 1)
                );
                let record = sql_query(select_sql)
                    .bind::<Text, _>(&device_code_hash)
                    .get_result::<DeviceAuthorizationRecord>(conn)
                    .map_err(AppError::from)?;
                let status = device_authorization_status(&record, polled_at);
                Ok(DeviceAuthorizationTransition {
                    status: if affected == 1 {
                        status
                    } else if status == DeviceAuthorizationStatus::Pending {
                        DeviceAuthorizationStatus::SlowDown
                    } else {
                        status
                    },
                    changed: affected == 1,
                    record,
                })
            })
        })
    }

    pub async fn authorize_device_authorization(
        &self,
        user_code_hash: &str,
        user_id: &str,
    ) -> AppResult<DeviceAuthorizationTransition> {
        let user_code_hash = user_code_hash.to_string();
        let user_id = user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<DeviceAuthorizationTransition, AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE device_authorizations SET authorized_user_id = {}, authorized_at = {} WHERE user_code_hash = {} AND authorized_user_id IS NULL AND denied_at IS NULL AND consumed_at IS NULL AND expires_at > {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let affected = sql_query(update_sql)
                    .bind::<Text, _>(user_id)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&user_code_hash)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!(
                    "{} WHERE user_code_hash = {}",
                    select_device_authorization_sql(),
                    ph(kind, 1)
                );
                let record = sql_query(select_sql)
                    .bind::<Text, _>(user_code_hash)
                    .get_result::<DeviceAuthorizationRecord>(conn)
                    .map_err(AppError::from)?;
                Ok(DeviceAuthorizationTransition {
                    status: device_authorization_status(&record, now),
                    changed: affected == 1,
                    record,
                })
            })
        })
    }

    pub async fn deny_device_authorization(
        &self,
        user_code_hash: &str,
    ) -> AppResult<DeviceAuthorizationTransition> {
        let user_code_hash = user_code_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<DeviceAuthorizationTransition, AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE device_authorizations SET denied_at = {} WHERE user_code_hash = {} AND authorized_user_id IS NULL AND denied_at IS NULL AND consumed_at IS NULL AND expires_at > {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&user_code_hash)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!(
                    "{} WHERE user_code_hash = {}",
                    select_device_authorization_sql(),
                    ph(kind, 1)
                );
                let record = sql_query(select_sql)
                    .bind::<Text, _>(user_code_hash)
                    .get_result::<DeviceAuthorizationRecord>(conn)
                    .map_err(AppError::from)?;
                Ok(DeviceAuthorizationTransition {
                    status: device_authorization_status(&record, now),
                    changed: affected == 1,
                    record,
                })
            })
        })
    }

    pub async fn consume_device_authorization(
        &self,
        device_code_hash: &str,
    ) -> AppResult<DeviceAuthorizationTransition> {
        let device_code_hash = device_code_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<DeviceAuthorizationTransition, AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE device_authorizations SET consumed_at = {} WHERE device_code_hash = {} AND authorized_user_id IS NOT NULL AND denied_at IS NULL AND consumed_at IS NULL AND expires_at > {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&device_code_hash)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!(
                    "{} WHERE device_code_hash = {}",
                    select_device_authorization_sql(),
                    ph(kind, 1)
                );
                let record = sql_query(select_sql)
                    .bind::<Text, _>(device_code_hash)
                    .get_result::<DeviceAuthorizationRecord>(conn)
                    .map_err(AppError::from)?;
                Ok(DeviceAuthorizationTransition {
                    status: device_authorization_status(&record, now),
                    changed: affected == 1,
                    record,
                })
            })
        })
    }
}

fn select_device_authorization_sql() -> &'static str {
    "SELECT device_code_hash, user_code_hash, user_code_display, client_id, scope, resource, authorization_details, expires_at, interval_seconds, authorized_user_id, authorized_at, denied_at, consumed_at, last_poll_at, created_at FROM device_authorizations"
}

fn device_authorization_status(
    record: &DeviceAuthorizationRecord,
    now: i64,
) -> DeviceAuthorizationStatus {
    if record.expires_at <= now {
        DeviceAuthorizationStatus::Expired
    } else if record.consumed_at.is_some() {
        DeviceAuthorizationStatus::Consumed
    } else if record.denied_at.is_some() {
        DeviceAuthorizationStatus::Denied
    } else if record.authorized_user_id.is_some() {
        DeviceAuthorizationStatus::Authorized
    } else {
        DeviceAuthorizationStatus::Pending
    }
}

fn select_pushed_authorization_request_sql() -> &'static str {
    "SELECT request_uri_hash, client_id, request_json, expires_at, consumed_at, created_at FROM pushed_authorization_requests"
}
