//! Type-neutral application authentication credentials.
//!
//! Identity ownership lives in `users`, `sub_identities` and external identity
//! bindings. This store holds *application integration* secrets, never a user
//! identity. A credential type and public identifier select its adapter;
//! provider-specific options are versionable JSON instead of schema columns.

use super::{AppError, AppResult, AuditEventRecord, DatabaseKind, Db, blocking, ph};
use crate::util;
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};

pub const WECHAT_MINI_TYPE: &str = "wechat_mini";

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ApplicationAuthCredentialRecord {
    #[diesel(sql_type = Text)]
    pub credential_type: String,
    #[diesel(sql_type = Text)]
    pub external_id: String,
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Text)]
    pub secret_ciphertext: String,
    #[diesel(sql_type = Text)]
    pub config_json: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(diesel::QueryableByName)]
struct LegacyWechatRow {
    #[diesel(sql_type = Text)]
    app_id: String,
    #[diesel(sql_type = Text)]
    application_id: String,
    #[diesel(sql_type = Text)]
    app_secret_ciphertext: String,
    #[diesel(sql_type = Text)]
    scopes_json: String,
    #[diesel(sql_type = Integer)]
    allow_registration: i32,
    #[diesel(sql_type = Integer)]
    is_active: i32,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

fn select_sql() -> &'static str {
    "SELECT credential_type, external_id, application_id, secret_ciphertext, config_json, is_active, created_at, updated_at FROM application_auth_credentials"
}

fn valid_credential_type(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn valid_external_id(value: &str) -> bool {
    // OpenID ClientIDs, issuer IDs, and third-party subjects do not share the
    // WeChat AppID alphabet. Treat these as opaque, bounded public strings;
    // provider adapters apply their own stricter format rules.
    !value.trim().is_empty() && value == value.trim() && value.len() <= 255
        && !value.chars().any(char::is_control)
}

impl Db {
    /// Called after creating the generic schema. Older Signet deployments
    /// receive an additive, lossless migration before the dedicated table is
    /// retired; repeated startup is harmless. The existing v1 ciphertext is
    /// decryptable only by the WeChat adapter and new writes use generic AAD.
    pub(crate) async fn migrate_legacy_wechat_application_credentials(&self) -> AppResult<()> {
        with_conn!(self, |conn, kind| {
            let was_present = conn.transaction::<bool, AppError, _>(|conn| {
                let exists_query = match kind {
                    DatabaseKind::Sqlite =>
                        "SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name='wechat_mini_application_credentials'",
                    DatabaseKind::Postgres =>
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='wechat_mini_application_credentials'",
                    DatabaseKind::Mysql =>
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='wechat_mini_application_credentials'",
                };
                let exists = sql_query(exists_query).get_result::<super::CountRow>(conn)
                    .map_err(AppError::from)?.count != 0;
                if !exists { return Ok(false); }
                let old = sql_query("SELECT app_id, application_id, app_secret_ciphertext, scopes_json, allow_registration, is_active, created_at, updated_at FROM wechat_mini_application_credentials")
                    .load::<LegacyWechatRow>(conn).map_err(AppError::from)?;
                for row in old {
                    let current = sql_query(format!(
                        "{} WHERE credential_type = {} AND external_id = {}",
                        select_sql(), ph(kind, 1), ph(kind, 2)))
                        .bind::<Text, _>(WECHAT_MINI_TYPE)
                        .bind::<Text, _>(&row.app_id)
                        .get_result::<ApplicationAuthCredentialRecord>(conn)
                        .optional().map_err(AppError::from)?;
                    if let Some(current) = current {
                        if current.application_id != row.application_id {
                            return Err(AppError::Forbidden);
                        }
                        // A newer row in the generic store wins over an old
                        // table left behind by a partially completed upgrade.
                        continue;
                    }
                    let scopes: serde_json::Value = serde_json::from_str(&row.scopes_json)
                        .map_err(|_| AppError::Database("invalid legacy Mini Program scopes".into()))?;
                    if !scopes.is_array() { return Err(AppError::Database("invalid legacy Mini Program scopes".into())); }
                    let options = util::to_json(&serde_json::json!({
                        "scopes": scopes,
                        "allow_registration": row.allow_registration == 1,
                    }))?;
                    let sql = format!(
                        "INSERT INTO application_auth_credentials (credential_type, external_id, application_id, secret_ciphertext, config_json, is_active, created_at, updated_at) VALUES ({},{},{},{},{},{},{},{})",
                        ph(kind,1),ph(kind,2),ph(kind,3),ph(kind,4),ph(kind,5),ph(kind,6),ph(kind,7),ph(kind,8));
                    sql_query(sql)
                        .bind::<Text,_>(WECHAT_MINI_TYPE)
                        .bind::<Text,_>(row.app_id)
                        .bind::<Text,_>(row.application_id)
                        .bind::<Text,_>(row.app_secret_ciphertext)
                        .bind::<Text,_>(options)
                        .bind::<Integer,_>(row.is_active)
                        .bind::<BigInt,_>(row.created_at)
                        .bind::<BigInt,_>(row.updated_at)
                        .execute(conn).map_err(AppError::from)?;
                }
                Ok(true)
            })?;
            if was_present {
                // MySQL DDL implicitly commits. Finish the copy transaction
                // *before* dropping the old table; a failed drop is safe to
                // retry and generic rows win on the next migration run.
                sql_query("DROP TABLE IF EXISTS wechat_mini_application_credentials")
                    .execute(&mut conn).map_err(AppError::from)?;
            }
            Ok(())
        })
    }

    pub async fn find_application_auth_credential(&self, credential_type: &str, external_id: &str)
        -> AppResult<Option<ApplicationAuthCredentialRecord>> {
        let credential_type = credential_type.to_owned();
        let external_id = external_id.to_owned();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE credential_type = {} AND external_id = {}",
                select_sql(), ph(kind,1), ph(kind,2));
            sql_query(sql).bind::<Text,_>(credential_type).bind::<Text,_>(external_id)
                .get_result::<ApplicationAuthCredentialRecord>(&mut conn)
                .optional().map_err(AppError::from)
        })
    }

    pub async fn list_application_auth_credentials(&self, application_id: &str, credential_type: &str)
        -> AppResult<Vec<ApplicationAuthCredentialRecord>> {
        let application_id = application_id.to_owned();
        let credential_type = credential_type.to_owned();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE application_id = {} AND credential_type = {} ORDER BY external_id ASC",
                select_sql(), ph(kind,1), ph(kind,2));
            sql_query(sql).bind::<Text,_>(application_id).bind::<Text,_>(credential_type)
                .load::<ApplicationAuthCredentialRecord>(&mut conn).map_err(AppError::from)
        })
    }

    pub async fn upsert_application_auth_credential(&self,
        application_id: &str, credential_type: &str, external_id: &str,
        encrypted_secret: Option<&str>, config_json: &str, is_active: bool,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationAuthCredentialRecord> {
        if !valid_credential_type(credential_type) || !valid_external_id(external_id)
            || config_json.len() > 32768 || !serde_json::from_str::<serde_json::Value>(config_json)
                .is_ok_and(|value| value.is_object()) {
            return Err(AppError::BadRequest("invalid application authentication credential".into()));
        }
        let application_id = application_id.to_owned();
        let credential_type = credential_type.to_owned();
        let external_id = external_id.to_owned();
        let encrypted_secret = encrypted_secret.map(str::to_owned);
        let config_json = config_json.to_owned();
        let webhook_db = self.clone();
        let (result, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationAuthCredentialRecord, AuditEventRecord), AppError, _>(|conn| {
                let lock = format!("UPDATE applications SET updated_at=updated_at WHERE id={}",ph(kind,1));
                if sql_query(lock).bind::<Text,_>(&application_id).execute(conn)
                    .map_err(AppError::from)? == 0 { return Err(AppError::NotFound); }
                let select = format!("{} WHERE credential_type={} AND external_id={}",
                    select_sql(),ph(kind,1),ph(kind,2));
                let old = sql_query(select).bind::<Text,_>(&credential_type)
                    .bind::<Text,_>(&external_id)
                    .get_result::<ApplicationAuthCredentialRecord>(conn)
                    .optional().map_err(AppError::from)?;
                let now = util::now_ts();
                if let Some(old) = old {
                    if old.application_id != application_id { return Err(AppError::Forbidden); }
                    let secret = encrypted_secret.unwrap_or(old.secret_ciphertext);
                    let sql = format!(
                        "UPDATE application_auth_credentials SET secret_ciphertext={}, config_json={}, is_active={}, updated_at={} WHERE credential_type={} AND external_id={} AND application_id={}",
                        ph(kind,1),ph(kind,2),ph(kind,3),ph(kind,4),ph(kind,5),ph(kind,6),ph(kind,7));
                    sql_query(sql).bind::<Text,_>(secret).bind::<Text,_>(&config_json)
                        .bind::<Integer,_>(i32::from(is_active)).bind::<BigInt,_>(now)
                        .bind::<Text,_>(&credential_type).bind::<Text,_>(&external_id)
                        .bind::<Text,_>(&application_id).execute(conn).map_err(AppError::from)?;
                } else {
                    let secret = encrypted_secret.ok_or_else(||
                        AppError::BadRequest("secret required for a new authentication credential".into()))?;
                    let sql = format!("SELECT COUNT(*) AS count FROM application_auth_credentials WHERE application_id={} AND credential_type={}",ph(kind,1),ph(kind,2));
                    if sql_query(sql).bind::<Text,_>(&application_id)
                        .bind::<Text,_>(&credential_type).get_result::<super::CountRow>(conn)
                        .map_err(AppError::from)?.count >= 32 {
                        return Err(AppError::BadRequest("too many authentication credentials for this type".into()));
                    }
                    let sql = format!(
                        "INSERT INTO application_auth_credentials (credential_type,external_id,application_id,secret_ciphertext,config_json,is_active,created_at,updated_at) VALUES ({},{},{},{},{},{},{},{})",
                        ph(kind,1),ph(kind,2),ph(kind,3),ph(kind,4),ph(kind,5),ph(kind,6),ph(kind,7),ph(kind,8));
                    sql_query(sql).bind::<Text,_>(&credential_type).bind::<Text,_>(&external_id)
                        .bind::<Text,_>(&application_id).bind::<Text,_>(secret)
                        .bind::<Text,_>(&config_json).bind::<Integer,_>(i32::from(is_active))
                        .bind::<BigInt,_>(now).bind::<BigInt,_>(now)
                        .execute(conn).map_err(AppError::from)?;
                }
                let sql = format!("{} WHERE credential_type={} AND external_id={}",
                    select_sql(),ph(kind,1),ph(kind,2));
                let row = sql_query(sql).bind::<Text,_>(&credential_type)
                    .bind::<Text,_>(&external_id).get_result::<ApplicationAuthCredentialRecord>(conn)
                    .map_err(AppError::from)?;
                let audit = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((row,audit))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db,audit_event);
        Ok(result)
    }

    pub async fn delete_application_auth_credential(&self,
        application_id: &str, credential_type: &str, external_id: &str,
        event: crate::audit::AuditEvent,
    ) -> AppResult<bool> {
        let application_id=application_id.to_owned();
        let credential_type=credential_type.to_owned();
        let external_id=external_id.to_owned();
        let webhook_db=self.clone();
        let (removed,audit_event)=with_conn!(self, |conn,kind| {
            conn.transaction::<(bool,Option<AuditEventRecord>),AppError,_>(|conn| {
                let lock=format!("UPDATE applications SET updated_at=updated_at WHERE id={}",ph(kind,1));
                if sql_query(lock).bind::<Text,_>(&application_id).execute(conn)
                    .map_err(AppError::from)?==0 { return Err(AppError::NotFound); }
                let sql=format!("DELETE FROM application_auth_credentials WHERE application_id={} AND credential_type={} AND external_id={}",
                    ph(kind,1),ph(kind,2),ph(kind,3));
                let count=sql_query(sql).bind::<Text,_>(&application_id)
                    .bind::<Text,_>(&credential_type).bind::<Text,_>(&external_id)
                    .execute(conn).map_err(AppError::from)?;
                if count==0 { return Ok((false,None)); }
                let audit=insert_audit_event_on_conn!(conn,kind,event)?;
                Ok((true,Some(audit)))
            })
        })?;
        if let Some(event)=audit_event { crate::webhooks::spawn_audit_webhook_delivery(webhook_db,event); }
        Ok(removed)
    }
}
