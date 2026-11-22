//! Independent Signet users with an optional primary-account management link.
//! A missing primary is an anonymous *sub-identity*, not an unauthenticated
//! session; it still has its own Signet subject and credentials/provider link.

use super::{
    CountRow, Db, NewUser, UserIdentityCandidate, UserRecord, UserRegistrationSource,
    blocking, count_user_identity_conflicts_sql, insert_user_sql, ph, select_user_sql,
};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    util,
};
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use serde::Serialize;

pub const SUB_IDENTITY_LINK_TTL_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone, Serialize, diesel::QueryableByName)]
pub struct SubIdentityRecord {
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub primary_user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub origin_application_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub created_via: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, diesel::QueryableByName)]
pub struct SubIdentityChildRecord {
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub username: String,
    #[diesel(sql_type = Text)]
    pub email: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub display_name: Option<String>,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Nullable<Text>)]
    pub origin_application_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub created_via: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

impl Db {
    /// Stored site setting. A missing row is secure-by-default (false).
    pub async fn anonymous_sub_identity_creation_setting(
        &self,
        application_id: &str,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM application_anonymous_identity_policies \
                 WHERE application_id = {} AND allow_auto_create = 1",
                ph(kind, 1)
            );
            let count = sql_query(sql)
                .bind::<Text, _>(application_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count;
            Ok(count > 0)
        })
    }

    /// The effective admission gate additionally requires an active website.
    pub async fn anonymous_sub_identity_creation_allowed(
        &self,
        application_id: &str,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM application_anonymous_identity_policies p \
                 JOIN applications a ON a.id = p.application_id \
                 WHERE p.application_id = {} AND p.allow_auto_create = 1 AND a.is_active = 1",
                ph(kind, 1)
            );
            let count = sql_query(sql)
                .bind::<Text, _>(application_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count;
            Ok(count > 0)
        })
    }

    pub async fn set_anonymous_sub_identity_creation_allowed(
        &self,
        application_id: &str,
        allowed: bool,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let exists = sql_query(format!(
                    "SELECT COUNT(*) AS count FROM applications WHERE id = {}",
                    ph(kind, 1)
                ))
                .bind::<Text, _>(&application_id)
                .get_result::<CountRow>(conn)
                .map_err(AppError::from)?
                .count > 0;
                if !exists {
                    return Err(AppError::NotFound);
                }
                sql_query(format!(
                    "DELETE FROM application_anonymous_identity_policies WHERE application_id = {}",
                    ph(kind, 1)
                ))
                .bind::<Text, _>(&application_id)
                .execute(conn)
                .map_err(AppError::from)?;
                sql_query(format!(
                    "INSERT INTO application_anonymous_identity_policies (application_id, allow_auto_create, updated_at) VALUES ({}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3)
                ))
                .bind::<Text, _>(&application_id)
                .bind::<Integer, _>(i32::from(allowed))
                .bind::<BigInt, _>(util::now_ts())
                .execute(conn)
                .map_err(AppError::from)?;
                Ok(())
            })
        })
    }

    pub async fn find_sub_identity(&self, user_id: &str) -> AppResult<Option<SubIdentityRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            sql_query(format!(
                "SELECT user_id, primary_user_id, origin_application_id, created_via, created_at, updated_at \
                 FROM sub_identities WHERE user_id = {}",
                ph(kind, 1)
            ))
            .bind::<Text, _>(user_id)
            .get_result::<SubIdentityRecord>(&mut conn)
            .optional()
            .map_err(AppError::from)
        })
    }

    pub async fn list_managed_sub_identities(
        &self,
        primary_user_id: &str,
    ) -> AppResult<Vec<SubIdentityChildRecord>> {
        let primary_user_id = primary_user_id.to_string();
        with_conn!(self, |conn, kind| {
            sql_query(format!(
                "SELECT s.user_id AS user_id, u.username AS username, u.email AS email, \
                 u.display_name AS display_name, u.is_active AS is_active, \
                 s.origin_application_id AS origin_application_id, s.created_via AS created_via, \
                 s.created_at AS created_at FROM sub_identities s \
                 JOIN users u ON u.id = s.user_id WHERE s.primary_user_id = {} \
                 ORDER BY s.created_at DESC LIMIT 200",
                ph(kind, 1)
            ))
            .bind::<Text, _>(primary_user_id)
            .load::<SubIdentityChildRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    /// A managed child is a real, distinct, non-admin Signet user. The user
    /// insertion and owner relationship are atomic, including email uniqueness.
    pub async fn create_managed_sub_identity(
        &self,
        primary_user_id: &str,
        user: NewUser,
    ) -> AppResult<UserRecord> {
        if user.is_admin || !user.is_active || user.archived_at.is_some() {
            return Err(AppError::Forbidden);
        }
        let primary_user_id = primary_user_id.to_string();
        let user_id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let candidate = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                let can_manage = sql_query(format!(
                    "SELECT COUNT(*) AS count FROM users WHERE id = {} \
                     AND is_active = 1 AND archived_at IS NULL AND \
                     NOT EXISTS (SELECT 1 FROM sub_identities WHERE user_id = {})",
                    ph(kind, 1), ph(kind, 2)
                ))
                .bind::<Text, _>(&primary_user_id)
                .bind::<Text, _>(&primary_user_id)
                .get_result::<CountRow>(conn)
                .map_err(AppError::from)?
                .count > 0;
                if !can_manage {
                    return Err(AppError::Forbidden);
                }
                ensure_user_identity_available!(
                    conn, kind, candidate, "sub-identity email or username already exists"
                )?;
                sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&user.email)
                    .bind::<Text, _>(&user.username)
                    .bind::<Nullable<Text>, _>(&user.display_name)
                    .bind::<Nullable<Text>, _>(&user.phone)
                    .bind::<Text, _>(&user.password_hash)
                    .bind::<Nullable<BigInt>, _>(&user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(&user.phone_verified_at)
                    .bind::<Integer, _>(0)
                    .bind::<Integer, _>(1)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                sql_query(format!(
                    "INSERT INTO sub_identities (user_id, primary_user_id, origin_application_id, created_via, created_at, updated_at) \
                     VALUES ({}, {}, NULL, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5)
                ))
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&primary_user_id)
                .bind::<Text, _>("manual")
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(conn)
                .map_err(AppError::from)?;
                sql_query(format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1)))
                    .bind::<Text, _>(user_id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// The anonymous sub-account itself must authenticate and request a
    /// short-lived one-time claim. A parent cannot seize an arbitrary user.
    pub async fn issue_anonymous_sub_identity_link_claim(&self, user_id: &str) -> AppResult<String> {
        let user_id = user_id.to_string();
        let code = util::random_token(32);
        let hash = util::sha256_base64url(&code);
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let eligible = sql_query(format!(
                    "SELECT COUNT(*) AS count FROM sub_identities s \
                     JOIN users u ON u.id = s.user_id WHERE s.user_id = {} \
                     AND s.primary_user_id IS NULL AND u.is_active = 1 AND u.archived_at IS NULL",
                    ph(kind, 1)
                ))
                .bind::<Text, _>(&user_id)
                .get_result::<CountRow>(conn)
                .map_err(AppError::from)?
                .count > 0;
                if !eligible {
                    return Err(AppError::Forbidden);
                }
                sql_query(format!(
                    "DELETE FROM sub_identity_link_claims WHERE user_id = {}", ph(kind, 1)
                ))
                .bind::<Text, _>(&user_id)
                .execute(conn)
                .map_err(AppError::from)?;
                sql_query(format!(
                    "INSERT INTO sub_identity_link_claims (user_id, token_hash, expires_at, created_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
                ))
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&hash)
                .bind::<BigInt, _>(now + SUB_IDENTITY_LINK_TTL_SECONDS)
                .bind::<BigInt, _>(now)
                .execute(conn)
                .map_err(AppError::from)?;
                Ok(())
            })
        })?;
        Ok(code)
    }

    pub async fn attach_claimed_sub_identity(
        &self,
        primary_user_id: &str,
        code: &str,
    ) -> AppResult<()> {
        if code.len() < 32 || code.len() > 256 {
            return Err(AppError::Unauthorized);
        }
        let hash = util::sha256_base64url(code);
        let primary_user_id = primary_user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let primary_exists = sql_query(format!(
                    "SELECT COUNT(*) AS count FROM users WHERE id = {} AND is_active = 1 \
                     AND archived_at IS NULL AND NOT EXISTS \
                     (SELECT 1 FROM sub_identities WHERE user_id = {})",
                    ph(kind, 1), ph(kind, 2)
                ))
                .bind::<Text, _>(&primary_user_id)
                .bind::<Text, _>(&primary_user_id)
                .get_result::<CountRow>(conn)
                .map_err(AppError::from)?
                .count > 0;
                if !primary_exists {
                    return Err(AppError::Forbidden);
                }
                let changed = sql_query(format!(
                    "UPDATE sub_identities SET primary_user_id = {}, updated_at = {} \
                     WHERE primary_user_id IS NULL AND user_id <> {} AND user_id IN \
                     (SELECT user_id FROM sub_identity_link_claims \
                      WHERE token_hash = {} AND expires_at >= {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5)
                ))
                .bind::<Text, _>(&primary_user_id)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&primary_user_id)
                .bind::<Text, _>(&hash)
                .bind::<BigInt, _>(now)
                .execute(conn)
                .map_err(AppError::from)?;
                if changed != 1 {
                    return Err(AppError::Unauthorized);
                }
                sql_query(format!(
                    "DELETE FROM sub_identity_link_claims WHERE token_hash = {}", ph(kind, 1)
                ))
                .bind::<Text, _>(&hash)
                .execute(conn)
                .map_err(AppError::from)?;
                Ok(())
            })
        })
    }

    pub async fn detach_managed_sub_identity(
        &self,
        primary_user_id: &str,
        child_user_id: &str,
    ) -> AppResult<()> {
        let primary_user_id = primary_user_id.to_string();
        let child_user_id = child_user_id.to_string();
        with_conn!(self, |conn, kind| {
            let changed = sql_query(format!(
                "UPDATE sub_identities SET primary_user_id = NULL, updated_at = {} \
                 WHERE user_id = {} AND primary_user_id = {}",
                ph(kind, 1), ph(kind, 2), ph(kind, 3)
            ))
            .bind::<BigInt, _>(util::now_ts())
            .bind::<Text, _>(child_user_id)
            .bind::<Text, _>(primary_user_id)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            if changed == 1 { Ok(()) } else { Err(AppError::NotFound) }
        })
    }
}
