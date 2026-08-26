use super::*;

use super::{
    AccountLoginFlowRecord, AppError, AppResult, AuthorizationCodeType,
    BrowserContextAccountOption, BrowserContextAccountOptionRow, BrowserContextAccountRecord,
    BrowserContextRecord, Db, LoginCodeLevel, SessionRecord, TrialEnrollmentRecord, UserRecord, ph,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};

impl Db {
    pub async fn insert_browser_context(
        &self,
        id: &str,
        csrf_token: &str,
        ttl_seconds: i64,
    ) -> AppResult<BrowserContextRecord> {
        let id = id.to_string();
        let csrf_token = csrf_token.to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO browser_contexts (id, csrf_token, expires_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&csrf_token)
                .bind::<BigInt, _>(expires_at)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(BrowserContextRecord {
                id,
                csrf_token,
                expires_at,
                created_at: now,
                updated_at: now,
            })
        })
    }

    pub async fn find_browser_context(&self, id: &str) -> AppResult<Option<BrowserContextRecord>> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, csrf_token, expires_at, created_at, updated_at FROM browser_contexts WHERE id = {} AND expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<BigInt, _>(now)
                .get_result::<BrowserContextRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_browser_context_accounts(
        &self,
        browser_context_id: &str,
    ) -> AppResult<Vec<BrowserContextAccountRecord>> {
        let browser_context_id = browser_context_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT browser_context_accounts.id, browser_context_accounts.browser_context_id, browser_context_accounts.user_id, browser_context_accounts.session_id, browser_context_accounts.added_at, browser_context_accounts.last_selected_at FROM browser_context_accounts INNER JOIN sessions ON sessions.id = browser_context_accounts.session_id WHERE browser_context_accounts.browser_context_id = {} AND sessions.expires_at >= {} ORDER BY sessions.created_at DESC, browser_context_accounts.added_at DESC, browser_context_accounts.id ASC",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(browser_context_id)
                .bind::<BigInt, _>(now)
                .load::<BrowserContextAccountRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Loads all chooser data in one set-based read. Expired sessions are
    /// excluded in SQL; trial and account-recovery metadata are joined once so
    /// the browser layer can apply the same lifecycle policy without an N+1
    /// query loop.
    pub async fn list_browser_context_account_options(
        &self,
        browser_context_id: &str,
    ) -> AppResult<Vec<BrowserContextAccountOption>> {
        let browser_context_id = browser_context_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT browser_context_accounts.id AS account_id, browser_context_accounts.browser_context_id AS account_browser_context_id, browser_context_accounts.user_id AS account_user_id, browser_context_accounts.session_id AS account_session_id, browser_context_accounts.added_at AS account_added_at, browser_context_accounts.last_selected_at AS account_last_selected_at, users.id AS user_id, users.email AS user_email, users.username AS user_username, users.display_name AS user_display_name, users.phone AS user_phone, '' AS user_password_hash, users.email_verified_at AS user_email_verified_at, users.phone_verified_at AS user_phone_verified_at, users.is_admin AS user_is_admin, users.is_active AS user_is_active, users.archived_at AS user_archived_at, users.registration_source AS user_registration_source, users.last_login_at AS user_last_login_at, users.last_login_ip AS user_last_login_ip, users.last_oidc_client_id AS user_last_oidc_client_id, users.last_login_method AS user_last_login_method, users.created_at AS user_created_at, users.updated_at AS user_updated_at, sessions.id AS session_id, sessions.user_id AS session_user_id, sessions.csrf_token AS session_csrf_token, sessions.ip_address AS session_ip_address, sessions.user_agent AS session_user_agent, sessions.login_method AS session_login_method, sessions.expires_at AS session_expires_at, sessions.created_at AS session_created_at, trial_enrollments.user_id AS trial_user_id, trial_enrollments.invitation_id AS trial_invitation_id, trial_enrollments.organization_id AS trial_organization_id, trial_enrollments.organization_role AS trial_organization_role, trial_enrollments.allowed_client_ids AS trial_allowed_client_ids, trial_enrollments.expires_at AS trial_expires_at, trial_enrollments.revoked_at AS trial_revoked_at, trial_enrollments.created_at AS trial_created_at, CASE WHEN EXISTS (SELECT 1 FROM invitation_redemptions INNER JOIN invitations ON invitations.id = invitation_redemptions.invitation_id WHERE invitation_redemptions.user_id = users.id AND invitations.code_type = {} AND invitations.login_code_level = {}) THEN 1 ELSE 0 END AS has_authorization_code_redemption FROM browser_context_accounts INNER JOIN sessions ON sessions.id = browser_context_accounts.session_id INNER JOIN users ON users.id = browser_context_accounts.user_id LEFT JOIN trial_enrollments ON trial_enrollments.user_id = users.id WHERE browser_context_accounts.browser_context_id = {} AND sessions.expires_at >= {} ORDER BY sessions.created_at DESC, browser_context_accounts.added_at DESC, browser_context_accounts.id ASC",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
            );
            let rows = sql_query(sql)
                .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                .bind::<Text, _>(LoginCodeLevel::AccountRecovery.as_str())
                .bind::<Text, _>(browser_context_id)
                .bind::<BigInt, _>(now)
                .load::<BrowserContextAccountOptionRow>(&mut conn)
                .map_err(AppError::from)?;
            rows.into_iter()
                .map(|row| {
                    let trial_enrollment = match row.trial_user_id.clone() {
                        Some(user_id) => Some(TrialEnrollmentRecord {
                            user_id,
                            invitation_id: row.trial_invitation_id.clone().ok_or_else(|| {
                                AppError::Configuration(
                                    "trial enrollment is missing an invitation".to_string(),
                                )
                            })?,
                            organization_id: row.trial_organization_id.clone().ok_or_else(
                                || {
                                    AppError::Configuration(
                                        "trial enrollment is missing an organization".to_string(),
                                    )
                                },
                            )?,
                            organization_role: row.trial_organization_role.clone().ok_or_else(
                                || {
                                    AppError::Configuration(
                                        "trial enrollment is missing an organization role"
                                            .to_string(),
                                    )
                                },
                            )?,
                            allowed_client_ids: row.trial_allowed_client_ids.clone().ok_or_else(
                                || {
                                    AppError::Configuration(
                                        "trial enrollment is missing an allowed client list"
                                            .to_string(),
                                    )
                                },
                            )?,
                            expires_at: row.trial_expires_at,
                            revoked_at: row.trial_revoked_at,
                            created_at: row.trial_created_at.ok_or_else(|| {
                                AppError::Configuration(
                                    "trial enrollment is missing a creation time".to_string(),
                                )
                            })?,
                        }),
                        None => None,
                    };
                    Ok(BrowserContextAccountOption {
                        account: BrowserContextAccountRecord {
                            id: row.account_id,
                            browser_context_id: row.account_browser_context_id,
                            user_id: row.account_user_id,
                            session_id: row.account_session_id,
                            added_at: row.account_added_at,
                            last_selected_at: row.account_last_selected_at,
                        },
                        user: UserRecord {
                            id: row.user_id,
                            email: row.user_email,
                            username: row.user_username,
                            display_name: row.user_display_name,
                            phone: row.user_phone,
                            password_hash: row.user_password_hash,
                            email_verified_at: row.user_email_verified_at,
                            phone_verified_at: row.user_phone_verified_at,
                            is_admin: row.user_is_admin,
                            is_active: row.user_is_active,
                            archived_at: row.user_archived_at,
                            registration_source: row.user_registration_source,
                            last_login_at: row.user_last_login_at,
                            last_login_ip: row.user_last_login_ip,
                            last_oidc_client_id: row.user_last_oidc_client_id,
                            last_login_method: row.user_last_login_method,
                            created_at: row.user_created_at,
                            updated_at: row.user_updated_at,
                        },
                        session: SessionRecord {
                            id: row.session_id,
                            user_id: row.session_user_id,
                            csrf_token: row.session_csrf_token,
                            ip_address: row.session_ip_address,
                            user_agent: row.session_user_agent,
                            login_method: row.session_login_method,
                            expires_at: row.session_expires_at,
                            created_at: row.session_created_at,
                        },
                        trial_enrollment,
                        has_authorization_code_redemption: row.has_authorization_code_redemption
                            == 1,
                    })
                })
                .collect()
        })
    }

    pub async fn find_browser_context_account(
        &self,
        browser_context_id: &str,
        account_ref: &str,
    ) -> AppResult<Option<BrowserContextAccountRecord>> {
        let browser_context_id = browser_context_id.to_string();
        let account_ref = account_ref.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(browser_context_id)
                .bind::<Text, _>(account_ref)
                .get_result::<BrowserContextAccountRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_browser_context_account_by_session(
        &self,
        browser_context_id: &str,
        session_id: &str,
    ) -> AppResult<Option<BrowserContextAccountRecord>> {
        let browser_context_id = browser_context_id.to_string();
        let session_id = session_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND session_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(browser_context_id)
                .bind::<Text, _>(session_id)
                .get_result::<BrowserContextAccountRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn attach_browser_context_account(
        &self,
        browser_context_id: &str,
        user_id: &str,
        session_id: &str,
    ) -> AppResult<BrowserContextAccountRecord> {
        let browser_context_id = browser_context_id.to_string();
        let user_id = user_id.to_string();
        let session_id = session_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<BrowserContextAccountRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND user_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&user_id)
                    .get_result::<BrowserContextAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;

                let remove_other_mapping_sql = format!(
                    "DELETE FROM browser_context_accounts WHERE session_id = {} AND browser_context_id <> {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(remove_other_mapping_sql)
                    .bind::<Text, _>(&session_id)
                    .bind::<Text, _>(&browser_context_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let remove_other_credentials_sql = format!(
                    "DELETE FROM session_credentials WHERE session_id = {} AND browser_context_id <> {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(remove_other_credentials_sql)
                    .bind::<Text, _>(&session_id)
                    .bind::<Text, _>(&browser_context_id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                if let Some(existing) = existing {
                    if existing.session_id != session_id {
                        let delete_credentials_sql = format!(
                            "DELETE FROM session_credentials WHERE session_id = {}",
                            ph(kind, 1)
                        );
                        sql_query(delete_credentials_sql)
                            .bind::<Text, _>(&existing.session_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                        let delete_session_sql = format!(
                            "DELETE FROM sessions WHERE id = {}",
                            ph(kind, 1)
                        );
                        sql_query(delete_session_sql)
                            .bind::<Text, _>(&existing.session_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let update_sql = format!(
                        "UPDATE browser_context_accounts SET session_id = {}, last_selected_at = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    sql_query(update_sql)
                        .bind::<Text, _>(&session_id)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&existing.id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    return Ok(BrowserContextAccountRecord {
                        session_id,
                        last_selected_at: Some(now),
                        ..existing
                    });
                }

                let id = uuid::Uuid::new_v4().to_string();
                let insert_sql = format!(
                    "INSERT INTO browser_context_accounts (id, browser_context_id, user_id, session_id, added_at, last_selected_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&session_id)
                    .bind::<BigInt, _>(now)
                    .bind::<Nullable<BigInt>, _>(Some(now))
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(BrowserContextAccountRecord {
                    id,
                    browser_context_id,
                    user_id,
                    session_id,
                    added_at: now,
                    last_selected_at: Some(now),
                })
            })
        })
    }

    pub async fn mint_browser_account_session_credential(
        &self,
        browser_context_id: &str,
        account_ref: &str,
    ) -> AppResult<(SessionRecord, String)> {
        let browser_context_id = browser_context_id.to_string();
        let account_ref = account_ref.to_string();
        let (credential_id, cookie_value) = util::new_session_credentials();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<SessionRecord, AppError, _>(|conn| {
                let account_sql = format!(
                    "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let account = sql_query(account_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&account_ref)
                    .get_result::<BrowserContextAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                let session_sql = format!(
                    "SELECT id, user_id, csrf_token, ip_address, user_agent, login_method, expires_at, created_at FROM sessions WHERE id = {} AND user_id = {} AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let session = sql_query(session_sql)
                    .bind::<Text, _>(&account.session_id)
                    .bind::<Text, _>(&account.user_id)
                    .bind::<BigInt, _>(now)
                    .get_result::<SessionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                let delete_sql = format!(
                    "DELETE FROM session_credentials WHERE browser_context_id = {} AND session_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&session.id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let insert_sql = format!(
                    "INSERT INTO session_credentials (credential_id, session_id, browser_context_id, expires_at, created_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(credential_id)
                    .bind::<Text, _>(&session.id)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<BigInt, _>(session.expires_at)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let update_sql = format!(
                    "UPDATE browser_context_accounts SET last_selected_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(account.id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(session)
            })
        })
        .map(|session| (session, cookie_value))
    }

    pub async fn remove_browser_context_account(
        &self,
        browser_context_id: &str,
        account_ref: &str,
    ) -> AppResult<BrowserContextAccountRecord> {
        let browser_context_id = browser_context_id.to_string();
        let account_ref = account_ref.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<BrowserContextAccountRecord, AppError, _>(|conn| {
                let select_sql = format!(
                    "SELECT id, browser_context_id, user_id, session_id, added_at, last_selected_at FROM browser_context_accounts WHERE browser_context_id = {} AND id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let account = sql_query(select_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&account_ref)
                    .get_result::<BrowserContextAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                for (table, column) in [
                    ("session_credentials", "session_id"),
                    ("browser_context_accounts", "session_id"),
                ] {
                    let sql = format!("DELETE FROM {table} WHERE {column} = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&account.session_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let delete_session_sql =
                    format!("DELETE FROM sessions WHERE id = {}", ph(kind, 1));
                sql_query(delete_session_sql)
                    .bind::<Text, _>(&account.session_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(account)
            })
        })
    }

    pub async fn delete_browser_context(&self, browser_context_id: &str) -> AppResult<()> {
        let browser_context_id = browser_context_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let delete_credentials_sql = format!(
                    "DELETE FROM session_credentials WHERE browser_context_id = {} OR session_id IN (SELECT session_id FROM browser_context_accounts WHERE browser_context_id = {})",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(delete_credentials_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<Text, _>(&browser_context_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let delete_sessions_sql = format!(
                    "DELETE FROM sessions WHERE id IN (SELECT session_id FROM browser_context_accounts WHERE browser_context_id = {})",
                    ph(kind, 1)
                );
                sql_query(delete_sessions_sql)
                    .bind::<Text, _>(&browser_context_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for table in ["browser_context_accounts", "account_login_flows"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE browser_context_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&browser_context_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let delete_context_sql =
                    format!("DELETE FROM browser_contexts WHERE id = {}", ph(kind, 1));
                sql_query(delete_context_sql)
                    .bind::<Text, _>(browser_context_id)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_account_login_flow(
        &self,
        id_hash: &str,
        browser_context_id: &str,
        return_to: &str,
        expected_user_id: Option<&str>,
        ttl_seconds: i64,
    ) -> AppResult<AccountLoginFlowRecord> {
        let id_hash = id_hash.to_string();
        let browser_context_id = browser_context_id.to_string();
        let return_to = return_to.to_string();
        let expected_user_id = expected_user_id.map(ToOwned::to_owned);
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM account_login_flows WHERE expires_at < {} OR consumed_at IS NOT NULL",
                ph(kind, 1)
            );
            sql_query(cleanup_sql)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let insert_sql = format!(
                "INSERT INTO account_login_flows (id_hash, browser_context_id, return_to, expected_user_id, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(&id_hash)
                .bind::<Text, _>(&browser_context_id)
                .bind::<Text, _>(&return_to)
                .bind::<Nullable<Text>, _>(expected_user_id.as_deref())
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(AccountLoginFlowRecord {
                id_hash,
                browser_context_id,
                return_to,
                expected_user_id,
                expires_at,
                consumed_at: None,
                created_at: now,
            })
        })
    }

    pub async fn consume_account_login_flow(
        &self,
        id_hash: &str,
        browser_context_id: &str,
        authenticated_user_id: &str,
    ) -> AppResult<AccountLoginFlowRecord> {
        let id_hash = id_hash.to_string();
        let browser_context_id = browser_context_id.to_string();
        let authenticated_user_id = authenticated_user_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<AccountLoginFlowRecord, AppError, _>(|conn| {
                let select_sql = format!(
                    "SELECT id_hash, browser_context_id, return_to, expected_user_id, expires_at, consumed_at, created_at FROM account_login_flows WHERE id_hash = {} AND browser_context_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let flow = sql_query(select_sql)
                    .bind::<Text, _>(&id_hash)
                    .bind::<Text, _>(&browser_context_id)
                    .get_result::<AccountLoginFlowRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if flow.consumed_at.is_some() || flow.expires_at < now {
                    return Err(AppError::Unauthorized);
                }
                if flow
                    .expected_user_id
                    .as_deref()
                    .is_some_and(|expected| expected != authenticated_user_id)
                {
                    return Err(AppError::Unauthorized);
                }
                let update_sql = format!(
                    "UPDATE account_login_flows SET consumed_at = {} WHERE id_hash = {} AND browser_context_id = {} AND consumed_at IS NULL AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id_hash)
                    .bind::<Text, _>(&browser_context_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                Ok(AccountLoginFlowRecord {
                    consumed_at: Some(now),
                    ..flow
                })
            })
        })
    }
}
