use super::{
    AppError, AppResult, DatabaseKind, Db, FIRST_REGISTERED_USER_IS_ADMIN, LoginEventRecord,
    LoginSettingsRecord, NewLoginSettings, NewRegistrationSettings, NewRuntimeSettings,
    NewSecurityPolicy, RegistrationSettingsRecord, RuntimeSettingsRecord, SecurityPolicyRecord,
    blocking, merge_missing_quick_links, ph, select_security_policy_sql,
};
use crate::util;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{OptionalExtension, RunQueryDsl, sql_query};

impl Db {
    pub async fn registration_settings(&self) -> AppResult<RegistrationSettingsRecord> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, allow_password_registration, require_email_verification, require_phone_verification, allow_external_oidc_registration, require_invitation, first_user_direct_admin, default_user_active, updated_at FROM registration_settings WHERE id = 'default'")
                .get_result::<RegistrationSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_registration_settings(
        &self,
        settings: NewRegistrationSettings,
    ) -> AppResult<RegistrationSettingsRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE registration_settings SET allow_password_registration = {}, require_email_verification = {}, require_phone_verification = {}, allow_external_oidc_registration = {}, require_invitation = {}, first_user_direct_admin = {}, default_user_active = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9)
            );
            let changed = sql_query(update_sql)
                .bind::<Integer, _>(i32::from(settings.allow_password_registration))
                .bind::<Integer, _>(i32::from(settings.require_email_verification))
                .bind::<Integer, _>(i32::from(settings.require_phone_verification))
                .bind::<Integer, _>(i32::from(settings.allow_external_oidc_registration))
                .bind::<Integer, _>(i32::from(settings.require_invitation))
                .bind::<Integer, _>(i32::from(FIRST_REGISTERED_USER_IS_ADMIN))
                .bind::<Integer, _>(i32::from(settings.default_user_active))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>("default")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO registration_settings (id, allow_password_registration, require_email_verification, require_phone_verification, allow_external_oidc_registration, require_invitation, first_user_direct_admin, default_user_active, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Integer, _>(i32::from(settings.allow_password_registration))
                    .bind::<Integer, _>(i32::from(settings.require_email_verification))
                    .bind::<Integer, _>(i32::from(settings.require_phone_verification))
                    .bind::<Integer, _>(i32::from(settings.allow_external_oidc_registration))
                    .bind::<Integer, _>(i32::from(settings.require_invitation))
                    .bind::<Integer, _>(i32::from(FIRST_REGISTERED_USER_IS_ADMIN))
                    .bind::<Integer, _>(i32::from(settings.default_user_active))
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            sql_query("SELECT id, allow_password_registration, require_email_verification, require_phone_verification, allow_external_oidc_registration, require_invitation, first_user_direct_admin, default_user_active, updated_at FROM registration_settings WHERE id = 'default'")
                .get_result::<RegistrationSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn security_policy(&self) -> AppResult<SecurityPolicyRecord> {
        with_conn!(self, |conn, _kind| {
            sql_query(format!(
                "{} WHERE id = 'default'",
                select_security_policy_sql()
            ))
            .get_result::<SecurityPolicyRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn ensure_security_policy(
        &self,
        settings: NewSecurityPolicy,
    ) -> AppResult<SecurityPolicyRecord> {
        let trusted_ip_cidrs = util::to_json(&settings.trusted_ip_cidrs)?;
        let allowed_ip_cidrs = util::to_json(&settings.allowed_ip_cidrs)?;
        let blocked_ip_cidrs = util::to_json(&settings.blocked_ip_cidrs)?;
        let allowed_email_domains = util::to_json(&settings.allowed_email_domains)?;
        let blocked_email_domains = util::to_json(&settings.blocked_email_domains)?;
        with_conn!(self, |conn, kind| {
            let existing = sql_query(format!(
                "{} WHERE id = 'default'",
                select_security_policy_sql()
            ))
            .get_result::<SecurityPolicyRecord>(&mut conn)
            .optional()
            .map_err(AppError::from)?;
            if let Some(existing) = existing {
                Ok(existing)
            } else {
                let now = util::now_ts();
                let insert_sql = format!(
                    "INSERT INTO security_policy (id, password_min_length, password_require_uppercase, password_require_lowercase, password_require_digit, password_require_symbol, password_reject_user_info, login_lockout_enabled, max_failed_login_attempts, failure_window_seconds, lockout_seconds, trusted_ip_cidrs, require_mfa_outside_trusted_networks, allowed_ip_cidrs, blocked_ip_cidrs, allowed_email_domains, blocked_email_domains, captcha_enabled, captcha_after_failed_attempts, captcha_ttl_seconds, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 15),
                    ph(kind, 16),
                    ph(kind, 17),
                    ph(kind, 18),
                    ph(kind, 19),
                    ph(kind, 20),
                    ph(kind, 21)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Integer, _>(settings.password_min_length)
                    .bind::<Integer, _>(i32::from(settings.password_require_uppercase))
                    .bind::<Integer, _>(i32::from(settings.password_require_lowercase))
                    .bind::<Integer, _>(i32::from(settings.password_require_digit))
                    .bind::<Integer, _>(i32::from(settings.password_require_symbol))
                    .bind::<Integer, _>(i32::from(settings.password_reject_user_info))
                    .bind::<Integer, _>(i32::from(settings.login_lockout_enabled))
                    .bind::<Integer, _>(settings.max_failed_login_attempts)
                    .bind::<BigInt, _>(settings.failure_window_seconds)
                    .bind::<BigInt, _>(settings.lockout_seconds)
                    .bind::<Text, _>(trusted_ip_cidrs)
                    .bind::<Integer, _>(i32::from(settings.require_mfa_outside_trusted_networks))
                    .bind::<Text, _>(allowed_ip_cidrs)
                    .bind::<Text, _>(blocked_ip_cidrs)
                    .bind::<Text, _>(allowed_email_domains)
                    .bind::<Text, _>(blocked_email_domains)
                    .bind::<Integer, _>(i32::from(settings.captcha_enabled))
                    .bind::<Integer, _>(settings.captcha_after_failed_attempts)
                    .bind::<BigInt, _>(settings.captcha_ttl_seconds)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
                sql_query(format!(
                    "{} WHERE id = 'default'",
                    select_security_policy_sql()
                ))
                .get_result::<SecurityPolicyRecord>(&mut conn)
                .map_err(AppError::from)
            }
        })
    }

    pub async fn upsert_security_policy(
        &self,
        settings: NewSecurityPolicy,
    ) -> AppResult<SecurityPolicyRecord> {
        let now = util::now_ts();
        let trusted_ip_cidrs = util::to_json(&settings.trusted_ip_cidrs)?;
        let allowed_ip_cidrs = util::to_json(&settings.allowed_ip_cidrs)?;
        let blocked_ip_cidrs = util::to_json(&settings.blocked_ip_cidrs)?;
        let allowed_email_domains = util::to_json(&settings.allowed_email_domains)?;
        let blocked_email_domains = util::to_json(&settings.blocked_email_domains)?;
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE security_policy SET password_min_length = {}, password_require_uppercase = {}, password_require_lowercase = {}, password_require_digit = {}, password_require_symbol = {}, password_reject_user_info = {}, login_lockout_enabled = {}, max_failed_login_attempts = {}, failure_window_seconds = {}, lockout_seconds = {}, trusted_ip_cidrs = {}, require_mfa_outside_trusted_networks = {}, allowed_ip_cidrs = {}, blocked_ip_cidrs = {}, allowed_email_domains = {}, blocked_email_domains = {}, captcha_enabled = {}, captcha_after_failed_attempts = {}, captcha_ttl_seconds = {}, updated_at = {} WHERE id = {}",
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
                ph(kind, 15),
                ph(kind, 16),
                ph(kind, 17),
                ph(kind, 18),
                ph(kind, 19),
                ph(kind, 20),
                ph(kind, 21)
            );
            let changed = sql_query(update_sql)
                .bind::<Integer, _>(settings.password_min_length)
                .bind::<Integer, _>(i32::from(settings.password_require_uppercase))
                .bind::<Integer, _>(i32::from(settings.password_require_lowercase))
                .bind::<Integer, _>(i32::from(settings.password_require_digit))
                .bind::<Integer, _>(i32::from(settings.password_require_symbol))
                .bind::<Integer, _>(i32::from(settings.password_reject_user_info))
                .bind::<Integer, _>(i32::from(settings.login_lockout_enabled))
                .bind::<Integer, _>(settings.max_failed_login_attempts)
                .bind::<BigInt, _>(settings.failure_window_seconds)
                .bind::<BigInt, _>(settings.lockout_seconds)
                .bind::<Text, _>(&trusted_ip_cidrs)
                .bind::<Integer, _>(i32::from(settings.require_mfa_outside_trusted_networks))
                .bind::<Text, _>(&allowed_ip_cidrs)
                .bind::<Text, _>(&blocked_ip_cidrs)
                .bind::<Text, _>(&allowed_email_domains)
                .bind::<Text, _>(&blocked_email_domains)
                .bind::<Integer, _>(i32::from(settings.captcha_enabled))
                .bind::<Integer, _>(settings.captcha_after_failed_attempts)
                .bind::<BigInt, _>(settings.captcha_ttl_seconds)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>("default")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO security_policy (id, password_min_length, password_require_uppercase, password_require_lowercase, password_require_digit, password_require_symbol, password_reject_user_info, login_lockout_enabled, max_failed_login_attempts, failure_window_seconds, lockout_seconds, trusted_ip_cidrs, require_mfa_outside_trusted_networks, allowed_ip_cidrs, blocked_ip_cidrs, allowed_email_domains, blocked_email_domains, captcha_enabled, captcha_after_failed_attempts, captcha_ttl_seconds, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 15),
                    ph(kind, 16),
                    ph(kind, 17),
                    ph(kind, 18),
                    ph(kind, 19),
                    ph(kind, 20),
                    ph(kind, 21)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Integer, _>(settings.password_min_length)
                    .bind::<Integer, _>(i32::from(settings.password_require_uppercase))
                    .bind::<Integer, _>(i32::from(settings.password_require_lowercase))
                    .bind::<Integer, _>(i32::from(settings.password_require_digit))
                    .bind::<Integer, _>(i32::from(settings.password_require_symbol))
                    .bind::<Integer, _>(i32::from(settings.password_reject_user_info))
                    .bind::<Integer, _>(i32::from(settings.login_lockout_enabled))
                    .bind::<Integer, _>(settings.max_failed_login_attempts)
                    .bind::<BigInt, _>(settings.failure_window_seconds)
                    .bind::<BigInt, _>(settings.lockout_seconds)
                    .bind::<Text, _>(trusted_ip_cidrs)
                    .bind::<Integer, _>(i32::from(settings.require_mfa_outside_trusted_networks))
                    .bind::<Text, _>(allowed_ip_cidrs)
                    .bind::<Text, _>(blocked_ip_cidrs)
                    .bind::<Text, _>(allowed_email_domains)
                    .bind::<Text, _>(blocked_email_domains)
                    .bind::<Integer, _>(i32::from(settings.captcha_enabled))
                    .bind::<Integer, _>(settings.captcha_after_failed_attempts)
                    .bind::<BigInt, _>(settings.captcha_ttl_seconds)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            sql_query(format!(
                "{} WHERE id = 'default'",
                select_security_policy_sql()
            ))
            .get_result::<SecurityPolicyRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn runtime_settings(&self) -> AppResult<RuntimeSettingsRecord> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, public_base_url, issuer, trust_proxy_headers, updated_at FROM runtime_settings WHERE id = 'default'")
                .get_result::<RuntimeSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_runtime_settings(
        &self,
        settings: NewRuntimeSettings,
    ) -> AppResult<RuntimeSettingsRecord> {
        with_conn!(self, |conn, kind| {
            let existing = sql_query("SELECT id, public_base_url, issuer, trust_proxy_headers, updated_at FROM runtime_settings WHERE id = 'default'")
                .get_result::<RuntimeSettingsRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?;
            if let Some(existing) = existing {
                return Ok(existing);
            }
            let now = util::now_ts();
            let insert_sql = format!(
                "INSERT INTO runtime_settings (id, public_base_url, issuer, trust_proxy_headers, updated_at) VALUES ({}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(insert_sql)
                .bind::<Text, _>("default")
                .bind::<Text, _>(settings.public_base_url)
                .bind::<Text, _>(settings.issuer)
                .bind::<Integer, _>(i32::from(settings.trust_proxy_headers))
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            sql_query("SELECT id, public_base_url, issuer, trust_proxy_headers, updated_at FROM runtime_settings WHERE id = 'default'")
                .get_result::<RuntimeSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_runtime_settings(
        &self,
        settings: NewRuntimeSettings,
    ) -> AppResult<RuntimeSettingsRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE runtime_settings SET public_base_url = {}, issuer = {}, trust_proxy_headers = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            let changed = sql_query(update_sql)
                .bind::<Text, _>(&settings.public_base_url)
                .bind::<Text, _>(&settings.issuer)
                .bind::<Integer, _>(i32::from(settings.trust_proxy_headers))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>("default")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO runtime_settings (id, public_base_url, issuer, trust_proxy_headers, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Text, _>(settings.public_base_url)
                    .bind::<Text, _>(settings.issuer)
                    .bind::<Integer, _>(i32::from(settings.trust_proxy_headers))
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            sql_query("SELECT id, public_base_url, issuer, trust_proxy_headers, updated_at FROM runtime_settings WHERE id = 'default'")
                .get_result::<RuntimeSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn login_settings(&self) -> AppResult<LoginSettingsRecord> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                .get_result::<LoginSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_login_settings(
        &self,
        settings: NewLoginSettings,
    ) -> AppResult<LoginSettingsRecord> {
        let NewLoginSettings {
            brand_logo_url,
            email_domains,
            quick_links,
        } = settings;
        let email_domains = util::to_json(&email_domains)?;
        let quick_links_json = util::to_json(&quick_links)?;
        with_conn!(self, |conn, kind| {
            let existing =
                sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                    .get_result::<LoginSettingsRecord>(&mut conn)
                    .optional()
                    .map_err(AppError::from)?;
            if let Some(existing) = existing {
                if let Some(quick_links) = merge_missing_quick_links(&existing, &quick_links)? {
                    let now = util::now_ts();
                    let update_sql = format!(
                        "UPDATE login_settings SET quick_links = {}, updated_at = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    sql_query(update_sql)
                        .bind::<Text, _>(quick_links)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>("default")
                        .execute(&mut conn)
                        .map_err(AppError::from)?;
                    return sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                        .get_result::<LoginSettingsRecord>(&mut conn)
                        .map_err(AppError::from);
                }
                return Ok(existing);
            }
            let now = util::now_ts();
            let insert_sql = format!(
                "INSERT INTO login_settings (id, brand_logo_url, email_domains, quick_links, updated_at) VALUES ({}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            sql_query(insert_sql)
                .bind::<Text, _>("default")
                .bind::<Text, _>(brand_logo_url)
                .bind::<Text, _>(email_domains)
                .bind::<Text, _>(quick_links_json)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                .get_result::<LoginSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_login_settings(
        &self,
        settings: NewLoginSettings,
    ) -> AppResult<LoginSettingsRecord> {
        let now = util::now_ts();
        let NewLoginSettings {
            brand_logo_url,
            email_domains,
            quick_links,
        } = settings;
        let email_domains = util::to_json(&email_domains)?;
        let quick_links = util::to_json(&quick_links)?;
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE login_settings SET brand_logo_url = {}, email_domains = {}, quick_links = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            let changed = sql_query(update_sql)
                .bind::<Text, _>(&brand_logo_url)
                .bind::<Text, _>(&email_domains)
                .bind::<Text, _>(&quick_links)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>("default")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if changed == 0 {
                let insert_sql = format!(
                    "INSERT INTO login_settings (id, brand_logo_url, email_domains, quick_links, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>("default")
                    .bind::<Text, _>(&brand_logo_url)
                    .bind::<Text, _>(email_domains)
                    .bind::<Text, _>(quick_links)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            sql_query("SELECT id, brand_logo_url, email_domains, quick_links, updated_at FROM login_settings WHERE id = 'default'")
                .get_result::<LoginSettingsRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }
    pub async fn record_login_event(
        &self,
        user_id: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        method: &str,
        oidc_client_id: Option<String>,
        external_provider: Option<String>,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let user_id = user_id.to_string();
        let method = method.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let insert_sql = format!(
                "INSERT INTO login_events (id, user_id, login_at, ip_address, user_agent, method, oidc_client_id, external_provider) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(&user_id)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(&ip_address)
                .bind::<Nullable<Text>, _>(&user_agent)
                .bind::<Text, _>(&method)
                .bind::<Nullable<Text>, _>(&oidc_client_id)
                .bind::<Nullable<Text>, _>(&external_provider)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let update_sql = format!(
                "UPDATE users SET last_login_at = {}, last_login_ip = {}, last_oidc_client_id = {}, last_login_method = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            sql_query(update_sql)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(ip_address)
                .bind::<Nullable<Text>, _>(oidc_client_id)
                .bind::<Text, _>(method)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(user_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_login_events(
        &self,
        user_id: &str,
        limit: i64,
    ) -> AppResult<Vec<LoginEventRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, login_at, ip_address, user_agent, method, oidc_client_id, external_provider FROM login_events WHERE user_id = {} ORDER BY login_at DESC, id DESC LIMIT {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<BigInt, _>(limit)
                .load::<LoginEventRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }
}
