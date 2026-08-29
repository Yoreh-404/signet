use crate::{error::AppResult, util};
use diesel::sql_types::{BigInt, Integer, Text};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct SecurityPolicyRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Integer)]
    pub password_min_length: i32,
    #[diesel(sql_type = Integer)]
    pub password_require_uppercase: i32,
    #[diesel(sql_type = Integer)]
    pub password_require_lowercase: i32,
    #[diesel(sql_type = Integer)]
    pub password_require_digit: i32,
    #[diesel(sql_type = Integer)]
    pub password_require_symbol: i32,
    #[diesel(sql_type = Integer)]
    pub password_reject_user_info: i32,
    #[diesel(sql_type = Integer)]
    pub login_lockout_enabled: i32,
    #[diesel(sql_type = Integer)]
    pub max_failed_login_attempts: i32,
    #[diesel(sql_type = BigInt)]
    pub failure_window_seconds: i64,
    #[diesel(sql_type = BigInt)]
    pub lockout_seconds: i64,
    #[diesel(sql_type = Text)]
    pub trusted_ip_cidrs: String,
    #[diesel(sql_type = Integer)]
    pub require_mfa_outside_trusted_networks: i32,
    #[diesel(sql_type = Text)]
    pub allowed_ip_cidrs: String,
    #[diesel(sql_type = Text)]
    pub blocked_ip_cidrs: String,
    #[diesel(sql_type = Text)]
    pub allowed_email_domains: String,
    #[diesel(sql_type = Text)]
    pub blocked_email_domains: String,
    #[diesel(sql_type = Integer)]
    pub captcha_enabled: i32,
    #[diesel(sql_type = Integer)]
    pub captcha_after_failed_attempts: i32,
    #[diesel(sql_type = BigInt)]
    pub captcha_ttl_seconds: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewSecurityPolicy {
    pub password_min_length: i32,
    pub password_require_uppercase: bool,
    pub password_require_lowercase: bool,
    pub password_require_digit: bool,
    pub password_require_symbol: bool,
    pub password_reject_user_info: bool,
    pub login_lockout_enabled: bool,
    pub max_failed_login_attempts: i32,
    pub failure_window_seconds: i64,
    pub lockout_seconds: i64,
    pub trusted_ip_cidrs: Vec<String>,
    pub require_mfa_outside_trusted_networks: bool,
    pub allowed_ip_cidrs: Vec<String>,
    pub blocked_ip_cidrs: Vec<String>,
    pub allowed_email_domains: Vec<String>,
    pub blocked_email_domains: Vec<String>,
    pub captcha_enabled: bool,
    pub captcha_after_failed_attempts: i32,
    pub captcha_ttl_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicSecurityPolicy {
    pub id: String,
    pub password_min_length: i32,
    pub password_require_uppercase: i32,
    pub password_require_lowercase: i32,
    pub password_require_digit: i32,
    pub password_require_symbol: i32,
    pub password_reject_user_info: i32,
    pub login_lockout_enabled: i32,
    pub max_failed_login_attempts: i32,
    pub failure_window_seconds: i64,
    pub lockout_seconds: i64,
    pub trusted_ip_cidrs: Vec<String>,
    pub require_mfa_outside_trusted_networks: bool,
    pub allowed_ip_cidrs: Vec<String>,
    pub blocked_ip_cidrs: Vec<String>,
    pub allowed_email_domains: Vec<String>,
    pub blocked_email_domains: Vec<String>,
    pub captcha_enabled: bool,
    pub captcha_after_failed_attempts: i32,
    pub captcha_ttl_seconds: i64,
    pub updated_at: i64,
}

impl SecurityPolicyRecord {
    pub fn public(&self) -> AppResult<PublicSecurityPolicy> {
        Ok(PublicSecurityPolicy {
            id: self.id.clone(),
            password_min_length: self.password_min_length,
            password_require_uppercase: self.password_require_uppercase,
            password_require_lowercase: self.password_require_lowercase,
            password_require_digit: self.password_require_digit,
            password_require_symbol: self.password_require_symbol,
            password_reject_user_info: self.password_reject_user_info,
            login_lockout_enabled: self.login_lockout_enabled,
            max_failed_login_attempts: self.max_failed_login_attempts,
            failure_window_seconds: self.failure_window_seconds,
            lockout_seconds: self.lockout_seconds,
            trusted_ip_cidrs: util::from_json(&self.trusted_ip_cidrs)?,
            require_mfa_outside_trusted_networks: self.require_mfa_outside_trusted_networks == 1,
            allowed_ip_cidrs: util::from_json(&self.allowed_ip_cidrs)?,
            blocked_ip_cidrs: util::from_json(&self.blocked_ip_cidrs)?,
            allowed_email_domains: util::from_json(&self.allowed_email_domains)?,
            blocked_email_domains: util::from_json(&self.blocked_email_domains)?,
            captcha_enabled: self.captcha_enabled == 1,
            captcha_after_failed_attempts: self.captcha_after_failed_attempts,
            captcha_ttl_seconds: self.captcha_ttl_seconds,
            updated_at: self.updated_at,
        })
    }
}
