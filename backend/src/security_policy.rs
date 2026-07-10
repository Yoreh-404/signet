use crate::{
    db::{LoginFailureSummary, SecurityPolicyRecord},
    error::{AppError, AppResult},
    network_policy, util,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PasswordSubject<'a> {
    pub email: &'a str,
    pub username: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginLockState {
    pub locked: bool,
    pub locked_until: Option<i64>,
}

pub trait PasswordPolicy {
    fn validate_password(&self, password: &str, subject: PasswordSubject<'_>) -> AppResult<()>;
}

impl PasswordPolicy for SecurityPolicyRecord {
    fn validate_password(&self, password: &str, subject: PasswordSubject<'_>) -> AppResult<()> {
        let mut violations = Vec::new();
        if password.chars().count() < self.password_min_length as usize {
            violations.push(format!(
                "password must be at least {} characters",
                self.password_min_length
            ));
        }
        if self.password_require_uppercase != 0 && !password.chars().any(|ch| ch.is_uppercase()) {
            violations.push("password must include an uppercase character".to_string());
        }
        if self.password_require_lowercase != 0 && !password.chars().any(|ch| ch.is_lowercase()) {
            violations.push("password must include a lowercase character".to_string());
        }
        if self.password_require_digit != 0 && !password.chars().any(|ch| ch.is_ascii_digit()) {
            violations.push("password must include a digit".to_string());
        }
        if self.password_require_symbol != 0
            && !password
                .chars()
                .any(|ch| !ch.is_alphanumeric() && !ch.is_whitespace())
        {
            violations.push("password must include a symbol".to_string());
        }
        if self.password_reject_user_info != 0 && contains_subject_part(password, subject) {
            violations.push("password must not contain account identifiers".to_string());
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(AppError::BadRequest(violations.join("; ")))
        }
    }
}

pub trait LoginLockPolicy {
    fn lock_state(&self, summary: LoginFailureSummary, now: i64) -> LoginLockState;
}

impl LoginLockPolicy for SecurityPolicyRecord {
    fn lock_state(&self, summary: LoginFailureSummary, now: i64) -> LoginLockState {
        if self.login_lockout_enabled == 0 || summary.count < self.max_failed_login_attempts as i64
        {
            return LoginLockState {
                locked: false,
                locked_until: None,
            };
        }
        let Some(latest_at) = summary.latest_at else {
            return LoginLockState {
                locked: false,
                locked_until: None,
            };
        };
        let locked_until = latest_at + self.lockout_seconds;
        LoginLockState {
            locked: locked_until > now,
            locked_until: Some(locked_until),
        }
    }
}

pub fn normalize_login_subject(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSurface {
    Login,
    Registration,
}

#[derive(Debug, Clone, Copy)]
pub struct AccessRiskContext<'a> {
    pub surface: AccessSurface,
    pub ip_address: Option<&'a str>,
    pub subject: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkAccessRiskContext<'a> {
    pub surface: AccessSurface,
    pub ip_address: Option<&'a str>,
}

pub trait AccessRiskPolicy {
    fn evaluate_access_risk(&self, context: AccessRiskContext<'_>) -> AppResult<()>;
}

pub trait NetworkAccessRiskPolicy {
    fn evaluate_network_access_risk(&self, context: NetworkAccessRiskContext<'_>) -> AppResult<()>;
}

impl AccessRiskPolicy for SecurityPolicyRecord {
    fn evaluate_access_risk(&self, context: AccessRiskContext<'_>) -> AppResult<()> {
        evaluate_network_rules(self, context.surface, context.ip_address)?;

        let allowed_domains = email_domains_from_json(&self.allowed_email_domains)?;
        let blocked_domains = email_domains_from_json(&self.blocked_email_domains)?;
        let domain = context.subject.and_then(email_domain);
        if domain_matches_any(domain.as_deref(), &blocked_domains) {
            return Err(access_denied(context.surface, "email domain is blocked"));
        }
        if !allowed_domains.is_empty() && !domain_matches_any(domain.as_deref(), &allowed_domains) {
            return Err(access_denied(
                context.surface,
                "email domain is outside the allowlist",
            ));
        }

        Ok(())
    }
}

impl NetworkAccessRiskPolicy for SecurityPolicyRecord {
    fn evaluate_network_access_risk(&self, context: NetworkAccessRiskContext<'_>) -> AppResult<()> {
        evaluate_network_rules(self, context.surface, context.ip_address)
    }
}

fn evaluate_network_rules(
    policy: &SecurityPolicyRecord,
    surface: AccessSurface,
    ip_address: Option<&str>,
) -> AppResult<()> {
    let allowed_ips =
        network_policy::networks_from_json(&policy.allowed_ip_cidrs, "allowed IP networks")?;
    let blocked_ips =
        network_policy::networks_from_json(&policy.blocked_ip_cidrs, "blocked IP networks")?;
    if network_policy::ip_in_networks(ip_address, &blocked_ips) {
        return Err(access_denied(surface, "IP address is blocked"));
    }
    if !allowed_ips.is_empty() && !network_policy::ip_in_networks(ip_address, &allowed_ips) {
        return Err(access_denied(
            surface,
            "IP address is outside the allowlist",
        ));
    }
    Ok(())
}

pub fn assert_not_locked(
    policy: &SecurityPolicyRecord,
    summary: LoginFailureSummary,
) -> AppResult<()> {
    let state = policy.lock_state(summary, util::now_ts());
    if state.locked {
        Err(AppError::Unauthorized)
    } else {
        Ok(())
    }
}

pub fn validate_policy_input(policy: &SecurityPolicyRecord) -> AppResult<()> {
    if policy.password_min_length < 8 {
        return Err(AppError::BadRequest(
            "password minimum length must be at least 8".to_string(),
        ));
    }
    if policy.max_failed_login_attempts < 1 {
        return Err(AppError::BadRequest(
            "max failed login attempts must be positive".to_string(),
        ));
    }
    if policy.failure_window_seconds < 60 || policy.lockout_seconds < 60 {
        return Err(AppError::BadRequest(
            "login lockout windows must be at least 60 seconds".to_string(),
        ));
    }
    if policy.captcha_after_failed_attempts < 1 {
        return Err(AppError::BadRequest(
            "captcha failed-attempt threshold must be positive".to_string(),
        ));
    }
    if policy.captcha_ttl_seconds < 60 {
        return Err(AppError::BadRequest(
            "captcha ttl must be at least 60 seconds".to_string(),
        ));
    }
    network_policy::trusted_networks_from_json(&policy.trusted_ip_cidrs)?;
    network_policy::networks_from_json(&policy.allowed_ip_cidrs, "allowed IP networks")?;
    network_policy::networks_from_json(&policy.blocked_ip_cidrs, "blocked IP networks")?;
    email_domains_from_json(&policy.allowed_email_domains)?;
    email_domains_from_json(&policy.blocked_email_domains)?;
    Ok(())
}

pub fn normalize_email_domain_rules(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut domains = Vec::new();
    for value in values {
        let domain = value
            .trim()
            .trim_start_matches('@')
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        if domain.contains('@')
            || domain.contains('/')
            || domain.contains('\\')
            || domain.chars().any(char::is_whitespace)
            || domain.split('.').any(str::is_empty)
        {
            return Err(AppError::BadRequest(format!(
                "email domain rule is invalid: {domain}"
            )));
        }
        if !domains.iter().any(|existing| existing == &domain) {
            domains.push(domain);
        }
    }
    Ok(domains)
}

fn contains_subject_part(password: &str, subject: PasswordSubject<'_>) -> bool {
    let password = password.to_ascii_lowercase();
    let local = subject.email.split('@').next().unwrap_or_default();
    [subject.email, local, subject.username]
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| value.len() >= 4)
        .any(|value| password.contains(&value))
}

fn email_domains_from_json(value: &str) -> AppResult<Vec<String>> {
    normalize_email_domain_rules(
        util::from_json::<Vec<String>>(value).map_err(|err| {
            AppError::BadRequest(format!("email domain rules are invalid: {err}"))
        })?,
    )
}

pub fn email_domain(subject: &str) -> Option<String> {
    let subject = subject.trim().to_ascii_lowercase();
    let (_, domain) = subject.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.');
    (!domain.is_empty()).then(|| domain.to_string())
}

pub fn domain_matches_any(domain: Option<&str>, rules: &[String]) -> bool {
    let Some(domain) = domain else {
        return false;
    };
    rules.iter().any(|rule| {
        domain == rule
            || domain
                .strip_suffix(rule)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn access_denied(_surface: AccessSurface, _reason: &str) -> AppError {
    AppError::Forbidden
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SecurityPolicyRecord {
        SecurityPolicyRecord {
            id: "default".to_string(),
            password_min_length: 8,
            password_require_uppercase: 0,
            password_require_lowercase: 0,
            password_require_digit: 0,
            password_require_symbol: 0,
            password_reject_user_info: 1,
            login_lockout_enabled: 1,
            max_failed_login_attempts: 5,
            failure_window_seconds: 900,
            lockout_seconds: 900,
            trusted_ip_cidrs: "[]".to_string(),
            require_mfa_outside_trusted_networks: 0,
            allowed_ip_cidrs: "[]".to_string(),
            blocked_ip_cidrs: "[]".to_string(),
            allowed_email_domains: "[]".to_string(),
            blocked_email_domains: "[]".to_string(),
            captcha_enabled: 0,
            captcha_after_failed_attempts: 3,
            captcha_ttl_seconds: 300,
            updated_at: 1,
        }
    }

    #[test]
    fn access_risk_policy_applies_ip_allow_and_block_lists() {
        let mut policy = policy();
        policy.allowed_ip_cidrs = util::to_json(&vec!["10.0.0.0/8".to_string()]).unwrap();
        policy.blocked_ip_cidrs = util::to_json(&vec!["10.1.0.0/16".to_string()]).unwrap();

        assert!(
            policy
                .evaluate_access_risk(AccessRiskContext {
                    surface: AccessSurface::Login,
                    ip_address: Some("10.2.3.4"),
                    subject: Some("user@example.com"),
                })
                .is_ok()
        );
        assert!(matches!(
            policy.evaluate_access_risk(AccessRiskContext {
                surface: AccessSurface::Login,
                ip_address: Some("10.1.2.3"),
                subject: Some("user@example.com"),
            }),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            policy.evaluate_access_risk(AccessRiskContext {
                surface: AccessSurface::Login,
                ip_address: Some("192.0.2.10"),
                subject: Some("user@example.com"),
            }),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn network_access_risk_ignores_email_domain_rules() {
        let mut policy = policy();
        policy.allowed_email_domains = util::to_json(&vec!["company.example".to_string()]).unwrap();
        policy.blocked_email_domains = util::to_json(&vec!["blocked.example".to_string()]).unwrap();

        assert!(
            policy
                .evaluate_network_access_risk(NetworkAccessRiskContext {
                    surface: AccessSurface::Registration,
                    ip_address: Some("192.0.2.10"),
                })
                .is_ok()
        );
        assert!(matches!(
            policy.evaluate_access_risk(AccessRiskContext {
                surface: AccessSurface::Registration,
                ip_address: Some("192.0.2.10"),
                subject: Some("visitor@outside.example"),
            }),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn network_access_risk_still_applies_ip_rules() {
        let mut policy = policy();
        policy.blocked_ip_cidrs = util::to_json(&vec!["192.0.2.0/24".to_string()]).unwrap();

        assert!(matches!(
            policy.evaluate_network_access_risk(NetworkAccessRiskContext {
                surface: AccessSurface::Registration,
                ip_address: Some("192.0.2.10"),
            }),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn access_risk_policy_applies_domain_allow_and_block_lists() {
        let mut policy = policy();
        policy.allowed_email_domains = util::to_json(&vec![
            "example.com".to_string(),
            "contractor.test".to_string(),
        ])
        .unwrap();
        policy.blocked_email_domains =
            util::to_json(&vec!["blocked.example.com".to_string()]).unwrap();

        assert!(
            policy
                .evaluate_access_risk(AccessRiskContext {
                    surface: AccessSurface::Registration,
                    ip_address: Some("192.0.2.10"),
                    subject: Some("alice@team.example.com"),
                })
                .is_ok()
        );
        assert!(matches!(
            policy.evaluate_access_risk(AccessRiskContext {
                surface: AccessSurface::Registration,
                ip_address: Some("192.0.2.10"),
                subject: Some("alice@blocked.example.com"),
            }),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            policy.evaluate_access_risk(AccessRiskContext {
                surface: AccessSurface::Registration,
                ip_address: Some("192.0.2.10"),
                subject: Some("alice@other.test"),
            }),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn email_domain_rules_are_normalized() {
        assert_eq!(
            normalize_email_domain_rules(vec![
                "@Example.COM.".to_string(),
                ".team.example.com".to_string(),
                "example.com".to_string(),
            ])
            .unwrap(),
            vec!["example.com".to_string(), "team.example.com".to_string()]
        );
        assert!(matches!(
            normalize_email_domain_rules(vec!["bad/domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
    }
}
