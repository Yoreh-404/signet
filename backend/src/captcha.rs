use crate::{
    db::{CaptchaChallengeRecord, LoginFailureSummary, SecurityPolicyRecord},
    error::AppResult,
};
use rand_core::{OsRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LoginCaptchaPrompt {
    pub challenge_id: String,
    pub prompt: String,
    pub expires_at: i64,
}

impl From<CaptchaChallengeRecord> for LoginCaptchaPrompt {
    fn from(record: CaptchaChallengeRecord) -> Self {
        Self {
            challenge_id: record.id,
            prompt: record.prompt,
            expires_at: record.expires_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptchaChallenge {
    pub prompt: String,
    pub answer: String,
}

pub trait CaptchaProvider {
    fn generate(&self) -> AppResult<CaptchaChallenge>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ArithmeticCaptchaProvider;

impl CaptchaProvider for ArithmeticCaptchaProvider {
    fn generate(&self) -> AppResult<CaptchaChallenge> {
        let left = random_digit(2, 9);
        let right = random_digit(2, 9);
        Ok(CaptchaChallenge {
            prompt: format!("{left} + {right} = ?"),
            answer: (left + right).to_string(),
        })
    }
}

pub trait LoginCaptchaPolicy {
    fn requires_login_captcha(&self, summary: LoginFailureSummary) -> bool;
}

impl LoginCaptchaPolicy for SecurityPolicyRecord {
    fn requires_login_captcha(&self, summary: LoginFailureSummary) -> bool {
        self.captcha_enabled != 0
            && self.captcha_after_failed_attempts > 0
            && summary.count >= self.captcha_after_failed_attempts as i64
    }
}

fn random_digit(min: u32, max: u32) -> u32 {
    let range = max - min + 1;
    min + (OsRng.next_u32() % range)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(enabled: i32, after: i32) -> SecurityPolicyRecord {
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
            captcha_enabled: enabled,
            captcha_after_failed_attempts: after,
            captcha_ttl_seconds: 300,
            updated_at: 1,
        }
    }

    #[test]
    fn captcha_policy_requires_challenge_at_threshold() {
        let summary = LoginFailureSummary {
            count: 3,
            latest_at: Some(100),
        };
        assert!(policy(1, 3).requires_login_captcha(summary));
        assert!(!policy(1, 4).requires_login_captcha(summary));
        assert!(!policy(0, 3).requires_login_captcha(summary));
    }

    #[test]
    fn arithmetic_provider_generates_answerable_prompt() {
        let challenge = ArithmeticCaptchaProvider.generate().unwrap();
        let (left, rest) = challenge.prompt.split_once(" + ").unwrap();
        let (right, _) = rest.split_once(" = ").unwrap();
        let expected = left.parse::<u32>().unwrap() + right.parse::<u32>().unwrap();
        assert_eq!(challenge.answer, expected.to_string());
    }
}
