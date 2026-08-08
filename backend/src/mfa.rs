use crate::{
    AppState,
    db::{MfaChallengeRecord, MfaRecoveryCodeRecord, MfaTotpMethodRecord},
    error::{AppError, AppResult},
    util,
};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha1::Sha1;
use url::Url;

type HmacSha1 = Hmac<Sha1>;

const TOTP_STEP_SECONDS: i64 = 30;
const TOTP_DIGITS: u32 = 6;
const TOTP_WINDOW: i64 = 1;
pub const MFA_CHALLENGE_TTL_SECONDS: i64 = 300;
pub const MFA_SETUP_TTL_SECONDS: i64 = 600;
pub const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryCode {
    pub code: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MfaCompletion {
    pub method: String,
    pub consumed_recovery_code: bool,
}

pub trait TotpVerifier {
    fn verify_code(
        &self,
        secret: &str,
        code: &str,
        now: i64,
        last_used_step: Option<i64>,
    ) -> AppResult<Option<i64>>;
}

#[derive(Debug, Clone, Copy)]
pub struct StandardTotpVerifier {
    step_seconds: i64,
    digits: u32,
    window: i64,
}

impl Default for StandardTotpVerifier {
    fn default() -> Self {
        Self {
            step_seconds: TOTP_STEP_SECONDS,
            digits: TOTP_DIGITS,
            window: TOTP_WINDOW,
        }
    }
}

impl TotpVerifier for StandardTotpVerifier {
    fn verify_code(
        &self,
        secret: &str,
        code: &str,
        now: i64,
        last_used_step: Option<i64>,
    ) -> AppResult<Option<i64>> {
        let normalized = normalize_code(code);
        if normalized.len() != self.digits as usize {
            return Ok(None);
        }
        let current_step = now / self.step_seconds;
        for offset in -self.window..=self.window {
            let step = current_step + offset;
            if step < 0 || last_used_step.is_some_and(|last| step <= last) {
                continue;
            }
            if totp_at(secret, step, self.digits)? == normalized {
                return Ok(Some(step));
            }
        }
        Ok(None)
    }
}

pub trait RecoveryCodeIssuer {
    fn issue_recovery_codes(&self, count: usize) -> AppResult<Vec<RecoveryCode>>;
}

#[derive(Debug, Clone, Copy)]
pub struct StandardRecoveryCodeIssuer;

impl RecoveryCodeIssuer for StandardRecoveryCodeIssuer {
    fn issue_recovery_codes(&self, count: usize) -> AppResult<Vec<RecoveryCode>> {
        let mut codes = Vec::with_capacity(count);
        for _ in 0..count {
            let code = generate_recovery_code();
            let hash = util::hash_password(&code)?;
            codes.push(RecoveryCode { code, hash });
        }
        Ok(codes)
    }
}

pub fn generate_totp_secret() -> String {
    let mut bytes = [0_u8; 20];
    OsRng.fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}

pub fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> AppResult<String> {
    let label = format!("{}:{account}", issuer.trim().trim_end_matches('/'));
    let mut url = Url::parse("otpauth://totp/")
        .map_err(|err| AppError::Internal(format!("invalid otpauth base URL: {err}")))?;
    url.set_path(&label);
    url.query_pairs_mut()
        .append_pair("secret", secret)
        .append_pair("issuer", issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", &TOTP_DIGITS.to_string())
        .append_pair("period", &TOTP_STEP_SECONDS.to_string());
    Ok(url.to_string())
}

pub fn verify_setup_code(secret: &str, code: &str) -> AppResult<bool> {
    StandardTotpVerifier::default()
        .verify_code(secret, code, util::now_ts(), None)
        .map(|step| step.is_some())
}

pub async fn complete_challenge(
    state: &AppState,
    challenge: MfaChallengeRecord,
    code: &str,
) -> AppResult<MfaCompletion> {
    if challenge.expires_at < util::now_ts() || challenge.consumed_at.is_some() {
        return Err(AppError::Unauthorized);
    }

    let method = state
        .db
        .find_totp_method(&challenge.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if let Some(step) = StandardTotpVerifier::default().verify_code(
        &method.secret,
        code,
        util::now_ts(),
        method.last_used_step,
    )? {
        state
            .db
            .complete_mfa_challenge_with_totp(&challenge.id, &method.user_id, step)
            .await?;
        return Ok(MfaCompletion {
            method: "totp".to_string(),
            consumed_recovery_code: false,
        });
    }

    if let Some(recovery_code) = matching_recovery_code(
        state
            .db
            .list_unused_recovery_codes(&challenge.user_id)
            .await?,
        code,
    ) {
        state
            .db
            .complete_mfa_challenge_with_recovery_code(
                &challenge.id,
                &challenge.user_id,
                &recovery_code.id,
            )
            .await?;
        return Ok(MfaCompletion {
            method: "recovery_code".to_string(),
            consumed_recovery_code: true,
        });
    }

    Err(AppError::Unauthorized)
}

pub async fn complete_challenge_by_id(
    state: &AppState,
    challenge_id: &str,
    user_id: &str,
    purpose: &str,
    code: &str,
) -> AppResult<MfaCompletion> {
    let challenge = state
        .db
        .find_mfa_challenge(challenge_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if challenge.user_id != user_id || challenge.purpose != purpose {
        return Err(AppError::Unauthorized);
    }
    complete_challenge(state, challenge, code).await
}

pub fn plaintext_codes(codes: &[RecoveryCode]) -> Vec<String> {
    codes.iter().map(|code| code.code.clone()).collect()
}

pub fn code_hashes(codes: &[RecoveryCode]) -> Vec<String> {
    codes.iter().map(|code| code.hash.clone()).collect()
}

fn matching_recovery_code(
    codes: Vec<MfaRecoveryCodeRecord>,
    submitted: &str,
) -> Option<MfaRecoveryCodeRecord> {
    let normalized = normalize_recovery_code(submitted);
    codes
        .into_iter()
        .find(|record| util::verify_password(&record.code_hash, &normalized))
}

fn generate_recovery_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut bytes);
    let chars = bytes
        .into_iter()
        .map(|byte| ALPHABET[(byte as usize) % ALPHABET.len()] as char)
        .collect::<Vec<_>>();
    format!(
        "{}{}{}{}-{}{}{}{}-{}{}{}{}",
        chars[0],
        chars[1],
        chars[2],
        chars[3],
        chars[4],
        chars[5],
        chars[6],
        chars[7],
        chars[8],
        chars[9],
        chars[10],
        chars[11]
    )
}

fn normalize_recovery_code(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect::<String>()
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

fn normalize_code(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<String>()
}

fn totp_at(secret: &str, step: i64, digits: u32) -> AppResult<String> {
    let key = BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|err| AppError::BadRequest(format!("invalid TOTP secret: {err}")))?;
    let counter = (step as u64).to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(&key)
        .map_err(|err| AppError::Internal(format!("failed to create TOTP HMAC: {err}")))?;
    mac.update(&counter);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    let modulo = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = digits as usize
    ))
}

pub fn recovery_codes_remaining(codes: &[MfaRecoveryCodeRecord]) -> usize {
    codes.iter().filter(|code| code.used_at.is_none()).count()
}

pub fn method_enabled(method: Option<&MfaTotpMethodRecord>) -> bool {
    method.is_some()
}
