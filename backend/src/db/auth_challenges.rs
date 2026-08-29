use super::{AppError, AppResult, DatabaseKind, Db, blocking, ph};
use crate::util;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct LoginFailureSummary {
    pub count: i64,
    pub latest_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct CaptchaChallengeRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub subject: String,
    #[diesel(sql_type = Text)]
    pub prompt: String,
    #[diesel(sql_type = Text)]
    pub answer_hash: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct VerificationCodeRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub channel: String,
    #[diesel(sql_type = Text)]
    pub target: String,
    #[diesel(sql_type = Text)]
    pub purpose: String,
    #[diesel(sql_type = Text)]
    pub code_hash: String,
    #[diesel(sql_type = Integer)]
    pub attempts: i32,
    #[diesel(sql_type = Integer)]
    pub max_attempts: i32,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewVerificationCode<'a> {
    pub channel: &'a str,
    pub target: &'a str,
    pub purpose: &'a str,
    pub code_hash: String,
    pub ttl_seconds: i64,
    pub resend_interval_seconds: i64,
    pub max_attempts: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerificationCodeDecision {
    Accepted(String),
    RejectedAttempt(String),
}

pub(crate) trait VerificationCodeVerifier {
    fn verify_hash(&self, code_hash: &str, now: i64) -> AppResult<VerificationCodeDecision>;
}

impl VerificationCodeVerifier for VerificationCodeRecord {
    fn verify_hash(&self, code_hash: &str, now: i64) -> AppResult<VerificationCodeDecision> {
        if self.expires_at < now {
            return Err(AppError::BadRequest(
                "verification code expired".to_string(),
            ));
        }
        if self.attempts >= self.max_attempts {
            return Err(AppError::BadRequest(
                "verification code attempts exceeded".to_string(),
            ));
        }
        if self.code_hash != code_hash {
            return Ok(VerificationCodeDecision::RejectedAttempt(self.id.clone()));
        }
        Ok(VerificationCodeDecision::Accepted(self.id.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct VerificationCodeClaim {
    pub channel: String,
    pub target: String,
    pub purpose: String,
    pub code: String,
}

impl VerificationCodeClaim {
    pub fn new(channel: &str, target: &str, purpose: &str, code: &str) -> Self {
        Self {
            channel: channel.to_string(),
            target: target.to_string(),
            purpose: purpose.to_string(),
            code: code.trim().to_string(),
        }
    }
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct LoginFailureSummaryRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    latest_at: Option<i64>,
}

fn select_verification_code_sql() -> &'static str {
    "SELECT id, channel, target, purpose, code_hash, attempts, max_attempts, expires_at, consumed_at, created_at FROM verification_codes"
}

pub(crate) fn select_verification_code_by_id_sql(kind: DatabaseKind) -> String {
    format!(
        "{} WHERE id = {}",
        select_verification_code_sql(),
        ph(kind, 1)
    )
}

pub(crate) fn select_latest_verification_code_sql(kind: DatabaseKind) -> String {
    format!(
        "{} WHERE channel = {} AND target = {} AND purpose = {} AND consumed_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1",
        select_verification_code_sql(),
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3)
    )
}

fn select_latest_verification_issue_sql(kind: DatabaseKind) -> String {
    format!(
        "{} WHERE channel = {} AND target = {} AND purpose = {} ORDER BY created_at DESC, id DESC LIMIT 1",
        select_verification_code_sql(),
        ph(kind, 1),
        ph(kind, 2),
        ph(kind, 3)
    )
}

pub(crate) fn ensure_verification_resend_allowed(
    latest: Option<&VerificationCodeRecord>,
    now: i64,
    resend_interval_seconds: i64,
) -> AppResult<()> {
    let Some(latest) = latest else {
        return Ok(());
    };
    let retry_at = latest.created_at + resend_interval_seconds;
    if retry_at > now {
        return Err(AppError::BadRequest(format!(
            "verification code was sent too recently; retry after {} seconds",
            retry_at - now
        )));
    }
    Ok(())
}

pub(crate) fn increment_verification_attempts_sql(kind: DatabaseKind) -> String {
    format!(
        "UPDATE verification_codes SET attempts = attempts + 1 WHERE id = {}",
        ph(kind, 1)
    )
}

pub(crate) fn consume_verification_code_sql(kind: DatabaseKind) -> String {
    format!(
        "UPDATE verification_codes SET consumed_at = {} WHERE id = {} AND consumed_at IS NULL",
        ph(kind, 1),
        ph(kind, 2)
    )
}

impl Db {
    pub async fn record_login_failure(
        &self,
        subject: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        reason: &str,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let subject = subject.to_string();
        let reason = reason.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO login_failures (id, subject, ip_address, user_agent, reason, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(subject)
                .bind::<Nullable<Text>, _>(ip_address)
                .bind::<Nullable<Text>, _>(user_agent)
                .bind::<Text, _>(reason)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn clear_login_failures(&self, subject: &str) -> AppResult<()> {
        let subject = subject.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("DELETE FROM login_failures WHERE subject = {}", ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(subject)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn login_failure_summary(
        &self,
        subject: &str,
        window_seconds: i64,
    ) -> AppResult<LoginFailureSummary> {
        let subject = subject.to_string();
        let since = util::now_ts() - window_seconds;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count, MAX(created_at) AS latest_at FROM login_failures WHERE subject = {} AND created_at >= {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(subject)
                .bind::<BigInt, _>(since)
                .get_result::<LoginFailureSummaryRow>(&mut conn)
                .map(|row| LoginFailureSummary {
                    count: row.count,
                    latest_at: row.latest_at,
                })
                .map_err(AppError::from)
        })
    }

    pub async fn create_captcha_challenge(
        &self,
        subject: &str,
        prompt: &str,
        answer: &str,
        ttl_seconds: i64,
    ) -> AppResult<CaptchaChallengeRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let subject = subject.to_string();
        let prompt = prompt.to_string();
        let answer_hash = util::hash_password(answer)?;
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM captcha_challenges WHERE expires_at < {} OR (subject = {} AND consumed_at IS NULL)",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(cleanup_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&subject)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let insert_sql = format!(
                "INSERT INTO captcha_challenges (id, subject, prompt, answer_hash, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&subject)
                .bind::<Text, _>(&prompt)
                .bind::<Text, _>(&answer_hash)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let select_sql = format!(
                "SELECT id, subject, prompt, answer_hash, expires_at, consumed_at, created_at FROM captcha_challenges WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(select_sql)
                .bind::<Text, _>(id)
                .get_result::<CaptchaChallengeRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn consume_captcha_challenge(
        &self,
        id: &str,
        subject: &str,
        answer: &str,
    ) -> AppResult<()> {
        let id = id.to_string();
        let subject = subject.to_string();
        let answer = answer.trim().to_string();
        let now = util::now_ts();
        let record = with_conn!(self, |conn, kind| {
            let select_sql = format!(
                "SELECT id, subject, prompt, answer_hash, expires_at, consumed_at, created_at FROM captcha_challenges WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(select_sql)
                .bind::<Text, _>(&id)
                .get_result::<CaptchaChallengeRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })?
        .ok_or_else(|| AppError::BadRequest("captcha challenge is invalid".to_string()))?;
        if record.subject != subject || record.consumed_at.is_some() || record.expires_at < now {
            return Err(AppError::BadRequest(
                "captcha challenge is invalid".to_string(),
            ));
        }
        if !self
            .mark_captcha_challenge_consumed(&record.id, &subject, now)
            .await?
        {
            return Err(AppError::BadRequest(
                "captcha challenge is invalid".to_string(),
            ));
        }
        if util::verify_password(&record.answer_hash, &answer) {
            Ok(())
        } else {
            Err(AppError::BadRequest(
                "captcha answer is invalid".to_string(),
            ))
        }
    }

    async fn mark_captcha_challenge_consumed(
        &self,
        id: &str,
        subject: &str,
        now: i64,
    ) -> AppResult<bool> {
        let id = id.to_string();
        let subject = subject.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE captcha_challenges SET consumed_at = {} WHERE id = {} AND subject = {} AND expires_at > {} AND consumed_at IS NULL",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4)
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .bind::<Text, _>(subject)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_verification_code(
        &self,
        code: NewVerificationCode<'_>,
    ) -> AppResult<VerificationCodeRecord> {
        let NewVerificationCode {
            channel,
            target,
            purpose,
            code_hash,
            ttl_seconds,
            resend_interval_seconds,
            max_attempts,
        } = code;
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        let channel = channel.to_string();
        let target = target.to_string();
        let purpose = purpose.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<VerificationCodeRecord, AppError, _>(|conn| {
                let latest = sql_query(select_latest_verification_issue_sql(kind))
                    .bind::<Text, _>(&channel)
                    .bind::<Text, _>(&target)
                    .bind::<Text, _>(&purpose)
                    .get_result::<VerificationCodeRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                ensure_verification_resend_allowed(latest.as_ref(), now, resend_interval_seconds)?;
                let sql = format!(
                    "INSERT INTO verification_codes (id, channel, target, purpose, code_hash, attempts, max_attempts, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&channel)
                    .bind::<Text, _>(&target)
                    .bind::<Text, _>(&purpose)
                    .bind::<Text, _>(code_hash)
                    .bind::<Integer, _>(0)
                    .bind::<Integer, _>(max_attempts)
                    .bind::<BigInt, _>(expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                sql_query(select_verification_code_by_id_sql(kind))
                    .bind::<Text, _>(id)
                    .get_result::<VerificationCodeRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_unconsumed_verification_code(&self, id: &str) -> AppResult<bool> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM verification_codes WHERE id = {} AND consumed_at IS NULL",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|affected| affected > 0)
                .map_err(AppError::from)
        })
    }

    pub(crate) async fn verify_verification_claims(
        &self,
        claims: Vec<VerificationCodeClaim>,
    ) -> AppResult<()> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            for claim in &claims {
                let code_hash = util::token_hash(&claim.code);
                let record =
                    latest_verification_code!(&mut conn, kind, claim).ok_or_else(|| {
                        AppError::BadRequest("verification code is missing".to_string())
                    })?;
                match record.verify_hash(&code_hash, now)? {
                    VerificationCodeDecision::Accepted(_) => {}
                    VerificationCodeDecision::RejectedAttempt(id) => {
                        increment_verification_attempts!(&mut conn, kind, &id);
                        return Err(AppError::BadRequest(
                            "verification code is invalid".to_string(),
                        ));
                    }
                }
            }
            Ok(())
        })
    }

    pub async fn consume_verification_code(
        &self,
        channel: &str,
        target: &str,
        purpose: &str,
        code: &str,
    ) -> AppResult<()> {
        let channel = channel.to_string();
        let target = target.to_string();
        let purpose = purpose.to_string();
        let code_hash = util::token_hash(code);
        let code = code.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let claim = VerificationCodeClaim {
                channel,
                target,
                purpose,
                code,
            };
            let record = latest_verification_code!(&mut conn, kind, claim)
                .ok_or_else(|| AppError::BadRequest("verification code is missing".to_string()))?;
            let id = match record.verify_hash(&code_hash, now)? {
                VerificationCodeDecision::Accepted(id) => id,
                VerificationCodeDecision::RejectedAttempt(id) => {
                    increment_verification_attempts!(&mut conn, kind, &id);
                    return Err(AppError::BadRequest(
                        "verification code is invalid".to_string(),
                    ));
                }
            };
            if mark_verification_code_consumed!(&mut conn, kind, now, &id) == 0 {
                return Err(AppError::BadRequest(
                    "verification code is missing".to_string(),
                ));
            }
            Ok(())
        })
    }
}
