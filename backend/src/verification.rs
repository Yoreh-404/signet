use crate::{
    config::{VerificationChannelSettings, VerificationDelivery},
    error::{AppError, AppResult},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use serde::Serialize;
use sha2::Sha256;
use std::{future::Future, time::Duration};

const DEFAULT_HTTP_TIMEOUT_SECONDS: u64 = 5;

type HmacSha256 = Hmac<Sha256>;

pub struct VerificationDeliveryContext<'a> {
    pub channel: &'a str,
    pub target: &'a str,
    pub purpose: &'a str,
    pub code: &'a str,
    pub expires_at: i64,
    pub message: &'a str,
}

pub struct VerificationDeliveryOutcome {
    pub dev_code: Option<String>,
}

pub trait VerificationSender {
    fn send<'a>(
        &'a self,
        context: &'a VerificationDeliveryContext<'a>,
    ) -> impl Future<Output = AppResult<VerificationDeliveryOutcome>> + Send + 'a;
}

pub async fn deliver_verification_code(
    settings: &VerificationChannelSettings,
    context: &VerificationDeliveryContext<'_>,
) -> AppResult<VerificationDeliveryOutcome> {
    match settings.delivery {
        VerificationDelivery::DevLog => DevLogVerificationSender.send(context).await,
        VerificationDelivery::Smtp => {
            SmtpVerificationSender {
                host: required_setting(
                    settings.smtp_host.as_deref(),
                    "smtp delivery requires verification.email.smtp_host",
                )?,
                port: settings.smtp_port.unwrap_or(587),
                username: nonempty(settings.smtp_username.as_deref()),
                password: nonempty(settings.smtp_password.as_deref()),
                from: required_setting(
                    settings.smtp_from.as_deref(),
                    "smtp delivery requires verification.email.smtp_from",
                )?,
                starttls: settings.smtp_starttls.unwrap_or(true),
            }
            .send(context)
            .await
        }
        VerificationDelivery::SmsProvider => {
            let url = required_setting(
                settings.sms_provider.as_deref(),
                "sms_provider delivery requires verification.<channel>.sms_provider to be an HTTP URL",
            )?;
            HttpJsonVerificationSender {
                url,
                bearer_token: nonempty(settings.sms_api_key.as_deref()),
                hmac_secret: None,
                timeout_seconds: settings
                    .webhook_timeout_seconds
                    .unwrap_or(DEFAULT_HTTP_TIMEOUT_SECONDS),
            }
            .send(context)
            .await
        }
        VerificationDelivery::Webhook => {
            let url = required_setting(
                settings.webhook_url.as_deref(),
                "webhook delivery requires verification.<channel>.webhook_url",
            )?;
            HttpJsonVerificationSender {
                url,
                bearer_token: None,
                hmac_secret: nonempty(settings.webhook_secret.as_deref()),
                timeout_seconds: settings
                    .webhook_timeout_seconds
                    .unwrap_or(DEFAULT_HTTP_TIMEOUT_SECONDS),
            }
            .send(context)
            .await
        }
    }
}

struct DevLogVerificationSender;

impl VerificationSender for DevLogVerificationSender {
    fn send<'a>(
        &'a self,
        context: &'a VerificationDeliveryContext<'a>,
    ) -> impl Future<Output = AppResult<VerificationDeliveryOutcome>> + Send + 'a {
        async move {
            tracing::info!(
                channel = context.channel,
                target = context.target,
                purpose = context.purpose,
                code = context.code,
                log_message = context.message
            );
            Ok(VerificationDeliveryOutcome {
                dev_code: Some(context.code.to_string()),
            })
        }
    }
}

struct HttpJsonVerificationSender<'a> {
    url: &'a str,
    bearer_token: Option<&'a str>,
    hmac_secret: Option<&'a str>,
    timeout_seconds: u64,
}

impl VerificationSender for HttpJsonVerificationSender<'_> {
    fn send<'a>(
        &'a self,
        context: &'a VerificationDeliveryContext<'a>,
    ) -> impl Future<Output = AppResult<VerificationDeliveryOutcome>> + Send + 'a {
        async move {
            let payload = VerificationWebhookPayload::from_context(context);
            let body = serde_json::to_string(&payload).map_err(|err| {
                AppError::Internal(format!("failed to encode verification payload: {err}"))
            })?;
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(self.timeout_seconds))
                .build()
                .map_err(|err| {
                    AppError::Internal(format!("failed to build verification HTTP client: {err}"))
                })?;
            let mut request = client
                .post(self.url)
                .header("content-type", "application/json")
                .header("user-agent", "gpt-sso-verification/0.1")
                .header("x-gpt-sso-verification-channel", context.channel)
                .header("x-gpt-sso-verification-purpose", context.purpose)
                .body(body.clone());
            if let Some(token) = self.bearer_token {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            if let Some(secret) = self.hmac_secret {
                request = request.header("x-gpt-sso-signature", sign_body(secret, &body)?);
            }
            let response = request.send().await.map_err(delivery_error)?;
            let status = response.status();
            if !status.is_success() {
                return Err(AppError::Internal(format!(
                    "verification delivery endpoint returned {status}"
                )));
            }
            Ok(VerificationDeliveryOutcome { dev_code: None })
        }
    }
}

struct SmtpVerificationSender<'a> {
    host: &'a str,
    port: u16,
    username: Option<&'a str>,
    password: Option<&'a str>,
    from: &'a str,
    starttls: bool,
}

impl VerificationSender for SmtpVerificationSender<'_> {
    fn send<'a>(
        &'a self,
        context: &'a VerificationDeliveryContext<'a>,
    ) -> impl Future<Output = AppResult<VerificationDeliveryOutcome>> + Send + 'a {
        async move {
            if context.channel != "email" {
                return Err(AppError::Configuration(
                    "smtp verification delivery can only send email codes".to_string(),
                ));
            }
            let message = Message::builder()
                .from(parse_mailbox(self.from, "verification.email.smtp_from")?)
                .to(parse_mailbox(context.target, "verification email target")?)
                .subject(smtp_subject(context))
                .body(smtp_body(context))
                .map_err(|err| {
                    AppError::Internal(format!("failed to build SMTP message: {err}"))
                })?;
            let mut builder = if self.starttls {
                AsyncSmtpTransport::<Tokio1Executor>::relay(self.host).map_err(|err| {
                    AppError::Configuration(format!("invalid SMTP relay configuration: {err}"))
                })?
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(self.host)
            }
            .port(self.port);
            if let (Some(username), Some(password)) = (self.username, self.password) {
                builder = builder
                    .credentials(Credentials::new(username.to_string(), password.to_string()));
            }
            builder.build().send(message).await.map_err(|err| {
                AppError::Internal(format!("SMTP verification delivery failed: {err}"))
            })?;
            Ok(VerificationDeliveryOutcome { dev_code: None })
        }
    }
}

#[derive(Serialize)]
struct VerificationWebhookPayload<'a> {
    r#type: &'static str,
    channel: &'a str,
    target: &'a str,
    purpose: &'a str,
    code: &'a str,
    expires_at: i64,
    message: &'a str,
}

impl<'a> VerificationWebhookPayload<'a> {
    fn from_context(context: &'a VerificationDeliveryContext<'a>) -> Self {
        Self {
            r#type: "verification.code",
            channel: context.channel,
            target: context.target,
            purpose: context.purpose,
            code: context.code,
            expires_at: context.expires_at,
            message: context.message,
        }
    }
}

fn delivery_error(err: reqwest::Error) -> AppError {
    if err.is_timeout() {
        AppError::Internal("verification delivery timed out".to_string())
    } else {
        AppError::Internal(format!("verification delivery HTTP error: {err}"))
    }
}

fn required_setting<'a>(value: Option<&'a str>, message: &str) -> AppResult<&'a str> {
    nonempty(value).ok_or_else(|| AppError::Configuration(message.to_string()))
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn sign_body(secret: &str, body: &str) -> AppResult<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|err| AppError::Internal(format!("failed to create HMAC: {err}")))?;
    mac.update(body.as_bytes());
    Ok(format!(
        "sha256={}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn parse_mailbox(value: &str, label: &str) -> AppResult<Mailbox> {
    value
        .parse::<Mailbox>()
        .map_err(|err| AppError::Configuration(format!("{label} is invalid: {err}")))
}

fn smtp_subject(context: &VerificationDeliveryContext<'_>) -> String {
    match context.purpose {
        "password_reset" => "GPT SSO password reset code".to_string(),
        "registration" => "GPT SSO registration verification code".to_string(),
        _ => "GPT SSO verification code".to_string(),
    }
}

fn smtp_body(context: &VerificationDeliveryContext<'_>) -> String {
    format!(
        "{}\n\nVerification code: {}\nExpires at: {}\n\nIf you did not request this code, ignore this email.",
        context.message, context.code, context.expires_at
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable() {
        let signature = sign_body("secret", r#"{"code":"123456"}"#).unwrap();
        assert_eq!(
            signature,
            "sha256=Z2-8KempokgsDMuAzLAtW-faINNxf9oxLWaO7fQIlko"
        );
    }

    #[tokio::test]
    async fn dev_log_returns_code_for_development_ui() {
        let settings = VerificationChannelSettings {
            enabled: true,
            delivery: VerificationDelivery::DevLog,
            code_ttl_seconds: 600,
            resend_interval_seconds: 60,
            max_attempts: 5,
            webhook_url: None,
            webhook_secret: None,
            webhook_timeout_seconds: None,
            smtp_host: None,
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            smtp_from: None,
            smtp_starttls: None,
            sms_provider: None,
            sms_api_key: None,
        };
        let context = VerificationDeliveryContext {
            channel: "email",
            target: "dev@example.com",
            purpose: "registration",
            code: "123456",
            expires_at: 1000,
            message: "test code",
        };
        let outcome = deliver_verification_code(&settings, &context)
            .await
            .unwrap();
        assert_eq!(outcome.dev_code.as_deref(), Some("123456"));
    }

    #[test]
    fn smtp_message_subject_and_body_are_purpose_aware() {
        let context = VerificationDeliveryContext {
            channel: "email",
            target: "user@example.com",
            purpose: "password_reset",
            code: "654321",
            expires_at: 1_700_000_000,
            message: "password reset verification code",
        };

        assert_eq!(smtp_subject(&context), "GPT SSO password reset code");
        let body = smtp_body(&context);
        assert!(body.contains("password reset verification code"));
        assert!(body.contains("654321"));
        assert!(body.contains("1700000000"));
    }

    #[test]
    fn smtp_mailbox_validation_rejects_invalid_addresses() {
        assert!(parse_mailbox("SSO <sso@example.com>", "from").is_ok());
        assert!(matches!(
            parse_mailbox("not an address", "from"),
            Err(AppError::Configuration(_))
        ));
    }
}
