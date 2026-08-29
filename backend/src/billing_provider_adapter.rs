use super::{
    AppError, AppResult, CURRENCY_CNY, CheckoutRequest, NotificationRequest, PAYMENT_STATUS_FAILED,
    PAYMENT_STATUS_PAID, PAYMENT_STATUS_PENDING, PaymentNotification, PaymentOrderRecord,
    PaymentProvider, PaymentProviderSettings, PaymentQueryResult, ProviderFuture,
    ProviderRefundResult, Settings, format_minor, parse_decimal_to_minor, provider_outcome_unknown,
    provider_outcome_unknown_with_reason, util,
};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::{Digest as Md5Digest, Md5};
use reqwest::{Client, Response as ProviderResponse};
use rsa::{
    Pkcs1v15Sign, RsaPrivateKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use std::{collections::BTreeMap, time::Duration};
use url::Url;
use x509_parser::prelude::FromDer;

pub(super) fn provider_settings<'a>(
    settings: &'a Settings,
    slug: &str,
) -> AppResult<&'a PaymentProviderSettings> {
    settings
        .billing
        .providers
        .iter()
        .find(|provider| provider.slug == slug && provider.enabled)
        .ok_or(AppError::NotFound)
}

pub(super) fn configured_provider(
    settings: &Settings,
    slug: &str,
) -> AppResult<Box<dyn PaymentProvider>> {
    let config = provider_settings(settings, slug)?.clone();
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| {
            AppError::Configuration(format!("failed to build payment client: {error}"))
        })?;
    match config.kind.as_str() {
        "epay_v1" => Ok(Box::new(EpayProvider { config })),
        "alipay_page" => Ok(Box::new(AlipayProvider { config, client })),
        "wechat_native" => Ok(Box::new(WechatProvider { config, client })),
        _ => Err(AppError::Configuration(
            "unsupported billing provider".to_string(),
        )),
    }
}

pub(super) fn notification_from_fields(
    fields: &BTreeMap<String, String>,
    amount_minor: i64,
    currency: &str,
    provider_trade_id: String,
    status: &str,
) -> AppResult<PaymentNotification> {
    let merchant_order_no = fields.get("out_trade_no").cloned().ok_or_else(|| {
        AppError::BadRequest("provider notification has no order number".to_string())
    })?;
    Ok(PaymentNotification {
        merchant_order_no,
        provider_trade_id,
        amount_minor,
        currency: currency.to_string(),
        paid_at: util::now_ts(),
        status: status.to_string(),
    })
}

fn form_fields(body: &[u8]) -> AppResult<BTreeMap<String, String>> {
    serde_urlencoded::from_bytes(body)
        .map_err(|_| AppError::BadRequest("provider notification form is invalid".to_string()))
}

fn json_fields(body: &[u8]) -> AppResult<Map<String, Value>> {
    serde_json::from_slice(body)
        .map_err(|_| AppError::BadRequest("provider notification JSON is invalid".to_string()))
}

pub(super) fn sign_epay(fields: &BTreeMap<String, String>, secret: &str) -> String {
    let mut canonical = fields
        .iter()
        .filter(|(key, value)| {
            key.as_str() != "sign" && key.as_str() != "sign_type" && !value.is_empty()
        })
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    canonical.sort();
    canonical.push(format!("key={secret}"));
    let mut digest = Md5::new();
    Md5Digest::update(&mut digest, canonical.join("&").as_bytes());
    format!("{:x}", Md5Digest::finalize(digest))
}

fn verify_constant_time(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut result = 0_u8;
    for (a, b) in left.iter().zip(right) {
        result |= a ^ b;
    }
    result == 0
}

fn signed_query_url(base: &str, fields: &BTreeMap<String, String>) -> AppResult<String> {
    let mut url = Url::parse(base).map_err(|_| {
        AppError::Configuration("billing provider gateway_url is invalid".to_string())
    })?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in fields {
            pairs.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

pub(super) fn rsa_sha256_sign(private_key_pem: &str, value: &str) -> AppResult<String> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|_| {
        AppError::Configuration("payment provider private key is invalid".to_string())
    })?;
    let digest = Sha256::digest(value.as_bytes());
    let signature = private_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|error| AppError::Internal(format!("payment provider signing failed: {error}")))?;
    Ok(STANDARD.encode(signature))
}

pub(super) fn rsa_sha256_verify(
    public_key_pem: &str,
    value: &str,
    signature: &str,
) -> AppResult<()> {
    let public_key = rsa::RsaPublicKey::from_public_key_pem(public_key_pem).map_err(|_| {
        AppError::Configuration("payment provider public key is invalid".to_string())
    })?;
    let signature = STANDARD
        .decode(signature)
        .map_err(|_| AppError::Unauthorized)?;
    let digest = Sha256::digest(value.as_bytes());
    public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
        .map_err(|_| AppError::Unauthorized)
}

pub(super) fn alipay_sign_content(fields: &BTreeMap<String, String>) -> String {
    fields
        .iter()
        .filter(|(key, value)| {
            key.as_str() != "sign" && key.as_str() != "sign_type" && !value.is_empty()
        })
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn provider_refund_request_id(idempotency_key: &str) -> String {
    format!("sgt-{}", util::sha256_base64url(idempotency_key))
}

fn request_headers_with_json() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("user-agent", "signet-billing/0.1".parse().unwrap());
    headers
}

/// Provider HTTP responses are classified at the adapter boundary.  A 4xx
/// response is a deterministic rejection; a 5xx response is deliberately
/// unknown because the provider may have accepted the request before failing
/// to return a response.
fn provider_response_error(response: &ProviderResponse, operation: &str) -> AppResult<()> {
    if response.status().is_success() {
        return Ok(());
    }
    if response.status().is_client_error() {
        return Err(AppError::BadRequest(format!(
            "{operation} was rejected by the payment provider"
        )));
    }
    Err(provider_outcome_unknown_with_reason(
        "provider returned 5xx or another non-success response",
    ))
}

async fn provider_json_response(response: ProviderResponse, operation: &str) -> AppResult<Value> {
    provider_response_error(&response, operation)?;
    response
        .json()
        .await
        .map_err(|_| provider_outcome_unknown_with_reason("provider response JSON is invalid"))
}

struct EpayProvider {
    config: PaymentProviderSettings,
}

impl PaymentProvider for EpayProvider {
    fn slug(&self) -> &str {
        &self.config.slug
    }

    fn create_checkout<'a>(
        &'a self,
        request: &'a CheckoutRequest,
    ) -> ProviderFuture<'a, (String, String)> {
        Box::pin(async move {
            if request.currency != CURRENCY_CNY {
                return Err(AppError::BadRequest(
                    "EPay v1 currently supports CNY only".to_string(),
                ));
            }
            let mut fields = BTreeMap::from([
                ("pid".to_string(), self.config.merchant_id.clone()),
                ("type".to_string(), self.config.payment_channel.clone()),
                (
                    "out_trade_no".to_string(),
                    request.merchant_order_no.clone(),
                ),
                ("notify_url".to_string(), request.notify_url.clone()),
                ("return_url".to_string(), request.return_url.clone()),
                ("name".to_string(), request.subject.clone()),
                ("money".to_string(), format_minor(request.amount_minor, 2)),
            ]);
            fields.insert("sign_type".to_string(), "MD5".to_string());
            fields.insert(
                "sign".to_string(),
                sign_epay(&fields, &self.config.merchant_secret),
            );
            Ok((
                "redirect".to_string(),
                signed_query_url(&self.config.gateway_url, &fields)?,
            ))
        })
    }

    fn verify_notification<'a>(
        &'a self,
        request: NotificationRequest<'a>,
    ) -> ProviderFuture<'a, PaymentNotification> {
        Box::pin(async move {
            let fields = form_fields(request.body)?;
            if fields.get("pid").map(String::as_str) != Some(self.config.merchant_id.as_str())
                || fields.get("sign_type").map(String::as_str) != Some("MD5")
            {
                return Err(AppError::Unauthorized);
            }
            let sign = fields.get("sign").ok_or_else(|| {
                AppError::BadRequest("EPay notification has no signature".to_string())
            })?;
            if !verify_constant_time(sign, &sign_epay(&fields, &self.config.merchant_secret)) {
                return Err(AppError::Unauthorized);
            }
            let amount_minor = parse_decimal_to_minor(
                fields.get("money").map(String::as_str).unwrap_or_default(),
                2,
            )?;
            let status = fields
                .get("trade_status")
                .map(String::as_str)
                .unwrap_or_default();
            let provider_trade_id = fields
                .get("trade_no")
                .cloned()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_default();
            notification_from_fields(
                &fields,
                amount_minor,
                CURRENCY_CNY,
                provider_trade_id,
                if matches!(status, "TRADE_SUCCESS" | "TRADE_FINISHED") {
                    "paid"
                } else {
                    "pending"
                },
            )
        })
    }

    fn query_payment<'a>(
        &'a self,
        _order: &'a PaymentOrderRecord,
    ) -> ProviderFuture<'a, PaymentQueryResult> {
        Box::pin(async move {
            Err(AppError::Configuration(
                "EPay v1 query is not standardized; reconcile this order manually".to_string(),
            ))
        })
    }

    fn refund_payment<'a>(
        &'a self,
        _order: &'a PaymentOrderRecord,
        _amount_minor: i64,
        _idempotency_key: &'a str,
    ) -> ProviderFuture<'a, ProviderRefundResult> {
        Box::pin(async move {
            Err(AppError::Configuration(
                "EPay v1 refund is not standardized; reconcile this order manually".to_string(),
            ))
        })
    }
}

struct AlipayProvider {
    config: PaymentProviderSettings,
    client: Client,
}

impl PaymentProvider for AlipayProvider {
    fn slug(&self) -> &str {
        &self.config.slug
    }

    fn create_checkout<'a>(
        &'a self,
        request: &'a CheckoutRequest,
    ) -> ProviderFuture<'a, (String, String)> {
        Box::pin(async move {
            if request.currency != CURRENCY_CNY {
                return Err(AppError::BadRequest(
                    "Alipay page pay currently supports CNY only".to_string(),
                ));
            }
            let biz_content = json!({
                "out_trade_no": request.merchant_order_no,
                "product_code": "FAST_INSTANT_TRADE_PAY",
                "total_amount": format_minor(request.amount_minor, 2),
                "subject": request.subject,
            })
            .to_string();
            let mut fields = BTreeMap::from([
                ("app_id".to_string(), self.config.app_id.clone()),
                ("method".to_string(), "alipay.trade.page.pay".to_string()),
                ("format".to_string(), "JSON".to_string()),
                ("charset".to_string(), "utf-8".to_string()),
                ("sign_type".to_string(), "RSA2".to_string()),
                (
                    "timestamp".to_string(),
                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                ),
                ("version".to_string(), "1.0".to_string()),
                ("notify_url".to_string(), request.notify_url.clone()),
                ("return_url".to_string(), request.return_url.clone()),
                ("biz_content".to_string(), biz_content),
            ]);
            let sign_content = alipay_sign_content(&fields);
            fields.insert(
                "sign".to_string(),
                rsa_sha256_sign(&self.config.private_key_pem, &sign_content)?,
            );
            Ok((
                "redirect".to_string(),
                signed_query_url(&self.config.gateway_url, &fields)?,
            ))
        })
    }

    fn verify_notification<'a>(
        &'a self,
        request: NotificationRequest<'a>,
    ) -> ProviderFuture<'a, PaymentNotification> {
        Box::pin(async move {
            let fields = form_fields(request.body)?;
            if fields.get("app_id").map(String::as_str) != Some(self.config.app_id.as_str())
                || fields.get("sign_type").map(String::as_str) != Some("RSA2")
            {
                return Err(AppError::Unauthorized);
            }
            let sign = fields.get("sign").ok_or_else(|| {
                AppError::BadRequest("Alipay notification has no signature".to_string())
            })?;
            let sign_content = alipay_sign_content(&fields);
            if sign.is_empty() || sign_content.is_empty() {
                return Err(AppError::Unauthorized);
            }
            rsa_sha256_verify(&self.config.alipay_public_key_pem, &sign_content, sign)?;
            let amount_minor = parse_decimal_to_minor(
                fields
                    .get("total_amount")
                    .map(String::as_str)
                    .unwrap_or_default(),
                2,
            )?;
            let status = fields
                .get("trade_status")
                .map(String::as_str)
                .unwrap_or_default();
            notification_from_fields(
                &fields,
                amount_minor,
                CURRENCY_CNY,
                fields.get("trade_no").cloned().unwrap_or_default(),
                if matches!(status, "TRADE_SUCCESS" | "TRADE_FINISHED") {
                    "paid"
                } else {
                    "pending"
                },
            )
        })
    }

    fn query_payment<'a>(
        &'a self,
        order: &'a PaymentOrderRecord,
    ) -> ProviderFuture<'a, PaymentQueryResult> {
        Box::pin(async move {
            let mut fields = BTreeMap::from([
                ("app_id".to_string(), self.config.app_id.clone()),
                ("method".to_string(), "alipay.trade.query".to_string()),
                ("format".to_string(), "JSON".to_string()),
                ("charset".to_string(), "utf-8".to_string()),
                ("sign_type".to_string(), "RSA2".to_string()),
                (
                    "timestamp".to_string(),
                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                ),
                ("version".to_string(), "1.0".to_string()),
                (
                    "biz_content".to_string(),
                    json!({"out_trade_no": order.merchant_order_no}).to_string(),
                ),
            ]);
            let sign_content = alipay_sign_content(&fields);
            fields.insert(
                "sign".to_string(),
                rsa_sha256_sign(&self.config.private_key_pem, &sign_content)?,
            );
            let response = self
                .client
                .get(&self.config.gateway_url)
                .query(&fields)
                .send()
                .await
                .map_err(provider_http_error)?;
            let body = provider_json_response(response, "Alipay payment query").await?;
            let trade = body
                .get("alipay_trade_query_response")
                .cloned()
                .unwrap_or(body);
            let response_code = trade
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !response_code.is_empty() && response_code != "10000" {
                // Alipay's documented "交易不存在" response is a terminal
                // provider observation for this order, not a made-up trade
                // id.  The reconcile layer will mark the local intent failed.
                if response_code == "40004" {
                    return Ok(PaymentQueryResult {
                        notification: PaymentNotification {
                            merchant_order_no: order.merchant_order_no.clone(),
                            provider_trade_id: String::new(),
                            amount_minor: order.amount_minor,
                            currency: order.currency.clone(),
                            paid_at: util::now_ts(),
                            status: PAYMENT_STATUS_FAILED.to_string(),
                        },
                    });
                }
                return Err(AppError::BadRequest(
                    "Alipay payment query was rejected".to_string(),
                ));
            }
            let trade_status = trade
                .get("trade_status")
                .and_then(Value::as_str)
                .ok_or_else(provider_outcome_unknown)?;
            let amount = trade
                .get("total_amount")
                .and_then(Value::as_str)
                .ok_or_else(provider_outcome_unknown)?;
            let amount_minor =
                parse_decimal_to_minor(amount, 2).map_err(|_| provider_outcome_unknown())?;
            Ok(PaymentQueryResult {
                notification: PaymentNotification {
                    merchant_order_no: order.merchant_order_no.clone(),
                    provider_trade_id: trade
                        .get("trade_no")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    amount_minor,
                    currency: CURRENCY_CNY.to_string(),
                    paid_at: util::now_ts(),
                    status: if matches!(trade_status, "TRADE_SUCCESS" | "TRADE_FINISHED") {
                        PAYMENT_STATUS_PAID
                    } else if trade_status == "TRADE_CLOSED" {
                        PAYMENT_STATUS_FAILED
                    } else {
                        PAYMENT_STATUS_PENDING
                    }
                    .to_string(),
                },
            })
        })
    }

    fn refund_payment<'a>(
        &'a self,
        order: &'a PaymentOrderRecord,
        amount_minor: i64,
        idempotency_key: &'a str,
    ) -> ProviderFuture<'a, ProviderRefundResult> {
        Box::pin(async move {
            let mut fields = BTreeMap::from([
                ("app_id".to_string(), self.config.app_id.clone()),
                ("method".to_string(), "alipay.trade.refund".to_string()),
                ("format".to_string(), "JSON".to_string()),
                ("charset".to_string(), "utf-8".to_string()),
                ("sign_type".to_string(), "RSA2".to_string()),
                ("timestamp".to_string(), chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()),
                ("version".to_string(), "1.0".to_string()),
                ("biz_content".to_string(), json!({"out_trade_no": order.merchant_order_no, "refund_amount": format_minor(amount_minor, 2), "out_request_no": provider_refund_request_id(idempotency_key)}).to_string()),
            ]);
            let sign_content = alipay_sign_content(&fields);
            fields.insert(
                "sign".to_string(),
                rsa_sha256_sign(&self.config.private_key_pem, &sign_content)?,
            );
            let response = self
                .client
                .get(&self.config.gateway_url)
                .query(&fields)
                .send()
                .await
                .map_err(provider_http_error)?;
            let body = provider_json_response(response, "Alipay refund").await?;
            let refund = body
                .get("alipay_trade_refund_response")
                .cloned()
                .unwrap_or(body);
            let code = refund
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if code != "10000" {
                if code.is_empty() {
                    return Err(provider_outcome_unknown());
                }
                return Err(AppError::BadRequest(
                    "Alipay refund was rejected".to_string(),
                ));
            }
            let provider_refund_id = refund
                .get("trade_no")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(provider_outcome_unknown)?;
            Ok(ProviderRefundResult {
                provider_refund_id: provider_refund_id.to_string(),
            })
        })
    }
}

struct WechatProvider {
    config: PaymentProviderSettings,
    client: Client,
}

fn wechat_base_url(config: &PaymentProviderSettings, path: &str) -> AppResult<String> {
    let base = config.gateway_url.trim_end_matches('/');
    if !base.starts_with("https://") {
        return Err(AppError::Configuration(
            "WeChat Pay gateway_url must use HTTPS".to_string(),
        ));
    }
    Ok(format!("{base}{path}"))
}

fn wechat_authorization(
    config: &PaymentProviderSettings,
    method: &str,
    url: &str,
    body: &str,
) -> AppResult<HeaderMap> {
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = util::random_token(16);
    let message = format!("{method}\n{url}\n{timestamp}\n{nonce}\n{body}\n");
    let signature = rsa_sha256_sign(&config.private_key_pem, &message)?;
    let mut headers = request_headers_with_json();
    headers.insert(
        "authorization",
        format!(
            "WECHATPAY2-SHA256-RSA2048 mchid=\"{}\",nonce_str=\"{}\",timestamp=\"{}\",serial_no=\"{}\",signature=\"{}\"",
            config.merchant_id, nonce, timestamp, config.certificate_serial_no, signature
        )
        .parse()
        .map_err(|_| AppError::Internal("invalid WeChat authorization header".to_string()))?,
    );
    Ok(headers)
}

fn verify_wechat_callback(
    config: &PaymentProviderSettings,
    request: &NotificationRequest<'_>,
) -> AppResult<Vec<u8>> {
    let timestamp = request
        .headers
        .get("wechatpay-timestamp")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let timestamp_value = timestamp
        .parse::<i64>()
        .map_err(|_| AppError::Unauthorized)?;
    if (chrono::Utc::now().timestamp() - timestamp_value).abs() > 300 {
        return Err(AppError::Unauthorized);
    }
    let nonce = request
        .headers
        .get("wechatpay-nonce")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let signature = request
        .headers
        .get("wechatpay-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let message = format!(
        "{timestamp}\n{nonce}\n{}\n",
        String::from_utf8_lossy(request.body)
    );
    let signature = STANDARD
        .decode(signature)
        .map_err(|_| AppError::Unauthorized)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(config.platform_certificate_pem.as_bytes())
        .map_err(|_| {
            AppError::Configuration("WeChat platform certificate is invalid".to_string())
        })?;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .map_err(|_| {
            AppError::Configuration("WeChat platform certificate is invalid".to_string())
        })?;
    let public_key =
        rsa::RsaPublicKey::from_public_key_der(certificate.tbs_certificate.subject_pki.raw)
            .map_err(|_| {
                AppError::Configuration(
                    "WeChat platform certificate does not contain an RSA key".to_string(),
                )
            })?;
    let digest = Sha256::digest(message.as_bytes());
    public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
        .map_err(|_| AppError::Unauthorized)?;
    Ok(request.body.to_vec())
}

fn decrypt_wechat_resource(config: &PaymentProviderSettings, resource: &Value) -> AppResult<Value> {
    let nonce = resource
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("WeChat notification has no nonce".to_string()))?;
    let associated_data = resource
        .get("associated_data")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ciphertext = resource
        .get("ciphertext")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("WeChat notification has no ciphertext".to_string()))?;
    if config.api_v3_key.len() != 32 || nonce.len() != 12 {
        return Err(AppError::Configuration(
            "WeChat API v3 key or nonce has invalid length".to_string(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(config.api_v3_key.as_bytes())
        .map_err(|_| AppError::Configuration("WeChat API v3 key is invalid".to_string()))?;
    let ciphertext = STANDARD
        .decode(ciphertext)
        .map_err(|_| AppError::Unauthorized)?;
    let nonce = Nonce::try_from(nonce.as_bytes())
        .map_err(|_| AppError::Configuration("WeChat notification nonce is invalid".to_string()))?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad: associated_data.as_bytes(),
            },
        )
        .map_err(|_| AppError::Unauthorized)?;
    serde_json::from_slice(&plaintext)
        .map_err(|_| AppError::BadRequest("WeChat notification plaintext is invalid".to_string()))
}

impl PaymentProvider for WechatProvider {
    fn slug(&self) -> &str {
        &self.config.slug
    }

    fn create_checkout<'a>(
        &'a self,
        request: &'a CheckoutRequest,
    ) -> ProviderFuture<'a, (String, String)> {
        Box::pin(async move {
            if request.currency != CURRENCY_CNY {
                return Err(AppError::BadRequest(
                    "WeChat Native currently supports CNY only".to_string(),
                ));
            }
            let url = wechat_base_url(&self.config, "/v3/pay/transactions/native")?;
            let body = json!({
                "appid": self.config.app_id,
                "mchid": self.config.merchant_id,
                "description": request.subject,
                "out_trade_no": request.merchant_order_no,
                "time_expire": chrono::DateTime::from_timestamp(request.expires_at, 0)
                    .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                "notify_url": request.notify_url,
                "amount": {"total": request.amount_minor, "currency": request.currency},
            });
            let body = body.to_string();
            let response = self
                .client
                .post(&url)
                .headers(wechat_authorization(
                    &self.config,
                    "POST",
                    "/v3/pay/transactions/native",
                    &body,
                )?)
                .body(body)
                .send()
                .await
                .map_err(provider_http_error)?;
            let payload = provider_json_response(response, "WeChat checkout").await?;
            let code_url = payload
                .get("code_url")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(provider_outcome_unknown)?;
            Ok(("qr".to_string(), code_url.to_string()))
        })
    }

    fn verify_notification<'a>(
        &'a self,
        request: NotificationRequest<'a>,
    ) -> ProviderFuture<'a, PaymentNotification> {
        Box::pin(async move {
            let verified = verify_wechat_callback(&self.config, &request)?;
            let envelope = json_fields(&verified)?;
            let resource = envelope.get("resource").ok_or_else(|| {
                AppError::BadRequest("WeChat notification has no resource".to_string())
            })?;
            let payload = decrypt_wechat_resource(&self.config, resource)?;
            if payload
                .get("mchid")
                .and_then(Value::as_str)
                .is_some_and(|value| value != self.config.merchant_id)
            {
                return Err(AppError::Unauthorized);
            }
            if payload
                .get("appid")
                .and_then(Value::as_str)
                .is_some_and(|value| value != self.config.app_id)
            {
                return Err(AppError::Unauthorized);
            }
            let order_no = payload
                .get("out_trade_no")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let trade_id = payload
                .get("transaction_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let amount_minor = payload
                .get("amount")
                .and_then(|value| value.get("total"))
                .and_then(Value::as_i64)
                .ok_or_else(|| {
                    AppError::BadRequest("WeChat notification amount is invalid".to_string())
                })?;
            let status = matches!(
                payload.get("trade_state").and_then(Value::as_str),
                Some("SUCCESS")
            )
            .then_some("paid")
            .unwrap_or("pending");
            Ok(PaymentNotification {
                merchant_order_no: order_no.to_string(),
                provider_trade_id: trade_id.to_string(),
                amount_minor,
                currency: payload
                    .get("amount")
                    .and_then(|value| value.get("currency"))
                    .and_then(Value::as_str)
                    .unwrap_or(CURRENCY_CNY)
                    .to_string(),
                paid_at: util::now_ts(),
                status: status.to_string(),
            })
        })
    }

    fn query_payment<'a>(
        &'a self,
        order: &'a PaymentOrderRecord,
    ) -> ProviderFuture<'a, PaymentQueryResult> {
        Box::pin(async move {
            let path = format!(
                "/v3/pay/transactions/out-trade-no/{}?mchid={}",
                order.merchant_order_no, self.config.merchant_id
            );
            let url = wechat_base_url(&self.config, &path)?;
            let response = self
                .client
                .get(&url)
                .headers(wechat_authorization(&self.config, "GET", &path, "")?)
                .send()
                .await
                .map_err(provider_http_error)?;
            let payload = provider_json_response(response, "WeChat payment query").await?;
            let trade_state = payload
                .get("trade_state")
                .and_then(Value::as_str)
                .ok_or_else(provider_outcome_unknown)?;
            let amount_minor = payload
                .get("amount")
                .and_then(|value| value.get("total"))
                .and_then(Value::as_i64)
                .ok_or_else(provider_outcome_unknown)?;
            let currency = payload
                .get("amount")
                .and_then(|value| value.get("currency"))
                .and_then(Value::as_str)
                .ok_or_else(provider_outcome_unknown)?;
            Ok(PaymentQueryResult {
                notification: PaymentNotification {
                    merchant_order_no: order.merchant_order_no.clone(),
                    provider_trade_id: payload
                        .get("transaction_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    amount_minor,
                    currency: currency.to_string(),
                    paid_at: util::now_ts(),
                    status: if trade_state == "SUCCESS" {
                        PAYMENT_STATUS_PAID
                    } else if matches!(trade_state, "CLOSED" | "REVOKED" | "PAYERROR") {
                        PAYMENT_STATUS_FAILED
                    } else {
                        PAYMENT_STATUS_PENDING
                    }
                    .to_string(),
                },
            })
        })
    }

    fn refund_payment<'a>(
        &'a self,
        order: &'a PaymentOrderRecord,
        amount_minor: i64,
        idempotency_key: &'a str,
    ) -> ProviderFuture<'a, ProviderRefundResult> {
        Box::pin(async move {
            let path = "/v3/refund/domestic/refunds";
            let url = wechat_base_url(&self.config, path)?;
            let refund_no = provider_refund_request_id(idempotency_key);
            let body = json!({
                "out_trade_no": order.merchant_order_no,
                "out_refund_no": refund_no,
                "reason": "Signet billing refund",
                "amount": {"refund": amount_minor, "total": order.amount_minor, "currency": order.currency},
            })
            .to_string();
            let response = self
                .client
                .post(&url)
                .headers(wechat_authorization(&self.config, "POST", path, &body)?)
                .body(body)
                .send()
                .await
                .map_err(provider_http_error)?;
            let payload = provider_json_response(response, "WeChat refund").await?;
            let provider_refund_id = payload
                .get("refund_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(provider_outcome_unknown)?;
            Ok(ProviderRefundResult {
                provider_refund_id: provider_refund_id.to_string(),
            })
        })
    }
}

fn provider_http_error(error: reqwest::Error) -> AppError {
    let reason = if error.is_timeout() {
        "provider request timed out"
    } else if error.is_connect() || error.is_request() {
        "provider network/request failed"
    } else {
        "provider transport outcome is unknown"
    };
    provider_outcome_unknown_with_reason(reason)
}
