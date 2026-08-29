use crate::{
    config::Settings,
    error::{AppError, AppResult},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, net::SocketAddr};

pub fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn random_token(bytes: usize) -> String {
    let mut data = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut data);
    URL_SAFE_NO_PAD.encode(data)
}

pub fn generate_rsa_private_key_pem() -> AppResult<String> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|err| AppError::Configuration(format!("failed to generate RSA key: {err}")))?;
    private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|err| AppError::Configuration(format!("failed to encode RSA key: {err}")))
}

pub fn sha256_base64url(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|value| value.to_string())
        .map_err(|err| AppError::Internal(format!("failed to hash password: {err}")))
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn token_hash(token: &str) -> String {
    sha256_base64url(token)
}

/// Produces a keyed, domain-separated digest for application-local identity
/// uniqueness checks. Unlike a bare phone/email hash, this cannot be cheaply
/// enumerated from a database copy without the instance secret.
pub fn identity_factor_digest(secret: &str, factor_type: &str, value: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(b"signet:application-identity-factor:v1:");
    mac.update(factor_type.as_bytes());
    mac.update(b":");
    mac.update(value.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Domain-separates the short-lived authorization-code display secret from
/// every other use of the instance signing key.  The encrypted value is never
/// sent in a list response; it is only decrypted for an authorized, audited
/// management request.
const AUTHORIZATION_CODE_REVEAL_LABEL: &str = "gpt-sso:authorization-code-reveal:v1";

const DISCOVERY_SECRET_CIPHERTEXT_PREFIX: &str = "signet-discovery-secret:v1";
const DISCOVERY_SECRET_AAD: &[u8] = b"signet:discovery-fetch-secret:v1";

fn decode_discovery_key(value: &str) -> AppResult<[u8; 32]> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    let decoded = URL_SAFE_NO_PAD
        .decode(value.trim())
        .or_else(|_| STANDARD.decode(value.trim()))
        .map_err(|_| AppError::Configuration("discovery encryption key is invalid".to_string()))?;
    decoded.try_into().map_err(|_| {
        AppError::Configuration("discovery encryption key must be exactly 32 bytes".to_string())
    })
}

/// Encrypts a website Discovery fetch secret for database storage. The
/// plaintext is intentionally never returned after this function completes.
pub fn encrypt_discovery_secret(key: &str, secret: &str) -> AppResult<String> {
    if secret.is_empty() {
        return Err(AppError::BadRequest(
            "discovery fetch secret cannot be empty".to_string(),
        ));
    }
    let key = decode_discovery_key(key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Configuration("discovery encryption key is invalid".to_string()))?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| {
        AppError::Internal("failed to construct discovery encryption nonce".to_string())
    })?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: secret.as_bytes(),
                aad: DISCOVERY_SECRET_AAD,
            },
        )
        .map_err(|_| AppError::Internal("failed to encrypt discovery fetch secret".to_string()))?;
    Ok(format!(
        "{DISCOVERY_SECRET_CIPHERTEXT_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce_bytes),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

/// Decrypts a Discovery fetch secret only immediately before an outbound
/// request. Ciphertext and authentication failures intentionally share the
/// same error so they cannot become an oracle.
pub fn decrypt_discovery_secret(key: &str, ciphertext: &str) -> AppResult<String> {
    let mut parts = ciphertext.split('.');
    let prefix = parts.next();
    let nonce_part = parts.next();
    let ciphertext_part = parts.next();
    if prefix != Some(DISCOVERY_SECRET_CIPHERTEXT_PREFIX)
        || nonce_part.is_none()
        || ciphertext_part.is_none()
        || parts.next().is_some()
    {
        return Err(AppError::Configuration(
            "discovery fetch secret ciphertext is invalid".to_string(),
        ));
    }
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(nonce_part.unwrap_or_default())
        .map_err(|_| {
            AppError::Configuration("discovery fetch secret ciphertext is invalid".to_string())
        })?;
    let ciphertext_bytes = URL_SAFE_NO_PAD
        .decode(ciphertext_part.unwrap_or_default())
        .map_err(|_| {
            AppError::Configuration("discovery fetch secret ciphertext is invalid".to_string())
        })?;
    let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
        AppError::Configuration("discovery fetch secret ciphertext is invalid".to_string())
    })?;
    let key = decode_discovery_key(key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Configuration("discovery encryption key is invalid".to_string()))?;
    let nonce = Nonce::try_from(&nonce[..]).map_err(|_| {
        AppError::Configuration("discovery fetch secret ciphertext is invalid".to_string())
    })?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: &ciphertext_bytes,
                aad: DISCOVERY_SECRET_AAD,
            },
        )
        .map_err(|_| {
            AppError::Configuration("discovery fetch secret ciphertext is invalid".to_string())
        })?;
    String::from_utf8(plaintext).map_err(|_| {
        AppError::Configuration("discovery fetch secret ciphertext is invalid".to_string())
    })
}

/// Encrypts an administrator-visible authorization code at rest with RSA-OAEP
/// (SHA-256).  The signing-key record is used as protected server key material:
/// a signing-key database compromise already permits token forgery, so it is a
/// suitable trust boundary without adding a second plaintext secret to the
/// database.
pub fn encrypt_authorization_code_for_reveal(
    private_key_pem: &str,
    authorization_code: &str,
) -> AppResult<String> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|err| {
        AppError::Configuration(format!(
            "invalid RSA private key for authorization-code reveal encryption: {err}"
        ))
    })?;
    let public_key = RsaPublicKey::from(&private_key);
    let mut rng = OsRng;
    let ciphertext = public_key
        .encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha256, _>(AUTHORIZATION_CODE_REVEAL_LABEL),
            authorization_code.as_bytes(),
        )
        .map_err(|err| {
            AppError::Internal(format!(
                "failed to encrypt authorization code for reveal: {err}"
            ))
        })?;
    Ok(URL_SAFE_NO_PAD.encode(ciphertext))
}

/// Decrypts a code previously encrypted by
/// [`encrypt_authorization_code_for_reveal`].  This deliberately has no
/// fallback to `code_hash`: hashes remain one-way and legacy hash-only codes
/// cannot be revealed.
pub fn decrypt_authorization_code_for_reveal(
    private_key_pem: &str,
    encrypted_authorization_code: &str,
) -> AppResult<String> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|err| {
        AppError::Configuration(format!(
            "invalid RSA private key for authorization-code reveal decryption: {err}"
        ))
    })?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(encrypted_authorization_code)
        .map_err(|err| {
            AppError::Internal(format!("invalid encrypted authorization code: {err}"))
        })?;
    let plaintext = private_key
        .decrypt(
            Oaep::new_with_label::<Sha256, _>(AUTHORIZATION_CODE_REVEAL_LABEL),
            &ciphertext,
        )
        .map_err(|err| {
            AppError::Internal(format!("failed to decrypt authorization code: {err}"))
        })?;
    String::from_utf8(plaintext)
        .map_err(|err| AppError::Internal(format!("invalid decrypted authorization code: {err}")))
}

const SESSION_COOKIE_PREFIX: &str = "v2.";
const SESSION_ID_PREFIX: &str = "v2id.";

/// Generates a browser bearer and a separate non-bearer database identifier.
/// The database identifier stays internal, is separately derived again for an
/// OIDC `sid`, and must never be accepted as a session cookie.
pub fn new_session_credentials() -> (String, String) {
    let secret = random_token(32);
    let cookie_value = format!("{SESSION_COOKIE_PREFIX}{secret}");
    let id = format!(
        "{SESSION_ID_PREFIX}{}",
        sha256_base64url(&format!("gpt-sso:session-cookie:{secret}"))
    );
    (id, cookie_value)
}

/// Resolves current v2 cookies. Legacy database session identifiers are
/// intentionally rejected because older releases exposed them as OIDC `sid`
/// values; upgrading therefore invalidates existing browser sessions once.
pub fn session_id_from_cookie(cookie_value: &str) -> Option<String> {
    let secret = cookie_value.strip_prefix(SESSION_COOKIE_PREFIX)?;
    if secret.is_empty() {
        return None;
    }
    Some(format!(
        "{SESSION_ID_PREFIX}{}",
        sha256_base64url(&format!("gpt-sso:session-cookie:{secret}"))
    ))
}

/// Stable opaque handle for session management and OIDC logout correlation.
pub fn session_public_id(session_id: &str) -> String {
    format!(
        "sid.{}",
        sha256_base64url(&format!("gpt-sso:session-public:{session_id}"))
    )
}

pub fn verification_code() -> String {
    let mut bytes = [0_u8; 4];
    OsRng.fill_bytes(&mut bytes);
    let value = u32::from_be_bytes(bytes) % 1_000_000;
    format!("{value:06}")
}

pub fn request_ip(headers: &HeaderMap) -> Option<String> {
    forwarded_request_ip(headers)
}

pub fn request_ip_for(
    trust_proxy_headers: bool,
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
) -> Option<String> {
    if trust_proxy_headers {
        forwarded_request_ip(headers).or_else(|| remote_addr.map(|addr| addr.ip().to_string()))
    } else {
        remote_addr.map(|addr| addr.ip().to_string())
    }
}

fn forwarded_request_ip(headers: &HeaderMap) -> Option<String> {
    for name in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"] {
        if let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) {
            let first = value.split(',').next().unwrap_or(value).trim();
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    None
}

pub fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect())
}

pub fn external_base_url(settings: &Settings, headers: &HeaderMap, fallback: &str) -> String {
    external_base_url_for(settings.server.trust_proxy_headers, headers, fallback)
}

pub fn external_base_url_for(
    trust_proxy_headers: bool,
    headers: &HeaderMap,
    fallback: &str,
) -> String {
    let fallback = fallback.trim_end_matches('/');
    if !trust_proxy_headers {
        return fallback.to_string();
    }
    forwarded_base_url(headers, fallback).unwrap_or_else(|| fallback.to_string())
}

fn forwarded_base_url(headers: &HeaderMap, fallback: &str) -> Option<String> {
    if let Some((scheme, host)) = forwarded_header_parts(headers) {
        return build_base_url(&scheme, &host);
    }
    let scheme = first_header(headers, "x-forwarded-proto")
        .or_else(|| first_header(headers, "x-forwarded-scheme"))
        .or_else(|| first_header(headers, "x-url-scheme"))
        .or_else(|| {
            first_header(headers, "x-forwarded-ssl")
                .filter(|value| value.eq_ignore_ascii_case("on"))
                .map(|_| "https".to_string())
        })
        .unwrap_or_else(|| fallback_scheme(fallback).to_string());
    let host = first_header(headers, "x-forwarded-host")
        .or_else(|| first_header(headers, "host"))
        .or_else(|| {
            let forwarded_port = first_header(headers, "x-forwarded-port")?;
            fallback_host(fallback).map(|host| format!("{host}:{forwarded_port}"))
        })?;
    build_base_url(&scheme, &host)
}

fn forwarded_header_parts(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get("forwarded")?.to_str().ok()?;
    let first = value.split(',').next()?.trim();
    let mut proto = None;
    let mut host = None;
    for pair in first.split(';') {
        let Some((key, value)) = pair.trim().split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "proto" => proto = Some(value),
            "host" => host = Some(value),
            _ => {}
        }
    }
    Some((proto?, host?))
}

fn first_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn build_base_url(scheme: &str, host: &str) -> Option<String> {
    let scheme = scheme.trim().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = host.trim();
    if host.is_empty()
        || host
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '/')
    {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

fn fallback_scheme(value: &str) -> &str {
    if value.starts_with("https://") {
        "https"
    } else {
        "http"
    }
}

fn fallback_host(value: &str) -> Option<String> {
    value
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub fn url_decode(value: &str) -> String {
    url::form_urlencoded::parse(value.as_bytes())
        .map(|(key, _)| key.into_owned())
        .next()
        .unwrap_or_else(|| value.to_string())
}

pub fn to_json<T: Serialize>(value: &T) -> AppResult<String> {
    serde_json::to_string(value).map_err(|err| AppError::Internal(err.to_string()))
}

pub fn from_json<T: for<'de> Deserialize<'de>>(value: &str) -> AppResult<T> {
    serde_json::from_str(value).map_err(|err| AppError::Internal(err.to_string()))
}

pub fn check_pkce(
    challenge: Option<&str>,
    method: Option<&str>,
    verifier: Option<&str>,
    required: bool,
    require_s256: bool,
) -> AppResult<()> {
    if challenge.is_none() && !required {
        return Ok(());
    }
    let challenge =
        challenge.ok_or_else(|| AppError::Oidc("missing code challenge".to_string()))?;
    let verifier = verifier.ok_or_else(|| AppError::Oidc("missing code verifier".to_string()))?;
    if !is_valid_pkce_verifier(verifier) {
        return Err(AppError::Oidc("invalid code verifier".to_string()));
    }
    let method = method.unwrap_or("plain");
    if require_s256 && method != "S256" {
        return Err(AppError::Oidc("this client requires PKCE S256".to_string()));
    }
    let candidate = match method {
        "S256" => sha256_base64url(verifier),
        "plain" => verifier.to_string(),
        other => return Err(AppError::Oidc(format!("unsupported PKCE method: {other}"))),
    };
    if candidate == challenge {
        Ok(())
    } else {
        Err(AppError::Oidc("invalid code verifier".to_string()))
    }
}

/// RFC 7636 section 4.1: a code verifier is 43–128 characters from the
/// unreserved URI character set. Keep this check at the token boundary so a
/// malformed verifier can never be accepted by a legacy/plain client.
pub fn is_valid_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

pub fn normalize_scopes(requested: Option<&str>, supported: &[String]) -> AppResult<Vec<String>> {
    let scopes: Vec<String> = requested
        .unwrap_or("openid")
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if scopes.is_empty() || !scopes.iter().any(|scope| scope == "openid") {
        return Err(AppError::Oidc("scope must include openid".to_string()));
    }
    let supported_set = supported.iter().map(String::as_str).collect::<HashSet<_>>();
    for scope in &scopes {
        if !supported_set.contains(scope.as_str()) {
            return Err(AppError::Oidc(format!("unsupported scope: {scope}")));
        }
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_secret_is_separate_from_database_and_public_ids() {
        let (session_id, cookie_value) = new_session_credentials();
        assert!(session_id.starts_with("v2id."));
        assert!(cookie_value.starts_with("v2."));
        assert_ne!(session_id, cookie_value);
        assert_eq!(
            session_id_from_cookie(&cookie_value).as_deref(),
            Some(session_id.as_str())
        );
        assert!(session_id_from_cookie(&session_id).is_none());
        assert_ne!(session_public_id(&session_id), session_id);
    }

    #[test]
    fn legacy_session_cookie_is_rejected_after_security_upgrade() {
        let legacy = "legacy-session-bearer";
        assert!(session_id_from_cookie(legacy).is_none());
        assert!(session_id_from_cookie("v2.").is_none());
        assert_ne!(session_public_id(legacy), legacy);
    }

    #[test]
    fn forwarded_header_builds_external_base_url() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            r#"for=192.0.2.60;proto=https;host="oidc.example.test""#
                .parse()
                .unwrap(),
        );
        assert_eq!(
            forwarded_base_url(&headers, "http://localhost:8080").as_deref(),
            Some("https://oidc.example.test")
        );
    }

    #[test]
    fn x_forwarded_headers_build_external_base_url() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "oidc.example.test".parse().unwrap());
        assert_eq!(
            forwarded_base_url(&headers, "http://localhost:8080").as_deref(),
            Some("https://oidc.example.test")
        );
    }

    #[test]
    fn request_ip_for_respects_proxy_trust() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        let remote = "192.0.2.10:443".parse().unwrap();
        assert_eq!(
            request_ip_for(false, &headers, Some(remote)).as_deref(),
            Some("192.0.2.10")
        );
        assert_eq!(
            request_ip_for(true, &headers, Some(remote)).as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn invalid_host_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "bad host".parse().unwrap());
        assert!(forwarded_base_url(&headers, "http://localhost:8080").is_none());
    }

    #[test]
    fn pkce_verifier_uses_rfc7636_bounds_and_character_set() {
        assert!(is_valid_pkce_verifier(&"a".repeat(43)));
        assert!(is_valid_pkce_verifier(&"~._-A9".repeat(8)[..48]));
        assert!(!is_valid_pkce_verifier(&"a".repeat(42)));
        assert!(!is_valid_pkce_verifier(&"a".repeat(129)));
        assert!(!is_valid_pkce_verifier(&format!("{}=", "a".repeat(42))));
        assert!(!is_valid_pkce_verifier(&format!("{} ", "a".repeat(42))));
    }

    #[test]
    fn check_pkce_enforces_verifier_and_current_s256_policy() {
        let verifier = "v".repeat(43);
        let challenge = sha256_base64url(&verifier);
        assert!(check_pkce(Some(&challenge), Some("S256"), Some(&verifier), true, true,).is_ok());
        assert!(check_pkce(Some(&verifier), Some("plain"), Some(&verifier), true, true,).is_err());
        assert!(check_pkce(Some("short"), Some("plain"), Some("short"), true, false,).is_err());
    }
}
