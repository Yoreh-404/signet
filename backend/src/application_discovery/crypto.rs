use crate::error::AppResult;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const DISCOVERY_CHALLENGE_VERSION: &str = "v1";
const DISCOVERY_CHALLENGE_LABEL: &[u8] = b"signet:application-discovery-challenge:v1:";

#[derive(Debug, Clone, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    jwk: Option<PinnedJwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PinnedJwks {
    pub(super) keys: Vec<PinnedJwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PinnedJwk {
    pub(super) kty: String,
    pub(super) crv: String,
    pub(super) x: String,
    #[serde(default)]
    pub(super) kid: Option<String>,
    #[serde(rename = "use", default)]
    pub(super) use_: Option<String>,
    #[serde(default)]
    pub(super) alg: Option<String>,
}

pub(super) fn encode_challenge(
    secret: &str,
    origin: &str,
    issued_at: i64,
    ttl_seconds: i64,
    nonce: &str,
) -> AppResult<String> {
    let issued_at = issued_at.to_string();
    let ttl_seconds = ttl_seconds.to_string();
    let mac = challenge_mac(secret, origin, &issued_at, &ttl_seconds, nonce)?;
    Ok(format!(
        "{DISCOVERY_CHALLENGE_VERSION}.{issued_at}.{ttl_seconds}.{nonce}.{mac}"
    ))
}

pub(super) fn verify_challenge(
    secret: &str,
    origin: &str,
    challenge: &str,
    now: i64,
    max_ttl_seconds: i64,
) -> AppResult<()> {
    let parts = validate_challenge(challenge, max_ttl_seconds)?;
    let issued_at = parts[1].parse::<i64>().map_err(|_| invalid_challenge())?;
    let ttl_seconds = parts[2].parse::<i64>().map_err(|_| invalid_challenge())?;
    if issued_at > now.saturating_add(60)
        || issued_at
            .checked_add(ttl_seconds)
            .is_none_or(|expires_at| expires_at <= now)
    {
        return Err(crate::error::AppError::Unauthorized);
    }
    let provided = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|_| invalid_challenge())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| {
        crate::error::AppError::Configuration("invalid discovery challenge secret".into())
    })?;
    update_challenge_mac(&mut mac, origin, parts[1], parts[2], parts[3]);
    mac.verify_slice(&provided)
        .map_err(|_| crate::error::AppError::Unauthorized)
}

fn challenge_mac(
    secret: &str,
    origin: &str,
    issued_at: &str,
    ttl_seconds: &str,
    nonce: &str,
) -> AppResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| {
        crate::error::AppError::Configuration("invalid discovery challenge secret".into())
    })?;
    update_challenge_mac(&mut mac, origin, issued_at, ttl_seconds, nonce);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn update_challenge_mac(
    mac: &mut Hmac<Sha256>,
    origin: &str,
    issued_at: &str,
    ttl_seconds: &str,
    nonce: &str,
) {
    mac.update(DISCOVERY_CHALLENGE_LABEL);
    mac.update(origin.as_bytes());
    mac.update(b":");
    mac.update(issued_at.as_bytes());
    mac.update(b":");
    mac.update(ttl_seconds.as_bytes());
    mac.update(b":");
    mac.update(nonce.as_bytes());
}

fn validate_challenge(challenge: &str, max_ttl_seconds: i64) -> AppResult<[&str; 5]> {
    let parts = challenge.split('.').collect::<Vec<_>>();
    if parts.len() != 5
        || parts[0] != DISCOVERY_CHALLENGE_VERSION
        || parts[1].parse::<i64>().ok().is_none_or(|value| value <= 0)
        || parts[2]
            .parse::<i64>()
            .ok()
            .is_none_or(|value| !(1..=max_ttl_seconds).contains(&value))
        || parts[3].len() < 16
        || parts[3].len() > 128
        || !parts[3]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || URL_SAFE_NO_PAD
            .decode(parts[4])
            .ok()
            .is_none_or(|value| value.len() != 32)
    {
        return Err(invalid_challenge());
    }
    parts.try_into().map_err(|_| invalid_challenge())
}

fn invalid_challenge() -> crate::error::AppError {
    crate::error::AppError::BadRequest("discovery challenge is invalid".to_string())
}

pub(super) fn verify_jws(token: &str, pinned_jwks: &str) -> AppResult<Vec<u8>> {
    let (header, payload, signature, signing_input) = parse_jws(token)?;
    let key_set = serde_json::from_str::<PinnedJwks>(pinned_jwks)
        .map_err(|_| crate::error::AppError::Unauthorized)?;
    let candidates = key_set
        .keys
        .iter()
        .filter(|key| {
            key.kty == "OKP"
                && key.crv == "Ed25519"
                && key.use_.as_deref().is_none_or(|value| value == "sig")
                && key.alg.as_deref().is_none_or(|value| value == "EdDSA")
                && header
                    .kid
                    .as_deref()
                    .is_none_or(|kid| key.kid.as_deref() == Some(kid))
        })
        .collect::<Vec<_>>();
    let key = match (header.kid.as_deref(), candidates.as_slice()) {
        (_, []) => return Err(crate::error::AppError::Unauthorized),
        (Some(_), [key, ..]) => *key,
        (None, [key]) => *key,
        (None, _) => return Err(crate::error::AppError::Unauthorized),
    };
    verify_signature(&header, key, &signing_input, &signature)?;
    Ok(payload)
}

pub(super) fn verify_jws_with_embedded_key(token: &str) -> AppResult<(Vec<u8>, PinnedJwk)> {
    let (header, payload, signature, signing_input) = parse_jws(token)?;
    let key = header
        .jwk
        .clone()
        .ok_or(crate::error::AppError::Unauthorized)?;
    verify_signature(&header, &key, &signing_input, &signature)?;
    Ok((payload, key))
}

fn parse_jws(token: &str) -> AppResult<(JwsHeader, Vec<u8>, Signature, String)> {
    let mut parts = token.split('.');
    let encoded_header = parts.next().ok_or(crate::error::AppError::Unauthorized)?;
    let encoded_payload = parts.next().ok_or(crate::error::AppError::Unauthorized)?;
    let encoded_signature = parts.next().ok_or(crate::error::AppError::Unauthorized)?;
    if parts.next().is_some() {
        return Err(crate::error::AppError::Unauthorized);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| crate::error::AppError::Unauthorized)?;
    let header = serde_json::from_slice::<JwsHeader>(&header_bytes)
        .map_err(|_| crate::error::AppError::Unauthorized)?;
    if header.alg != "EdDSA" {
        return Err(crate::error::AppError::Unauthorized);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| crate::error::AppError::Unauthorized)?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| crate::error::AppError::Unauthorized)
        .and_then(|value| {
            Signature::from_slice(&value).map_err(|_| crate::error::AppError::Unauthorized)
        })?;
    Ok((
        header,
        payload,
        signature,
        format!("{encoded_header}.{encoded_payload}"),
    ))
}

fn verify_signature(
    header: &JwsHeader,
    key: &PinnedJwk,
    signing_input: &str,
    signature: &Signature,
) -> AppResult<()> {
    if key.kty != "OKP"
        || key.crv != "Ed25519"
        || key.use_.as_deref().is_some_and(|value| value != "sig")
        || key.alg.as_deref().is_some_and(|value| value != "EdDSA")
        || header.kid.is_some() && header.kid.as_deref() != key.kid.as_deref()
    {
        return Err(crate::error::AppError::Unauthorized);
    }
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&key.x)
        .map_err(|_| crate::error::AppError::Unauthorized)?
        .try_into()
        .map_err(|_| crate::error::AppError::Unauthorized)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| crate::error::AppError::Unauthorized)?;
    verifying_key
        .verify(signing_input.as_bytes(), signature)
        .map_err(|_| crate::error::AppError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    #[test]
    fn challenge_encoding_is_deterministic_and_origin_bound() {
        let secret = "01234567890123456789012345678901";
        let challenge = encode_challenge(
            secret,
            "https://axon.example",
            100,
            300,
            "nonce-123456789012",
        )
        .unwrap();
        assert_eq!(
            challenge,
            encode_challenge(
                secret,
                "https://axon.example",
                100,
                300,
                "nonce-123456789012"
            )
            .unwrap()
        );
        assert!(challenge.starts_with("v1.100.300.nonce-123456789012."));
        assert!(verify_challenge(secret, "https://axon.example", &challenge, 100, 900).is_ok());
        assert!(verify_challenge(secret, "https://other.example", &challenge, 100, 900).is_err());
    }

    #[test]
    fn pinned_jws_requires_matching_kid_when_present() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key-1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(b"payload");
        let input = format!("{header}.{payload}");
        let signature = signing_key.sign(input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                "kid": "key-2"
            }]
        });
        assert!(verify_jws(&token, &jwks.to_string()).is_err());
    }
}
