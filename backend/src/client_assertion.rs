use crate::{
    AppState,
    db::ClientRecord,
    error::{AppError, AppResult},
    util,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::lookup_host;
use url::Url;

pub const PRIVATE_KEY_JWT: &str = "private_key_jwt";
pub const CLIENT_SECRET_JWT: &str = "client_secret_jwt";
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub const SUPPORTED_SIGNING_ALGS: &[&str] = &["RS256"];
pub const TOKEN_ENDPOINT_AUTH_SIGNING_ALGS: &[&str] = &["RS256", "HS256"];

const MAX_ASSERTION_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 512 * 1024;
const MAX_ASSERTION_TTL_SECONDS: i64 = 600;
const CLIENT_SECRET_JWT_MATERIAL_PREFIX: &str = "client_secret_jwt:v1:";

#[derive(Debug, Clone, Deserialize)]
struct ClientJwks {
    keys: Vec<ClientJwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientJwk {
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    kid: Option<String>,
    alg: Option<String>,
    n: String,
    e: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientAssertionPreview {
    iss: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    aud: AssertionAudience,
    exp: i64,
    iat: Option<i64>,
    nbf: Option<i64>,
    jti: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum AssertionAudience {
    One(String),
    Many(Vec<String>),
}

pub fn client_id_from_assertion(assertion: &str) -> AppResult<String> {
    ensure_assertion_size(assertion)?;
    let payload = assertion_payload(assertion)?;
    let preview = serde_json::from_slice::<ClientAssertionPreview>(&payload)
        .map_err(|_| AppError::Unauthorized)?;
    if preview.iss.trim().is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok(preview.iss)
}

pub fn normalize_jwks_json(value: &str) -> AppResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let json = serde_json::from_str::<Value>(trimmed)
        .map_err(|err| AppError::BadRequest(format!("client jwks is invalid JSON: {err}")))?;
    let jwks = serde_json::from_value::<ClientJwks>(json.clone())
        .map_err(|err| AppError::BadRequest(format!("client jwks is invalid: {err}")))?;
    validate_jwks(&jwks)?;
    serde_json::to_string(&json)
        .map_err(|err| AppError::Internal(format!("failed to encode client jwks: {err}")))
}

pub fn validate_jwks_uri(value: &str) -> AppResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let url = Url::parse(trimmed)
        .map_err(|err| AppError::BadRequest(format!("client jwks_uri is invalid: {err}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AppError::BadRequest(
            "client jwks_uri must be an absolute http(s) URL without credentials".to_string(),
        ));
    }
    if let Some(host) = url.host_str()
        && host_is_private_or_local(host)
    {
        return Err(AppError::BadRequest(
            "client jwks_uri must not target a private or local address".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

pub fn validate_key_source(auth_method: &str, jwks_uri: &str, jwks: &str) -> AppResult<()> {
    validate_jwks_uri(jwks_uri)?;
    normalize_jwks_json(jwks)?;
    if auth_method == PRIVATE_KEY_JWT && jwks_uri.trim().is_empty() && jwks.trim().is_empty() {
        return Err(AppError::BadRequest(
            "private_key_jwt clients require jwks or jwks_uri".to_string(),
        ));
    }
    Ok(())
}

pub fn store_client_secret(auth_method: &str, secret: &str) -> AppResult<Option<String>> {
    match auth_method {
        "none" | PRIVATE_KEY_JWT => Ok(None),
        CLIENT_SECRET_JWT => Ok(Some(encode_client_secret_jwt_material(secret)?)),
        "client_secret_basic" | "client_secret_post" => util::hash_password(secret).map(Some),
        _ => Err(AppError::BadRequest(
            "unsupported token_endpoint_auth_method".to_string(),
        )),
    }
}

pub fn stored_secret_supports_method(auth_method: &str, material: Option<&str>) -> bool {
    let Some(material) = material else {
        return false;
    };
    match auth_method {
        CLIENT_SECRET_JWT => decode_client_secret_jwt_material(material).is_ok(),
        "client_secret_basic" | "client_secret_post" => {
            !material.starts_with(CLIENT_SECRET_JWT_MATERIAL_PREFIX)
        }
        _ => false,
    }
}

pub async fn authenticate_private_key_jwt(
    state: &AppState,
    client: &ClientRecord,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
    accepted_audiences: &[String],
) -> AppResult<()> {
    if assertion_type != Some(JWT_BEARER_ASSERTION_TYPE) {
        return Err(AppError::Unauthorized);
    }
    let assertion = assertion.ok_or(AppError::Unauthorized)?;
    let claims = verify_signed_client_jwt(
        client,
        assertion,
        accepted_audiences,
        &["iss", "sub", "aud", "exp"],
        true,
    )
    .await?;
    validate_claims(&client.client_id, &claims)?;
    state
        .db
        .insert_client_assertion_jti(&client.client_id, &claims.jti, claims.exp)
        .await
        .map_err(|_| AppError::Unauthorized)
}

pub async fn authenticate_client_secret_jwt(
    state: &AppState,
    client: &ClientRecord,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
    accepted_audiences: &[String],
) -> AppResult<()> {
    if assertion_type != Some(JWT_BEARER_ASSERTION_TYPE) {
        return Err(AppError::Unauthorized);
    }
    let assertion = assertion.ok_or(AppError::Unauthorized)?;
    let secret = client
        .client_secret_hash
        .as_deref()
        .ok_or(AppError::Unauthorized)
        .and_then(decode_client_secret_jwt_material)
        .map_err(|_| AppError::Unauthorized)?;
    let claims = verify_client_secret_jwt_with_secret(
        &client.client_id,
        assertion,
        accepted_audiences,
        &secret,
    )?;
    validate_claims(&client.client_id, &claims)?;
    state
        .db
        .insert_client_assertion_jti(&client.client_id, &claims.jti, claims.exp)
        .await
        .map_err(|_| AppError::Unauthorized)
}

pub(crate) async fn verify_signed_client_jwt<T>(
    client: &ClientRecord,
    token: &str,
    accepted_audiences: &[String],
    required_spec_claims: &[&str],
    validate_nbf: bool,
) -> AppResult<T>
where
    T: DeserializeOwned,
{
    let jwks = load_client_jwks(client).await?;
    verify_signed_client_jwt_with_jwks(
        &client.client_id,
        token,
        accepted_audiences,
        required_spec_claims,
        validate_nbf,
        &jwks,
    )
}

/// Verifies a signed integration document with a client's registered public
/// JWKS while using an issuer chosen by the integration protocol.  Client
/// assertions bind `iss` to the OAuth client id; signed website manifests
/// instead bind it to the website origin, so they need this separate context.
pub async fn verify_signed_jwt_for_issuer<T>(
    client: &ClientRecord,
    token: &str,
    accepted_audiences: &[String],
    issuer: &str,
    required_spec_claims: &[&str],
) -> AppResult<T>
where
    T: DeserializeOwned,
{
    let jwks = load_client_jwks(client).await?;
    verify_signed_jwt_with_jwks(
        token,
        accepted_audiences,
        issuer,
        required_spec_claims,
        true,
        &jwks,
    )
}

async fn load_client_jwks(client: &ClientRecord) -> AppResult<ClientJwks> {
    if !client.jwks.trim().is_empty() {
        let jwks =
            serde_json::from_str::<ClientJwks>(&client.jwks).map_err(|_| AppError::Unauthorized)?;
        validate_jwks(&jwks).map_err(|_| AppError::Unauthorized)?;
        return Ok(jwks);
    }
    let jwks_uri = client.jwks_uri.trim();
    if jwks_uri.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let (jwks_url, resolved_address) = resolve_public_jwks_url(jwks_uri).await?;
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());
    if let (Some(host), Some(address)) = (jwks_url.host_str(), resolved_address) {
        // Pin the DNS answer which was checked above. This prevents a simple
        // DNS rebinding between validation and the actual request.
        client_builder = client_builder.resolve(host, address);
    }
    let client = client_builder
        .build()
        .map_err(|err| AppError::Internal(format!("failed to build jwks client: {err}")))?;
    let mut response = client
        .get(jwks_url)
        .send()
        .await
        .map_err(|_| AppError::Unauthorized)?;
    if !response.status().is_success() {
        return Err(AppError::Unauthorized);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
    {
        return Err(AppError::Unauthorized);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Unauthorized)? {
        if body.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
            return Err(AppError::Unauthorized);
        }
        body.extend_from_slice(&chunk);
    }
    let jwks = serde_json::from_slice::<ClientJwks>(&body).map_err(|_| AppError::Unauthorized)?;
    validate_jwks(&jwks).map_err(|_| AppError::Unauthorized)?;
    Ok(jwks)
}

async fn resolve_public_jwks_url(value: &str) -> AppResult<(Url, Option<SocketAddr>)> {
    let url = Url::parse(value).map_err(|_| AppError::Unauthorized)?;
    validate_jwks_uri(value).map_err(|_| AppError::Unauthorized)?;
    let Some(host) = url.host_str() else {
        return Err(AppError::Unauthorized);
    };
    let port = url.port_or_known_default().ok_or(AppError::Unauthorized)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if forbidden_remote_ip(ip) {
            return Err(AppError::Unauthorized);
        }
        return Ok((url, None));
    }
    let addresses = lookup_host((host, port))
        .await
        .map_err(|_| AppError::Unauthorized)?
        .collect::<Vec<_>>();
    let Some(first) = addresses.first().copied() else {
        return Err(AppError::Unauthorized);
    };
    if addresses
        .iter()
        .any(|address| forbidden_remote_ip(address.ip()))
    {
        return Err(AppError::Unauthorized);
    }
    Ok((url, Some(first)))
}

fn host_is_private_or_local(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(forbidden_remote_ip)
        .unwrap_or(false)
}

fn forbidden_remote_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| forbidden_remote_ip(IpAddr::V4(mapped)))
        }
    }
}

fn verify_signed_client_jwt_with_jwks<T>(
    client_id: &str,
    token: &str,
    accepted_audiences: &[String],
    required_spec_claims: &[&str],
    validate_nbf: bool,
    jwks: &ClientJwks,
) -> AppResult<T>
where
    T: DeserializeOwned,
{
    verify_signed_jwt_with_jwks(
        token,
        accepted_audiences,
        client_id,
        required_spec_claims,
        validate_nbf,
        jwks,
    )
}

fn verify_signed_jwt_with_jwks<T>(
    token: &str,
    accepted_audiences: &[String],
    issuer: &str,
    required_spec_claims: &[&str],
    validate_nbf: bool,
    jwks: &ClientJwks,
) -> AppResult<T>
where
    T: DeserializeOwned,
{
    ensure_assertion_size(token)?;
    if accepted_audiences.is_empty() || issuer.trim().is_empty() {
        return Err(AppError::Unauthorized);
    }
    let header = decode_header(token).map_err(|_| AppError::Unauthorized)?;
    if header.alg != Algorithm::RS256 {
        return Err(AppError::Unauthorized);
    }
    let key = select_decoding_key(jwks, header.kid.as_deref())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(required_spec_claims);
    validation.set_issuer(&[issuer]);
    validation.set_audience(accepted_audiences);
    validation.validate_nbf = validate_nbf;
    let claims = decode::<T>(token, &key, &validation)
        .map_err(|_| AppError::Unauthorized)?
        .claims;
    Ok(claims)
}

fn verify_client_secret_jwt_with_secret(
    client_id: &str,
    token: &str,
    accepted_audiences: &[String],
    secret: &[u8],
) -> AppResult<ClientAssertionClaims> {
    ensure_assertion_size(token)?;
    if accepted_audiences.is_empty() || secret.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let header = decode_header(token).map_err(|_| AppError::Unauthorized)?;
    if header.alg != Algorithm::HS256 {
        return Err(AppError::Unauthorized);
    }
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
    validation.set_issuer(&[client_id]);
    validation.set_audience(accepted_audiences);
    validation.validate_nbf = true;
    decode::<ClientAssertionClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map_err(|_| AppError::Unauthorized)
        .map(|data| data.claims)
}

fn validate_claims(client_id: &str, claims: &ClientAssertionClaims) -> AppResult<()> {
    if claims.iss != client_id || claims.sub != client_id {
        return Err(AppError::Unauthorized);
    }
    if claims.jti.trim().is_empty() {
        return Err(AppError::Unauthorized);
    }
    let now = util::now_ts();
    if let Some(iat) = claims.iat
        && iat > now + 60
    {
        return Err(AppError::Unauthorized);
    }
    if claims.exp > now + MAX_ASSERTION_TTL_SECONDS {
        return Err(AppError::Unauthorized);
    }
    let _ = &claims.aud;
    let _ = claims.nbf;
    Ok(())
}

fn encode_client_secret_jwt_material(secret: &str) -> AppResult<String> {
    if secret.is_empty() {
        return Err(AppError::BadRequest(
            "client_secret is required for client_secret_jwt".to_string(),
        ));
    }
    Ok(format!(
        "{}{}",
        CLIENT_SECRET_JWT_MATERIAL_PREFIX,
        URL_SAFE_NO_PAD.encode(secret.as_bytes())
    ))
}

fn decode_client_secret_jwt_material(material: &str) -> AppResult<Vec<u8>> {
    let encoded = material
        .strip_prefix(CLIENT_SECRET_JWT_MATERIAL_PREFIX)
        .ok_or(AppError::Unauthorized)?;
    let secret = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized)?;
    if secret.is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok(secret)
}

fn select_decoding_key(jwks: &ClientJwks, kid: Option<&str>) -> AppResult<DecodingKey> {
    let candidates = jwks
        .keys
        .iter()
        .filter(|key| is_supported_key(key, kid))
        .collect::<Vec<_>>();
    let key = match (kid, candidates.as_slice()) {
        (_, []) => return Err(AppError::Unauthorized),
        (Some(_), [key, ..]) => *key,
        (None, [key]) => *key,
        (None, _) => return Err(AppError::Unauthorized),
    };
    DecodingKey::from_rsa_components(&key.n, &key.e).map_err(|_| AppError::Unauthorized)
}

fn is_supported_key(key: &ClientJwk, kid: Option<&str>) -> bool {
    key.kty == "RSA"
        && key.use_.as_deref().is_none_or(|value| value == "sig")
        && key.alg.as_deref().is_none_or(|value| value == "RS256")
        && kid.is_none_or(|kid| key.kid.as_deref() == Some(kid))
}

fn validate_jwks(jwks: &ClientJwks) -> AppResult<()> {
    if !jwks.keys.iter().any(|key| is_supported_key(key, None)) {
        return Err(AppError::BadRequest(
            "client jwks must include at least one RSA signing key for RS256".to_string(),
        ));
    }
    Ok(())
}

fn ensure_assertion_size(assertion: &str) -> AppResult<()> {
    if assertion.len() > MAX_ASSERTION_BYTES {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

fn assertion_payload(assertion: &str) -> AppResult<Vec<u8>> {
    let mut parts = assertion.split('.');
    let _header = parts.next().ok_or(AppError::Unauthorized)?;
    let payload = parts.next().ok_or(AppError::Unauthorized)?;
    if parts.next().is_none() || parts.next().is_some() {
        return Err(AppError::Unauthorized);
    }
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AppError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
        jti: &'a str,
    }

    #[test]
    fn private_key_jwt_assertion_verifies_against_inline_jwks() {
        let private_pem = util::generate_rsa_private_key_pem().unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_pem).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let jwks = ClientJwks {
            keys: vec![ClientJwk {
                kty: "RSA".to_string(),
                use_: Some("sig".to_string()),
                kid: Some("test-key".to_string()),
                alg: Some("RS256".to_string()),
                n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }],
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_string());
        let now = util::now_ts();
        let token = encode(
            &header,
            &TestClaims {
                iss: "client-a",
                sub: "client-a",
                aud: "https://sso.example.com/oauth2/token",
                exp: now + 120,
                iat: now,
                jti: "assertion-1",
            },
            &EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap(),
        )
        .unwrap();
        let claims = verify_signed_client_jwt_with_jwks::<ClientAssertionClaims>(
            "client-a",
            &token,
            &["https://sso.example.com/oauth2/token".to_string()],
            &["iss", "sub", "aud", "exp"],
            true,
            &jwks,
        )
        .unwrap();
        validate_claims("client-a", &claims).unwrap();
        assert_eq!(claims.jti, "assertion-1");
        assert_eq!(client_id_from_assertion(&token).unwrap(), "client-a");
    }

    #[test]
    fn client_secret_jwt_assertion_verifies_against_shared_secret() {
        let secret = "client-shared-secret";
        let material = store_client_secret(CLIENT_SECRET_JWT, secret)
            .unwrap()
            .unwrap();
        assert!(stored_secret_supports_method(
            CLIENT_SECRET_JWT,
            Some(&material)
        ));
        assert!(!stored_secret_supports_method(
            "client_secret_basic",
            Some(&material)
        ));
        let now = util::now_ts();
        let token = encode(
            &Header::new(Algorithm::HS256),
            &TestClaims {
                iss: "client-a",
                sub: "client-a",
                aud: "https://sso.example.com/oauth2/token",
                exp: now + 120,
                iat: now,
                jti: "assertion-2",
            },
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let decoded_secret = decode_client_secret_jwt_material(&material).unwrap();
        let claims = verify_client_secret_jwt_with_secret(
            "client-a",
            &token,
            &["https://sso.example.com/oauth2/token".to_string()],
            &decoded_secret,
        )
        .unwrap();
        validate_claims("client-a", &claims).unwrap();
        assert_eq!(claims.jti, "assertion-2");
        assert_eq!(client_id_from_assertion(&token).unwrap(), "client-a");
    }

    #[test]
    fn jwks_json_must_have_supported_key() {
        let err = normalize_jwks_json(r#"{"keys":[]}"#).unwrap_err();
        assert!(err.to_string().contains("RSA signing key"));
    }

    #[test]
    fn jwks_uri_rejects_local_and_credentialed_endpoints() {
        assert!(validate_jwks_uri("http://127.0.0.1/keys").is_err());
        assert!(validate_jwks_uri("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_jwks_uri("https://user:secret@example.test/keys").is_err());
        assert!(validate_jwks_uri("https://keys.example.test/jwks").is_ok());
    }
}
