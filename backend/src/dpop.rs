use crate::{
    AppState,
    error::{AppError, AppResult},
    util,
};
use axum::http::{HeaderMap, Method, StatusCode};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const TOKEN_TYPE: &str = "DPoP";
pub const PROOF_HEADER: &str = "dpop";
pub const SUPPORTED_SIGNING_ALGS: &[&str] = &["RS256"];

const PROOF_WINDOW_SECONDS: i64 = 300;
const MAX_PROOF_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct DpopBinding {
    pub jkt: String,
}

#[derive(Debug, Deserialize)]
struct ProofHeader {
    typ: Option<String>,
    alg: String,
    jwk: ProofJwk,
}

#[derive(Debug, Clone, Deserialize)]
struct ProofJwk {
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    kid: Option<String>,
    n: String,
    e: String,
    d: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProofClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    ath: Option<String>,
    nonce: Option<String>,
}

pub(crate) async fn optional_token_endpoint_proof(
    state: &AppState,
    headers: &HeaderMap,
    endpoint_path: &str,
) -> AppResult<Option<DpopBinding>> {
    if headers.get(PROOF_HEADER).is_none() {
        return Ok(None);
    }
    validate_endpoint_proof(state, headers, &Method::POST, endpoint_path, None)
        .await
        .map(Some)
}

pub(crate) async fn validate_access_token_proof(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    endpoint_path: &str,
    access_token: &str,
    expected_jkt: &str,
) -> AppResult<()> {
    let binding =
        validate_endpoint_proof(state, headers, method, endpoint_path, Some(access_token)).await?;
    if binding.jkt == expected_jkt {
        Ok(())
    } else {
        Err(invalid_dpop_proof(
            "DPoP proof key does not match access token",
        ))
    }
}

pub(crate) fn cnf_claim(binding: &DpopBinding) -> Value {
    serde_json::json!({ "jkt": binding.jkt })
}

pub(crate) fn token_type(binding: Option<&DpopBinding>) -> &'static str {
    if binding.is_some() {
        TOKEN_TYPE
    } else {
        "Bearer"
    }
}

pub(crate) fn access_token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

async fn validate_endpoint_proof(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    endpoint_path: &str,
    access_token: Option<&str>,
) -> AppResult<DpopBinding> {
    let proof = proof_header(headers)?;
    let header = decode_proof_header(proof)?;
    validate_header(&header)?;
    let key = DecodingKey::from_rsa_components(&header.jwk.n, &header.jwk.e)
        .map_err(|_| invalid_dpop_proof("DPoP proof key is invalid"))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let claims = decode::<ProofClaims>(proof, &key, &validation)
        .map_err(|_| invalid_dpop_proof("DPoP proof signature is invalid"))?
        .claims;
    validate_claims(state, headers, method, endpoint_path, access_token, &claims).await?;
    let jkt = jwk_thumbprint(&header.jwk)?;
    state
        .db
        .insert_dpop_proof_jti(&jkt, &claims.jti, util::now_ts() + PROOF_WINDOW_SECONDS)
        .await
        .map_err(|_| invalid_dpop_proof("DPoP proof was already used"))?;
    Ok(DpopBinding { jkt })
}

async fn validate_claims(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    endpoint_path: &str,
    access_token: Option<&str>,
    claims: &ProofClaims,
) -> AppResult<()> {
    if claims.jti.trim().is_empty() {
        return Err(invalid_dpop_proof("DPoP proof jti is required"));
    }
    let now = util::now_ts();
    if claims.iat > now + 60 || claims.iat < now - PROOF_WINDOW_SECONDS {
        return Err(invalid_dpop_proof(
            "DPoP proof iat is outside the allowed window",
        ));
    }
    if claims.htm != method.as_str().to_ascii_uppercase() {
        return Err(invalid_dpop_proof(
            "DPoP proof htm does not match request method",
        ));
    }
    let expected_htu = endpoint_urls(state, headers, endpoint_path).await?;
    if !expected_htu.iter().any(|value| value == &claims.htu) {
        return Err(invalid_dpop_proof(
            "DPoP proof htu does not match request URI",
        ));
    }
    if let Some(token) = access_token
        && claims.ath.as_deref() != Some(access_token_hash(token).as_str())
    {
        return Err(invalid_dpop_proof(
            "DPoP proof ath does not match access token",
        ));
    }
    let _ = &claims.nonce;
    Ok(())
}

fn proof_header(headers: &HeaderMap) -> AppResult<&str> {
    let proof = headers
        .get(PROOF_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_dpop_proof("DPoP proof header is required"))?;
    if proof.len() > MAX_PROOF_BYTES {
        return Err(invalid_dpop_proof("DPoP proof is too large"));
    }
    Ok(proof)
}

fn decode_proof_header(proof: &str) -> AppResult<ProofHeader> {
    let header = proof
        .split('.')
        .next()
        .ok_or_else(|| invalid_dpop_proof("DPoP proof header is missing"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| invalid_dpop_proof("DPoP proof header is not base64url"))?;
    serde_json::from_slice::<ProofHeader>(&bytes)
        .map_err(|_| invalid_dpop_proof("DPoP proof header is invalid"))
}

fn validate_header(header: &ProofHeader) -> AppResult<()> {
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(invalid_dpop_proof("DPoP proof typ must be dpop+jwt"));
    }
    if header.alg != "RS256" {
        return Err(invalid_dpop_proof("unsupported DPoP proof alg"));
    }
    if header.jwk.kty != "RSA"
        || header
            .jwk
            .use_
            .as_deref()
            .is_some_and(|value| value != "sig")
        || header
            .jwk
            .alg
            .as_deref()
            .is_some_and(|value| value != "RS256")
        || header.jwk.d.is_some()
    {
        return Err(invalid_dpop_proof(
            "DPoP proof jwk is not a public RSA signing key",
        ));
    }
    let _ = &header.jwk.kid;
    Ok(())
}

fn jwk_thumbprint(jwk: &ProofJwk) -> AppResult<String> {
    let canonical = format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, jwk.e, jwk.n);
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

async fn endpoint_urls(
    state: &AppState,
    headers: &HeaderMap,
    endpoint_path: &str,
) -> AppResult<Vec<String>> {
    let mut urls = state
        .accepted_issuers(headers)
        .await?
        .into_iter()
        .map(|issuer| absolute(&issuer, endpoint_path))
        .collect::<Vec<_>>();
    urls.sort();
    urls.dedup();
    Ok(urls)
}

fn absolute(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            }
        )
    }
}

fn invalid_dpop_proof(description: &str) -> AppError {
    AppError::oauth("invalid_dpop_proof", description, StatusCode::UNAUTHORIZED)
}

pub(crate) fn add_cnf_claim(claims: &mut Map<String, Value>, binding: Option<&DpopBinding>) {
    if let Some(binding) = binding {
        claims.insert("cnf".to_string(), cnf_claim(binding));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_hash_is_base64url_sha256() {
        assert_eq!(
            access_token_hash("abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn rsa_thumbprint_uses_canonical_jwk_members() {
        let jwk = ProofJwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            alg: Some("RS256".to_string()),
            kid: None,
            n: "abc".to_string(),
            e: "AQAB".to_string(),
            d: None,
        };
        let expected =
            URL_SAFE_NO_PAD.encode(Sha256::digest(br#"{"e":"AQAB","kty":"RSA","n":"abc"}"#));
        assert_eq!(jwk_thumbprint(&jwk).unwrap(), expected);
    }
}
