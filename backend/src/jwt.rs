use crate::{
    config::Settings,
    db::{ClientRecord, SigningKeyRecord, UserRecord},
    error::{AppError, AppResult},
    util,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct JwtManager {
    default_issuer: String,
    key_set: Arc<RwLock<JwtKeySet>>,
}

struct JwtKeySet {
    active_key: Arc<KeyMaterial>,
    keys: Vec<Arc<KeyMaterial>>,
}

struct KeyMaterial {
    kid: String,
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    jwk: Jwk,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub token_use: String,
    pub client_id: String,
    pub scope: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub preferred_username: String,
    pub nonce: Option<String>,
    pub auth_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpt_sso_login_code_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationClaim {
    pub jkt: String,
}

#[derive(Debug, Clone)]
pub struct TokenSubject<'a> {
    pub user: &'a UserRecord,
    pub client_id: &'a str,
    pub audience: Option<&'a str>,
    pub scope: &'a str,
    pub nonce: Option<&'a str>,
    pub auth_time: Option<i64>,
}

impl JwtManager {
    pub fn from_signing_keys(
        settings: &Settings,
        records: Vec<SigningKeyRecord>,
    ) -> AppResult<Self> {
        let key_set = build_key_set(records)?;
        Ok(Self {
            default_issuer: settings.oidc.issuer.clone(),
            key_set: Arc::new(RwLock::new(key_set)),
        })
    }

    pub fn new(settings: &Settings) -> AppResult<Self> {
        let private_key_pem = if settings.security.rsa_private_key_pem.trim().is_empty() {
            util::generate_rsa_private_key_pem()?
        } else {
            settings.security.rsa_private_key_pem.clone()
        };
        let record = SigningKeyRecord {
            id: "config".to_string(),
            kid: settings.security.key_id.clone(),
            private_key_pem,
            is_active: 1,
            created_at: util::now_ts(),
            activated_at: Some(util::now_ts()),
            retired_at: None,
        };
        Self::from_signing_keys(settings, vec![record])
    }

    pub fn active_kid(&self) -> String {
        self.key_set
            .read()
            .map(|set| set.active_key.kid.clone())
            .unwrap_or_default()
    }

    pub fn key_count(&self) -> usize {
        self.key_set.read().map(|set| set.keys.len()).unwrap_or(0)
    }

    pub fn reload(&self, records: Vec<SigningKeyRecord>) -> AppResult<()> {
        let key_set = build_key_set(records)?;
        let mut guard = self
            .key_set
            .write()
            .map_err(|_| AppError::Internal("signing key set lock poisoned".to_string()))?;
        *guard = key_set;
        Ok(())
    }

    pub fn jwks(&self) -> Jwks {
        let Ok(guard) = self.key_set.read() else {
            return Jwks { keys: Vec::new() };
        };
        Jwks {
            keys: guard.keys.iter().map(|key| key.jwk.clone()).collect(),
        }
    }
}

fn build_key_set(records: Vec<SigningKeyRecord>) -> AppResult<JwtKeySet> {
    let mut keys = Vec::with_capacity(records.len());
    let mut active_key = None;
    for record in records {
        let material = Arc::new(KeyMaterial::from_record(&record)?);
        if record.is_active == 1 && active_key.is_none() {
            active_key = Some(material.clone());
        }
        keys.push(material);
    }
    let active_key = active_key
        .ok_or_else(|| AppError::Configuration("no active signing key is available".to_string()))?;
    Ok(JwtKeySet { active_key, keys })
}

impl KeyMaterial {
    fn from_record(record: &SigningKeyRecord) -> AppResult<Self> {
        Self::from_pem(record.kid.clone(), &record.private_key_pem)
    }

    fn from_pem(kid: String, private_key_pem: &str) -> AppResult<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .map_err(|err| AppError::Configuration(format!("invalid RSA private key: {err}")))?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|err| {
                AppError::Configuration(format!("failed to encode public key: {err}"))
            })?;
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|err| AppError::Configuration(format!("invalid RSA encoding key: {err}")))?;
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|err| AppError::Configuration(format!("invalid RSA decoding key: {err}")))?;
        let jwk = Jwk {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            kid: kid.clone(),
            alg: "RS256".to_string(),
            n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        };
        Ok(Self {
            kid,
            encoding_key: Arc::new(encoding_key),
            decoding_key: Arc::new(decoding_key),
            jwk,
        })
    }
}

impl JwtManager {
    pub fn sign_authorization_response(
        &self,
        issuer: &str,
        audience: &str,
        ttl_seconds: i64,
        mut claims: Map<String, Value>,
    ) -> AppResult<String> {
        let now = util::now_ts();
        claims.insert(
            "iss".to_string(),
            Value::String(issuer.trim_end_matches('/').to_string()),
        );
        claims.insert("aud".to_string(), Value::String(audience.to_string()));
        claims.insert("exp".to_string(), Value::Number((now + ttl_seconds).into()));
        claims.insert("iat".to_string(), Value::Number(now.into()));
        let key_set = self
            .key_set
            .read()
            .map_err(|_| AppError::Internal("signing key set lock poisoned".to_string()))?;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_set.active_key.kid.clone());
        encode(&header, &claims, &key_set.active_key.encoding_key).map_err(|err| {
            AppError::Internal(format!("failed to sign authorization response: {err}"))
        })
    }

    pub fn sign_logout_token(
        &self,
        issuer: &str,
        audience: &str,
        subject: &str,
        sid: Option<&str>,
        ttl_seconds: i64,
    ) -> AppResult<String> {
        let now = util::now_ts();
        let mut claims = Map::new();
        claims.insert(
            "iss".to_string(),
            Value::String(issuer.trim_end_matches('/').to_string()),
        );
        claims.insert("sub".to_string(), Value::String(subject.to_string()));
        claims.insert("aud".to_string(), Value::String(audience.to_string()));
        claims.insert("iat".to_string(), Value::Number(now.into()));
        claims.insert("exp".to_string(), Value::Number((now + ttl_seconds).into()));
        claims.insert("jti".to_string(), Value::String(util::random_token(24)));
        if let Some(sid) = sid.filter(|value| !value.trim().is_empty()) {
            claims.insert("sid".to_string(), Value::String(sid.to_string()));
        }
        let mut events = Map::new();
        events.insert(
            crate::backchannel_logout::LOGOUT_EVENT.to_string(),
            Value::Object(Map::new()),
        );
        claims.insert("events".to_string(), Value::Object(events));
        let key_set = self
            .key_set
            .read()
            .map_err(|_| AppError::Internal("signing key set lock poisoned".to_string()))?;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_set.active_key.kid.clone());
        encode(&header, &claims, &key_set.active_key.encoding_key)
            .map_err(|err| AppError::Internal(format!("failed to sign logout token: {err}")))
    }

    pub fn sign_id_token(&self, subject: TokenSubject<'_>, ttl_seconds: i64) -> AppResult<String> {
        self.sign_with_issuer(&self.default_issuer, subject, ttl_seconds, "id_token")
    }

    pub fn sign_id_token_with_issuer(
        &self,
        issuer: &str,
        subject: TokenSubject<'_>,
        ttl_seconds: i64,
    ) -> AppResult<String> {
        self.sign_with_issuer(issuer, subject, ttl_seconds, "id_token")
    }

    pub fn sign_id_token_with_issuer_and_claims(
        &self,
        issuer: &str,
        subject: TokenSubject<'_>,
        ttl_seconds: i64,
        extra_claims: Map<String, Value>,
    ) -> AppResult<String> {
        self.sign_with_issuer_and_claims(
            issuer,
            subject,
            ttl_seconds,
            "id_token",
            extra_claims,
            None,
        )
    }

    pub fn sign_id_token_with_subject_and_claims(
        &self,
        issuer: &str,
        subject: TokenSubject<'_>,
        subject_identifier: &str,
        ttl_seconds: i64,
        extra_claims: Map<String, Value>,
    ) -> AppResult<String> {
        self.sign_with_issuer_and_claims(
            issuer,
            subject,
            ttl_seconds,
            "id_token",
            extra_claims,
            Some(subject_identifier),
        )
    }

    pub fn sign_access_token(
        &self,
        subject: TokenSubject<'_>,
        ttl_seconds: i64,
    ) -> AppResult<String> {
        self.sign_with_issuer(&self.default_issuer, subject, ttl_seconds, "access_token")
    }

    pub fn sign_access_token_with_issuer(
        &self,
        issuer: &str,
        subject: TokenSubject<'_>,
        ttl_seconds: i64,
    ) -> AppResult<String> {
        self.sign_with_issuer(issuer, subject, ttl_seconds, "access_token")
    }

    pub fn sign_access_token_with_issuer_and_claims(
        &self,
        issuer: &str,
        subject: TokenSubject<'_>,
        ttl_seconds: i64,
        extra_claims: Map<String, Value>,
    ) -> AppResult<String> {
        self.sign_with_issuer_and_claims(
            issuer,
            subject,
            ttl_seconds,
            "access_token",
            extra_claims,
            None,
        )
    }

    pub fn sign_client_access_token_with_issuer(
        &self,
        issuer: &str,
        client: &ClientRecord,
        scope: &str,
        audience: Option<&str>,
        ttl_seconds: i64,
    ) -> AppResult<String> {
        self.sign_client_access_token_with_issuer_and_claims(
            issuer,
            client,
            scope,
            audience,
            ttl_seconds,
            Map::new(),
        )
    }

    pub fn sign_client_access_token_with_issuer_and_claims(
        &self,
        issuer: &str,
        client: &ClientRecord,
        scope: &str,
        audience: Option<&str>,
        ttl_seconds: i64,
        extra_claims: Map<String, Value>,
    ) -> AppResult<String> {
        let now = util::now_ts();
        let key_set = self
            .key_set
            .read()
            .map_err(|_| AppError::Internal("signing key set lock poisoned".to_string()))?;
        let claims = TokenClaims {
            iss: issuer.trim_end_matches('/').to_string(),
            sub: client.client_id.clone(),
            aud: audience.unwrap_or(&client.client_id).to_string(),
            exp: now + ttl_seconds,
            iat: now,
            token_use: "access_token".to_string(),
            client_id: client.client_id.clone(),
            scope: scope.to_string(),
            email: String::new(),
            email_verified: false,
            name: Some(client.client_name.clone()),
            preferred_username: client.client_id.clone(),
            nonce: None,
            auth_time: None,
            sid: None,
            cnf: None,
            authorization_details: None,
            gpt_sso_login_code_level: None,
        };
        let mut claims_value = serde_json::to_value(claims)
            .map_err(|err| AppError::Internal(format!("failed to encode claims: {err}")))?;
        let claims_object = claims_value.as_object_mut().ok_or_else(|| {
            AppError::Internal("token claims did not encode as object".to_string())
        })?;
        claims_object.extend(extra_claims);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_set.active_key.kid.clone());
        encode(&header, &claims_value, &key_set.active_key.encoding_key)
            .map_err(|err| AppError::Internal(format!("failed to sign token: {err}")))
    }

    pub fn verify_access_token(&self, token: &str) -> AppResult<TokenClaims> {
        self.verify_access_token_with_issuers(token, &[self.default_issuer.as_str()])
    }

    pub fn verify_access_token_with_issuers(
        &self,
        token: &str,
        issuers: &[&str],
    ) -> AppResult<TokenClaims> {
        self.verify_token_with_issuers(token, issuers, "access_token", true)
    }

    pub fn verify_id_token_hint_with_issuers(
        &self,
        token: &str,
        issuers: &[&str],
    ) -> AppResult<TokenClaims> {
        self.verify_token_with_issuers(token, issuers, "id_token", false)
    }

    fn verify_token_with_issuers(
        &self,
        token: &str,
        issuers: &[&str],
        token_use: &str,
        validate_exp: bool,
    ) -> AppResult<TokenClaims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(issuers);
        validation.validate_aud = false;
        validation.validate_exp = validate_exp;
        let kid = decode_header(token).ok().and_then(|header| header.kid);
        let key_set = self
            .key_set
            .read()
            .map_err(|_| AppError::Internal("signing key set lock poisoned".to_string()))?;
        let mut candidate_keys = key_set.keys.iter().collect::<Vec<_>>();
        if let Some(kid) = kid {
            candidate_keys.sort_by_key(|key| if key.kid == kid { 0 } else { 1 });
        }
        let mut last_error = None;
        let token = candidate_keys
            .into_iter()
            .find_map(
                |key| match decode::<TokenClaims>(token, &key.decoding_key, &validation) {
                    Ok(value) => Some(value),
                    Err(err) => {
                        last_error = Some(err);
                        None
                    }
                },
            )
            .ok_or_else(|| {
                let _ = last_error;
                AppError::Unauthorized
            })?;
        if token.claims.token_use != token_use {
            return Err(AppError::Unauthorized);
        }
        Ok(token.claims)
    }

    fn sign_with_issuer(
        &self,
        issuer: &str,
        subject: TokenSubject<'_>,
        ttl_seconds: i64,
        token_use: &str,
    ) -> AppResult<String> {
        self.sign_with_issuer_and_claims(issuer, subject, ttl_seconds, token_use, Map::new(), None)
    }

    fn sign_with_issuer_and_claims(
        &self,
        issuer: &str,
        subject: TokenSubject<'_>,
        ttl_seconds: i64,
        token_use: &str,
        extra_claims: Map<String, Value>,
        subject_identifier: Option<&str>,
    ) -> AppResult<String> {
        let now = util::now_ts();
        let key_set = self
            .key_set
            .read()
            .map_err(|_| AppError::Internal("signing key set lock poisoned".to_string()))?;
        let claims = TokenClaims {
            iss: issuer.trim_end_matches('/').to_string(),
            sub: subject_identifier
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| subject.user.id.clone()),
            aud: subject.audience.unwrap_or(subject.client_id).to_string(),
            exp: now + ttl_seconds,
            iat: now,
            token_use: token_use.to_string(),
            client_id: subject.client_id.to_string(),
            scope: subject.scope.to_string(),
            email: subject.user.email.clone(),
            email_verified: subject.user.email_verified_at.is_some(),
            name: subject
                .user
                .display_name
                .clone()
                .or_else(|| Some(subject.user.username.clone())),
            preferred_username: subject.user.username.clone(),
            nonce: subject.nonce.map(ToOwned::to_owned),
            auth_time: subject.auth_time,
            sid: None,
            cnf: None,
            authorization_details: None,
            gpt_sso_login_code_level: None,
        };
        let mut claims_value = serde_json::to_value(claims)
            .map_err(|err| AppError::Internal(format!("failed to encode claims: {err}")))?;
        let claims_object = claims_value.as_object_mut().ok_or_else(|| {
            AppError::Internal("token claims did not encode as object".to_string())
        })?;
        claims_object.extend(extra_claims);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_set.active_key.kid.clone());
        encode(&header, &claims_value, &key_set.active_key.encoding_key)
            .map_err(|err| AppError::Internal(format!("failed to sign token: {err}")))
    }
}

#[cfg(test)]
mod tests {
    use super::TokenClaims;

    #[test]
    fn legacy_token_claims_without_login_code_level_still_decode() {
        let claims: TokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "https://sso.example",
            "sub": "user-id",
            "aud": "client-id",
            "exp": 2,
            "iat": 1,
            "token_use": "access_token",
            "client_id": "client-id",
            "scope": "openid",
            "email": "user@example.com",
            "email_verified": true,
            "name": "User",
            "preferred_username": "user",
            "nonce": null,
            "auth_time": null
        }))
        .expect("legacy claims should remain compatible");

        assert_eq!(claims.gpt_sso_login_code_level, None);
    }
}
