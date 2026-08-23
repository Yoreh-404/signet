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
use std::collections::BTreeSet;
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
    /// A stable token identifier for audit and downstream revocation lists.
    /// Signet access tokens remain short-lived bearer credentials; this field
    /// is not, by itself, a replay cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    pub token_use: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_profile_id: Option<String>,
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
    /// RFC 8693 actor chain.  The value is kept as JSON because the claim is
    /// an object and a later exchange may add another actor layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Value>,
    /// Opaque reference to the authorization grant/consent lineage.  It is
    /// deliberately distinct from jti: exchanged tokens retain the grant
    /// reference while receiving a fresh jti.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
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
    let mut seen_kids = BTreeSet::new();
    let mut active_count = 0;
    for record in records {
        if !seen_kids.insert(record.kid.clone()) {
            return Err(AppError::Configuration(format!(
                "duplicate signing key id: {}",
                record.kid
            )));
        }
        let material = Arc::new(KeyMaterial::from_record(&record)?);
        if record.is_active == 1 {
            active_count += 1;
            active_key = Some(material.clone());
        }
        keys.push(material);
    }
    if active_count != 1 {
        return Err(AppError::Configuration(
            "exactly one active signing key is required".to_string(),
        ));
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
        if kid.trim().is_empty()
            || kid.len() > 128
            || kid.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(AppError::Configuration(
                "signing key id must be 1-128 printable characters".to_string(),
            ));
        }
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
        let jti = util::random_token(24);
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
            jti: Some(jti.clone()),
            token_use: "access_token".to_string(),
            client_id: client.client_id.clone(),
            application_id: extra_claims
                .get("application_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            authorization_profile_id: extra_claims
                .get("authorization_profile_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
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
            act: None,
            grant_id: Some(jti),
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
        self.verify_token_with_issuers(token, issuers, "access_token", true, None)
    }

    /// Verifies an access token for token exchange after issuer/signature
    /// validation. Token exchange is an issuer-level capability: the subject
    /// token may have been issued for another resource, while the exchange
    /// policy separately constrains the requested target audience.
    pub fn verify_access_token_for_token_exchange(
        &self,
        token: &str,
        issuers: &[&str],
    ) -> AppResult<TokenClaims> {
        self.verify_access_token_with_issuers(token, issuers)
    }

    /// Verifies an access token for RFC 7662 introspection. Introspection is
    /// not a resource endpoint, so a token's `aud` may be an RFC 8707
    /// resource. The handler must still bind the result to the authenticated
    /// introspection client using `claims.client_id`.
    pub fn verify_access_token_for_introspection(
        &self,
        token: &str,
        issuers: &[&str],
    ) -> AppResult<TokenClaims> {
        self.verify_access_token_with_issuers(token, issuers)
    }

    /// Verifies a bearer token for a caller that has no concrete resource
    /// context. This is deliberately audience-free and must not be used by a
    /// protocol/resource endpoint that can name its expected audience.
    pub fn verify_access_token_for_generic_bearer(
        &self,
        token: &str,
        issuers: &[&str],
    ) -> AppResult<TokenClaims> {
        self.verify_access_token_with_issuers(token, issuers)
    }

    /// Verifies an access token for a concrete resource or client audience.
    /// Callers that know the resource they protect should use this method.
    pub fn verify_access_token_with_issuers_and_audiences(
        &self,
        token: &str,
        issuers: &[&str],
        audiences: &[String],
    ) -> AppResult<TokenClaims> {
        self.verify_token_with_issuers(token, issuers, "access_token", true, Some(audiences))
    }

    pub fn verify_id_token_hint_with_issuers(
        &self,
        token: &str,
        issuers: &[&str],
    ) -> AppResult<TokenClaims> {
        self.verify_token_with_issuers(token, issuers, "id_token", false, None)
    }

    /// Performs the first, audience-free verification needed by RP-initiated
    /// logout to discover the client whose ID token was presented. The logout
    /// handler must immediately repeat verification with that client's
    /// audience before accepting the hint.
    pub fn verify_id_token_hint_for_logout_bootstrap(
        &self,
        token: &str,
        issuers: &[&str],
    ) -> AppResult<TokenClaims> {
        self.verify_id_token_hint_with_issuers(token, issuers)
    }

    pub fn verify_id_token_hint_with_issuers_and_audiences(
        &self,
        token: &str,
        issuers: &[&str],
        audiences: &[String],
    ) -> AppResult<TokenClaims> {
        self.verify_token_with_issuers(token, issuers, "id_token", false, Some(audiences))
    }

    fn verify_token_with_issuers(
        &self,
        token: &str,
        issuers: &[&str],
        token_use: &str,
        validate_exp: bool,
        audiences: Option<&[String]>,
    ) -> AppResult<TokenClaims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(issuers);
        if let Some(audiences) = audiences {
            if audiences.is_empty() {
                return Err(AppError::Unauthorized);
            }
            validation.set_audience(audiences);
        } else {
            validation.validate_aud = false;
        }
        validation.validate_exp = validate_exp;
        let header = decode_header(token).map_err(|_| AppError::Unauthorized)?;
        if header.alg != Algorithm::RS256 {
            return Err(AppError::Unauthorized);
        }
        let key_set = self
            .key_set
            .read()
            .map_err(|_| AppError::Internal("signing key set lock poisoned".to_string()))?;
        let candidate_keys = if let Some(kid) = header.kid.as_deref() {
            let matching = key_set
                .keys
                .iter()
                .filter(|key| key.kid == kid)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                return Err(AppError::Unauthorized);
            }
            matching
        } else {
            key_set.keys.iter().collect::<Vec<_>>()
        };
        let token = candidate_keys
            .into_iter()
            .find_map(|key| decode::<TokenClaims>(token, &key.decoding_key, &validation).ok())
            .ok_or(AppError::Unauthorized)?;
        let now = util::now_ts();
        if token.claims.iat > now + 60 || token.claims.exp < token.claims.iat {
            return Err(AppError::Unauthorized);
        }
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
        let jti = util::random_token(24);
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
            jti: Some(jti.clone()),
            token_use: token_use.to_string(),
            client_id: subject.client_id.to_string(),
            application_id: extra_claims
                .get("application_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            authorization_profile_id: extra_claims
                .get("authorization_profile_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
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
            act: None,
            grant_id: Some(jti),
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
    use super::{JwtManager, TokenClaims};
    use crate::{db::SigningKeyRecord, util};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::sync::{Arc, RwLock};

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

    #[test]
    fn key_set_rejects_duplicate_kids_and_multiple_active_keys() {
        let pem = util::generate_rsa_private_key_pem().unwrap();
        let first = signing_key("key-a", &pem, 1);
        assert!(super::build_key_set(vec![first.clone(), first]).is_err());

        let second = signing_key("key-b", &pem, 1);
        assert!(super::build_key_set(vec![second, signing_key("key-c", &pem, 1)]).is_err());
    }

    #[test]
    fn token_verification_enforces_audience_and_unknown_kid_is_rejected() {
        let pem = util::generate_rsa_private_key_pem().unwrap();
        let key_set = super::build_key_set(vec![signing_key("key-a", &pem, 1)]).unwrap();
        let manager = JwtManager {
            default_issuer: "https://issuer.example".to_string(),
            key_set: Arc::new(RwLock::new(key_set)),
        };
        let user = crate::db::UserRecord {
            id: "user-id".to_string(),
            email: "user@example.test".to_string(),
            username: "user".to_string(),
            display_name: None,
            phone: None,
            password_hash: String::new(),
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: 0,
            is_active: 1,
            archived_at: None,
            registration_source: "local".to_string(),
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        };
        let token = manager
            .sign_access_token_with_issuer(
                "https://issuer.example",
                super::TokenSubject {
                    user: &user,
                    client_id: "client-a",
                    audience: Some("https://api.example"),
                    scope: "openid",
                    nonce: None,
                    auth_time: None,
                },
                300,
            )
            .unwrap();
        assert!(
            manager
                .verify_access_token_with_issuers_and_audiences(
                    &token,
                    &["https://issuer.example"],
                    &["https://api.example".to_string()],
                )
                .is_ok()
        );
        assert!(
            manager
                .verify_access_token_with_issuers_and_audiences(
                    &token,
                    &["https://issuer.example"],
                    &["https://other.example".to_string()],
                )
                .is_err()
        );

        let claims = serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "user-id",
            "aud": "https://api.example",
            "exp": util::now_ts() + 300,
            "iat": util::now_ts(),
            "jti": "unknown-kid-jti",
            "token_use": "access_token",
            "client_id": "client-a",
            "scope": "openid",
            "email": "user@example.test",
            "email_verified": false,
            "preferred_username": "user"
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("unknown".to_string());
        let unknown_kid_token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(
            manager
                .verify_access_token_with_issuers(&unknown_kid_token, &["https://issuer.example"])
                .is_err()
        );
    }

    fn signing_key(kid: &str, private_key_pem: &str, is_active: i32) -> SigningKeyRecord {
        SigningKeyRecord {
            id: kid.to_string(),
            kid: kid.to_string(),
            private_key_pem: private_key_pem.to_string(),
            is_active,
            created_at: 1,
            activated_at: (is_active == 1).then_some(1),
            retired_at: (is_active == 1).then_some(0),
        }
    }
}
