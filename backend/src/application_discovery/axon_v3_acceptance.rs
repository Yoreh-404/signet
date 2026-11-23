//! Offline verification only. No operator command, storage, or token projection
//! consumes this yet; V2 enrollment is not V3 approval.
#![allow(dead_code)]

use super::{crypto::PinnedJwks, normalize_permission_key, website_origin};
use crate::error::{AppError, AppResult};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const POLICY_FORMAT: &str = "axon.signet.application-admin.policy.v3";
const ACCEPTANCE_FORMAT: &str = "axon.signet.application-admin.acceptance.v3";
const ACCEPTANCE_TYP: &str = "axon-signet-admin-acceptance-v3+jwt";

/// Supplied by separately approved V3 registration and the independently
/// retained current rollback floor, never derived from either untrusted input.
pub(super) struct TrustedRegistration<'a> {
    pub organization_id: &'a str,
    pub enrollment_id: &'a str,
    pub application_id: &'a str,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub audience: &'a str,
    pub origin: &'a str,
    pub permissions: &'a [String],
    pub approval_audience: &'a str,
    pub approval_jwks: &'a str,
    pub floor: &'a TrustedFloor<'a>,
}

pub(super) struct TrustedFloor<'a> {
    pub policy_sha256: &'a str,
    pub revision: i64,
    pub generation: i64,
    pub halted: bool,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct StablePolicy {
    format: String,
    pub organization_id: String,
    pub enrollment_id: String,
    pub application_id: String,
    pub issuer: String,
    pub client_id: String,
    pub audience: String,
    pub origin: String,
    pub revision: i64,
    pub generation: i64,
    pub permissions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acceptance {
    format: String,
    policy_sha256: String,
    revision: i64,
    generation: i64,
    aud: String,
    iat: i64,
    exp: i64,
}

fn exact_https_origin(value: &str) -> bool {
    value.starts_with("https://") && website_origin(value).is_ok_and(|origin| origin == value)
}

pub(super) fn verify_acceptance(
    policy_bytes: &[u8], approval: &str, trusted: &TrustedRegistration<'_>, now: i64,
) -> AppResult<StablePolicy> {
    let deny = || AppError::Unauthorized;
    if policy_bytes.len() > 65_536 || approval.len() > 8192 || trusted.floor.halted {
        return Err(deny());
    }
    let stable: StablePolicy = serde_json::from_slice(policy_bytes).map_err(|_| deny())?;
    let digest = format!("sha256:{:x}", Sha256::digest(policy_bytes));
    if stable.format != POLICY_FORMAT || digest != trusted.floor.policy_sha256
        || stable.revision <= 0 || stable.revision != trusted.floor.revision
        || stable.generation <= 0 || stable.generation != trusted.floor.generation
        || stable.organization_id.is_empty() || stable.organization_id != trusted.organization_id
        || stable.application_id.is_empty() || stable.application_id != trusted.application_id
        || stable.enrollment_id.is_empty() || stable.enrollment_id != trusted.enrollment_id
        || stable.client_id.is_empty() || stable.client_id != trusted.client_id
        || stable.audience.is_empty() || stable.audience != trusted.audience
        || !exact_https_origin(&stable.origin) || stable.origin != trusted.origin
        || !exact_https_origin(&stable.issuer) || stable.issuer != trusted.issuer
        || stable.permissions.is_empty() || stable.permissions != trusted.permissions
        || !stable.permissions.iter().all(|p| normalize_permission_key(p).is_ok_and(|n| n == *p))
        || stable.permissions.iter().collect::<BTreeSet<_>>().len() != stable.permissions.len()
    {
        return Err(deny());
    }
    let (signing_input, encoded_signature) = approval.rsplit_once('.').ok_or_else(deny)?;
    let (encoded_header, encoded_payload) = signing_input.split_once('.').ok_or_else(deny)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded_header).map_err(|_| deny())?;
    let header: Header = serde_json::from_slice(&bytes).map_err(|_| deny())?;
    if header.alg != "EdDSA" || header.typ != ACCEPTANCE_TYP || header.kid.is_empty() {
        return Err(deny());
    }
    let keyring: PinnedJwks = serde_json::from_str(trusted.approval_jwks).map_err(|_| deny())?;
    let mut keys = keyring.keys.iter().filter(|key| key.kid.as_deref() == Some(header.kid.as_str()));
    let key = keys.next().ok_or_else(deny)?;
    if keys.next().is_some() || key.kty != "OKP" || key.crv != "Ed25519"
        || key.use_.as_deref().is_some_and(|usage| usage != "sig")
        || key.alg.as_deref().is_some_and(|alg| alg != "EdDSA")
    {
        return Err(deny());
    }
    let public: [u8; 32] = URL_SAFE_NO_PAD.decode(&key.x).map_err(|_| deny())?
        .try_into().map_err(|_| deny())?;
    let key = VerifyingKey::from_bytes(&public).map_err(|_| deny())?;
    let signature = URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|_| deny())?;
    let signature = Signature::from_slice(&signature).map_err(|_| deny())?;
    key.verify_strict(signing_input.as_bytes(), &signature).map_err(|_| deny())?;
    let payload = URL_SAFE_NO_PAD.decode(encoded_payload).map_err(|_| deny())?;
    let signed: Acceptance = serde_json::from_slice(&payload).map_err(|_| deny())?;
    if signed.format != ACCEPTANCE_FORMAT || signed.policy_sha256 != digest
        || signed.revision != stable.revision || signed.generation != stable.generation
        || signed.aud.is_empty() || signed.aud != trusted.approval_audience
        || signed.iat <= 0 || signed.iat > now || signed.exp <= now
        || !signed.exp.checked_sub(signed.iat).is_some_and(|lifetime| (1..=900).contains(&lifetime))
    {
        return Err(deny());
    }
    Ok(stable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    fn sign(raw: &str, seed: u8, header: &str) -> String {
        let signing_input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(raw));
        let key = SigningKey::from_bytes(&[seed; 32]);
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()).to_bytes()))
    }

    fn policy() -> Value {
        json!({
            "format": POLICY_FORMAT, "organization_id": "example-org",
            "enrollment_id": "enrollment", "application_id": "axon",
            "issuer": "https://signet.example", "client_id": "bound-client",
            "audience": "https://axon.example/admin", "origin": "https://axon.example",
            "revision": 4, "generation": 7, "permissions": ["admin:session:read"]
        })
    }

    const HEADER: &str = r#"{"alg":"EdDSA","typ":"axon-signet-admin-acceptance-v3+jwt","kid":"approval"}"#;

    fn verify_case(
        raw: &str,
        change: impl FnOnce(&mut Value),
        seed: u8,
        header: &str,
        floor: (i64, i64, bool),
        now: i64,
    ) -> AppResult<StablePolicy> {
        let digest = format!("sha256:{:x}", Sha256::digest(raw));
        let mut claims = json!({
            "format": ACCEPTANCE_FORMAT, "policy_sha256": digest, "revision": 4,
            "generation": 7, "aud": "signet-verifier", "iat": 1000, "exp": 1900
        });
        change(&mut claims);
        let approval = sign(&claims.to_string(), seed, header);
        verify_raw(raw, &approval, &digest, floor, now, SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes())
    }

    fn verify_raw(raw: &str, approval: &str, digest: &str, floor: (i64, i64, bool), now: i64, public: &[u8; 32])
        -> AppResult<StablePolicy>
    {
        let jwks = json!({"keys":[{"kty":"OKP","crv":"Ed25519",
            "kid":"approval","x":URL_SAFE_NO_PAD.encode(public)}]}).to_string();
        verify_acceptance(raw.as_bytes(), approval, &TrustedRegistration {
            organization_id: "example-org", enrollment_id: "enrollment", application_id: "axon",
            issuer: "https://signet.example", client_id: "bound-client",
            audience: "https://axon.example/admin", origin: "https://axon.example",
            permissions: &["admin:session:read".into()], approval_audience: "signet-verifier",
            approval_jwks: &jwks, floor: &TrustedFloor {
                policy_sha256: digest, revision: floor.0, generation: floor.1, halted: floor.2,
            },
        }, now)
    }

    #[test]
    fn accepts_exact_policy_but_only_live_acceptance() {
        let raw = policy().to_string();
        assert!(verify_case(&raw, |_| {}, 9, HEADER, (4, 7, false), 1899).is_ok());
        for now in [999, 1900] {
            assert!(verify_case(&raw, |_| {}, 9, HEADER, (4, 7, false), now).is_err());
        }
        for field in ["iat", "exp", "expires_at"] {
            let mut p = policy();
            p[field] = json!(1900);
            assert!(verify_case(&p.to_string(), |_| {}, 9, HEADER, (4, 7, false), 1100).is_err());
        }
    }

    #[test]
    fn denies_changed_authority_signer_or_floor() {
        let raw = policy().to_string();
        for (field, value) in [("org", "other-org"), ("issuer", "https://other.example"),
            ("origin", "https://axon.example/"), ("client_id", "ordinary-client"),
            ("audience", "foreign"), ("application_id", "other"), ("enrollment_id", "stale")] {
            let mut p = policy();
            p[if field == "org" { "organization_id" } else { field }] = json!(value);
            assert!(verify_case(&p.to_string(), |_| {}, 9, HEADER, (4, 7, false), 1100).is_err());
        }
        let mut p = policy();
        p["permissions"] = json!(["admin:session:read", "admin:session:read"]);
        assert!(verify_case(&p.to_string(), |_| {}, 9, HEADER, (4, 7, false), 1100).is_err());
        for floor in [(5, 7, false), (4, 8, false), (4, 7, true)] {
            assert!(verify_case(&raw, |_| {}, 9, HEADER, floor, 1100).is_err());
        }
        assert!(verify_case(&raw, |_| {}, 8, HEADER, (4, 7, false), 1100).is_err());
    }

    #[test]
    fn denies_mismatched_acceptance_and_duplicate_fields() {
        let raw = policy().to_string();
        for (field, value) in [("format", json!("legacy-v2")), ("aud", json!("other-audience")),
            ("revision", json!(3)), ("generation", json!(6)), ("policy_sha256", json!("changed")),
            ("exp", json!(1901))] {
            assert!(verify_case(&raw, |c| c[field] = value, 9, HEADER, (4, 7, false), 1100).is_err());
        }
        let duplicate = format!(r#"{{"revision":4,{}"#, &raw[1..]);
        assert!(verify_case(&duplicate, |_| {}, 9, HEADER, (4, 7, false), 1100).is_err());
        let duplicate_header = HEADER.replace(r#""kid":"approval""#, r#""kid":"approval","kid":"approval""#);
        assert!(verify_case(&raw, |_| {}, 9, &duplicate_header, (4, 7, false), 1100).is_err());
    }

    #[test]
    fn immutable_floor_denies_same_tuple_equivocation_and_signed_duplicate_claims() {
        let raw = policy().to_string();
        let digest = format!("sha256:{:x}", Sha256::digest(&raw));
        let public = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let claims = json!({"format": ACCEPTANCE_FORMAT, "policy_sha256": digest, "revision": 4,
            "generation": 7, "aud": "signet-verifier", "iat": 1000, "exp": 1900});
        let approval = sign(&claims.to_string(), 9, HEADER);
        let verify = |bytes: &str, jws: &str| verify_raw(bytes, jws, &digest, (4, 7, false), 1100, public.as_bytes());
        assert!(verify(&raw, &approval).is_ok());

        let equivalent = format!("{raw}\n");
        let mut equivocated_claims = claims.clone();
        equivocated_claims["policy_sha256"] = json!(format!("sha256:{:x}", Sha256::digest(&equivalent)));
        assert!(verify(&equivalent, &sign(&equivocated_claims.to_string(), 9, HEADER)).is_err());

        let encoded = claims.to_string();
        let duplicate = format!(r#"{{"revision":4,{}"#, &encoded[1..]);
        assert!(verify(&raw, &sign(&duplicate, 9, HEADER)).is_err());

        // The compressed Edwards identity is a weak Ed25519 key. An identity
        // R and zero S produce a signature that non-strict verification accepts.
        let mut weak_key = [0; 32];
        weak_key[0] = 1;
        let mut weak_signature = [0; 64];
        weak_signature[0] = 1;
        let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(HEADER), URL_SAFE_NO_PAD.encode(encoded));
        use ed25519_dalek::Verifier;
        assert!(VerifyingKey::from_bytes(&weak_key).unwrap()
            .verify(input.as_bytes(), &Signature::from_bytes(&weak_signature)).is_ok());
        let forged = format!("{input}.{}", URL_SAFE_NO_PAD.encode(weak_signature));
        assert!(verify_raw(&raw, &forged, &digest, (4, 7, false), 1100, &weak_key).is_err());
    }
}
