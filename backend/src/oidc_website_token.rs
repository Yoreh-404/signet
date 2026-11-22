use super::{ensure_trial_enrollment_client_allowed_for_user, load_oidc_user};
use crate::{
    AppState,
    db::{ApplicationClientBindingRecord, ClientRecord, UserRecord},
    dpop::{self, DpopBinding},
    error::{AppError, AppResult},
    oidc_authorization::AuthorizationSnapshot,
    subject, util,
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use axum::{
    Json,
    http::{HeaderMap, Method},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub(super) const PREFIX: &str = "sw1.";
const PURPOSE: &[u8] = b"signet:website-userinfo:v1";

/// Only UserInfo accepts this authenticated envelope. No refresh records,
/// signing claims, profile attributes, or entitlements are exported.
#[derive(Serialize, Deserialize)]
struct Grant {
    issuer: String,
    client: String,
    user: String,
    application: String,
    profile: String,
    generation: Option<String>,
    // Required marker rejects old envelopes (missing Option fields deserialize as None).
    generation_bound: bool,
    exp: i64,
    jkt: Option<String>,
}

fn cipher(private_pem: &str) -> Aes256Gcm {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(private_pem.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(PURPOSE);
    Aes256Gcm::new_from_slice(&mac.finalize().into_bytes()).expect("SHA-256 produces a 256-bit key")
}

pub(super) async fn generation(
    state: &AppState,
    client: &str,
    user: &str,
) -> AppResult<Option<String>> {
    Ok(state
        .db
        .find_client_grant(user, client)
        .await?
        .and_then(|g| g.website_generation))
}

pub(super) fn bind_code(random: &str, generation: Option<&str>) -> String {
    let tag = util::identity_factor_digest(
        generation.unwrap_or_default(),
        "website-authorization-code",
        random,
    );
    format!("{random}.{tag}")
}

pub(super) async fn issue(
    state: &AppState,
    issuer: &str,
    client: &ClientRecord,
    user: &UserRecord,
    binding: &ApplicationClientBindingRecord,
    proof: Option<&DpopBinding>,
    code: &str,
) -> AppResult<String> {
    let generation = generation(state, &client.client_id, &user.id).await?;
    let (random, _) = code.split_once('.').ok_or_else(invalid_code)?;
    if bind_code(random, generation.as_deref()) != code {
        return Err(invalid_code());
    }
    let grant = Grant {
        issuer: issuer.into(),
        client: client.client_id.clone(),
        user: user.id.clone(),
        application: binding.application_id.clone(),
        profile: binding.authorization_profile_id.clone(),
        generation,
        generation_bound: true,
        exp: util::now_ts() + state.settings.oidc.access_token_ttl_seconds,
        jkt: proof.map(|p| p.jkt.clone()),
    };
    let key = state
        .db
        .find_active_signing_key()
        .await?
        .ok_or(AppError::Internal(
            "website credential key unavailable".into(),
        ))?;
    let message = serde_json::to_vec(&grant).map_err(|e| AppError::Internal(e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher(&key.private_key_pem)
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &message,
                aad: PURPOSE,
            },
        )
        .map_err(|_| AppError::Internal("website credential encryption failed".into()))?;
    Ok(format!(
        "{PREFIX}{}.{}.{}",
        URL_SAFE_NO_PAD.encode(key.kid),
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

pub(super) async fn userinfo(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    scheme: &str,
    token: &str,
    issuers: &[String],
) -> AppResult<Json<serde_json::Value>> {
    let mut parts = token
        .strip_prefix(PREFIX)
        .ok_or(AppError::Unauthorized)?
        .split('.');
    let mut part = || {
        URL_SAFE_NO_PAD
            .decode(parts.next().ok_or(AppError::Unauthorized)?)
            .map_err(|_| AppError::Unauthorized)
    };
    let kid = String::from_utf8(part()?).map_err(|_| AppError::Unauthorized)?;
    let nonce: [u8; 12] = part()?.try_into().map_err(|_| AppError::Unauthorized)?;
    let ciphertext = part()?;
    if parts.next().is_some() || kid.is_empty() || kid.len() > 128 {
        return Err(AppError::Unauthorized);
    }
    let key = state
        .db
        .find_signing_key_by_kid(&kid)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let message = cipher(&key.private_key_pem)
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: PURPOSE,
            },
        )
        .map_err(|_| AppError::Unauthorized)?;
    let grant: Grant = serde_json::from_slice(&message).map_err(|_| AppError::Unauthorized)?;
    if !grant.generation_bound
        || grant.exp <= util::now_ts()
        || !issuers.contains(&grant.issuer)
        || !crate::dcr::is_website_client_id(&grant.client)
    {
        return Err(AppError::Unauthorized);
    }
    match (scheme, grant.jkt.as_deref()) {
        ("Bearer", None) => (),
        (dpop::TOKEN_TYPE, Some(jkt)) => {
            dpop::validate_access_token_proof(
                state,
                headers,
                method,
                &state.settings.oidc.userinfo_endpoint,
                token,
                jkt,
            )
            .await?;
        }
        _ => return Err(AppError::Unauthorized),
    }
    let client = state
        .db
        .find_client_by_client_id(&grant.client)
        .await?
        .filter(|c| c.is_active == 1 && c.subject_type == subject::SUBJECT_TYPE_PAIRWISE)
        .ok_or(AppError::Unauthorized)?;
    let user = load_oidc_user(state, &grant.user).await?;
    ensure_trial_enrollment_client_allowed_for_user(state, &user.id, &client.client_id).await?;
    if generation(state, &client.client_id, &user.id).await? != grant.generation {
        return Err(AppError::Unauthorized);
    }
    let snapshot = AuthorizationSnapshot::load(state, &client, &user).await?;
    if !snapshot.binding.is_some_and(|b| {
        b.application_id == grant.application && b.authorization_profile_id == grant.profile
    }) {
        return Err(AppError::Unauthorized);
    }
    Ok(Json(
        serde_json::json!({"sub": subject::subject_for_client(&grant.issuer, &user, &client)?}),
    ))
}

fn invalid_code() -> AppError {
    AppError::Oidc("invalid authorization code".into())
}
