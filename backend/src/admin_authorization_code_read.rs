use super::admin_guards::require_authorization_code_manager;
use crate::{
    AppState,
    audit::{self, AuditSink},
    db::{PublicInvitation, PublicInvitationRedemption},
    error::{AppError, AppResult},
    util,
};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

pub(super) async fn list_invitations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicInvitation>>> {
    require_authorization_code_manager(&state, &jar).await?;
    Ok(Json(
        state
            .db
            .list_invitations()
            .await?
            .into_iter()
            .map(crate::db::InvitationRecord::public)
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

#[derive(Debug, Serialize)]
pub(super) struct InvitationRevealResponse {
    code: String,
}

/// Deliberately uses POST: revealing a credential is sensitive, should not be
/// link-prefetched, and receives the same CSRF protection as other management
/// operations.  List responses never include the ciphertext or plaintext.
pub(super) async fn reveal_invitation_code(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<InvitationRevealResponse>> {
    let current = require_authorization_code_manager(&state, &jar).await?;
    let invitation = state
        .db
        .find_invitation_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let key_id = invitation.code_reveal_key_id.clone().ok_or_else(|| {
        AppError::BadRequest(
            "this authorization code was created before secure reveal was available".to_string(),
        )
    })?;
    let ciphertext = invitation.code_reveal_ciphertext.clone().ok_or_else(|| {
        AppError::BadRequest(
            "this authorization code was created before secure reveal was available".to_string(),
        )
    })?;
    let signing_key = state
        .db
        .find_signing_key_by_kid(&key_id)
        .await?
        .ok_or_else(|| {
            AppError::Configuration(
                "authorization code reveal key is unavailable; retain retired signing keys while revealable codes exist"
                    .to_string(),
            )
        })?;
    let code =
        util::decrypt_authorization_code_for_reveal(&signing_key.private_key_pem, &ciphertext)?;
    if util::token_hash(&code) != invitation.code_hash {
        return Err(AppError::Internal(
            "decrypted authorization code does not match its stored verifier".to_string(),
        ));
    }
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.reveal",
            "authorization_code",
            Some(invitation.id),
            serde_json::json!({
                "code_type": invitation.code_type,
                "login_code_level": invitation.login_code_level,
            }),
        ))
        .await?;
    Ok(Json(InvitationRevealResponse { code }))
}

const INVITATION_REDEMPTIONS_DEFAULT_PAGE_SIZE: usize = 50;
const INVITATION_REDEMPTIONS_MAX_PAGE_SIZE: usize = 100;

#[derive(Debug, Deserialize)]
pub(super) struct InvitationRedemptionsQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(super) struct InvitationRedemptionsResponse {
    redemptions: Vec<PublicInvitationRedemption>,
    next_cursor: Option<String>,
}

fn parse_invitation_redemptions_cursor(value: Option<&str>) -> AppResult<Option<(i64, String)>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let (redeemed_at, id) = value.rsplit_once(':').ok_or_else(|| {
        AppError::BadRequest("invalid authorization-code redemption cursor".to_string())
    })?;
    let redeemed_at = redeemed_at.parse::<i64>().map_err(|_| {
        AppError::BadRequest("invalid authorization-code redemption cursor".to_string())
    })?;
    if id.is_empty() || id.len() > 128 {
        return Err(AppError::BadRequest(
            "invalid authorization-code redemption cursor".to_string(),
        ));
    }
    Ok(Some((redeemed_at, id.to_string())))
}

pub(super) async fn list_invitation_redemptions(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Query(query): Query<InvitationRedemptionsQuery>,
) -> AppResult<Json<InvitationRedemptionsResponse>> {
    require_authorization_code_manager(&state, &jar).await?;
    state
        .db
        .find_invitation_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let limit = query
        .limit
        .unwrap_or(INVITATION_REDEMPTIONS_DEFAULT_PAGE_SIZE);
    if !(1..=INVITATION_REDEMPTIONS_MAX_PAGE_SIZE).contains(&limit) {
        return Err(AppError::BadRequest(format!(
            "authorization-code redemption limit must be between 1 and {INVITATION_REDEMPTIONS_MAX_PAGE_SIZE}"
        )));
    }
    let cursor = parse_invitation_redemptions_cursor(query.cursor.as_deref())?;
    let mut records = state
        .db
        .list_invitation_redemptions_for_invitation(&id, cursor, (limit + 1) as i32)
        .await?;
    let has_more = records.len() > limit;
    records.truncate(limit);
    let next_cursor = has_more
        .then(|| {
            records
                .last()
                .map(|record| format!("{}:{}", record.redeemed_at, record.id))
        })
        .flatten();
    Ok(Json(InvitationRedemptionsResponse {
        redemptions: records
            .into_iter()
            .map(crate::db::InvitationRedemptionRecord::public)
            .collect(),
        next_cursor,
    }))
}
