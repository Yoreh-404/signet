use super::*;
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
        .list_signing_keys()
        .await?
        .into_iter()
        .find(|key| key.kid == key_id)
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

#[derive(Debug, Deserialize)]
pub(super) struct InvitationInput {
    code_type: Option<AuthorizationCodeType>,
    login_code_level: Option<LoginCodeLevel>,
    allowed_client_ids: Option<Vec<String>>,
    organization_id: Option<String>,
    organization_role: Option<String>,
    description: Option<String>,
    authorized_email: Option<String>,
    authorized_username: Option<String>,
    authorized_display_name: Option<String>,
    expires_at: Option<i64>,
    max_uses: Option<i32>,
    is_active: bool,
}

async fn ensure_trial_enrollment_role_manager(
    state: &AppState,
    user: &crate::db::UserRecord,
    code_type: AuthorizationCodeType,
    login_code_level: LoginCodeLevel,
    _organization_role: Option<&str>,
) -> AppResult<()> {
    if code_type == AuthorizationCodeType::Login
        && login_code_level == LoginCodeLevel::TrialEnrollment
    {
        // An enrollment code grants organization membership, even for the
        // default member role. Keep that authority with organization managers
        // rather than broad authorization-code operators.
        state
            .db
            .require_permission(user, Permission::OrganizationsManage)
            .await?;
    }
    Ok(())
}

async fn validate_authorization_code_input(
    state: &AppState,
    input: AuthorizationCodeValidationInput<'_>,
) -> AppResult<()> {
    let AuthorizationCodeValidationInput {
        code_type,
        login_code_level,
        authorized_email,
        authorized_username,
        authorized_display_name,
        allowed_client_ids,
        organization_id,
        organization_role,
    } = input;
    match code_type {
        AuthorizationCodeType::Registration => {
            if login_code_level != LoginCodeLevel::AccountRecovery {
                return Err(AppError::BadRequest(
                    "registration authorization codes cannot set a login code level".to_string(),
                ));
            }
            if !allowed_client_ids.is_empty() {
                return Err(AppError::BadRequest(
                    "registration authorization codes cannot allow OIDC clients".to_string(),
                ));
            }
            if organization_id.is_some() || organization_role.is_some() {
                return Err(AppError::BadRequest(
                    "registration authorization codes cannot bind an organization".to_string(),
                ));
            }
        }
        AuthorizationCodeType::Login => {
            validate_login_code_binding_metadata(
                login_code_level,
                authorized_email,
                authorized_username,
                authorized_display_name,
            )?;
            match login_code_level {
                LoginCodeLevel::AccountRecovery => {
                    if authorized_username.is_none_or(|value| value.trim().is_empty()) {
                        return Err(AppError::BadRequest(
                            "account recovery authorization codes require authorized_username"
                                .to_string(),
                        ));
                    }
                    if !allowed_client_ids.is_empty() {
                        return Err(AppError::BadRequest(
                            "account recovery authorization codes cannot allow OIDC clients"
                                .to_string(),
                        ));
                    }
                    if organization_id.is_some() || organization_role.is_some() {
                        return Err(AppError::BadRequest(
                            "account recovery authorization codes cannot bind an organization"
                                .to_string(),
                        ));
                    }
                }
                LoginCodeLevel::AdminUniversal => {
                    if allowed_client_ids.is_empty() {
                        return Err(AppError::BadRequest(
                        "admin universal authorization codes require at least one allowed OIDC client"
                            .to_string(),
                    ));
                    }
                    if organization_id.is_some() || organization_role.is_some() {
                        return Err(AppError::BadRequest(
                            "admin universal authorization codes cannot bind an organization"
                                .to_string(),
                        ));
                    }
                    validate_active_allowed_clients(state, allowed_client_ids).await?;
                }
                LoginCodeLevel::TrialEnrollment => {
                    let organization_id = organization_id
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "trial enrollment authorization codes require organization_id"
                                    .to_string(),
                            )
                        })?;
                    let role = organization_role
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "trial enrollment authorization codes require organization_role"
                                    .to_string(),
                            )
                        })?;
                    organizations::normalize_role(role)?;
                    if allowed_client_ids.is_empty() {
                        return Err(AppError::BadRequest(
                            "trial enrollment authorization codes require at least one allowed OIDC client"
                                .to_string(),
                        ));
                    }
                    let organization = state
                        .db
                        .find_organization_by_id(organization_id)
                        .await?
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "trial enrollment organization does not exist".to_string(),
                            )
                        })?;
                    if organization.is_active != 1 {
                        return Err(AppError::BadRequest(
                            "trial enrollment organization is disabled".to_string(),
                        ));
                    }
                    validate_active_allowed_clients(state, allowed_client_ids).await?;
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub(super) struct InvitationCreateResponse {
    invitation: PublicInvitation,
    code: String,
}

pub(super) async fn create_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<InvitationInput>,
) -> AppResult<Json<InvitationCreateResponse>> {
    let current = require_authorization_code_manager(&state, &jar).await?;
    if matches!(payload.max_uses, Some(value) if value <= 0) {
        return Err(AppError::BadRequest(
            "max_uses must be positive when provided".to_string(),
        ));
    }
    let code_type = payload.code_type.unwrap_or(AuthorizationCodeType::Login);
    let login_code_level = payload
        .login_code_level
        .unwrap_or(LoginCodeLevel::AccountRecovery);
    ensure_admin_universal_manager(&current.user, code_type, login_code_level)?;
    let allowed_client_ids = normalized_client_ids(payload.allowed_client_ids);
    let organization_id = normalize_optional_text(payload.organization_id);
    let organization_role = normalize_optional_text(payload.organization_role)
        .map(|value| organizations::normalize_role(&value))
        .transpose()?;
    let authorized_email = normalize_optional_email(payload.authorized_email)?;
    let authorized_username = normalize_optional_text(payload.authorized_username);
    let authorized_display_name = normalize_optional_text(payload.authorized_display_name);
    validate_authorization_code_input(
        &state,
        AuthorizationCodeValidationInput {
            code_type,
            login_code_level,
            authorized_email: authorized_email.as_deref(),
            authorized_username: authorized_username.as_deref(),
            authorized_display_name: authorized_display_name.as_deref(),
            allowed_client_ids: &allowed_client_ids,
            organization_id: organization_id.as_deref(),
            organization_role: organization_role.as_deref(),
        },
    )
    .await?;
    ensure_trial_enrollment_role_manager(
        &state,
        &current.user,
        code_type,
        login_code_level,
        organization_role.as_deref(),
    )
    .await?;
    if login_code_level == LoginCodeLevel::TrialEnrollment {
        if payload
            .expires_at
            .is_none_or(|expires_at| expires_at <= util::now_ts())
        {
            return Err(AppError::BadRequest(
                "trial enrollment authorization codes require a future expires_at".to_string(),
            ));
        }
        if payload.max_uses.is_none() {
            return Err(AppError::BadRequest(
                "trial enrollment authorization codes require max_uses".to_string(),
            ));
        }
    }
    let authorized_user_id = if code_type == AuthorizationCodeType::Login
        && login_code_level == LoginCodeLevel::AccountRecovery
    {
        let username = authorized_username
            .as_deref()
            .ok_or_else(|| AppError::BadRequest("authorized_username is required".to_string()))?;
        Some(recovery_target_user_id(
            username,
            state.db.find_user_by_username(username).await?,
        )?)
    } else {
        None
    };
    // Store a separate, OAEP-encrypted display copy before hashing the code
    // for normal redemption.  The public list still receives only the prefix;
    // full-code access is an explicit, audited POST to the reveal endpoint.
    let code = format!(
        "{}-{}",
        match code_type {
            AuthorizationCodeType::Registration => "REG",
            AuthorizationCodeType::Login => "LOGIN",
        },
        util::random_token(18)
    );
    let signing_key = state
        .db
        .list_signing_keys()
        .await?
        .into_iter()
        .find(|key| key.is_active == 1)
        .ok_or_else(|| {
            AppError::Configuration(
                "an active signing key is required to create a revealable authorization code"
                    .to_string(),
            )
        })?;
    let code_reveal_ciphertext =
        util::encrypt_authorization_code_for_reveal(&signing_key.private_key_pem, &code)?;
    let (invitation, code) = state
        .db
        .insert_invitation_with_reveal_secret(
            NewInvitation {
                code_type,
                login_code_level,
                allowed_client_ids: allowed_client_ids.clone(),
                organization_id: organization_id.clone(),
                organization_role: organization_role.clone(),
                description: payload.description,
                authorized_email,
                authorized_username,
                authorized_user_id,
                authorized_display_name,
                expires_at: payload.expires_at,
                max_uses: payload.max_uses,
                is_active: payload.is_active,
                created_by: Some(current.user.id.clone()),
            },
            code,
            signing_key.kid,
            code_reveal_ciphertext,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.create",
            "authorization_code",
            Some(invitation.id.clone()),
            serde_json::json!({
                "code_type": code_type,
                "login_code_level": login_code_level,
                "allowed_client_ids": allowed_client_ids,
                "organization_id": invitation.organization_id.clone(),
                "organization_role": invitation.organization_role.clone(),
                "max_uses": invitation.max_uses
            }),
        ))
        .await?;
    Ok(Json(InvitationCreateResponse {
        invitation: invitation.public()?,
        code,
    }))
}

pub(super) async fn update_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<InvitationInput>,
) -> AppResult<Json<PublicInvitation>> {
    let current = require_authorization_code_manager(&state, &jar).await?;
    if matches!(payload.max_uses, Some(value) if value <= 0) {
        return Err(AppError::BadRequest(
            "max_uses must be positive when provided".to_string(),
        ));
    }
    let existing = state
        .db
        .find_invitation_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let code_type = existing.authorization_code_type()?;
    let login_code_level = existing.login_code_level()?;
    ensure_admin_universal_manager(&current.user, code_type, login_code_level)?;
    if payload.code_type.is_some_and(|value| value != code_type)
        || payload
            .login_code_level
            .is_some_and(|value| value != login_code_level)
    {
        return Err(AppError::BadRequest(
            "authorization code type cannot be changed after creation".to_string(),
        ));
    }
    let allowed_client_ids =
        immutable_allowed_client_ids(existing.allowed_client_ids()?, payload.allowed_client_ids)?;
    let requested_organization_role = normalize_optional_text(payload.organization_role)
        .map(|value| organizations::normalize_role(&value))
        .transpose()?;
    let organization_id = if login_code_level == LoginCodeLevel::TrialEnrollment {
        immutable_optional_text(
            "organization_id",
            existing.organization_id.as_deref(),
            payload.organization_id,
        )?
    } else {
        normalize_optional_text(payload.organization_id)
    };
    let organization_role = if login_code_level == LoginCodeLevel::TrialEnrollment {
        immutable_optional_text(
            "organization_role",
            existing.organization_role.as_deref(),
            requested_organization_role,
        )?
    } else {
        requested_organization_role
    };
    let authorized_email = normalize_optional_email(payload.authorized_email)?;
    let authorized_username = if code_type == AuthorizationCodeType::Login
        && login_code_level == LoginCodeLevel::AccountRecovery
    {
        immutable_recovery_username(
            existing.authorized_username.as_deref(),
            payload.authorized_username,
        )?
    } else {
        normalize_optional_text(payload.authorized_username)
    };
    let authorized_display_name = normalize_optional_text(payload.authorized_display_name);
    validate_authorization_code_input(
        &state,
        AuthorizationCodeValidationInput {
            code_type,
            login_code_level,
            authorized_email: authorized_email.as_deref(),
            authorized_username: authorized_username.as_deref(),
            authorized_display_name: authorized_display_name.as_deref(),
            allowed_client_ids: &allowed_client_ids,
            organization_id: organization_id.as_deref(),
            organization_role: organization_role.as_deref(),
        },
    )
    .await?;
    ensure_trial_enrollment_role_manager(
        &state,
        &current.user,
        code_type,
        login_code_level,
        organization_role.as_deref(),
    )
    .await?;
    if login_code_level == LoginCodeLevel::TrialEnrollment {
        if payload
            .expires_at
            .is_none_or(|expires_at| expires_at <= util::now_ts())
        {
            return Err(AppError::BadRequest(
                "trial enrollment authorization codes require a future expires_at".to_string(),
            ));
        }
        if payload.max_uses.is_none() {
            return Err(AppError::BadRequest(
                "trial enrollment authorization codes require max_uses".to_string(),
            ));
        }
    }
    let invitation = state
        .db
        .update_invitation(InvitationUpdate {
            id: &id,
            description: payload.description,
            authorized_email,
            authorized_username,
            authorized_display_name,
            expires_at: payload.expires_at,
            max_uses: payload.max_uses,
            is_active: payload.is_active,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.update",
            "authorization_code",
            Some(id),
            serde_json::json!({
                "code_type": code_type,
                "login_code_level": login_code_level,
                "allowed_client_ids": allowed_client_ids,
                "organization_id": organization_id,
                "organization_role": organization_role,
                "is_active": invitation.is_active == 1
            }),
        ))
        .await?;
    Ok(Json(invitation.public()?))
}

pub(super) async fn delete_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_authorization_code_manager(&state, &jar).await?;
    state.db.delete_invitation(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.delete",
            "authorization_code",
            Some(id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
