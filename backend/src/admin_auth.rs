use crate::{
    AppState, applications, auth, auth_flow, backchannel_logout, directory,
    error::{AppError, AppResult},
    frontchannel_logout, mfa,
    mfa_policy::MfaDecision,
    network_policy::TrustedNetworkPolicy,
    security_policy, util,
};
use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::HeaderMap,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
pub(super) struct LoginRequest {
    email: String,
    password: String,
    mfa_challenge_id: Option<String>,
    mfa_code: Option<String>,
    captcha_challenge_id: Option<String>,
    captcha_answer: Option<String>,
    return_to: Option<String>,
    account_flow: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct LoginResponse {
    user: Option<auth::CurrentUserResponse>,
    mfa_required: bool,
    mfa_challenge_id: Option<String>,
    recovery_available: bool,
    captcha_required: bool,
    captcha_challenge_id: Option<String>,
    captcha_prompt: Option<String>,
    captcha_expires_at: Option<i64>,
}

pub(crate) async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<(CookieJar, Json<LoginResponse>)> {
    let subject = security_policy::normalize_login_subject(&payload.email);
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
    auth::assert_login_entry_allowed(&state, &subject, request_ip.as_deref()).await?;
    let login_context = crate::oidc::authorization_login_context_from_return_to(
        &state,
        &headers,
        payload.return_to.as_deref(),
    )
    .await?;
    let local_password_allowed = match login_context.application.as_ref() {
        Some(application) => {
            applications::application_signet_password_enabled(&state, &application.id).await?
        }
        None => true,
    };
    if let Some(captcha) = auth::login_captcha_prompt_if_required(
        &state,
        &subject,
        request_ip.as_deref(),
        payload.captcha_challenge_id.as_deref(),
        payload.captcha_answer.as_deref(),
    )
    .await?
    {
        return Ok((
            jar,
            Json(LoginResponse {
                user: None,
                mfa_required: false,
                mfa_challenge_id: None,
                recovery_available: false,
                captcha_required: true,
                captcha_challenge_id: Some(captcha.challenge_id),
                captcha_prompt: Some(captcha.prompt),
                captcha_expires_at: Some(captcha.expires_at),
            }),
        ));
    }
    let local_user = state.db.find_user_by_email(&subject).await?;
    let failure_reason = if local_user.is_some() {
        "bad_credentials"
    } else {
        "unknown_user"
    };
    let mut login_method = "password".to_string();
    let mut external_provider = None;
    let mut user = local_user.filter(|candidate| {
        local_password_allowed
            && candidate.is_active == 1
            && candidate.archived_at.is_none()
            && util::verify_password(&candidate.password_hash, &payload.password)
    });
    if user.is_none() {
        let directory_login =
            match directory::authenticate_with_configured_directories_for_application(
                &state,
                &subject,
                &payload.password,
                login_context.application.as_ref(),
            )
            .await
            {
                Ok(value) => value,
                Err(AppError::Unauthorized | AppError::Forbidden) => None,
                Err(err) => return Err(err),
            };
        if let Some(login) = directory_login {
            login_method = "ldap".to_string();
            external_provider = Some(login.provider_key);
            user = Some(login.user);
        }
    }
    let Some(user) = user else {
        auth::record_login_failure(
            &state,
            request_ip.clone(),
            &headers,
            &subject,
            failure_reason,
        )
        .await?;
        return Err(AppError::Unauthorized);
    };
    let has_totp = state.db.find_totp_method(&user.id).await?.is_some();
    let policy = state.db.security_policy().await?;
    let policy_requires_mfa =
        policy.requires_mfa_for_ip(request_ip.as_deref())? || login_context.request_requires_mfa;
    match auth_flow::oidc_login_mfa_decision(
        &policy,
        login_context.client.as_ref(),
        has_totp,
        policy_requires_mfa,
    )? {
        MfaDecision::SetupRequired => {
            auth::record_login_failure(
                &state,
                request_ip.clone(),
                &headers,
                &subject,
                "mfa_required_no_totp",
            )
            .await?;
            return Err(AppError::BadRequest(
                "MFA is required for this login but this account has no TOTP method".to_string(),
            ));
        }
        MfaDecision::Challenge => {
            let recovery_codes = state.db.list_unused_recovery_codes(&user.id).await?;
            let Some(challenge_id) = payload.mfa_challenge_id.as_deref() else {
                let challenge = state
                    .db
                    .create_mfa_challenge(
                        &user.id,
                        "api_login",
                        None,
                        mfa::MFA_CHALLENGE_TTL_SECONDS,
                    )
                    .await?;
                return Ok((
                    jar,
                    Json(LoginResponse {
                        user: None,
                        mfa_required: true,
                        mfa_challenge_id: Some(challenge.id),
                        recovery_available: !recovery_codes.is_empty(),
                        captcha_required: false,
                        captcha_challenge_id: None,
                        captcha_prompt: None,
                        captcha_expires_at: None,
                    }),
                ));
            };
            let code = payload.mfa_code.as_deref().ok_or(AppError::Unauthorized)?;
            let completion = match mfa::complete_challenge_by_id(
                &state,
                challenge_id,
                &user.id,
                "api_login",
                code,
            )
            .await
            {
                Ok(value) => value,
                Err(err) => {
                    auth::record_login_failure(
                        &state,
                        request_ip.clone(),
                        &headers,
                        &subject,
                        "bad_mfa",
                    )
                    .await?;
                    return Err(err);
                }
            };
            let completed_method = if login_method == "ldap" {
                format!("ldap_{}", completion.method)
            } else {
                completion.method
            };
            let jar = auth::issue_session_with_login_event(
                &state,
                jar,
                &headers,
                request_ip.clone(),
                &user,
                &completed_method,
                auth::LoginEventContext {
                    external_provider: external_provider.clone(),
                    account_flow: payload.account_flow.clone(),
                    ..Default::default()
                },
            )
            .await?;
            auth::clear_login_failures(&state, &subject).await?;
            return Ok((
                jar,
                Json(LoginResponse {
                    user: Some(auth::current_user_response(&state, user.clone()).await?),
                    mfa_required: false,
                    mfa_challenge_id: None,
                    recovery_available: false,
                    captcha_required: false,
                    captcha_challenge_id: None,
                    captcha_prompt: None,
                    captcha_expires_at: None,
                }),
            ));
        }
        MfaDecision::Satisfied => {}
    }

    let jar = auth::issue_session_with_login_event(
        &state,
        jar,
        &headers,
        request_ip,
        &user,
        &login_method,
        auth::LoginEventContext {
            external_provider,
            account_flow: payload.account_flow,
            ..Default::default()
        },
    )
    .await?;
    auth::clear_login_failures(&state, &subject).await?;
    Ok((
        jar,
        Json(LoginResponse {
            user: Some(auth::current_user_response(&state, user.clone()).await?),
            mfa_required: false,
            mfa_challenge_id: None,
            recovery_available: false,
            captcha_required: false,
            captcha_challenge_id: None,
            captcha_prompt: None,
            captcha_expires_at: None,
        }),
    ))
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<(CookieJar, Json<serde_json::Value>)> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let mut frontchannel_frames = Vec::new();
    if let Some(current) = current.as_ref() {
        let public_session_id = util::session_public_id(&current.session_id);
        frontchannel_frames = match frontchannel_logout::frames_for_user(
            &state,
            &headers,
            &current.user,
            &public_session_id,
        )
        .await
        {
            Ok(frames) => frames,
            Err(err) => {
                tracing::warn!(error = %err, "front-channel logout notification preparation failed");
                Vec::new()
            }
        };
        if let Err(err) = backchannel_logout::notify_user_logout(
            &state,
            &headers,
            &current.user,
            Some(&public_session_id),
        )
        .await
        {
            tracing::warn!(error = %err, "back-channel logout notification failed");
        }
    }
    if let Some(current) = current.as_ref() {
        state.db.delete_session(&current.session_id).await?;
    }
    Ok((
        jar.add(auth::expired_session_cookie(&state)),
        Json(serde_json::json!({
            "ok": true,
            "frontchannel_logout_frames": frontchannel_frames,
        })),
    ))
}
