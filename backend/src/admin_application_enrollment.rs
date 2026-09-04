use super::{
    admin_application_scope::managed_application,
    admin_defaults::{default_organization_role, default_true},
    admin_settings::normalize_optional_text,
};
use crate::{
    AppState, applications,
    audit::{self, AuditSink},
    db::{
        ApplicationRecord, AuthorizationCodeType, LoginCodeLevel, NewInvitation, PublicInvitation,
    },
    error::{AppError, AppResult},
    organizations, util,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
#[derive(Debug, Deserialize)]
pub(super) struct ApplicationEnrollmentCodeInput {
    #[serde(default)]
    description: Option<String>,
    /// Normal enrollment creates a reusable multi-enterprise Signet account.
    /// Restricted trial is retained for short-lived, application-only trials.
    #[serde(default = "default_application_enrollment_account_kind")]
    account_kind: String,
    expires_at: i64,
    max_uses: i32,
    #[serde(default = "default_organization_role")]
    organization_role: String,
    #[serde(default = "default_true")]
    is_active: bool,
}

#[derive(Debug, Clone, Copy)]
enum ApplicationEnrollmentAccountKind {
    Normal,
    RestrictedTrial,
}

impl ApplicationEnrollmentAccountKind {
    fn parse(value: &str) -> AppResult<Self> {
        match value.trim() {
            "normal" => Ok(Self::Normal),
            "restricted_trial" => Ok(Self::RestrictedTrial),
            other => Err(AppError::BadRequest(format!(
                "unsupported application enrollment account kind: {other}"
            ))),
        }
    }

    const fn audit_value(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::RestrictedTrial => "restricted_trial",
        }
    }
}

// Keep the previous API behavior for callers that have not yet sent the new
// field. The management UI deliberately sends `normal` as its product
// default, because it is the right choice for a regular enterprise member.
fn default_application_enrollment_account_kind() -> String {
    "restricted_trial".to_string()
}

#[derive(Debug, Serialize)]
pub(super) struct ApplicationEnrollmentCodeCreateResponse {
    invitation: PublicInvitation,
    code: String,
}

async fn active_application_client_ids(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<Vec<String>> {
    let mut client_ids = Vec::new();
    for client in state.db.list_application_clients(&application.id).await? {
        if client.organization_id.as_deref() != Some(application.organization_id.as_str()) {
            return Err(AppError::Internal(
                "application has an OIDC connection from a different organization".to_string(),
            ));
        }
        if client.is_active == 1 {
            client_ids.push(client.client_id);
        }
    }
    Ok(client_ids)
}

pub(super) async fn list_application_enrollment_codes(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicInvitation>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    Ok(Json(
        state
            .db
            .list_application_enrollment_codes(&id)
            .await?
            .into_iter()
            .map(|invitation| invitation.public())
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

pub(super) async fn create_application_enrollment_code(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationEnrollmentCodeInput>,
) -> AppResult<Json<ApplicationEnrollmentCodeCreateResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    if application.is_active != 1 {
        return Err(AppError::BadRequest(
            "application enrollment is unavailable while the application is disabled".to_string(),
        ));
    }
    if application.registration_mode != applications::REGISTRATION_INVITATION {
        return Err(AppError::BadRequest(
            "set this application's registration policy to invitation before creating enrollment codes"
                .to_string(),
        ));
    }
    if payload.expires_at <= util::now_ts() {
        return Err(AppError::BadRequest(
            "application enrollment codes require a future expiry".to_string(),
        ));
    }
    if payload.max_uses <= 0 {
        return Err(AppError::BadRequest(
            "application enrollment codes require a positive maximum use count".to_string(),
        ));
    }
    let account_kind = ApplicationEnrollmentAccountKind::parse(&payload.account_kind)?;
    let organization_role = organizations::normalize_role(&payload.organization_role)?;
    let allowed_client_ids = active_application_client_ids(&state, &application).await?;
    if allowed_client_ids.is_empty() {
        return Err(AppError::BadRequest(
            "attach at least one active OIDC connection before creating an enrollment code"
                .to_string(),
        ));
    }
    let code = format!("APP-{}", util::random_token(18));
    let signing_key = state.db.find_active_signing_key().await?.ok_or_else(|| {
        AppError::Configuration(
            "an active signing key is required to create a revealable enrollment code".to_string(),
        )
    })?;
    let ciphertext =
        util::encrypt_authorization_code_for_reveal(&signing_key.private_key_pem, &code)?;
    let (invitation, code) = state
        .db
        .insert_invitation_with_reveal_secret(
            NewInvitation {
                code_type: match account_kind {
                    ApplicationEnrollmentAccountKind::Normal => AuthorizationCodeType::Registration,
                    ApplicationEnrollmentAccountKind::RestrictedTrial => {
                        AuthorizationCodeType::Login
                    }
                },
                login_code_level: match account_kind {
                    ApplicationEnrollmentAccountKind::Normal => LoginCodeLevel::AccountRecovery,
                    ApplicationEnrollmentAccountKind::RestrictedTrial => {
                        LoginCodeLevel::TrialEnrollment
                    }
                },
                allowed_client_ids: allowed_client_ids.clone(),
                organization_id: Some(application.organization_id.clone()),
                organization_role: Some(organization_role.clone()),
                description: normalize_optional_text(payload.description),
                authorized_email: None,
                authorized_username: None,
                authorized_user_id: None,
                authorized_display_name: None,
                expires_at: Some(payload.expires_at),
                max_uses: Some(payload.max_uses),
                is_active: payload.is_active,
                created_by: Some(current.user.id.clone()),
            },
            code,
            signing_key.kid,
            ciphertext,
        )
        .await?;
    state
        .db
        .link_application_enrollment_code(&application.id, &invitation.id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.enrollment_code.create",
            "application",
            Some(application.id),
            serde_json::json!({
                "invitation_id": invitation.id,
                "organization_id": application.organization_id,
                "allowed_client_ids": allowed_client_ids,
                "organization_role": organization_role,
                "max_uses": payload.max_uses,
                "account_kind": account_kind.audit_value(),
            }),
        ))
        .await?;
    Ok(Json(ApplicationEnrollmentCodeCreateResponse {
        invitation: invitation.public()?,
        code,
    }))
}

pub(super) async fn delete_application_enrollment_code(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, code_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, _application) = managed_application(&state, &jar, &id).await?;
    if !state
        .db
        .application_enrollment_code_belongs_to(&id, &code_id)
        .await?
    {
        return Err(AppError::NotFound);
    }
    state.db.delete_invitation(&code_id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.enrollment_code.delete",
            "application",
            Some(id),
            serde_json::json!({ "invitation_id": code_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
