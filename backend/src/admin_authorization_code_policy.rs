use super::admin_settings::normalize_optional_text;
use crate::{
    AppState,
    db::{AuthorizationCodeType, ClientRecord, LoginCodeLevel, UserRecord},
    error::{AppError, AppResult},
};
use std::collections::{BTreeSet, HashMap};

pub(super) fn normalized_client_ids(values: Option<Vec<String>>) -> Vec<String> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn immutable_allowed_client_ids(
    existing: Vec<String>,
    requested: Option<Vec<String>>,
) -> AppResult<Vec<String>> {
    let existing = normalized_client_ids(Some(existing));
    let Some(requested) = requested else {
        return Ok(existing);
    };
    if normalized_client_ids(Some(requested)) != existing {
        return Err(AppError::BadRequest(
            "allowed_client_ids cannot be changed after creation".to_string(),
        ));
    }
    Ok(existing)
}

pub(super) fn immutable_optional_text(
    field: &str,
    existing: Option<&str>,
    requested: Option<String>,
) -> AppResult<Option<String>> {
    let existing = existing
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let Some(requested) = requested else {
        return Ok(existing);
    };
    let requested = normalize_optional_text(Some(requested));
    if requested != existing {
        return Err(AppError::BadRequest(format!(
            "{field} cannot be changed after trial enrollment code creation"
        )));
    }
    Ok(existing)
}

pub(super) fn immutable_recovery_username(
    existing: Option<&str>,
    requested: Option<String>,
) -> AppResult<Option<String>> {
    let existing = existing
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::Configuration(
                "account recovery authorization code is missing its bound username".to_string(),
            )
        })?
        .to_string();
    let Some(requested) = requested else {
        return Ok(Some(existing));
    };
    let requested = normalize_optional_text(Some(requested)).ok_or_else(|| {
        AppError::BadRequest(
            "authorized_username cannot be cleared after account recovery code creation"
                .to_string(),
        )
    })?;
    if requested != existing {
        return Err(AppError::BadRequest(
            "authorized_username cannot be changed after account recovery code creation"
                .to_string(),
        ));
    }
    Ok(Some(existing))
}

pub(super) fn ensure_admin_universal_manager(
    user: &UserRecord,
    code_type: AuthorizationCodeType,
    login_code_level: LoginCodeLevel,
) -> AppResult<()> {
    if code_type == AuthorizationCodeType::Login
        && login_code_level == LoginCodeLevel::AdminUniversal
        && user.is_admin != 1
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

pub(super) fn recovery_target_user_id(
    username: &str,
    user: Option<UserRecord>,
) -> AppResult<String> {
    let user = user.ok_or_else(|| {
        AppError::BadRequest(
            "account recovery authorization codes require an existing account".to_string(),
        )
    })?;
    if user.username != username {
        return Err(AppError::BadRequest(
            "authorized_username must exactly match the existing account username".to_string(),
        ));
    }
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(AppError::BadRequest(
            "account recovery authorization codes require an active account".to_string(),
        ));
    }
    Ok(user.id)
}

pub(super) fn validate_login_code_binding_metadata(
    login_code_level: LoginCodeLevel,
    authorized_email: Option<&str>,
    authorized_username: Option<&str>,
    authorized_display_name: Option<&str>,
) -> AppResult<()> {
    if authorized_email.is_some() || authorized_display_name.is_some() {
        return Err(AppError::BadRequest(
            "login authorization codes cannot set email or display-name metadata".to_string(),
        ));
    }
    if matches!(
        login_code_level,
        LoginCodeLevel::AdminUniversal | LoginCodeLevel::TrialEnrollment
    ) && authorized_username.is_some()
    {
        return Err(AppError::BadRequest(
            "this login authorization code cannot set account binding metadata".to_string(),
        ));
    }
    Ok(())
}

pub(super) struct AuthorizationCodeValidationInput<'a> {
    pub(super) code_type: AuthorizationCodeType,
    pub(super) login_code_level: LoginCodeLevel,
    pub(super) authorized_email: Option<&'a str>,
    pub(super) authorized_username: Option<&'a str>,
    pub(super) authorized_display_name: Option<&'a str>,
    pub(super) allowed_client_ids: &'a [String],
    pub(super) organization_id: Option<&'a str>,
    pub(super) organization_role: Option<&'a str>,
}

pub(super) async fn validate_active_allowed_clients(
    state: &AppState,
    allowed_client_ids: &[String],
) -> AppResult<()> {
    let clients = state
        .db
        .list_clients_by_client_ids(allowed_client_ids)
        .await?;
    let clients = clients
        .into_iter()
        .map(|client: ClientRecord| (client.client_id.clone(), client))
        .collect::<HashMap<_, _>>();
    for client_id in allowed_client_ids {
        let client = clients.get(client_id).ok_or_else(|| {
            AppError::BadRequest(format!("allowed OIDC client does not exist: {client_id}"))
        })?;
        if client.is_active != 1 {
            return Err(AppError::BadRequest(format!(
                "allowed OIDC client is disabled: {client_id}"
            )));
        }
    }
    Ok(())
}
