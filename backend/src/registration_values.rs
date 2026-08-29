use crate::{
    error::{AppError, AppResult},
    util,
};

pub(crate) fn normalize_email(value: &str) -> AppResult<String> {
    let email = value.trim().to_ascii_lowercase();
    if !email.contains('@') {
        return Err(AppError::BadRequest("email is invalid".to_string()));
    }
    Ok(email)
}

pub(crate) fn required_register_email(value: &Option<String>) -> AppResult<String> {
    optional_register_email(value)?
        .ok_or_else(|| AppError::BadRequest("email is required".to_string()))
}

pub(crate) fn optional_register_email(value: &Option<String>) -> AppResult<Option<String>> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_email)
        .transpose()
}

pub(crate) fn register_username_or_email_local(value: &Option<String>, email: &str) -> String {
    normalize_optional(value).unwrap_or_else(|| {
        email
            .split('@')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("user")
            .to_string()
    })
}

pub(crate) fn first_nonempty_code(left: &Option<String>, right: &Option<String>) -> Option<String> {
    [left.as_deref(), right.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn required_register_password(value: &Option<String>) -> AppResult<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest("password is required".to_string()))
}

pub(crate) fn normalize_authorization_code_login_email(value: &str) -> AppResult<String> {
    let email = value.trim();
    if email.is_empty()
        || email.len() > 320
        || email.chars().any(|character| character.is_control())
    {
        return Err(AppError::Unauthorized);
    }
    normalize_email(email).map_err(|_| AppError::Unauthorized)
}

pub(crate) fn normalize_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn optional_login_hint(value: &Option<String>) -> AppResult<Option<String>> {
    let Some(value) = normalize_optional(value) else {
        return Ok(None);
    };
    if value.len() > 320 || value.contains(['\r', '\n']) {
        return Err(AppError::BadRequest("login_hint is invalid".to_string()));
    }
    Ok(Some(value))
}

pub(crate) fn normalize_external_issuer(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

pub(crate) fn unique_username(preferred: &str, sub: &str) -> String {
    let base = if preferred.trim().is_empty() {
        "external-user".to_string()
    } else {
        preferred.trim().to_ascii_lowercase()
    };
    let suffix = util::token_hash(sub).chars().take(8).collect::<String>();
    format!("{base}-{suffix}")
}

pub(crate) fn external_subject_email_local_part(external_subject: &str) -> String {
    let base = external_subject
        .trim()
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(*character, '-' | '_' | '.')
        })
        .map(|character| character.to_ascii_lowercase())
        .take(32)
        .collect::<String>();
    let base = if base.is_empty() {
        "external-user".to_string()
    } else {
        base
    };
    let suffix = util::token_hash(external_subject)
        .chars()
        .take(8)
        .collect::<String>();
    format!("{base}-{suffix}")
}
