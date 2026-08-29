use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, NaiveDate};
use serde::{Deserialize, Serialize};

use crate::{
    db::{
        UserListFilters, UserListLinkedIdentityFilter, UserListLoginRegion, UserListRoleFilter,
        UserListScope,
    },
    error::{AppError, AppResult},
};

pub(super) const USER_DIRECTORY_DEFAULT_PAGE_SIZE: usize = 25;
pub(super) const USER_DIRECTORY_MAX_PAGE_SIZE: usize = 200;
pub(super) const USER_OPTION_DEFAULT_LIMIT: usize = 100;
pub(super) const USER_OPTION_MAX_LIMIT: usize = 200;

#[derive(Debug, Deserialize, Default)]
pub(super) struct UserListQuery {
    pub(super) status: Option<String>,
    pub(super) page: Option<String>,
    pub(super) page_size: Option<String>,
    pub(super) cursor: Option<String>,
    // Offset/limit remain accepted for non-UI callers during migration. The
    // response contract is the one-based page envelope below.
    pub(super) offset: Option<String>,
    pub(super) limit: Option<String>,
    #[serde(alias = "q")]
    pub(super) search: Option<String>,
    pub(super) organization_id: Option<String>,
    pub(super) linked_identity: Option<String>,
    pub(super) email: Option<String>,
    pub(super) phone: Option<String>,
    pub(super) role: Option<String>,
    #[serde(alias = "registration_from", alias = "date_from")]
    pub(super) created_from: Option<String>,
    #[serde(alias = "registration_to", alias = "date_to")]
    pub(super) created_to: Option<String>,
    pub(super) last_login_from: Option<String>,
    pub(super) last_login_to: Option<String>,
    #[serde(alias = "region")]
    pub(super) login_region: Option<String>,
}

#[derive(Debug)]
pub(super) struct ParsedUserListQuery {
    pub(super) scope: UserListScope,
    pub(super) filters: UserListFilters,
    pub(super) page: usize,
    pub(super) page_size: usize,
    pub(super) offset: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct UserListPageResponse {
    pub(super) items: Vec<crate::db::PublicUser>,
    pub(super) page: usize,
    pub(super) page_size: usize,
    pub(super) total: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct UserDirectoryCursorResponse {
    pub(super) items: Vec<crate::db::PublicUser>,
    pub(super) page_size: usize,
    pub(super) next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct UserOptionQuery {
    pub(super) status: Option<String>,
    pub(super) organization_id: Option<String>,
    #[serde(alias = "q")]
    pub(super) search: Option<String>,
    pub(super) limit: Option<String>,
}

pub(super) fn encode_user_directory_cursor(
    cursor: &crate::db::UserDirectoryCursor,
) -> AppResult<String> {
    let bytes = serde_json::to_vec(cursor)
        .map_err(|error| AppError::Internal(format!("failed to encode user cursor: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn decode_user_directory_cursor(
    value: Option<String>,
) -> AppResult<Option<crate::db::UserDirectoryCursor>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value.len() > 2048 {
        return Err(AppError::BadRequest("cursor is invalid".to_string()));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::BadRequest("cursor is invalid".to_string()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| AppError::BadRequest("cursor is invalid".to_string()))
}

pub(super) fn normalize_user_list_text(
    value: Option<String>,
    field: &str,
    max_chars: usize,
) -> AppResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > max_chars || value.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!("{field} is invalid")));
    }
    Ok(Some(value))
}

pub(super) fn parse_user_list_number(
    value: Option<String>,
    field: &str,
    default: usize,
    max: Option<usize>,
    allow_zero: bool,
) -> AppResult<usize> {
    let Some(value) = value else {
        return Ok(default);
    };
    let value = value.trim();
    let parsed = value
        .parse::<u64>()
        .map_err(|_| AppError::BadRequest(format!("{field} must be a positive integer")))?;
    let parsed = usize::try_from(parsed)
        .map_err(|_| AppError::BadRequest(format!("{field} is too large")))?;
    if (!allow_zero && parsed == 0) || max.is_some_and(|max| parsed > max) {
        let message = max.map_or_else(
            || {
                if allow_zero {
                    format!("{field} must be a non-negative integer")
                } else {
                    format!("{field} must be a positive integer")
                }
            },
            |max| format!("{field} must be between 1 and {max}"),
        );
        return Err(AppError::BadRequest(message));
    }
    Ok(parsed)
}

fn parse_user_list_date(
    value: Option<String>,
    field: &str,
    upper_bound: bool,
) -> AppResult<Option<i64>> {
    let Some(value) = normalize_user_list_text(value, field, 64)? else {
        return Ok(None);
    };
    let (timestamp, date_only) = if let Ok(timestamp) = value.parse::<i64>() {
        (timestamp, false)
    } else if let Ok(date) = NaiveDate::parse_from_str(&value, "%Y-%m-%d") {
        (
            date.and_hms_opt(0, 0, 0)
                .expect("midnight is always valid")
                .and_utc()
                .timestamp(),
            true,
        )
    } else if let Ok(datetime) = DateTime::parse_from_rfc3339(&value) {
        (datetime.timestamp(), false)
    } else {
        return Err(AppError::BadRequest(format!(
            "{field} must be an RFC3339 timestamp, Unix timestamp, or YYYY-MM-DD"
        )));
    };
    if timestamp < 0 {
        return Err(AppError::BadRequest(format!("{field} is invalid")));
    }
    let timestamp = if upper_bound && date_only {
        timestamp
            .checked_add(86_400)
            .ok_or_else(|| AppError::BadRequest(format!("{field} is out of range")))?
    } else {
        timestamp
    };
    Ok(Some(timestamp))
}

pub(super) fn parse_user_list_query(query: UserListQuery) -> AppResult<ParsedUserListQuery> {
    let scope = user_list_scope(query.status.as_deref())?;
    let page_size = if query.page_size.is_some() {
        parse_user_list_number(
            query.page_size,
            "page_size",
            USER_DIRECTORY_DEFAULT_PAGE_SIZE,
            Some(USER_DIRECTORY_MAX_PAGE_SIZE),
            false,
        )?
    } else if query.limit.is_some() {
        parse_user_list_number(
            query.limit,
            "limit",
            USER_DIRECTORY_DEFAULT_PAGE_SIZE,
            Some(USER_DIRECTORY_MAX_PAGE_SIZE),
            false,
        )?
    } else {
        USER_DIRECTORY_DEFAULT_PAGE_SIZE
    };
    let page = if query.page.is_some() {
        parse_user_list_number(query.page, "page", 1, None, false)?
    } else if query.offset.is_some() {
        let offset = parse_user_list_number(query.offset, "offset", 0, None, true)?;
        offset
            .checked_div(page_size)
            .and_then(|page| page.checked_add(1))
            .ok_or_else(|| AppError::BadRequest("offset is too large".to_string()))?
    } else {
        1
    };
    let offset = page
        .checked_sub(1)
        .and_then(|page| page.checked_mul(page_size))
        .ok_or_else(|| AppError::BadRequest("page is too large".to_string()))?;

    let linked_identity = match query
        .linked_identity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("all")
    {
        "all" => UserListLinkedIdentityFilter::All,
        "linked" => UserListLinkedIdentityFilter::Linked,
        "unlinked" => UserListLinkedIdentityFilter::Unlinked,
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported linked identity filter: {other}"
            )));
        }
    };
    let role = match query
        .role
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("all")
    {
        "all" => UserListRoleFilter::Any,
        "admin" => UserListRoleFilter::Admin,
        "user" => UserListRoleFilter::User,
        value => UserListRoleFilter::Named(
            normalize_user_list_text(Some(value.to_string()), "role", 128)?
                .expect("non-empty role was checked above"),
        ),
    };
    let login_region = match query
        .login_region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("all")
    {
        "all" => UserListLoginRegion::All,
        "domestic" => UserListLoginRegion::Domestic,
        "overseas" => UserListLoginRegion::Overseas,
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported login region filter: {other}"
            )));
        }
    };
    let created_from = parse_user_list_date(query.created_from, "registration_from", false)?;
    let created_to = parse_user_list_date(query.created_to, "registration_to", true)?;
    let last_login_from = parse_user_list_date(query.last_login_from, "last_login_from", false)?;
    let last_login_to = parse_user_list_date(query.last_login_to, "last_login_to", true)?;
    if created_from
        .zip(created_to)
        .is_some_and(|(from, to)| from >= to)
    {
        return Err(AppError::BadRequest(
            "registration_from must be before registration_to".to_string(),
        ));
    }
    if last_login_from
        .zip(last_login_to)
        .is_some_and(|(from, to)| from >= to)
    {
        return Err(AppError::BadRequest(
            "last_login_from must be before last_login_to".to_string(),
        ));
    }

    Ok(ParsedUserListQuery {
        scope,
        filters: UserListFilters {
            organization_id: normalize_user_list_text(
                query.organization_id,
                "organization_id",
                128,
            )?,
            linked_identity,
            search: normalize_user_list_text(query.search, "search", 256)?,
            email: normalize_user_list_text(query.email, "email", 320)?,
            phone: normalize_user_list_text(query.phone, "phone", 128)?,
            role,
            created_from,
            created_to,
            last_login_from,
            last_login_to,
            login_region,
        },
        page,
        page_size,
        offset,
    })
}

pub(super) fn user_list_scope(status: Option<&str>) -> AppResult<UserListScope> {
    match status.unwrap_or("live") {
        "live" => Ok(UserListScope::Live),
        "active" => Ok(UserListScope::Active),
        "disabled" => Ok(UserListScope::Disabled),
        "archived" => Ok(UserListScope::Archived),
        "authorization_code" => Ok(UserListScope::AuthorizationCode),
        "all" => Ok(UserListScope::All),
        other => Err(AppError::BadRequest(format!(
            "unsupported user status filter: {other}"
        ))),
    }
}
