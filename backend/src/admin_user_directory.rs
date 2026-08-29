use crate::{
    AppState,
    db::{
        LinkedIdentityRecord, LoginEventRecord, PublicUser, UserOptionRecord,
        UserOrganizationRecord,
    },
    error::{AppError, AppResult},
};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

use super::{
    admin_user_query::{
        USER_OPTION_DEFAULT_LIMIT, USER_OPTION_MAX_LIMIT, UserDirectoryCursorResponse,
        UserListPageResponse, UserListQuery, UserOptionQuery, decode_user_directory_cursor,
        encode_user_directory_cursor, normalize_user_list_text, parse_user_list_number,
        parse_user_list_query, user_list_scope,
    },
    require_user_list_reader, require_user_reader,
};

pub(super) async fn list_users(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<UserListQuery>,
) -> AppResult<Json<UserListPageResponse>> {
    let parsed = parse_user_list_query(query)?;
    require_user_list_reader(&state, &jar, parsed.filters.organization_id.as_deref()).await?;
    let page = state
        .db
        .list_admin_users_page(
            parsed.scope,
            parsed.filters,
            parsed.offset,
            parsed.page_size,
        )
        .await?;
    Ok(Json(UserListPageResponse {
        items: page.users.into_iter().map(|user| user.public()).collect(),
        page: parsed.page,
        page_size: page.limit,
        total: page.total,
    }))
}

pub(super) async fn list_users_cursor(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<UserListQuery>,
) -> AppResult<Json<UserDirectoryCursorResponse>> {
    let cursor = decode_user_directory_cursor(query.cursor.clone())?;
    let parsed = parse_user_list_query(query)?;
    require_user_list_reader(&state, &jar, parsed.filters.organization_id.as_deref()).await?;
    let page = state
        .db
        .list_admin_users_page_after(parsed.scope, parsed.filters, cursor, parsed.page_size)
        .await?;
    Ok(Json(UserDirectoryCursorResponse {
        items: page.users.into_iter().map(|user| user.public()).collect(),
        page_size: page.limit,
        next_cursor: page
            .next_cursor
            .as_ref()
            .map(encode_user_directory_cursor)
            .transpose()?,
    }))
}

pub(super) async fn list_user_options(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<UserOptionQuery>,
) -> AppResult<Json<Vec<UserOptionRecord>>> {
    let scope = user_list_scope(query.status.as_deref())?;
    let organization_id = normalize_user_list_text(query.organization_id, "organization_id", 128)?;
    let search = normalize_user_list_text(query.search, "search", 256)?;
    let limit = parse_user_list_number(
        query.limit,
        "limit",
        USER_OPTION_DEFAULT_LIMIT,
        Some(USER_OPTION_MAX_LIMIT),
        false,
    )?;
    require_user_list_reader(&state, &jar, organization_id.as_deref()).await?;
    Ok(Json(
        state
            .db
            .list_user_options(scope, organization_id.as_deref(), search.as_deref(), limit)
            .await?,
    ))
}

#[derive(Debug, Serialize)]
pub(super) struct UserDetailResponse {
    user: PublicUser,
    login_events: Vec<LoginEventRecord>,
    linked_identities: Vec<LinkedIdentityRecord>,
    organizations: Vec<UserOrganizationRecord>,
}

pub(super) async fn user_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<UserDetailResponse>> {
    require_user_reader(&state, &jar).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (login_events, linked_identities, organizations) = tokio::try_join!(
        state.db.list_login_events(&id, 20),
        state.db.list_linked_identities(&id),
        state.db.list_user_organizations(&id),
    )?;
    Ok(Json(UserDetailResponse {
        user: user.public(),
        login_events,
        linked_identities,
        organizations,
    }))
}

pub(super) async fn user_login_events(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<LoginEventRecord>>> {
    require_user_reader(&state, &jar).await?;
    Ok(Json(state.db.list_login_events(&id, 100).await?))
}

pub(super) async fn user_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<String>>> {
    require_user_reader(&state, &jar).await?;
    state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(state.db.list_effective_permissions(&id).await?))
}
