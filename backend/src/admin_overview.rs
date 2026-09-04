use super::admin_guards::require_admin_reader;
use crate::{AppState, error::AppResult};
use axum::{Json, extract::State, http::HeaderMap};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct OverviewResponse {
    users: usize,
    active_users: usize,
    clients: usize,
    active_clients: usize,
    issuer: String,
    database_kind: String,
}

pub(crate) async fn overview(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<Json<OverviewResponse>> {
    require_admin_reader(&state, &jar).await?;
    let (user_counts, client_counts) = tokio::try_join!(
        state.db.count_user_overview(),
        state.db.count_client_overview(),
    )?;
    let (users, active_users) = user_counts;
    let (clients, active_clients) = client_counts;
    Ok(Json(OverviewResponse {
        active_users: active_users as usize,
        users: users as usize,
        active_clients: active_clients as usize,
        clients: clients as usize,
        issuer: state.effective_issuer(&headers).await?,
        database_kind: format!("{:?}", state.settings.database.kind).to_ascii_lowercase(),
    }))
}
