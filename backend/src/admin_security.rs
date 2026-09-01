use crate::{AppState, csrf, error::AppResult};
use axum::{Json, extract::State};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct CsrfTokenResponse {
    csrf_token: String,
}

pub(crate) async fn csrf_token(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<CsrfTokenResponse>> {
    Ok(Json(CsrfTokenResponse {
        csrf_token: csrf::token_for_current_session(&state, &jar).await?,
    }))
}
