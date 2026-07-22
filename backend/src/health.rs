use crate::AppState;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/health", get(live))
        .route("/api/health/live", get(live))
        .route("/api/health/ready", get(ready))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    status: &'static str,
    service: &'static str,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    checks: Option<HealthChecks>,
}

#[derive(Debug, Serialize)]
struct HealthChecks {
    database: &'static str,
    runtime_settings: &'static str,
    signing_key: &'static str,
}

async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        status: "alive",
        service: "signet",
        version: env!("CARGO_PKG_VERSION"),
        checks: None,
    })
}

async fn ready(State(state): State<AppState>) -> Response {
    let result = async {
        state.db.ping().await?;
        state.db.runtime_settings().await?;
        let has_active_key = state
            .db
            .list_signing_keys()
            .await?
            .into_iter()
            .any(|key| key.is_active == 1);
        if !has_active_key {
            return Err(crate::error::AppError::Configuration(
                "no active signing key".to_string(),
            ));
        }
        Ok::<(), crate::error::AppError>(())
    }
    .await;

    match result {
        Ok(()) => (
            StatusCode::OK,
            Json(HealthResponse {
                ok: true,
                status: "ready",
                service: "signet",
                version: env!("CARGO_PKG_VERSION"),
                checks: Some(HealthChecks {
                    database: "ok",
                    runtime_settings: "ok",
                    signing_key: "ok",
                }),
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    ok: false,
                    status: "not_ready",
                    service: "signet",
                    version: env!("CARGO_PKG_VERSION"),
                    checks: None,
                }),
            )
                .into_response()
        }
    }
}
