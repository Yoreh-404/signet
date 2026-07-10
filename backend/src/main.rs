use anyhow::Context;
use axum::{
    Router,
    http::{HeaderName, HeaderValue, Method},
};
use sso_backend::{
    AppState, Settings, admin, db::Db, frontend, iap, jwt::JwtManager, oidc, passkeys,
    registration, scim,
};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowCredentials, CorsLayer},
    trace::TraceLayer,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sso_backend=info,tower_http=info,axum=info".to_string()),
        )
        .init();

    let settings = Settings::load()?;
    let db = Db::connect(&settings)?;
    if settings.database.run_migrations {
        db.migrate().await?;
    }
    db.seed(&settings).await?;
    let signing_keys = db.ensure_signing_key_seed(&settings).await?;
    let jwt = JwtManager::from_signing_keys(&settings, signing_keys)?;
    let state = AppState {
        settings: settings.clone(),
        db,
        jwt,
    };

    let app = Router::new()
        .merge(admin::routes())
        .merge(oidc::routes())
        .merge(iap::routes())
        .merge(passkeys::routes())
        .merge(registration::routes())
        .merge(scim::routes())
        .fallback(frontend::serve)
        .layer(cors_layer(&settings)?)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = settings.socket_addr()?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind server on {addr}"))?;
    tracing::info!("gpt-sso backend listening on http://{addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server failed")?;
    Ok(())
}

fn cors_layer(settings: &Settings) -> anyhow::Result<CorsLayer> {
    let origins = settings
        .cors
        .allowed_origins
        .iter()
        .map(|origin| origin.parse::<HeaderValue>())
        .collect::<Result<Vec<_>, _>>()?;
    let methods = settings
        .cors
        .allowed_methods
        .iter()
        .map(|method| method.parse::<Method>())
        .collect::<Result<Vec<_>, _>>()?;
    let headers = settings
        .cors
        .allowed_headers
        .iter()
        .map(|header| header.parse::<HeaderName>())
        .collect::<Result<Vec<_>, _>>()?;
    let layer = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(methods)
        .allow_headers(headers)
        .max_age(Duration::from_secs(3600));
    if settings.cors.allow_credentials {
        Ok(layer.allow_credentials(AllowCredentials::yes()))
    } else {
        Ok(layer)
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
