use sso_backend::{AppState, Settings, application_discovery, db::Db, jwt::JwtManager, server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sso_backend=info,tower_http=info,axum=info".to_string()),
        )
        .init();

    let settings = Settings::load()?;
    if settings.security.disable_csrf_origin_check {
        tracing::warn!(
            "CSRF Origin/Referer verification is disabled; use this setting only for local testing"
        );
    }
    let db = Db::connect_with_retry(&settings).await?;
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

    // A website-managed application stays unavailable until this initial
    // refresh succeeds, but one unavailable website must not prevent Signet
    // from starting. The failed attempt is persisted as operator-visible
    // discovery status by the synchronizer.
    if let Err(error) = application_discovery::sync_all(&state).await {
        tracing::warn!(error = %error, "initial website application discovery sweep failed");
    }

    server::serve(state, &settings).await
}
