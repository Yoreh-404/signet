use sso_backend::{AppState, Settings, db::Db, jwt::JwtManager, server};

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

    server::serve(state, &settings).await
}
