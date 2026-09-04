#![cfg(feature = "sqlite")]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use serde_json::Value;
use sso_backend::{
    AppState, Settings, admin,
    config::DatabaseKind,
    db::{Db, NewUser, SessionMetadata},
    jwt::JwtManager,
    util,
};
use std::path::PathBuf;
use tower::util::ServiceExt;

struct TestContext {
    app: Router,
    db: Db,
    cookie: String,
    user_id: String,
    current_session_id: String,
    path: PathBuf,
}

impl TestContext {
    async fn new() -> Self {
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "signet-admin-account-sessions-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();

        let db = Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        let user = db
            .insert_user(NewUser {
                email: "session-manager@example.test".to_string(),
                username: "session-manager".to_string(),
                display_name: Some("Session Manager".to_string()),
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: None,
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let (current_session, cookie_value) = db
            .insert_session(&user.id, 600, SessionMetadata::default())
            .await
            .unwrap();
        let cookie_name = settings.security.cookie_name.clone();
        let cookie = format!("{cookie_name}={cookie_value}");
        let jwt = JwtManager::new(&settings).unwrap();
        let state = AppState {
            settings,
            db: db.clone(),
            jwt,
        };

        Self {
            app: admin::routes().with_state(state),
            db,
            cookie,
            user_id: user.id,
            current_session_id: current_session.id,
            path,
        }
    }

    async fn request(&self, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, body.to_vec())
    }

    async fn get(&self, uri: &str) -> (StatusCode, Vec<u8>) {
        self.request(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("cookie", &self.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn get_with_headers(&self, uri: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("cookie", &self.cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, headers, body.to_vec())
    }

    async fn delete(&self, uri: &str) -> (StatusCode, Vec<u8>) {
        self.request(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("cookie", &self.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    fn cleanup(self) {
        drop(self.app);
        drop(self.db);
        let _ = std::fs::remove_file(self.path);
    }
}

async fn insert_user(db: &Db, email: &str, username: &str) -> sso_backend::db::UserRecord {
    db.insert_user(NewUser {
        email: email.to_string(),
        username: username.to_string(),
        display_name: None,
        phone: None,
        password_hash: "test-hash".to_string(),
        email_verified_at: None,
        phone_verified_at: None,
        is_admin: false,
        is_active: true,
        archived_at: None,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn account_session_management_preserves_boundaries_and_cleans_revoked_session() {
    let context = TestContext::new().await;
    let (target_session, _) = context
        .db
        .insert_session(&context.user_id, 600, SessionMetadata::default())
        .await
        .unwrap();

    let (status, body) = context.get("/api/me/sessions").await;
    assert_eq!(status, StatusCode::OK);
    let body_text = String::from_utf8(body).unwrap();
    let sessions: Vec<Value> = serde_json::from_str(&body_text).unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.iter().any(|session| session["current"] == true));
    assert!(sessions.iter().all(|session| session["id"].is_string()));
    assert!(!body_text.contains("csrf_token"));
    assert!(!body_text.contains("csrf"));

    let browser_context_id = "session-management-browser-context";
    context
        .db
        .insert_browser_context(browser_context_id, "browser-context-csrf", 600)
        .await
        .unwrap();
    let account = context
        .db
        .attach_browser_context_account(browser_context_id, &context.user_id, &target_session.id)
        .await
        .unwrap();
    let (_, _target_credential) = context
        .db
        .mint_browser_account_session_credential(browser_context_id, &account.id)
        .await
        .unwrap();

    let target_handle = util::session_public_id(&target_session.id);
    let (status, _) = context
        .delete(&format!("/api/me/sessions/{target_handle}"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        context
            .db
            .find_session(&target_session.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        context
            .db
            .list_browser_context_accounts(browser_context_id)
            .await
            .unwrap()
            .is_empty()
    );

    let current_handle = util::session_public_id(&context.current_session_id);
    let (status, _) = context
        .delete(&format!("/api/me/sessions/{current_handle}"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        context
            .db
            .find_session(&context.current_session_id)
            .await
            .unwrap()
            .is_some()
    );

    let other_user = insert_user(
        &context.db,
        "other-session-user@example.test",
        "other-session-user",
    )
    .await;
    let (other_session, _) = context
        .db
        .insert_session(&other_user.id, 600, SessionMetadata::default())
        .await
        .unwrap();
    let other_handle = util::session_public_id(&other_session.id);
    let (status, _) = context
        .delete(&format!("/api/me/sessions/{other_handle}"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        context
            .db
            .find_session(&other_session.id)
            .await
            .unwrap()
            .is_some()
    );

    let (status, _) = context
        .delete("/api/me/sessions/sid.unknown-session-handle")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    context.cleanup();
}

#[tokio::test]
async fn account_session_list_is_bounded_and_cursor_paginated() {
    let context = TestContext::new().await;
    for _ in 0..100 {
        context
            .db
            .insert_session(&context.user_id, 600, SessionMetadata::default())
            .await
            .unwrap();
    }

    let (status, headers, body) = context
        .get_with_headers("/api/me/sessions?limit=1000")
        .await;
    assert_eq!(status, StatusCode::OK);
    let first_page: Vec<Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(first_page.len(), 100);
    let next_cursor = headers
        .get("x-next-cursor")
        .and_then(|value| value.to_str().ok())
        .expect("first page should include a cursor");

    let (status, second_headers, body) = context
        .get_with_headers(&format!("/api/me/sessions?limit=100&cursor={next_cursor}"))
        .await;
    assert_eq!(status, StatusCode::OK);
    let second_page: Vec<Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(second_page.len(), 1);
    assert!(second_headers.get("x-next-cursor").is_none());

    let first_ids: std::collections::HashSet<&str> = first_page
        .iter()
        .map(|session| session["id"].as_str().unwrap())
        .collect();
    assert!(
        second_page
            .iter()
            .all(|session| !first_ids.contains(session["id"].as_str().unwrap()))
    );

    let (status, headers, body) = context.get_with_headers("/api/me/sessions").await;
    assert_eq!(status, StatusCode::OK);
    let default_page: Vec<Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(default_page.len(), 100);
    assert!(headers.get("x-next-cursor").is_some());

    context.cleanup();
}
