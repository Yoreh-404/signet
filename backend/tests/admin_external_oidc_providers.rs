#![cfg(feature = "sqlite")]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sso_backend::{
    AppState, Settings, admin,
    config::DatabaseKind,
    db::{Db, NewExternalOidcProvider, NewOrganization, NewUser, SessionMetadata},
    jwt::JwtManager,
};
use std::path::PathBuf;
use tower::util::ServiceExt;

struct TestContext {
    app: Router,
    db: Db,
    cookie: String,
    cookie_name: String,
    organization_id: String,
    path: PathBuf,
}

impl TestContext {
    async fn new() -> Self {
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "signet-admin-external-oidc-provider-test-{}.sqlite3",
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
                email: "provider-manager@example.test".to_string(),
                username: "provider-manager".to_string(),
                display_name: Some("Provider Manager".to_string()),
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
        let organization = db
            .insert_organization(NewOrganization {
                slug: "provider-manager-org".to_string(),
                name: "Provider Manager Org".to_string(),
                kind: "tenant".to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization.id,
            &user.id,
            sso_backend::organizations::ROLE_OWNER,
        )
        .await
        .unwrap();
        db.set_active_user_organization(&user.id, &organization.id)
            .await
            .unwrap();
        let (_, cookie_value) = db
            .insert_session(
                &user.id,
                settings.security.session_ttl_seconds,
                SessionMetadata::default(),
            )
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
            cookie_name,
            organization_id: organization.id,
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

    async fn put(&self, uri: &str, payload: Value) -> (StatusCode, Vec<u8>) {
        self.request(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header("cookie", &self.cookie)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
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

fn external_oidc_provider(slug: &str, organization_id: &str) -> NewExternalOidcProvider {
    NewExternalOidcProvider {
        slug: slug.to_string(),
        display_name: format!("{slug} provider"),
        organization_id: Some(organization_id.to_string()),
        issuer: format!("https://{slug}.example.test"),
        client_id: format!("{slug}-client"),
        client_secret: format!("{slug}-secret"),
        authorization_endpoint: format!("https://{slug}.example.test/authorize"),
        token_endpoint: format!("https://{slug}.example.test/token"),
        userinfo_endpoint: format!("https://{slug}.example.test/userinfo"),
        redirect_path: format!("/api/register/oidc/{slug}/callback"),
        scopes: vec!["openid".to_string()],
        email_domains: Vec::new(),
        is_active: true,
        allow_login: true,
        allow_registration: true,
    }
}

fn provider_update_payload(slug: &str, organization_id: &str) -> Value {
    json!({
        "slug": slug,
        "display_name": format!("{slug} updated"),
        "organization_id": organization_id,
        "issuer": format!("https://{slug}.example.test"),
        "client_id": format!("{slug}-client"),
        "client_secret": "",
        "clear_client_secret": false,
        "authorization_endpoint": format!("https://{slug}.example.test/authorize"),
        "token_endpoint": format!("https://{slug}.example.test/token"),
        "userinfo_endpoint": format!("https://{slug}.example.test/userinfo"),
        "redirect_path": format!("/api/register/oidc/{slug}/callback"),
        "scopes": ["openid"],
        "email_domains": [],
        "is_active": true,
        "allow_login": true,
        "allow_registration": true,
    })
}

#[tokio::test]
async fn organization_provider_manager_sees_only_own_provider_and_cannot_mutate_foreign_one() {
    let context = TestContext::new().await;
    let foreign_organization = context
        .db
        .insert_organization(NewOrganization {
            slug: "foreign-provider-org".to_string(),
            name: "Foreign Provider Org".to_string(),
            kind: "tenant".to_string(),
            description: None,
            allowed_email_domains: Vec::new(),
            is_active: true,
        })
        .await
        .unwrap();
    let own_provider = context
        .db
        .insert_external_oidc_provider(external_oidc_provider(
            "own-provider",
            &context.organization_id,
        ))
        .await
        .unwrap();
    let foreign_provider = context
        .db
        .insert_external_oidc_provider(external_oidc_provider(
            "foreign-provider",
            &foreign_organization.id,
        ))
        .await
        .unwrap();

    let (status, body) = context.get("/api/admin/external-oidc-providers").await;
    assert_eq!(status, StatusCode::OK);
    let body = String::from_utf8(body).unwrap();
    let providers: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["id"], own_provider.id);
    assert_eq!(providers[0]["slug"], "own-provider");
    assert!(!body.contains("own-provider-secret"));
    assert!(!body.contains("client_secret"));

    let (status, _) = context
        .put(
            &format!("/api/admin/external-oidc-providers/{}", foreign_provider.id),
            provider_update_payload("foreign-provider", &foreign_organization.id),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = context
        .delete(&format!(
            "/api/admin/external-oidc-providers/{}",
            foreign_provider.id
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let unchanged = context
        .db
        .find_external_oidc_provider_by_id(&foreign_provider.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.slug, "foreign-provider");
    assert_eq!(unchanged.client_secret, "foreign-provider-secret");

    context.cleanup();
}

#[tokio::test]
async fn organization_member_without_providers_manage_is_forbidden() {
    let context = TestContext::new().await;
    let user = context
        .db
        .insert_user(NewUser {
            email: "provider-member@example.test".to_string(),
            username: "provider-member".to_string(),
            display_name: Some("Provider Member".to_string()),
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
    context
        .db
        .upsert_organization_member(
            &context.organization_id,
            &user.id,
            sso_backend::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
    context
        .db
        .set_active_user_organization(&user.id, &context.organization_id)
        .await
        .unwrap();
    let (_, cookie_value) = context
        .db
        .insert_session(&user.id, 600, SessionMetadata::default())
        .await
        .unwrap();
    let request = Request::builder()
        .method("GET")
        .uri("/api/admin/external-oidc-providers")
        .header("cookie", format!("{}={cookie_value}", context.cookie_name))
        .body(Body::empty())
        .unwrap();
    let response = context.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    context.cleanup();
}
