#![cfg(feature = "sqlite")]

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use sso_backend::{
    AppState, Settings,
    application_contract::ApplicationContract,
    applications::{ACCESS_ALL_SIGNET_USERS, ACCOUNT_SELECTION_OPTIONAL, REGISTRATION_DISABLED},
    config::DatabaseKind,
    db::{Db, NewApplication, NewClient, NewIapApplication, NewOrganization, NewUser},
    iap,
    jwt::{JwtManager, TokenSubject},
    organizations::ORGANIZATION_KIND_TENANT,
    util,
};
use std::{path::PathBuf, time::Duration};
use tower::util::ServiceExt;

struct Fixture {
    state: AppState,
    path: PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "signet-iap-oidc-edge-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();

        let db = Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = JwtManager::new(&settings).unwrap();
        Self {
            state: AppState::new(settings, db, jwt),
            path,
        }
    }

    fn cleanup(self) {
        drop(self.state);
        let _ = std::fs::remove_file(self.path);
    }
}

fn edge_client(organization_id: &str, active: bool) -> NewClient {
    NewClient {
        client_id: "legacy-edge-client".to_string(),
        client_secret_hash: None,
        client_name: "Legacy edge client".to_string(),
        logo_uri: String::new(),
        organization_id: Some(organization_id.to_string()),
        redirect_uris: vec!["https://legacy-edge.example.test/_signet/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_string(), "iap.assert".to_string()],
        audience: "legacy-edge-client".to_string(),
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        token_endpoint_auth_method: "none".to_string(),
        require_pkce: true,
        require_mfa: false,
        require_pushed_authorization_requests: false,
        require_s256_pkce: true,
        require_confidential_client: false,
        require_dpop: false,
        require_account_selection: false,
        trust_email_verified: false,
        authorization_details_types: Vec::new(),
        subject_type: "public".to_string(),
        sector_identifier_uri: String::new(),
        jwks_uri: String::new(),
        jwks: String::new(),
        backchannel_logout_uri: String::new(),
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: String::new(),
        frontchannel_logout_session_required: false,
        service_account_enabled: false,
        service_account_permissions: Vec::new(),
        is_active: active,
    }
}

fn signed_user_token(
    fixture: &Fixture,
    user: &sso_backend::db::UserRecord,
    application_id: &str,
    authorization_profile_id: &str,
    audience: &str,
    extra: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> String {
    let mut claims = serde_json::Map::new();
    claims.insert(
        "application_id".to_string(),
        Value::String(application_id.to_string()),
    );
    claims.insert(
        "authorization_profile_id".to_string(),
        Value::String(authorization_profile_id.to_string()),
    );
    extra(&mut claims);
    fixture
        .state
        .jwt
        .sign_access_token_with_issuer_and_claims(
            &fixture.state.settings.oidc.issuer,
            TokenSubject {
                user,
                client_id: "legacy-edge-client",
                audience: Some(audience),
                scope: "openid iap.assert",
                nonce: None,
                auth_time: Some(util::now_ts()),
            },
            300,
            claims,
        )
        .unwrap()
}

fn bearer_request(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/api/iap/bearer-auth?target=https%3A%2F%2Flegacy-edge.example.test%2Fprivate%2Fasset.js")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("x-original-method", "GET")
        .body(Body::empty())
        .unwrap()
}

#[test]
fn legacy_proxy_oidc_example_is_valid_and_rejects_long_lived_edge_credentials() {
    let mut contract: ApplicationContract = serde_json::from_str(include_str!(
        "../../docs/examples/application-v3-legacy-edge.json"
    ))
    .unwrap();
    let now = util::now_ts();
    contract.issued_at = now;
    contract.expires_at = now + 300;
    assert!(contract.validate(now).is_ok());

    let mut offline = contract.clone();
    offline.modules.clients[0]
        .scopes
        .push("offline_access".to_string());
    assert!(offline.validate(now).is_err());

    let mut weak_pkce = contract.clone();
    weak_pkce.modules.clients[0].require_s256_pkce = false;
    assert!(weak_pkce.validate(now).is_err());

    let mut wrong_scope = contract;
    wrong_scope.modules.clients[0].scopes = vec!["openid".to_string()];
    assert!(wrong_scope.validate(now).is_err());
}

#[tokio::test]
async fn bearer_auth_is_application_bound_and_observes_client_lifecycle() {
    let fixture = Fixture::new().await;
    let state = &fixture.state;
    let organization = state
        .db
        .insert_organization(NewOrganization {
            slug: "edge-org".to_string(),
            name: "Edge Org".to_string(),
            kind: ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: Vec::new(),
            is_active: true,
        })
        .await
        .unwrap();
    let application = state
        .db
        .insert_application(NewApplication {
            organization_id: organization.id.clone(),
            slug: "legacy-edge".to_string(),
            name: "Legacy Edge".to_string(),
            description: None,
            access_mode: ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: REGISTRATION_DISABLED.to_string(),
            account_selection_mode: ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        })
        .await
        .unwrap();
    let client = state
        .db
        .insert_client_for_application(&application.id, edge_client(&organization.id, true))
        .await
        .unwrap();
    let rule = state
        .db
        .insert_iap_application(NewIapApplication {
            application_id: application.id.clone(),
            slug: "edge-private".to_string(),
            name: "Edge Private".to_string(),
            description: None,
            external_host: "legacy-edge.example.test".to_string(),
            path_prefix: "/private".to_string(),
            required_organization_id: None,
            required_organization_roles: Vec::new(),
            required_permissions: Vec::new(),
            is_active: true,
        })
        .await
        .unwrap();
    let user = state
        .db
        .insert_user(NewUser {
            email: "edge-user@example.test".to_string(),
            username: "edge-user".to_string(),
            display_name: Some("Edge User".to_string()),
            phone: None,
            password_hash: "test-hash".to_string(),
            email_verified_at: Some(util::now_ts()),
            phone_verified_at: None,
            is_admin: false,
            is_active: true,
            archived_at: None,
        })
        .await
        .unwrap();
    let binding = state
        .db
        .find_application_client_binding_by_public_client_id("legacy-edge-client")
        .await
        .unwrap()
        .unwrap();

    let ordinary = signed_user_token(
        &fixture,
        &user,
        &application.id,
        &binding.authorization_profile_id,
        "legacy-edge-client",
        |_| {},
    );
    let temporary = signed_user_token(
        &fixture,
        &user,
        &application.id,
        &binding.authorization_profile_id,
        "legacy-edge-client",
        |claims| {
            claims.insert(
                "gpt_sso_login_code_level".to_string(),
                Value::String("account_recovery".to_string()),
            );
        },
    );
    let delegated = signed_user_token(
        &fixture,
        &user,
        &application.id,
        &binding.authorization_profile_id,
        "legacy-edge-client",
        |claims| {
            claims.insert(
                "act".to_string(),
                serde_json::json!({"sub": "service-account:edge-broker"}),
            );
        },
    );
    let resource_targeted = signed_user_token(
        &fixture,
        &user,
        &application.id,
        &binding.authorization_profile_id,
        "https://api.example.test",
        |_| {},
    );

    let http = iap::routes().with_state(state.clone());
    assert_eq!(
        http.clone()
            .oneshot(bearer_request(&temporary))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.clone()
            .oneshot(bearer_request(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.clone()
            .oneshot(bearer_request(&resource_targeted))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let response = http
        .clone()
        .oneshot(bearer_request(&ordinary))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response.headers().get("x-gpt-sso-iap-method").unwrap(),
        "GET"
    );
    let assertion = response
        .headers()
        .get("x-signet-assertion")
        .unwrap()
        .to_str()
        .unwrap();
    let assertion_claims = state
        .jwt
        .verify_iap_assertion(
            assertion,
            &[state.settings.oidc.issuer.as_str()],
            &[format!("signet:iap:{}", rule.id)],
        )
        .unwrap();
    assert_eq!(assertion_claims.sub, user.id);
    assert_eq!(
        assertion_claims.application_id.as_deref(),
        Some(application.id.as_str())
    );

    state
        .db
        .update_application_oidc_client_graph(
            &application.id,
            &client.id,
            edge_client(&organization.id, false),
            Vec::new(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(
        state.settings.performance.iap_authorization_cache_millis
            + state
                .settings
                .performance
                .iap_authorization_stale_while_refresh_millis
            + 25,
    ))
    .await;
    assert_eq!(
        http.oneshot(bearer_request(&ordinary))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    fixture.cleanup();
}
