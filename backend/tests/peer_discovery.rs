#![cfg(feature = "sqlite")]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sso_backend::{
    AppState, Settings,
    config::{DatabaseKind, PeerMember, PeerNamespace},
    db::{Db, NewAuthorizationCode, NewUser},
    jwt::JwtManager,
    oidc, util,
};
use tower::ServiceExt;

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

async fn register(api: &Router, origin: &str) -> (PeerMember, String) {
    let body = registration(api, "/connect/register/website", origin).await;
    assert_eq!(body["subject_type"], "pairwise");
    (
        PeerMember {
            client_id: body["client_id"].as_str().unwrap().into(),
            origin: origin.into(),
        },
        body["registration_access_token"].as_str().unwrap().into(),
    )
}

async fn registration(api: &Router, endpoint: &str, origin: &str) -> Value {
    let request = Request::post(endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"redirect_uris": [format!("{origin}/callback")]}).to_string(),
        ))
        .unwrap();
    let response = api.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn get(api: &Router, site: &PeerMember, ns: &str, token: &str) -> axum::response::Response {
    let mut request = Request::get(format!(
        "/connect/register/{}/namespaces/{ns}/peers",
        site.client_id
    ));
    if !token.is_empty() {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    api.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn fixture() -> (AppState, std::path::PathBuf) {
    let mut settings: Settings = toml::from_str(include_str!("../../config/default.toml")).unwrap();
    let path = std::env::temp_dir().join(format!("signet-peers-{}.sqlite3", uuid::Uuid::new_v4()));
    settings.database.kind = DatabaseKind::Sqlite;
    settings.database.url = path.to_string_lossy().into_owned();
    settings.bootstrap.admin.create_on_startup = false;
    settings.bootstrap.clients.clear();
    settings.oidc.allow_public_website_registration = true;
    let db = Db::connect(&settings).unwrap();
    db.migrate().await.unwrap();
    db.seed(&settings).await.unwrap();
    let signing_keys = db.ensure_signing_key_seed(&settings).await.unwrap();
    let jwt = JwtManager::from_signing_keys(&settings, signing_keys).unwrap();
    (AppState::new(settings, db, jwt), path)
}

#[tokio::test]
async fn peer_directory_tracks_registration_namespace_and_current_origin() {
    let (mut state, path) = fixture().await;
    state.settings.oidc.allow_dynamic_client_registration = true;
    let api = oidc::routes().with_state(state.clone());
    let legacy = registration(&api, "/connect/register", "https://legacy.example").await;
    assert_eq!(legacy["token_endpoint_auth_method"], "client_secret_basic");
    assert!(legacy["client_secret"].is_string());
    let (a, a_token) = register(&api, "https://a.example").await;
    let (b, b_token) = register(&api, "https://b.example").await;
    let (c, c_token) = register(&api, "https://c.example").await;
    state.settings.oidc.allow_public_website_registration = false;
    state.settings.oidc.allow_dynamic_client_registration = false;
    state.settings.discovery.namespaces = vec![
        PeerNamespace {
            id: "ab".into(),
            members: vec![a.clone(), b.clone()],
        },
        PeerNamespace {
            id: "c".into(),
            members: vec![c.clone()],
        },
    ];
    let api = oidc::routes().with_state(state.clone());
    assert_eq!(
        get(&api, &a, "ab", "").await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(&api, &a, "ab", &c_token).await.status(),
        StatusCode::UNAUTHORIZED
    );
    for ns in ["ab", "missing"] {
        assert_eq!(
            get(&api, &c, ns, &c_token).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    let response = get(&api, &a, "ab", &a_token).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(json_body(response).await, json!({"peers":[b]}));
    assert_eq!(
        json_body(get(&api, &b, "ab", &b_token).await).await,
        json!({"peers":[a]})
    );

    state.settings.discovery.namespaces[0].members[1].origin = "https://wrong.example".into();
    let stale = oidc::routes().with_state(state.clone());
    assert_eq!(
        get(&stale, &b, "ab", &b_token).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        json_body(get(&stale, &a, "ab", &a_token).await).await,
        json!({"peers":[]})
    );
    let client = state
        .db
        .find_client_by_client_id(&b.client_id)
        .await
        .unwrap()
        .unwrap();
    state.db.delete_client(&client.id).await.unwrap();
    assert_eq!(
        json_body(get(&api, &a, "ab", &a_token).await).await,
        json!({"peers":[]})
    );
    assert_eq!(
        get(&api, &b, "ab", &b_token).await.status(),
        StatusCode::UNAUTHORIZED
    );
    drop((api, stale, state));
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn website_login_tokens_disclose_only_a_pairwise_identity() {
    let (state, path) = fixture().await;
    let api = oidc::routes().with_state(state.clone());
    let (site, _) = register(&api, "https://privacy.example").await;
    let email = "example-user@privacy.example";
    let user = state
        .db
        .insert_user(NewUser {
            email: email.into(),
            username: "privacy-user".into(),
            display_name: Some("Sensitive Name".into()),
            phone: None,
            password_hash: "test-hash".into(),
            email_verified_at: Some(util::now_ts()),
            phone_verified_at: None,
            is_admin: false,
            is_active: true,
            archived_at: None,
        })
        .await
        .unwrap();
    let callback = format!("{}/callback", site.origin);
    let verifier = "abcdefghijklmnopqrstuvwxyz-01234567890123456789";
    let initial = state
        .db
        .upsert_client_grant(&user.id, &site.client_id, "openid".into())
        .await
        .unwrap();
    let generation = initial.website_generation.as_deref().unwrap();
    let code = |random: &str| {
        format!(
            "{random}.{}",
            util::identity_factor_digest(generation, "website-authorization-code", random)
        )
    };
    let first_code = code("website-login-test-code");
    let pending_code = code("website-pending-test-code");
    for code in [&first_code, &pending_code] {
        state
            .db
            .insert_authorization_code(NewAuthorizationCode {
                code: code.clone(),
                client_id: site.client_id.clone(),
                user_id: user.id.clone(),
                application_id: None,
                authorization_profile_id: None,
                auth_context_id: None,
                session_id: None,
                redirect_uri: callback.clone(),
                scope: "openid".into(),
                resource: None,
                authorization_details: None,
                nonce: Some("website-login-nonce".into()),
                code_challenge: Some(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier))),
                code_challenge_method: Some("S256".into()),
                auth_time: util::now_ts(),
                acr: sso_backend::assurance::ACR_PASSWORD.into(),
                amr: vec!["pwd".into()],
                expires_at: util::now_ts() + 300,
            })
            .await
            .unwrap();
    }
    let form = |code: &str| {
        serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("client_id", site.client_id.as_str()),
            ("redirect_uri", callback.as_str()),
            ("code", code),
            ("code_verifier", verifier),
        ])
        .unwrap()
    };
    let redeem = |code: &str| {
        api.clone().oneshot(
            Request::post("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(code)))
                .unwrap(),
        )
    };
    let response = redeem(&first_code).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = json_body(response).await;
    assert!(response.get("refresh_token").is_none());
    let access = response["access_token"].as_str().unwrap();
    assert!(access.starts_with("sw1."));
    assert_ne!(access.split('.').count(), 3);
    let id = response["id_token"].as_str().unwrap();
    assert_eq!(id.split('.').count(), 3);
    let decoded = URL_SAFE_NO_PAD
        .decode(id.split('.').nth(1).unwrap())
        .unwrap();
    let claims: Value = serde_json::from_slice(&decoded).unwrap();
    let subject = claims["sub"].as_str().unwrap();
    assert_ne!(subject, user.id);
    assert_eq!(claims["nonce"], "website-login-nonce");
    for key in [
        "email",
        "name",
        "roles",
        "user_id",
        "organization_id",
        "sid",
    ] {
        assert!(
            claims.get(key).is_none(),
            "unexpected ID token claim: {key}"
        );
    }
    let payload = claims.to_string();
    assert!(!payload.contains(&user.id) && !payload.contains(email));

    let userinfo = || {
        api.clone().oneshot(
            Request::get("/oauth2/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
    };
    let response = userinfo().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await, json!({"sub": subject}));
    assert!(
        state
            .db
            .revoke_client_grant(&user.id, &site.client_id)
            .await
            .unwrap()
    );
    let restored = state
        .db
        .upsert_client_grant(&user.id, &site.client_id, "openid".into())
        .await
        .unwrap();
    assert_ne!(initial.website_generation, restored.website_generation);
    assert_eq!(userinfo().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        redeem(&pending_code).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    drop(state);
    let _ = std::fs::remove_file(path);
}
