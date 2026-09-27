#![cfg(feature = "sqlite")]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use sso_backend::{
    AppState, Settings,
    applications::{ACCESS_ALL_SIGNET_USERS, ACCOUNT_SELECTION_OPTIONAL, REGISTRATION_DISABLED},
    config::DatabaseKind,
    db::{
        Db, NewApplication, NewClient, NewIapApplication, NewOrganization, NewRuntimeSettings,
        NewUser, SessionMetadata,
    },
    iap,
    jwt::{JwtManager, TokenSubject},
    organizations::ORGANIZATION_KIND_TENANT,
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use tower::util::ServiceExt;

const TARGET: &str =
    "/api/iap/forward-auth?target=https%3A%2F%2Flegacy.example.test%2Fprivate%2Fasset.js";

struct PerfFixture {
    db: Db,
    path: PathBuf,
    cookie: String,
    bearer: String,
    jwt: JwtManager,
    settings: Settings,
}

impl PerfFixture {
    async fn new() -> Self {
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "signet-performance-hot-paths-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.pool_size = 32;
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();

        let db = Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.ensure_runtime_settings(NewRuntimeSettings {
            public_base_url: "http://localhost:8080".to_string(),
            issuer: "http://localhost:8080".to_string(),
            trust_proxy_headers: false,
        })
        .await
        .unwrap();

        let organization = db
            .insert_organization(NewOrganization {
                slug: "perf-org".to_string(),
                name: "Perf Org".to_string(),
                kind: ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application = db
            .insert_application(NewApplication {
                organization_id: organization.id.clone(),
                slug: "perf-legacy".to_string(),
                name: "Perf Legacy".to_string(),
                description: None,
                access_mode: ACCESS_ALL_SIGNET_USERS.to_string(),
                registration_mode: REGISTRATION_DISABLED.to_string(),
                account_selection_mode: ACCOUNT_SELECTION_OPTIONAL.to_string(),
                unique_identity_factors: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        db.insert_client_for_application(
            &application.id,
            NewClient {
                client_id: "perf-edge-client".to_string(),
                client_secret_hash: None,
                client_name: "Perf edge client".to_string(),
                logo_uri: String::new(),
                organization_id: Some(organization.id.clone()),
                redirect_uris: vec!["https://legacy.example.test/_signet/callback".to_string()],
                post_logout_redirect_uris: Vec::new(),
                scopes: vec!["openid".to_string(), "iap.assert".to_string()],
                audience: "perf-edge-client".to_string(),
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
                is_active: true,
            },
        )
        .await
        .unwrap();
        db.insert_iap_application(NewIapApplication {
            application_id: application.id.clone(),
            slug: "perf-private".to_string(),
            name: "Perf Private".to_string(),
            description: None,
            external_host: "legacy.example.test".to_string(),
            path_prefix: "/private".to_string(),
            required_organization_id: None,
            required_organization_roles: Vec::new(),
            required_permissions: Vec::new(),
            is_active: true,
        })
        .await
        .unwrap();

        let user = db
            .insert_user(NewUser {
                email: "perf@example.test".to_string(),
                username: "perf".to_string(),
                display_name: Some("Perf User".to_string()),
                phone: None,
                password_hash: "unused-in-perf-harness".to_string(),
                email_verified_at: None,
                phone_verified_at: None,
                is_admin: true,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let (_, cookie_value) = db
            .insert_session(&user.id, 3_600, SessionMetadata::default())
            .await
            .unwrap();
        let cookie = format!("{}={cookie_value}", settings.security.cookie_name);
        let jwt = JwtManager::new(&settings).unwrap();
        let binding = db
            .find_application_client_binding_by_public_client_id("perf-edge-client")
            .await
            .unwrap()
            .unwrap();
        let mut claims = serde_json::Map::new();
        claims.insert(
            "application_id".to_string(),
            serde_json::Value::String(application.id.clone()),
        );
        claims.insert(
            "authorization_profile_id".to_string(),
            serde_json::Value::String(binding.authorization_profile_id),
        );
        let bearer = jwt
            .sign_access_token_with_issuer_and_claims(
                &settings.oidc.issuer,
                TokenSubject {
                    user: &user,
                    client_id: "perf-edge-client",
                    audience: Some("perf-edge-client"),
                    scope: "openid iap.assert",
                    nonce: None,
                    auth_time: Some(sso_backend::util::now_ts()),
                },
                3_600,
                claims,
            )
            .unwrap();

        Self {
            db,
            path,
            cookie,
            bearer,
            jwt,
            settings,
        }
    }

    fn app_with(&self, configure: impl FnOnce(&mut Settings)) -> Router {
        let mut settings = self.settings.clone();
        configure(&mut settings);
        iap::routes().with_state(AppState::new(settings, self.db.clone(), self.jwt.clone()))
    }

    fn cleanup(self) {
        drop(self.db);
        let _ = std::fs::remove_file(self.path);
    }
}

#[derive(Debug)]
struct Measurement {
    label: &'static str,
    requests: usize,
    concurrency: usize,
    elapsed: Duration,
    latencies_micros: Vec<u128>,
}

impl Measurement {
    fn rps(&self) -> f64 {
        self.requests as f64 / self.elapsed.as_secs_f64()
    }

    fn percentile_ms(&self, percentile: f64) -> f64 {
        let index = ((self.latencies_micros.len() as f64 * percentile).ceil() as usize)
            .saturating_sub(1)
            .min(self.latencies_micros.len().saturating_sub(1));
        self.latencies_micros[index] as f64 / 1_000.0
    }

    fn print(&self) {
        eprintln!(
            "{} requests={} concurrency={} rps={:.1} p50={:.2}ms p95={:.2}ms p99={:.2}ms p99.9={:.2}ms max={:.2}ms elapsed={:.2}s",
            self.label,
            self.requests,
            self.concurrency,
            self.rps(),
            self.percentile_ms(0.50),
            self.percentile_ms(0.95),
            self.percentile_ms(0.99),
            self.percentile_ms(0.999),
            self.latencies_micros.last().copied().unwrap_or_default() as f64 / 1_000.0,
            self.elapsed.as_secs_f64(),
        );
    }
}

fn cookie_request(cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(TARGET)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

fn bearer_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/api/iap/bearer-auth?target=https%3A%2F%2Flegacy.example.test%2Fprivate%2Fasset.js")
        .header("authorization", format!("Bearer {token}"))
        .header("x-original-method", "GET")
        .body(Body::empty())
        .unwrap()
}

async fn assert_auth(app: Router, credential: &str, request: fn(&str) -> Request<Body>) {
    let response = app.oneshot(request(credential)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().contains_key("x-signet-assertion"));
}

async fn measure(
    label: &'static str,
    app: Router,
    credential: &str,
    request: fn(&str) -> Request<Body>,
    requests: usize,
    concurrency: usize,
) -> Measurement {
    for _ in 0..concurrency.min(64) {
        assert_auth(app.clone(), credential, request).await;
    }

    let next = Arc::new(AtomicUsize::new(0));
    let latencies = Arc::new(Mutex::new(Vec::with_capacity(requests)));
    let credential = Arc::new(credential.to_string());
    let started = Instant::now();
    let mut workers = JoinSet::new();

    for _ in 0..concurrency {
        let app = app.clone();
        let next = next.clone();
        let latencies = latencies.clone();
        let credential = credential.clone();
        workers.spawn(async move {
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= requests {
                    break;
                }
                let request_started = Instant::now();
                let response = app.clone().oneshot(request(&credential)).await.unwrap();
                let elapsed = request_started.elapsed().as_micros();
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
                assert!(response.headers().contains_key("x-signet-assertion"));
                latencies.lock().unwrap().push(elapsed);
                // A real HTTP client naturally yields on socket I/O. The
                // in-process full-cache path can otherwise complete entirely
                // synchronously and starve the one task which must perform a
                // spawn_blocking database refresh, producing scheduler
                // artifacts rather than meaningful ForwardAuth tail latency.
                tokio::task::yield_now().await;
            }
        });
    }

    while let Some(result) = workers.join_next().await {
        result.unwrap();
    }
    let elapsed = started.elapsed();
    let mut latencies_micros = Arc::try_unwrap(latencies).unwrap().into_inner().unwrap();
    latencies_micros.sort_unstable();
    assert_eq!(latencies_micros.len(), requests);

    Measurement {
        label,
        requests,
        concurrency,
        elapsed,
        latencies_micros,
    }
}

fn perf_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual performance smoke; run with --ignored --nocapture"]
async fn forward_auth_cache_profiles() {
    let fixture = PerfFixture::new().await;
    let requests = perf_usize("SIGNET_PERF_REQUESTS", 1_000);
    let concurrency = perf_usize("SIGNET_PERF_CONCURRENCY", 32);
    let profile = std::env::var("SIGNET_PERF_PROFILE").unwrap_or_else(|_| "all".to_string());

    let uncached = fixture.app_with(|settings| {
        settings.performance.runtime_settings_cache_millis = 0;
        settings.performance.iap_routing_cache_millis = 0;
        settings.performance.iap_authorization_cache_millis = 0;
    });
    let routing_cached = fixture.app_with(|settings| {
        settings.performance.runtime_settings_cache_millis = 1_000;
        settings.performance.iap_routing_cache_millis = 1_000;
        settings.performance.iap_authorization_cache_millis = 0;
    });
    let fully_cached = fixture.app_with(|_| {});

    if profile == "full-cache" {
        let result = measure(
            "forward-auth/full-cache",
            fully_cached,
            &fixture.cookie,
            cookie_request,
            requests,
            concurrency,
        )
        .await;
        result.print();
        fixture.cleanup();
        return;
    }
    assert_eq!(
        profile, "all",
        "SIGNET_PERF_PROFILE must be either 'all' or 'full-cache'"
    );

    let uncached_result = measure(
        "forward-auth/uncached",
        uncached,
        &fixture.cookie,
        cookie_request,
        requests,
        concurrency,
    )
    .await;
    let routing_result = measure(
        "forward-auth/control-plane-cache",
        routing_cached,
        &fixture.cookie,
        cookie_request,
        requests,
        concurrency,
    )
    .await;
    let full_result = measure(
        "forward-auth/full-cache",
        fully_cached,
        &fixture.cookie,
        cookie_request,
        requests,
        concurrency,
    )
    .await;

    uncached_result.print();
    routing_result.print();
    full_result.print();
    eprintln!(
        "relative full/uncached throughput={:.2}x control-plane/uncached={:.2}x",
        full_result.rps() / uncached_result.rps(),
        routing_result.rps() / uncached_result.rps(),
    );

    fixture.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual bearer-IAP performance smoke; run with --ignored --nocapture"]
async fn bearer_auth_cache_profile() {
    let fixture = PerfFixture::new().await;
    let requests = perf_usize("SIGNET_PERF_REQUESTS", 10_000);
    let concurrency = perf_usize("SIGNET_PERF_CONCURRENCY", 32);
    let result = measure(
        "bearer-auth/full-cache",
        fixture.app_with(|_| {}),
        &fixture.bearer,
        bearer_request,
        requests,
        concurrency,
    )
    .await;
    result.print();
    fixture.cleanup();
}
