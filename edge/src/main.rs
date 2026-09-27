use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env, fs,
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use url::Url;

const START_PATH: &str = "/_signet/start";
const CALLBACK_PATH: &str = "/_signet/callback";
const AUTH_PATH: &str = "/_signet/auth";
const LOGOUT_PATH: &str = "/_signet/logout";
const HEALTH_PATH: &str = "/healthz";
const STATE_TTL_SECONDS: i64 = 300;
const DEFAULT_SESSION_CAP_SECONDS: u64 = 600;
const MAX_SESSION_CAP_SECONDS: u64 = 3_600;
const MAX_RETURN_TO_BYTES: usize = 2_048;
const MAX_SEALED_COOKIE_BYTES: usize = 3_800;
const MAX_COOKIE_KEY_FILE_BYTES: u64 = 16 * 1_024;

const IDENTITY_RESPONSE_HEADERS: &[&str] = &[
    "x-gpt-sso-iap-application",
    "x-gpt-sso-iap-method",
    "x-auth-request-user",
    "x-auth-request-email",
    "x-auth-request-user-id",
    "x-auth-request-name",
    "x-forwarded-user",
    "x-forwarded-email",
    "x-signet-subject",
    "x-signet-email",
    "x-signet-name",
    "x-signet-organization",
    "x-signet-roles",
    "x-signet-permissions",
    "x-signet-assertion",
    "x-signet-assertion-audience",
    "x-signet-assertion-expires-in",
];

#[derive(Debug)]
struct Config {
    public_origin: Url,
    issuer: Url,
    client_id: String,
    bind_host: String,
    bind_port: u16,
    upstream_timeout: Duration,
    max_session_seconds: u64,
    scopes: Vec<String>,
    session_cookie: String,
    state_cookie: String,
    cookie_keys: Vec<[u8; 32]>,
}

impl Config {
    fn from_env() -> Result<Self> {
        let allow_http = bool_env("SIGNET_EDGE_ALLOW_HTTP");
        let public_origin = safe_origin(
            &required_env("SIGNET_EDGE_PUBLIC_ORIGIN")?,
            allow_http,
            "SIGNET_EDGE_PUBLIC_ORIGIN",
        )?;
        let issuer = safe_origin(
            &required_env("SIGNET_EDGE_ISSUER")?,
            allow_http,
            "SIGNET_EDGE_ISSUER",
        )?;
        let client_id = required_env("SIGNET_EDGE_CLIENT_ID")?;
        let cookie_keys = parse_cookie_keys(&cookie_key_material_from_env()?)?;
        let scopes = env::var("SIGNET_EDGE_SCOPES")
            .unwrap_or_else(|_| "openid iap.assert".to_string())
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        validate_scopes(&scopes)?;

        let bind_host = env::var("SIGNET_EDGE_BIND_HOST")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let bind_port = positive_u64_env("SIGNET_EDGE_BIND_PORT", 4_180)?
            .try_into()
            .map_err(|_| anyhow!("SIGNET_EDGE_BIND_PORT must fit in u16"))?;
        let upstream_timeout =
            Duration::from_millis(positive_u64_env("SIGNET_EDGE_UPSTREAM_TIMEOUT_MS", 5_000)?);
        let max_session_seconds = validate_max_session_seconds(positive_u64_env(
            "SIGNET_EDGE_MAX_SESSION_SECONDS",
            DEFAULT_SESSION_CAP_SECONDS,
        )?)?;
        let session_cookie = host_cookie_name(
            env::var("SIGNET_EDGE_COOKIE_NAME").ok().as_deref(),
            "__Host-signet_edge",
            "SIGNET_EDGE_COOKIE_NAME",
        )?;
        let state_cookie = host_cookie_name(
            env::var("SIGNET_EDGE_STATE_COOKIE_NAME").ok().as_deref(),
            "__Host-signet_edge_state",
            "SIGNET_EDGE_STATE_COOKIE_NAME",
        )?;
        if session_cookie == state_cookie {
            bail!("edge session and state cookie names must differ");
        }

        Ok(Self {
            public_origin,
            issuer,
            client_id,
            bind_host,
            bind_port,
            upstream_timeout,
            max_session_seconds,
            scopes,
            session_cookie,
            state_cookie,
            cookie_keys,
        })
    }

    fn redirect_uri(&self) -> Url {
        self.public_origin
            .join(CALLBACK_PATH)
            .expect("fixed callback path must join public origin")
    }

    fn iap_endpoint(&self) -> Url {
        self.issuer
            .join("/api/iap/bearer-auth")
            .expect("fixed IAP path must join issuer")
    }
}

#[derive(Clone)]
struct EdgeState {
    config: Arc<Config>,
    codec: Arc<CookieCodec>,
    discovery: Arc<Discovery>,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
struct Discovery {
    authorization_endpoint: Url,
    token_endpoint: Url,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginState {
    state: String,
    verifier: String,
    return_to: String,
    exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct EdgeSession {
    access_token: String,
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct StartQuery {
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Debug, Clone)]
struct CookieKey {
    id: String,
    key: [u8; 32],
}

#[derive(Debug, Clone)]
struct CookieCodec {
    keys: Vec<CookieKey>,
    public_origin: String,
}

impl CookieCodec {
    fn new(keys: &[[u8; 32]], public_origin: &Url) -> Result<Self> {
        if keys.is_empty() {
            bail!("at least one cookie key is required");
        }
        let mut ids = BTreeSet::new();
        let keys = keys
            .iter()
            .map(|key| {
                let digest = Sha256::digest(key);
                let id = URL_SAFE_NO_PAD.encode(digest);
                let id = id[..12].to_string();
                if !ids.insert(id.clone()) {
                    bail!("cookie key identifiers must be unique");
                }
                Ok(CookieKey { id, key: *key })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            keys,
            public_origin: canonical_origin(public_origin),
        })
    }

    fn seal<T: Serialize>(&self, payload: &T, purpose: &str) -> Result<String> {
        let active = self
            .keys
            .first()
            .ok_or_else(|| anyhow!("cookie key ring is empty"))?;
        let cipher = Aes256Gcm::new_from_slice(&active.key)
            .map_err(|_| anyhow!("cookie encryption key is invalid"))?;
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce =
            Nonce::try_from(&nonce_bytes[..]).map_err(|_| anyhow!("cookie nonce is invalid"))?;
        let plaintext = serde_json::to_vec(payload).context("failed to encode edge cookie")?;
        let aad = self.aad(purpose);
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("failed to encrypt edge cookie"))?;
        Ok(format!(
            "v1.{}.{}.{}",
            active.id,
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            URL_SAFE_NO_PAD.encode(encrypted)
        ))
    }

    fn open<T: DeserializeOwned>(&self, value: &str, purpose: &str) -> Option<T> {
        if value.len() > 8_192 {
            return None;
        }
        let mut parts = value.split('.');
        if parts.next()? != "v1" {
            return None;
        }
        let id = parts.next()?;
        let nonce = canonical_base64url(parts.next()?).ok()?;
        let encrypted = canonical_base64url(parts.next()?).ok()?;
        if parts.next().is_some() || nonce.len() != 12 || encrypted.len() <= 16 {
            return None;
        }
        let material = self.keys.iter().find(|key| key.id == id)?;
        let cipher = Aes256Gcm::new_from_slice(&material.key).ok()?;
        let nonce = Nonce::try_from(nonce.as_slice()).ok()?;
        let aad = self.aad(purpose);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &encrypted,
                    aad: aad.as_bytes(),
                },
            )
            .ok()?;
        serde_json::from_slice(&plaintext).ok()
    }

    fn aad(&self, purpose: &str) -> String {
        format!("signet-edge:v1:{}:{purpose}", self.public_origin)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().any(|argument| argument == "--self-test") {
        self_test()?;
        println!("signet-edge self-test ok");
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Arc::new(Config::from_env()?);
    let client = build_upstream_client(config.upstream_timeout)?;
    let discovery = Arc::new(load_discovery(&client, &config).await?);
    let codec = Arc::new(CookieCodec::new(
        &config.cookie_keys,
        &config.public_origin,
    )?);
    let bind = format!("{}:{}", config.bind_host, config.bind_port);
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind Signet edge on {bind}"))?;
    let state = EdgeState {
        config,
        codec,
        discovery,
        client,
    };
    let router = routes(state);

    info!(bind = %bind, "signet edge listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Signet edge server failed")?;
    Ok(())
}

fn routes(state: EdgeState) -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health))
        .route(START_PATH, get(start_login))
        .route(CALLBACK_PATH, get(finish_login))
        .route(AUTH_PATH, get(authorize_request))
        .route(LOGOUT_PATH, get(logout))
        .with_state(state)
}

fn build_upstream_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        // Identity traffic must not silently inherit HTTP_PROXY/HTTPS_PROXY
        // from the host. The configured issuer origin is the trust boundary.
        .no_proxy()
        .redirect(Policy::none())
        .timeout(timeout)
        .user_agent(concat!("signet-edge/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build edge HTTP client")
}

async fn health() -> Response {
    let mut response = (StatusCode::OK, r#"{"status":"ok"}"#).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    harden_response(&mut response);
    response
}

async fn start_login(State(state): State<EdgeState>, Query(query): Query<StartQuery>) -> Response {
    let return_to = match normalize_path(
        query.return_to.as_deref().unwrap_or("/"),
        &state.config.public_origin,
    ) {
        Ok(value) => value,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid return_to"),
    };
    let csrf_state = random_base64url(24);
    let verifier = random_base64url(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let transient = LoginState {
        state: csrf_state.clone(),
        verifier,
        return_to,
        exp: now_ts() + STATE_TTL_SECONDS,
    };
    let sealed = match state.codec.seal(&transient, "state") {
        Ok(value) => value,
        Err(error) => {
            error!(%error, "failed to seal OIDC state cookie");
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal edge error");
        }
    };
    let state_cookie = set_cookie(
        &state.config.state_cookie,
        &sealed,
        STATE_TTL_SECONDS as u64,
    );
    if state_cookie.len() > MAX_SEALED_COOKIE_BYTES {
        return text_response(StatusCode::BAD_REQUEST, "return_to is too long");
    }
    let mut authorize = state.discovery.authorization_endpoint.clone();
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &state.config.client_id)
        .append_pair("redirect_uri", state.config.redirect_uri().as_str())
        .append_pair("scope", &state.config.scopes.join(" "))
        .append_pair("state", &csrf_state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    redirect_response(StatusCode::FOUND, authorize.as_str(), &[state_cookie])
}

async fn finish_login(
    State(state): State<EdgeState>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let clear_state = clear_cookie(&state.config.state_cookie);
    let cookies = parse_cookies(&headers);
    let transient = cookies
        .get(state.config.state_cookie.as_str())
        .and_then(|value| state.codec.open::<LoginState>(value, "state"));
    let Some(transient) = transient else {
        return response_with_cookies(
            StatusCode::UNAUTHORIZED,
            "OIDC callback rejected",
            &[clear_state],
        );
    };
    let Some(code) = query.code.as_deref().filter(|value| !value.is_empty()) else {
        return response_with_cookies(
            StatusCode::UNAUTHORIZED,
            "OIDC callback rejected",
            &[clear_state],
        );
    };
    let Some(callback_state) = query.state.as_deref().filter(|value| !value.is_empty()) else {
        return response_with_cookies(
            StatusCode::UNAUTHORIZED,
            "OIDC callback rejected",
            &[clear_state],
        );
    };
    if query.error.is_some()
        || transient.exp < now_ts()
        || !constant_time_equal(transient.state.as_bytes(), callback_state.as_bytes())
    {
        return response_with_cookies(
            StatusCode::UNAUTHORIZED,
            "OIDC callback rejected",
            &[clear_state],
        );
    }

    let token_response = state
        .client
        .post(state.discovery.token_endpoint.clone())
        .header(header::ACCEPT.as_str(), "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", state.config.client_id.as_str()),
            ("code", code),
            ("redirect_uri", state.config.redirect_uri().as_str()),
            ("code_verifier", transient.verifier.as_str()),
        ])
        .send()
        .await;
    let token_response = match token_response {
        Ok(response) => response,
        Err(error) => {
            error!(%error, "OIDC token endpoint unavailable");
            return response_with_cookies(
                StatusCode::BAD_GATEWAY,
                "identity upstream unavailable",
                &[clear_state],
            );
        }
    };
    if !token_response.status().is_success() {
        return response_with_cookies(
            StatusCode::BAD_GATEWAY,
            "OIDC token exchange failed",
            &[clear_state],
        );
    }
    let token = match token_response.json::<TokenResponse>().await {
        Ok(token) => token,
        Err(error) => {
            error!(%error, "OIDC token endpoint returned invalid JSON");
            return response_with_cookies(
                StatusCode::BAD_GATEWAY,
                "OIDC token response invalid",
                &[clear_state],
            );
        }
    };
    if token.access_token.is_empty() || !token.token_type.eq_ignore_ascii_case("bearer") {
        return response_with_cookies(
            StatusCode::BAD_GATEWAY,
            "OIDC token response invalid",
            &[clear_state],
        );
    }
    let usable_lifetime = token.expires_in.saturating_sub(5);
    if usable_lifetime == 0 {
        return response_with_cookies(
            StatusCode::BAD_GATEWAY,
            "OIDC access token expires too soon",
            &[clear_state],
        );
    }
    let session_lifetime = usable_lifetime.min(state.config.max_session_seconds);
    let session = EdgeSession {
        access_token: token.access_token,
        exp: now_ts().saturating_add(session_lifetime as i64),
    };
    let sealed = match state.codec.seal(&session, "session") {
        Ok(value) => value,
        Err(error) => {
            error!(%error, "failed to seal edge session cookie");
            return response_with_cookies(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal edge error",
                &[clear_state],
            );
        }
    };
    let session_cookie = set_cookie(&state.config.session_cookie, &sealed, session_lifetime);
    if session_cookie.len() > MAX_SEALED_COOKIE_BYTES {
        return response_with_cookies(
            StatusCode::BAD_GATEWAY,
            "OIDC access token is too large for the sealed edge cookie",
            &[clear_state],
        );
    }
    let return_to = match normalize_path(&transient.return_to, &state.config.public_origin) {
        Ok(value) => value,
        Err(_) => {
            return response_with_cookies(
                StatusCode::UNAUTHORIZED,
                "OIDC callback rejected",
                &[clear_state],
            );
        }
    };
    redirect_response(
        StatusCode::FOUND,
        &return_to,
        &[session_cookie, clear_state],
    )
}

async fn logout(State(state): State<EdgeState>) -> Response {
    redirect_response(
        StatusCode::FOUND,
        "/",
        &[
            clear_cookie(&state.config.session_cookie),
            clear_cookie(&state.config.state_cookie),
        ],
    )
}

async fn authorize_request(State(state): State<EdgeState>, headers: HeaderMap) -> Response {
    let target = match request_target(&headers, &state.config.public_origin) {
        Ok(target) => target,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid protected target"),
    };
    let method = match original_method(&headers) {
        Ok(method) => method,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid protected method"),
    };
    let cookies = parse_cookies(&headers);
    let session = cookies
        .get(state.config.session_cookie.as_str())
        .and_then(|value| state.codec.open::<EdgeSession>(value, "session"));
    let Some(session) =
        session.filter(|session| session.exp > now_ts() && !session.access_token.trim().is_empty())
    else {
        return login_challenge(&state.config, &target);
    };

    let mut endpoint = state.config.iap_endpoint();
    endpoint
        .query_pairs_mut()
        .append_pair("target", target.as_str());
    let decision = state
        .client
        .get(endpoint)
        .bearer_auth(&session.access_token)
        .header("x-original-method", method.as_str())
        .header(header::ACCEPT.as_str(), "*/*")
        .send()
        .await;
    let decision = match decision {
        Ok(response) => response,
        Err(error) => {
            error!(%error, "Signet IAP decision endpoint unavailable");
            return text_response(StatusCode::BAD_GATEWAY, "identity upstream unavailable");
        }
    };

    match decision.status().as_u16() {
        401 => login_challenge(&state.config, &target),
        403 => empty_response(StatusCode::FORBIDDEN),
        204 => {
            if decision.headers().get("x-signet-assertion").is_none()
                || decision.headers().get("x-signet-subject").is_none()
                || decision
                    .headers()
                    .get("x-signet-assertion-audience")
                    .is_none()
                || decision
                    .headers()
                    .get("x-gpt-sso-iap-method")
                    .and_then(|value| value.to_str().ok())
                    != Some(method.as_str())
            {
                error!("Signet IAP allow response omitted required identity headers");
                return text_response(StatusCode::BAD_GATEWAY, "Signet IAP decision incomplete");
            }
            let mut response = empty_response(StatusCode::NO_CONTENT);
            for name in IDENTITY_RESPONSE_HEADERS {
                if let Some(value) = decision.headers().get(*name)
                    && let Ok(value) = HeaderValue::from_bytes(value.as_bytes())
                {
                    response.headers_mut().insert(*name, value);
                }
            }
            response
        }
        _ => text_response(StatusCode::BAD_GATEWAY, "Signet IAP decision failed"),
    }
}

async fn load_discovery(client: &reqwest::Client, config: &Config) -> Result<Discovery> {
    let discovery_url = config
        .issuer
        .join("/.well-known/openid-configuration")
        .context("failed to construct OIDC discovery URL")?;
    let response = client
        .get(discovery_url)
        .header(header::ACCEPT.as_str(), "application/json")
        .send()
        .await
        .context("OIDC discovery request failed")?;
    if !response.status().is_success() {
        bail!("OIDC discovery failed with HTTP {}", response.status());
    }
    let document = response
        .json::<DiscoveryDocument>()
        .await
        .context("OIDC discovery response is invalid")?;
    let document_issuer = safe_origin(
        &document.issuer,
        config.issuer.scheme() == "http",
        "OIDC discovery issuer",
    )?;
    if canonical_origin(&document_issuer) != canonical_origin(&config.issuer) {
        bail!("OIDC discovery issuer mismatch");
    }
    Ok(Discovery {
        authorization_endpoint: validate_discovery_endpoint(
            &document.authorization_endpoint,
            &config.issuer,
            "authorization_endpoint",
        )?,
        token_endpoint: validate_discovery_endpoint(
            &document.token_endpoint,
            &config.issuer,
            "token_endpoint",
        )?,
    })
}

fn validate_discovery_endpoint(raw: &str, issuer: &Url, name: &str) -> Result<Url> {
    let endpoint = Url::parse(raw).with_context(|| format!("OIDC discovery {name} is invalid"))?;
    if canonical_origin(&endpoint) != canonical_origin(issuer)
        || endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("OIDC discovery {name} must stay on the configured issuer origin");
    }
    Ok(endpoint)
}

fn login_challenge(config: &Config, target: &Url) -> Response {
    let mut response = empty_response(StatusCode::UNAUTHORIZED);
    let login = local_login_url(target);
    if let Ok(value) = HeaderValue::from_str(&login) {
        response
            .headers_mut()
            .insert("x-auth-request-redirect", value);
    }
    append_header(
        &mut response,
        header::SET_COOKIE,
        &clear_cookie(&config.session_cookie),
    );
    response
}

fn local_login_url(target: &Url) -> String {
    let return_to = path_and_query(target);
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("return_to", &return_to)
        .finish();
    format!("{START_PATH}?{encoded}")
}

fn request_target(headers: &HeaderMap, public_origin: &Url) -> Result<Url> {
    let candidate = first_header(headers, "x-original-url")
        .or_else(|| first_header(headers, "x-original-uri"))
        .unwrap_or("/");
    let target = public_origin
        .join(candidate)
        .context("protected target is not a valid URL")?;
    if canonical_origin(&target) != canonical_origin(public_origin)
        || target.username() != ""
        || target.password().is_some()
        || target.fragment().is_some()
    {
        bail!("protected target must stay on SIGNET_EDGE_PUBLIC_ORIGIN");
    }
    Ok(target)
}

fn original_method(headers: &HeaderMap) -> Result<Method> {
    let raw = first_header(headers, "x-original-method").unwrap_or("GET");
    Method::from_bytes(raw.as_bytes()).context("protected method is invalid")
}

fn normalize_path(raw: &str, public_origin: &Url) -> Result<String> {
    let value = if raw.trim().is_empty() {
        "/"
    } else {
        raw.trim()
    };
    let target = public_origin
        .join(value)
        .context("return_to is not a valid URL/path")?;
    if canonical_origin(&target) != canonical_origin(public_origin)
        || target.username() != ""
        || target.password().is_some()
        || target.fragment().is_some()
    {
        bail!("return_to must stay on the protected site origin");
    }
    let normalized = path_and_query(&target);
    if normalized.len() > MAX_RETURN_TO_BYTES {
        bail!("return_to exceeds the maximum supported length");
    }
    Ok(normalized)
}

fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

fn safe_origin(raw: &str, allow_http: bool, name: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("{name} must be a valid URL"))?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("{name} must be an origin without credentials/path/query/fragment");
    }
    if url.scheme() == "https" || (allow_http && url.scheme() == "http" && is_loopback(&url)) {
        return Ok(url);
    }
    bail!("{name} must use HTTPS (HTTP is allowed only for loopback test origins)")
}

fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|address| address.is_loopback())
}

fn canonical_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn first_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok().map(str::trim)
}

fn parse_cookies(headers: &HeaderMap) -> std::collections::HashMap<String, String> {
    let mut cookies = std::collections::HashMap::new();
    for header_value in headers.get_all(header::COOKIE) {
        let Ok(header_value) = header_value.to_str() else {
            continue;
        };
        for item in header_value.split(';') {
            let Some((name, value)) = item.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if !name.is_empty() {
                cookies.insert(name.to_string(), value.trim().to_string());
            }
        }
    }
    cookies
}

fn set_cookie(name: &str, value: &str, max_age_seconds: u64) -> String {
    format!("{name}={value}; Path=/; Max-Age={max_age_seconds}; HttpOnly; Secure; SameSite=Lax")
}

fn clear_cookie(name: &str) -> String {
    format!(
        "{name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"
    )
}

fn response_with_cookies(status: StatusCode, body: &str, cookies: &[String]) -> Response {
    let mut response = text_response(status, body);
    for cookie in cookies {
        append_header(&mut response, header::SET_COOKIE, cookie);
    }
    response
}

fn redirect_response(status: StatusCode, location: &str, cookies: &[String]) -> Response {
    let mut response = empty_response(status);
    match HeaderValue::from_str(location) {
        Ok(location) => {
            response.headers_mut().insert(header::LOCATION, location);
        }
        Err(error) => {
            error!(%error, "refused to emit invalid redirect location");
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal edge error");
        }
    }
    for cookie in cookies {
        append_header(&mut response, header::SET_COOKIE, cookie);
    }
    response
}

fn text_response(status: StatusCode, body: &str) -> Response {
    let mut response = (status, body.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    harden_response(&mut response);
    response
}

fn empty_response(status: StatusCode) -> Response {
    let mut response = status.into_response();
    harden_response(&mut response);
    response
}

fn harden_response(response: &mut Response) {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
}

fn append_header(response: &mut Response, name: header::HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(name, value);
    }
}

fn required_env(name: &str) -> Result<String> {
    let value = env::var(name).unwrap_or_default().trim().to_string();
    if value.is_empty() {
        bail!("{name} is required");
    }
    Ok(value)
}

fn cookie_key_material_from_env() -> Result<String> {
    let inline = env::var("SIGNET_EDGE_COOKIE_KEYS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let file = env::var("SIGNET_EDGE_COOKIE_KEYS_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    cookie_key_material(inline, file)
}

fn cookie_key_material(inline: Option<String>, file: Option<String>) -> Result<String> {
    match (inline, file) {
        (Some(_), Some(_)) => {
            bail!("set only one of SIGNET_EDGE_COOKIE_KEYS or SIGNET_EDGE_COOKIE_KEYS_FILE")
        }
        (Some(value), None) => Ok(value),
        (None, Some(path)) => read_cookie_key_file(Path::new(&path)),
        (None, None) => {
            bail!("SIGNET_EDGE_COOKIE_KEYS or SIGNET_EDGE_COOKIE_KEYS_FILE is required")
        }
    }
}

fn read_cookie_key_file(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to stat cookie key file {}", path.display()))?;
    if !metadata.is_file() {
        bail!("cookie key path {} must be a regular file", path.display());
    }
    if metadata.len() > MAX_COOKIE_KEY_FILE_BYTES {
        bail!(
            "cookie key file {} exceeds {} bytes",
            path.display(),
            MAX_COOKIE_KEY_FILE_BYTES
        );
    }
    let value = fs::read_to_string(path)
        .with_context(|| format!("failed to read cookie key file {}", path.display()))?;
    if value.len() as u64 > MAX_COOKIE_KEY_FILE_BYTES {
        bail!(
            "cookie key file {} exceeds {} bytes",
            path.display(),
            MAX_COOKIE_KEY_FILE_BYTES
        );
    }
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("cookie key file {} is empty", path.display());
    }
    Ok(value)
}

fn bool_env(name: &str) -> bool {
    env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn positive_u64_env(name: &str, default: u64) -> Result<u64> {
    let Some(raw) = env::var(name).ok().filter(|value| !value.trim().is_empty()) else {
        return Ok(default);
    };
    let value = raw
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{name} must be a positive integer"))?;
    if value == 0 {
        bail!("{name} must be a positive integer");
    }
    Ok(value)
}

fn validate_max_session_seconds(value: u64) -> Result<u64> {
    if value > MAX_SESSION_CAP_SECONDS {
        bail!("SIGNET_EDGE_MAX_SESSION_SECONDS must not exceed {MAX_SESSION_CAP_SECONDS} seconds");
    }
    Ok(value)
}

fn parse_cookie_keys(raw: &str) -> Result<Vec<[u8; 32]>> {
    let mut keys = Vec::new();
    for (index, value) in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .enumerate()
    {
        let decoded = canonical_base64url(value)
            .with_context(|| format!("SIGNET_EDGE_COOKIE_KEYS[{index}] is invalid"))?;
        let key: [u8; 32] = decoded.try_into().map_err(|_| {
            anyhow!("each SIGNET_EDGE_COOKIE_KEYS entry must decode to exactly 32 bytes")
        })?;
        keys.push(key);
    }
    if keys.is_empty() {
        bail!("SIGNET_EDGE_COOKIE_KEYS must contain at least one key");
    }
    Ok(keys)
}

fn canonical_base64url(value: &str) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .context("value must be unpadded base64url")?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        bail!("value must be canonical unpadded base64url");
    }
    Ok(decoded)
}

fn validate_scopes(scopes: &[String]) -> Result<()> {
    let set = scopes.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if set.len() != scopes.len() {
        bail!("SIGNET_EDGE_SCOPES must not contain duplicate scopes");
    }
    if !set.contains("openid") || !set.contains("iap.assert") {
        bail!("SIGNET_EDGE_SCOPES must include openid and iap.assert");
    }
    if set.contains("offline_access") {
        bail!(
            "SIGNET_EDGE_SCOPES must not request offline_access; the edge keeps no refresh token"
        );
    }
    Ok(())
}

fn host_cookie_name(raw: Option<&str>, fallback: &str, name: &str) -> Result<String> {
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback);
    if !value.starts_with("__Host-") || !value.bytes().all(cookie_name_byte) {
        bail!("{name} must be a valid __Host- cookie name");
    }
    Ok(value.to_string())
}

fn cookie_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn random_base64url(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(%error, "failed to listen for Ctrl-C");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => error!(%error, "failed to listen for SIGTERM"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

fn self_test() -> Result<()> {
    let origin = Url::parse("https://legacy.example.test/")?;
    let old_key = [7_u8; 32];
    let new_key = [9_u8; 32];
    let old_codec = CookieCodec::new(&[old_key], &origin)?;
    let rotating_codec = CookieCodec::new(&[new_key, old_key], &origin)?;
    let payload = EdgeSession {
        access_token: "secret".to_string(),
        exp: 123,
    };
    let sealed = old_codec.seal(&payload, "session")?;
    let opened = rotating_codec
        .open::<EdgeSession>(&sealed, "session")
        .ok_or_else(|| anyhow!("cookie rotation self-test failed"))?;
    if opened.access_token != "secret"
        || rotating_codec
            .open::<EdgeSession>(&sealed, "state")
            .is_some()
    {
        bail!("cookie purpose-isolation self-test failed");
    }
    if normalize_path("/a?b=1", &origin)? != "/a?b=1" {
        bail!("return_to normalization self-test failed");
    }
    if normalize_path("https://evil.example/", &origin).is_ok()
        || normalize_path("/safe#fragment", &origin).is_ok()
    {
        bail!("return_to boundary self-test failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, extract::Form, routing::post};
    use std::{collections::HashMap, sync::Mutex};

    #[derive(Clone)]
    struct MockIssuerState {
        issuer: String,
        redirect_uri: String,
        target: String,
        expected_challenge: Arc<Mutex<Option<String>>>,
    }

    #[derive(Debug, Deserialize)]
    struct MockIapQuery {
        target: String,
    }

    async fn mock_discovery(State(state): State<MockIssuerState>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "issuer": state.issuer,
            "authorization_endpoint": format!("{}/authorize", state.issuer),
            "token_endpoint": format!("{}/token", state.issuer),
        }))
    }

    async fn mock_token(
        State(state): State<MockIssuerState>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Response {
        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let expected = state.expected_challenge.lock().unwrap().clone();
        if form.get("grant_type").map(String::as_str) != Some("authorization_code")
            || form.get("client_id").map(String::as_str) != Some("legacy-edge-client")
            || form.get("code").map(String::as_str) != Some("test-code")
            || form.get("redirect_uri").map(String::as_str) != Some(state.redirect_uri.as_str())
            || expected.as_deref() != Some(challenge.as_str())
        {
            return text_response(StatusCode::BAD_REQUEST, "invalid token request");
        }
        Json(serde_json::json!({
            "access_token": "edge-access-token",
            "token_type": "Bearer",
            "expires_in": 600,
        }))
        .into_response()
    }

    async fn mock_iap(
        State(state): State<MockIssuerState>,
        Query(query): Query<MockIapQuery>,
        headers: HeaderMap,
    ) -> Response {
        if query.target != state.target
            || first_header(&headers, header::AUTHORIZATION.as_str())
                != Some("Bearer edge-access-token")
            || first_header(&headers, "x-original-method") != Some("GET")
        {
            return text_response(StatusCode::FORBIDDEN, "invalid IAP request");
        }
        let mut response = empty_response(StatusCode::NO_CONTENT);
        response.headers_mut().insert(
            "x-signet-assertion",
            HeaderValue::from_static("signed-assertion"),
        );
        response
            .headers_mut()
            .insert("x-signet-subject", HeaderValue::from_static("user-123"));
        response.headers_mut().insert(
            "x-signet-assertion-audience",
            HeaderValue::from_static("signet:iap:rule-123"),
        );
        response.headers_mut().insert(
            "x-auth-request-user",
            HeaderValue::from_static("legacy-user"),
        );
        response
            .headers_mut()
            .insert("x-gpt-sso-iap-method", HeaderValue::from_static("GET"));
        response
    }

    fn cookie_pair(headers: &HeaderMap, name: &str) -> Option<String> {
        let prefix = format!("{name}=");
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                let value = value.to_str().ok()?;
                let pair = value.split(';').next()?.trim();
                pair.starts_with(&prefix).then(|| pair.to_string())
            })
    }

    #[test]
    fn cookie_codec_supports_rotation_and_purpose_isolation() {
        let origin = Url::parse("https://legacy.example.test/").unwrap();
        let old = CookieCodec::new(&[[1_u8; 32]], &origin).unwrap();
        let rotated = CookieCodec::new(&[[2_u8; 32], [1_u8; 32]], &origin).unwrap();
        let payload = EdgeSession {
            access_token: "token".to_string(),
            exp: 42,
        };
        let sealed = old.seal(&payload, "session").unwrap();
        assert_eq!(
            rotated
                .open::<EdgeSession>(&sealed, "session")
                .unwrap()
                .access_token,
            "token"
        );
        assert!(rotated.open::<EdgeSession>(&sealed, "state").is_none());

        let mut tampered = sealed.into_bytes();
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        assert!(
            rotated
                .open::<EdgeSession>(&String::from_utf8(tampered).unwrap(), "session")
                .is_none()
        );
    }

    #[test]
    fn return_targets_are_origin_bound_and_fragment_free() {
        let origin = Url::parse("https://legacy.example.test/").unwrap();
        assert_eq!(normalize_path("/a?b=1", &origin).unwrap(), "/a?b=1");
        assert!(normalize_path("https://evil.example/", &origin).is_err());
        assert!(normalize_path("//evil.example/path", &origin).is_err());
        assert!(normalize_path("/safe#hidden", &origin).is_err());
        assert!(normalize_path(&format!("/{}", "a".repeat(MAX_RETURN_TO_BYTES)), &origin).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-original-url",
            HeaderValue::from_static("https://legacy.example.test/private?a=1"),
        );
        assert_eq!(
            request_target(&headers, &origin).unwrap().as_str(),
            "https://legacy.example.test/private?a=1"
        );
        headers.insert(
            "x-original-url",
            HeaderValue::from_static("https://evil.example/private"),
        );
        assert!(request_target(&headers, &origin).is_err());
    }

    #[test]
    fn cookie_names_and_scopes_keep_the_edge_short_lived() {
        assert_eq!(
            host_cookie_name(None, "__Host-edge", "EDGE_COOKIE").unwrap(),
            "__Host-edge"
        );
        assert!(host_cookie_name(Some("edge"), "ignored", "EDGE_COOKIE").is_err());
        assert!(validate_scopes(&["openid".to_string(), "iap.assert".to_string()]).is_ok());
        assert!(
            validate_scopes(&[
                "openid".to_string(),
                "iap.assert".to_string(),
                "offline_access".to_string(),
            ])
            .is_err()
        );
        assert_eq!(
            validate_max_session_seconds(MAX_SESSION_CAP_SECONDS).unwrap(),
            MAX_SESSION_CAP_SECONDS
        );
        assert!(validate_max_session_seconds(MAX_SESSION_CAP_SECONDS + 1).is_err());
    }

    #[test]
    fn cookie_keys_support_secret_files_without_ambiguous_sources() {
        let encoded = URL_SAFE_NO_PAD.encode([11_u8; 32]);
        let path = env::temp_dir().join(format!(
            "signet-edge-cookie-keys-{}-{}.txt",
            std::process::id(),
            now_ts()
        ));
        fs::write(&path, format!("{encoded}\n")).unwrap();

        assert_eq!(
            cookie_key_material(None, Some(path.to_string_lossy().into_owned())).unwrap(),
            encoded
        );
        assert!(
            cookie_key_material(
                Some(URL_SAFE_NO_PAD.encode([12_u8; 32])),
                Some(path.to_string_lossy().into_owned())
            )
            .is_err()
        );

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn oidc_edge_completes_pkce_session_and_iap_projection() {
        let issuer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer_origin = format!("http://{}", issuer_listener.local_addr().unwrap());
        let edge_origin = format!("http://{}", edge_listener.local_addr().unwrap());
        let redirect_uri = format!("{edge_origin}{CALLBACK_PATH}");
        let protected_target = format!("{edge_origin}/private?x=1");
        let expected_challenge = Arc::new(Mutex::new(None));
        let mock_state = MockIssuerState {
            issuer: issuer_origin.clone(),
            redirect_uri: redirect_uri.clone(),
            target: protected_target.clone(),
            expected_challenge: expected_challenge.clone(),
        };
        let issuer_router = Router::new()
            .route("/.well-known/openid-configuration", get(mock_discovery))
            .route("/token", post(mock_token))
            .route("/api/iap/bearer-auth", get(mock_iap))
            .with_state(mock_state);
        let issuer_task = tokio::spawn(async move {
            let _ = axum::serve(issuer_listener, issuer_router).await;
        });

        let config = Arc::new(Config {
            public_origin: Url::parse(&format!("{edge_origin}/")).unwrap(),
            issuer: Url::parse(&format!("{issuer_origin}/")).unwrap(),
            client_id: "legacy-edge-client".to_string(),
            bind_host: "127.0.0.1".to_string(),
            bind_port: edge_listener.local_addr().unwrap().port(),
            upstream_timeout: Duration::from_secs(2),
            max_session_seconds: DEFAULT_SESSION_CAP_SECONDS,
            scopes: vec!["openid".to_string(), "iap.assert".to_string()],
            session_cookie: "__Host-signet_edge".to_string(),
            state_cookie: "__Host-signet_edge_state".to_string(),
            cookie_keys: vec![[7_u8; 32]],
        });
        let upstream = build_upstream_client(Duration::from_secs(2)).unwrap();
        let discovery = Arc::new(load_discovery(&upstream, &config).await.unwrap());
        let edge_state = EdgeState {
            config: config.clone(),
            codec: Arc::new(CookieCodec::new(&config.cookie_keys, &config.public_origin).unwrap()),
            discovery,
            client: upstream,
        };
        let edge_task = tokio::spawn(async move {
            let _ = axum::serve(edge_listener, routes(edge_state)).await;
        });

        let browser = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let start = browser
            .get(format!(
                "{edge_origin}{START_PATH}?return_to=%2Fprivate%3Fx%3D1"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(start.status(), reqwest::StatusCode::FOUND);
        let state_cookie = cookie_pair(start.headers(), &config.state_cookie).unwrap();
        let authorize = Url::parse(
            start
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(canonical_origin(&authorize), issuer_origin);
        let parameters = authorize
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<HashMap<_, _>>();
        assert_eq!(parameters.get("client_id").unwrap(), "legacy-edge-client");
        assert_eq!(parameters.get("redirect_uri").unwrap(), &redirect_uri);
        assert_eq!(parameters.get("code_challenge_method").unwrap(), "S256");
        *expected_challenge.lock().unwrap() = parameters.get("code_challenge").cloned();
        let callback_state = parameters.get("state").unwrap();

        let mut callback = Url::parse(&format!("{edge_origin}{CALLBACK_PATH}")).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("code", "test-code")
            .append_pair("state", callback_state);
        let callback_response = browser
            .get(callback)
            .header(header::COOKIE, state_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(callback_response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(
            callback_response
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "/private?x=1"
        );
        let session_cookie =
            cookie_pair(callback_response.headers(), &config.session_cookie).unwrap();
        assert!(!session_cookie.contains("edge-access-token"));

        let decision = browser
            .get(format!("{edge_origin}{AUTH_PATH}"))
            .header(header::COOKIE, session_cookie)
            .header("x-original-url", &protected_target)
            .header("x-original-method", "GET")
            .send()
            .await
            .unwrap();
        assert_eq!(decision.status(), reqwest::StatusCode::NO_CONTENT);
        assert_eq!(
            decision
                .headers()
                .get("x-signet-subject")
                .unwrap()
                .to_str()
                .unwrap(),
            "user-123"
        );
        assert_eq!(
            decision
                .headers()
                .get("x-auth-request-user")
                .unwrap()
                .to_str()
                .unwrap(),
            "legacy-user"
        );

        edge_task.abort();
        issuer_task.abort();
    }
}
