//! Website-owned application authentication discovery.
//!
//! The website publishes one complete, signed document. Signet verifies the
//! document against an operator-pinned Ed25519 key and turns it into a
//! normalized in-memory snapshot. Database reconciliation is intentionally
//! kept outside this module so signature/schema validation has no side
//! effects.

use crate::{
    AppState, client_assertion,
    db::{ApplicationDiscoveryRecord, NewClient},
    error::{AppError, AppResult},
    service_accounts, util,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::lookup_host;
use url::{Host, Url};

pub const FORMAT: &str = "signet-application/v2";
pub const DISCOVERY_PATH: &str = "/.well-known/signet-authorization.json";
pub const MANAGEMENT_MODE_SIGNET: &str = "signet_managed";
pub const MANAGEMENT_MODE_WEBSITE: &str = "website_managed";
pub const SOURCE_WEBSITE: &str = "website_manifest";
pub const SYNC_UNCONFIGURED: &str = "unconfigured";
pub const SYNC_PENDING: &str = "pending";
pub const SYNC_SYNCED: &str = "synced";
pub const SYNC_ERROR: &str = "error";
pub const SYNC_DISABLED: &str = "disabled";

const MAX_CLIENTS: usize = 512;
const MAX_CLIENT_ID_LENGTH: usize = 255;
const MAX_SCOPE_LENGTH: usize = 256;
const MAX_REVISION: i64 = i64::MAX;
const MAX_TOKEN_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationManifest {
    pub format: String,
    pub application_id: String,
    pub revision: i64,
    pub version: String,
    pub iss: String,
    pub aud: Value,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub clients: Vec<ManifestClient>,
    #[serde(default = "empty_object")]
    pub protocols: Map<String, Value>,
    #[serde(default = "empty_object")]
    pub login_adapters: Map<String, Value>,
    #[serde(default = "empty_object")]
    pub directory_sync: Map<String, Value>,
    #[serde(default = "empty_object")]
    pub authorization: Map<String, Value>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ManifestProfile>,
}

fn empty_object() -> Map<String, Value> {
    Map::new()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestClient {
    pub client_id: String,
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub logo_uri: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default = "default_client_auth_method")]
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub require_pkce: bool,
    #[serde(default)]
    pub require_mfa: bool,
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    #[serde(default)]
    pub require_s256_pkce: bool,
    #[serde(default)]
    pub require_confidential_client: bool,
    #[serde(default)]
    pub require_dpop: bool,
    #[serde(default)]
    pub require_account_selection: bool,
    #[serde(default)]
    pub trust_email_verified: bool,
    #[serde(default)]
    pub authorization_details_types: Vec<String>,
    #[serde(default = "default_subject_type")]
    pub subject_type: String,
    #[serde(default)]
    pub sector_identifier_uri: String,
    #[serde(default)]
    pub jwks_uri: String,
    #[serde(default)]
    pub jwks: Value,
    #[serde(default)]
    pub backchannel_logout_uri: String,
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    #[serde(default)]
    pub frontchannel_logout_uri: String,
    #[serde(default)]
    pub frontchannel_logout_session_required: bool,
    #[serde(default)]
    pub service_account_enabled: bool,
    #[serde(default)]
    pub service_account_permissions: Vec<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_client_auth_method() -> String {
    "none".to_string()
}

fn default_subject_type() -> String {
    "public".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestProfile {
    #[serde(default)]
    pub permissions: Vec<ManifestPermission>,
    #[serde(default)]
    pub roles: Vec<ManifestRole>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPermission {
    pub key: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRole {
    pub key: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NormalizedProfile {
    pub permissions: Vec<NormalizedPermission>,
    pub roles: Vec<NormalizedRole>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NormalizedPermission {
    pub key: String,
    pub label: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NormalizedRole {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone)]
pub struct NormalizedGroupMapping {
    pub group: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct NormalizedOrganizationRoleMapping {
    pub organization_role: String,
    pub role: String,
}

#[derive(Debug, Clone, Default)]
pub struct NormalizedAuthorizationMappings {
    pub default_role: Option<String>,
    pub group_mappings: Vec<NormalizedGroupMapping>,
    pub organization_role_mappings: Vec<NormalizedOrganizationRoleMapping>,
}

#[derive(Debug, Clone)]
pub struct VerifiedApplicationManifest {
    pub application_id: String,
    pub revision: i64,
    pub version: String,
    pub digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub clients: Vec<NewClient>,
    pub protocols: Value,
    pub login_adapters: Value,
    pub directory_sync: Value,
    pub authorization: Value,
    pub authorization_mappings: NormalizedAuthorizationMappings,
    pub profiles: BTreeMap<String, NormalizedProfile>,
    /// A redacted JSON representation suitable for storing as the last
    /// verified snapshot. Client secrets are deliberately omitted.
    pub redacted_payload: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PinnedJwks {
    keys: Vec<PinnedJwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct PinnedJwk {
    kty: String,
    crv: String,
    x: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(rename = "use", default)]
    use_: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

pub fn website_origin(website_url: &str) -> AppResult<String> {
    let parsed = Url::parse(website_url.trim())
        .map_err(|_| AppError::BadRequest("website URL is invalid".to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (!parsed.path().is_empty() && parsed.path() != "/")
    {
        return Err(AppError::BadRequest(
            "website URL must be an absolute http(s) origin".to_string(),
        ));
    }
    validate_host(parsed.host())?;
    let mut origin = parsed;
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    Ok(origin.to_string().trim_end_matches('/').to_string())
}

pub fn default_discovery_url(website_url: &str) -> AppResult<String> {
    let origin = website_origin(website_url)?;
    Ok(format!("{origin}{DISCOVERY_PATH}"))
}

fn validate_host(host: Option<Host<&str>>) -> AppResult<()> {
    let Some(host) = host else {
        return Err(AppError::BadRequest(
            "website URL must include a host".to_string(),
        ));
    };
    let host_name = host.to_string();
    if host_name.eq_ignore_ascii_case("localhost")
        || host_name.ends_with(".localhost")
        || host_name.ends_with(".local")
    {
        return Err(AppError::BadRequest(
            "website URL cannot target a local hostname".to_string(),
        ));
    }
    let ip = match host {
        Host::Ipv4(value) => IpAddr::V4(value),
        Host::Ipv6(value) => IpAddr::V6(value),
        Host::Domain(_) => return Ok(()),
    };
    if is_forbidden_ip(ip) {
        return Err(AppError::BadRequest(
            "website URL cannot target a private network address".to_string(),
        ));
    }
    Ok(())
}

fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            value.is_loopback()
                || value.is_private()
                || value.is_link_local()
                || value.is_unspecified()
                || value.is_multicast()
                || value.is_broadcast()
        }
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_unspecified()
                || value.is_multicast()
                || (value.segments()[0] & 0xfe00) == 0xfc00
                || (value.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn validate_fetch_url(discovery_url: &str, allow_private_networks: bool) -> AppResult<Url> {
    let parsed = Url::parse(discovery_url.trim())
        .map_err(|_| AppError::BadRequest("application discovery URL is invalid".to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.path() != DISCOVERY_PATH
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AppError::BadRequest(
            "application discovery URL must be the HTTP(S) well-known endpoint".to_string(),
        ));
    }
    if parsed.scheme() == "http" && !allow_private_networks {
        return Err(AppError::BadRequest(
            "application discovery URL must use HTTPS outside the private-network development mode"
                .to_string(),
        ));
    }
    if !allow_private_networks {
        validate_host(parsed.host())?;
    }
    Ok(parsed)
}

async fn resolve_public_host(url: &Url, allow_private_networks: bool) -> AppResult<SocketAddr> {
    let host = url
        .host_str()
        .ok_or_else(|| AppError::BadRequest("application discovery URL has no host".to_string()))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        AppError::BadRequest("application discovery URL has no known port".to_string())
    })?;
    let addresses = match url.host() {
        Some(Host::Ipv4(value)) => vec![SocketAddr::new(IpAddr::V4(value), port)],
        Some(Host::Ipv6(value)) => vec![SocketAddr::new(IpAddr::V6(value), port)],
        Some(Host::Domain(_)) => lookup_host((host, port))
            .await
            .map_err(|_| {
                AppError::BadRequest("application discovery host cannot be resolved".to_string())
            })?
            .collect(),
        None => Vec::new(),
    };
    if url.scheme() == "http"
        && (!allow_private_networks
            || addresses.is_empty()
            || addresses
                .iter()
                .any(|address| !is_forbidden_ip(address.ip())))
    {
        return Err(AppError::BadRequest(
            "HTTP application discovery is allowed only for private-network development hosts"
                .to_string(),
        ));
    }
    let address = addresses
        .into_iter()
        .find(|address| allow_private_networks || !is_forbidden_ip(address.ip()))
        .ok_or_else(|| {
            AppError::BadRequest(
                "application discovery host resolves to a private network address".to_string(),
            )
        })?;
    Ok(address)
}

pub fn verify_and_normalize(
    body: &[u8],
    pinned_jwks: &str,
    expected_issuer: &str,
    expected_application_id: &str,
    expected_audience: &str,
    organization_id: &str,
) -> AppResult<VerifiedApplicationManifest> {
    if body.is_empty() || body.len() > 512 * 1024 {
        return Err(AppError::BadRequest(
            "application discovery document is too large or empty".to_string(),
        ));
    }
    let token = extract_jws(body)?;
    let payload = verify_jws(&token, pinned_jwks)?;
    let manifest = serde_json::from_slice::<ApplicationManifest>(&payload)
        .map_err(|_| AppError::BadRequest("application discovery schema is invalid".to_string()))?;
    // The JWS is deliberately short-lived, so `iat` and `exp` change on every
    // fetch even when the website's authorization configuration is unchanged.
    // Revision reuse must compare the signed configuration, not that
    // transport/cache lifetime metadata. The signature is still verified over
    // the complete payload above, including both temporal claims.
    let digest = manifest_content_digest(&payload)?;
    validate_claims(
        &manifest,
        expected_issuer,
        expected_application_id,
        expected_audience,
    )?;
    if manifest.clients.len() > MAX_CLIENTS {
        return Err(AppError::BadRequest(
            "application discovery declares too many clients".to_string(),
        ));
    }
    if manifest.profiles.is_empty() || !manifest.profiles.contains_key("default") {
        return Err(AppError::BadRequest(
            "application discovery must declare a default authorization profile".to_string(),
        ));
    }
    let clients = manifest
        .clients
        .iter()
        .map(|client| normalize_client(client, organization_id))
        .collect::<AppResult<Vec<_>>>()?;
    let mut client_ids = BTreeSet::new();
    for client in &clients {
        if !client_ids.insert(client.client_id.clone()) {
            return Err(AppError::BadRequest(
                "application discovery repeats a client_id".to_string(),
            ));
        }
    }
    let protocols = normalize_module("protocols", &manifest.protocols, expected_issuer)?;
    let login_adapters =
        normalize_module("login_adapters", &manifest.login_adapters, expected_issuer)?;
    let directory_sync =
        normalize_module("directory_sync", &manifest.directory_sync, expected_issuer)?;
    let authorization =
        normalize_module("authorization", &manifest.authorization, expected_issuer)?;
    let mut profiles = manifest
        .profiles
        .iter()
        .map(|(key, profile)| Ok((normalize_profile_key(key)?, normalize_profile(profile)?)))
        .collect::<AppResult<BTreeMap<_, _>>>()?;
    if profiles
        .keys()
        .any(|profile_key| profile_key != "default" && !client_ids.contains(profile_key))
    {
        return Err(AppError::BadRequest(
            "application discovery profile must be default or a declared client_id".to_string(),
        ));
    }
    validate_protocol_client_bindings(&protocols, &clients)?;
    let authorization_mappings = normalize_authorization_bindings(&authorization, &profiles)?;
    if let Some(default_role) = authorization_mappings.default_role.as_deref() {
        let profile = profiles.get_mut("default").ok_or_else(|| {
            AppError::BadRequest("application discovery must declare a default profile".to_string())
        })?;
        if profile
            .roles
            .iter()
            .any(|role| role.is_default && role.key != default_role)
        {
            return Err(AppError::BadRequest(
                "authorization declares conflicting default roles".to_string(),
            ));
        }
        for role in &mut profile.roles {
            role.is_default = role.key == default_role;
        }
    }
    let redacted_payload = redacted_payload(
        &manifest,
        &protocols,
        &login_adapters,
        &directory_sync,
        &authorization,
        &profiles,
    )?;
    Ok(VerifiedApplicationManifest {
        application_id: manifest.application_id,
        revision: manifest.revision,
        version: manifest.version,
        digest,
        issued_at: manifest.iat,
        expires_at: manifest.exp,
        clients,
        protocols,
        login_adapters,
        directory_sync,
        authorization,
        authorization_mappings,
        profiles,
        redacted_payload,
    })
}

fn manifest_content_digest(payload: &[u8]) -> AppResult<String> {
    let mut value = serde_json::from_slice::<Value>(payload)
        .map_err(|_| AppError::BadRequest("application discovery schema is invalid".to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        AppError::BadRequest("application discovery schema is invalid".to_string())
    })?;
    object.remove("iat");
    object.remove("exp");
    let canonical = serde_json::to_string(&value).map_err(|_| {
        AppError::Internal("failed to encode application discovery digest".to_string())
    })?;
    Ok(util::sha256_base64url(&canonical))
}

pub async fn fetch_and_verify(
    discovery_url: &str,
    fetch_secret: &str,
    signing_public_jwks: &str,
    expected_issuer: &str,
    expected_application_id: &str,
    expected_audience: &str,
    organization_id: &str,
    allow_private_networks: bool,
) -> AppResult<VerifiedApplicationManifest> {
    if fetch_secret.trim().is_empty() {
        return Err(AppError::Configuration(
            "website-managed application has no fetch secret".to_string(),
        ));
    }
    let discovery_url = validate_fetch_url(discovery_url, allow_private_networks)?;
    let resolved_address = resolve_public_host(&discovery_url, allow_private_networks).await?;
    let host = discovery_url
        .host_str()
        .ok_or_else(|| AppError::BadRequest("application discovery URL has no host".to_string()))?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        // Pin the DNS result used for this request.  This closes the common
        // DNS-rebinding gap between a public-host check and the actual HTTP
        // connection.
        .resolve(host, resolved_address)
        .build()
        .map_err(|_| AppError::Internal("failed to build discovery HTTP client".to_string()))?
        .get(discovery_url.as_str())
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {fetch_secret}"),
        )
        .header(
            reqwest::header::ACCEPT,
            "application/jose, application/json",
        )
        .send()
        .await
        .map_err(|_| AppError::BadRequest("application discovery request failed".to_string()))?;
    if !response.status().is_success() {
        return Err(AppError::BadRequest(
            "application discovery returned an error".to_string(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > 512 * 1024)
    {
        return Err(AppError::BadRequest(
            "application discovery response is too large".to_string(),
        ));
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::BadRequest("application discovery body failed".to_string()))?
    {
        if body.len().saturating_add(chunk.len()) > 512 * 1024 {
            return Err(AppError::BadRequest(
                "application discovery response is too large".to_string(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    verify_and_normalize(
        &body,
        signing_public_jwks,
        expected_issuer,
        expected_application_id,
        expected_audience,
        organization_id,
    )
}

fn extract_jws(body: &[u8]) -> AppResult<String> {
    let text = std::str::from_utf8(body)
        .map_err(|_| AppError::BadRequest("application discovery is not UTF-8".to_string()))?
        .trim();
    if text.starts_with('{') {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DiscoveryEnvelope {
            format: String,
            token: String,
        }
        let envelope = serde_json::from_str::<DiscoveryEnvelope>(text).map_err(|_| {
            AppError::BadRequest("application discovery envelope is invalid".to_string())
        })?;
        if envelope.format != FORMAT {
            return Err(AppError::BadRequest(
                "application discovery format is unsupported".to_string(),
            ));
        }
        return Ok(envelope.token.trim().to_string());
    }
    Ok(text.to_string())
}

fn verify_jws(token: &str, pinned_jwks: &str) -> AppResult<Vec<u8>> {
    let mut parts = token.split('.');
    let encoded_header = parts.next().ok_or(AppError::Unauthorized)?;
    let encoded_payload = parts.next().ok_or(AppError::Unauthorized)?;
    let encoded_signature = parts.next().ok_or(AppError::Unauthorized)?;
    if parts.next().is_some() {
        return Err(AppError::Unauthorized);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| AppError::Unauthorized)?;
    let header =
        serde_json::from_slice::<JwsHeader>(&header_bytes).map_err(|_| AppError::Unauthorized)?;
    if header.alg != "EdDSA" {
        return Err(AppError::Unauthorized);
    }
    let key_set =
        serde_json::from_str::<PinnedJwks>(pinned_jwks).map_err(|_| AppError::Unauthorized)?;
    let candidates = key_set
        .keys
        .iter()
        .filter(|key| {
            key.kty == "OKP"
                && key.crv == "Ed25519"
                && key.use_.as_deref().is_none_or(|value| value == "sig")
                && key.alg.as_deref().is_none_or(|value| value == "EdDSA")
                && header
                    .kid
                    .as_deref()
                    .is_none_or(|kid| key.kid.as_deref() == Some(kid))
        })
        .collect::<Vec<_>>();
    let key = match (header.kid.as_deref(), candidates.as_slice()) {
        (_, []) => return Err(AppError::Unauthorized),
        (Some(_), [key, ..]) => *key,
        (None, [key]) => *key,
        (None, _) => return Err(AppError::Unauthorized),
    };
    let public_key = URL_SAFE_NO_PAD
        .decode(&key.x)
        .map_err(|_| AppError::Unauthorized)?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| AppError::Unauthorized)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AppError::Unauthorized)?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| AppError::Unauthorized)?;
    let signature = Signature::from_slice(&signature).map_err(|_| AppError::Unauthorized)?;
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AppError::Unauthorized)?;
    URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| AppError::Unauthorized)
}

fn validate_claims(
    manifest: &ApplicationManifest,
    expected_issuer: &str,
    expected_application_id: &str,
    expected_audience: &str,
) -> AppResult<()> {
    if manifest.format != FORMAT
        || manifest.application_id != expected_application_id
        || manifest.iss != expected_issuer
        || manifest.revision <= 0
        || manifest.revision > MAX_REVISION
        || manifest.version.trim().is_empty()
        || manifest.version.len() > 128
    {
        return Err(AppError::BadRequest(
            "application discovery claims are invalid".to_string(),
        ));
    }
    let now = util::now_ts();
    if manifest.iat > now + 60 || manifest.exp <= now || manifest.exp <= manifest.iat {
        return Err(AppError::BadRequest(
            "application discovery timestamps are invalid".to_string(),
        ));
    }
    if manifest.exp.saturating_sub(manifest.iat) > MAX_TOKEN_TTL_SECONDS {
        return Err(AppError::BadRequest(
            "application discovery expiry is too far in the future".to_string(),
        ));
    }
    let application_audience = format!("signet:application:{expected_application_id}");
    if !audience_contains(&manifest.aud, expected_audience)
        || !audience_contains(&manifest.aud, &application_audience)
    {
        return Err(AppError::BadRequest(
            "application discovery audience is invalid".to_string(),
        ));
    }
    Ok(())
}

fn audience_contains(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn normalize_client(client: &ManifestClient, organization_id: &str) -> AppResult<NewClient> {
    let client_id = visible_text(&client.client_id, MAX_CLIENT_ID_LENGTH, "client_id")?;
    let client_name = if client.client_name.trim().is_empty() {
        client_id.clone()
    } else {
        normalize_display_text(&client.client_name, 160, "client_name")?
    };
    let auth_method = client.token_endpoint_auth_method.trim();
    if !matches!(
        auth_method,
        "client_secret_basic"
            | "client_secret_post"
            | "client_secret_jwt"
            | "private_key_jwt"
            | "none"
    ) {
        return Err(AppError::BadRequest(
            "website-managed clients use an unsupported authentication method".to_string(),
        ));
    }
    let client_secret_hash = match auth_method {
        "client_secret_basic" | "client_secret_post" | "client_secret_jwt" => {
            let secret = client
                .client_secret
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "confidential website-managed clients require client_secret".to_string(),
                    )
                })?;
            Some(
                client_assertion::store_client_secret(auth_method, secret)?.ok_or_else(|| {
                    AppError::Internal("failed to hash website-managed client secret".to_string())
                })?,
            )
        }
        "private_key_jwt" | "none" => {
            if client
                .client_secret
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            {
                return Err(AppError::BadRequest(
                    "client_secret is not allowed for this website-managed authentication method"
                        .to_string(),
                ));
            }
            None
        }
        _ => unreachable!(),
    };
    let jwks = if client.jwks.is_null() {
        String::new()
    } else {
        client_assertion::normalize_jwks_json(&client.jwks.to_string())?
    };
    let jwks_uri = client_assertion::validate_jwks_uri(&client.jwks_uri)?;
    client_assertion::validate_key_source(auth_method, &jwks_uri, &jwks)?;
    let scopes = normalize_string_list(&client.scopes, MAX_SCOPE_LENGTH, "scope")?;
    let grant_types = normalize_string_list(&client.grant_types, 128, "grant_type")?;
    let response_types = normalize_string_list(&client.response_types, 128, "response_type")?;
    if grant_types
        .iter()
        .any(|value| value == "authorization_code")
        && (!scopes.iter().any(|value| value == "openid")
            || !response_types.iter().any(|value| value == "code"))
    {
        return Err(AppError::BadRequest(
            "authorization_code website-managed clients require openid and code".to_string(),
        ));
    }
    if client.service_account_enabled
        && !grant_types
            .iter()
            .any(|value| value == "client_credentials")
    {
        return Err(AppError::BadRequest(
            "website service accounts require client_credentials".to_string(),
        ));
    }
    if client.require_confidential_client && auth_method == "none" {
        return Err(AppError::BadRequest(
            "confidential website-managed clients cannot use none".to_string(),
        ));
    }
    let audience = visible_optional_text(&client.audience, 2048, "audience")?;
    let service_account_permissions =
        service_accounts::normalize_permissions(client.service_account_permissions.clone())?;
    Ok(NewClient {
        client_id,
        client_secret_hash,
        client_name,
        logo_uri: client.logo_uri.clone(),
        organization_id: Some(organization_id.to_string()),
        redirect_uris: normalize_url_list(&client.redirect_uris, "redirect_uri")?,
        post_logout_redirect_uris: normalize_url_list(
            &client.post_logout_redirect_uris,
            "post_logout_redirect_uri",
        )?,
        scopes,
        audience,
        grant_types,
        response_types,
        token_endpoint_auth_method: auth_method.to_string(),
        require_pkce: client.require_pkce,
        require_mfa: client.require_mfa,
        require_pushed_authorization_requests: client.require_pushed_authorization_requests,
        require_s256_pkce: client.require_s256_pkce,
        require_confidential_client: client.require_confidential_client,
        require_dpop: client.require_dpop,
        require_account_selection: client.require_account_selection,
        trust_email_verified: client.trust_email_verified,
        authorization_details_types: normalize_string_list(
            &client.authorization_details_types,
            128,
            "authorization_details_type",
        )?,
        subject_type: client.subject_type.clone(),
        sector_identifier_uri: client.sector_identifier_uri.clone(),
        jwks_uri,
        jwks,
        backchannel_logout_uri: client.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: client.backchannel_logout_session_required,
        frontchannel_logout_uri: client.frontchannel_logout_uri.clone(),
        frontchannel_logout_session_required: client.frontchannel_logout_session_required,
        service_account_enabled: client.service_account_enabled,
        service_account_permissions,
        is_active: client.is_active,
    })
}

fn normalize_profile(profile: &ManifestProfile) -> AppResult<NormalizedProfile> {
    if profile.permissions.len() > 4096 || profile.roles.len() > 512 {
        return Err(AppError::BadRequest(
            "application discovery profile is too large".to_string(),
        ));
    }
    let mut permission_keys = BTreeSet::new();
    let mut permissions = Vec::with_capacity(profile.permissions.len());
    for permission in &profile.permissions {
        let key = normalize_permission_key(&permission.key)?;
        if !permission_keys.insert(key.clone()) {
            return Err(AppError::BadRequest(
                "application discovery repeats a permission".to_string(),
            ));
        }
        let label = permission
            .label
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| key.rsplit(':').next().unwrap_or(&key))
            .to_string();
        normalize_display_text(&label, 160, "permission label")?;
        permissions.push(NormalizedPermission {
            key,
            label,
            description: normalize_description(permission.description.as_deref()),
        });
    }
    let mut role_keys = BTreeSet::new();
    let mut roles = Vec::with_capacity(profile.roles.len());
    let mut default_count = 0;
    for role in &profile.roles {
        let key = visible_text(&role.key, 128, "role key")?;
        if !role_keys.insert(key.clone()) {
            return Err(AppError::BadRequest(
                "application discovery repeats a role".to_string(),
            ));
        }
        let mut role_permissions = BTreeSet::new();
        for permission in &role.permissions {
            let permission = normalize_permission_key(permission)?;
            if !permission_keys.contains(&permission) {
                return Err(AppError::BadRequest(
                    "application discovery role references an undefined permission".to_string(),
                ));
            }
            role_permissions.insert(permission);
        }
        if role.is_default {
            default_count += 1;
        }
        let name = role
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&key);
        let name = normalize_display_text(name, 160, "role name")?;
        roles.push(NormalizedRole {
            key: key.clone(),
            name,
            description: normalize_description(role.description.as_deref()),
            permissions: role_permissions.into_iter().collect(),
            is_default: role.is_default,
        });
    }
    if default_count > 1 {
        return Err(AppError::BadRequest(
            "application discovery profile has multiple default roles".to_string(),
        ));
    }
    Ok(NormalizedProfile { permissions, roles })
}

fn normalize_module(
    module_key: &str,
    object: &Map<String, Value>,
    expected_issuer: &str,
) -> AppResult<Value> {
    let mut object = object.clone();
    if module_key == "protocols" {
        object.insert(
            "website_url".to_string(),
            Value::String(expected_issuer.to_string()),
        );
    }
    let value = Value::Object(object);
    crate::applications::normalize_module_config(module_key, value)
}

fn validate_protocol_client_bindings(protocols: &Value, clients: &[NewClient]) -> AppResult<()> {
    let known = clients
        .iter()
        .map(|client| client.client_id.as_str())
        .collect::<BTreeSet<_>>();
    let configured = protocols
        .get("oauth2_oidc")
        .and_then(Value::as_object)
        .and_then(|object| object.get("client_ids"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    for client_id in configured {
        if !known.contains(client_id) {
            return Err(AppError::BadRequest(
                "protocols references an undeclared client".to_string(),
            ));
        }
    }
    Ok(())
}

fn normalize_authorization_bindings(
    authorization: &Value,
    profiles: &BTreeMap<String, NormalizedProfile>,
) -> AppResult<NormalizedAuthorizationMappings> {
    let object = authorization.as_object().ok_or_else(|| {
        AppError::BadRequest("application discovery authorization must be an object".to_string())
    })?;
    let default_profile = profiles.get("default").ok_or_else(|| {
        AppError::BadRequest("application discovery must declare a default profile".to_string())
    })?;
    let default_roles = default_profile
        .roles
        .iter()
        .map(|role| role.key.as_str())
        .collect::<BTreeSet<_>>();
    let role_name = |value: &Value| {
        let role = value.as_str().ok_or_else(|| {
            AppError::BadRequest("authorization role mappings must contain strings".to_string())
        })?;
        let role = visible_text(role, 128, "authorization role")?;
        if !default_roles.contains(role.as_str()) {
            return Err(AppError::BadRequest(
                "authorization references an undeclared default-profile role".to_string(),
            ));
        }
        Ok(role)
    };
    let default_role = object.get("default_role").map(role_name).transpose()?;

    let mut group_mappings = Vec::new();
    if let Some(value) = object.get("group_mappings") {
        let values = value.as_array().ok_or_else(|| {
            AppError::BadRequest("authorization group_mappings must be a list".to_string())
        })?;
        if values.len() > 512 {
            return Err(AppError::BadRequest(
                "authorization group_mappings is too large".to_string(),
            ));
        }
        for value in values {
            let mapping = value.as_object().ok_or_else(|| {
                AppError::BadRequest(
                    "authorization group_mappings entries must be objects".to_string(),
                )
            })?;
            let group = mapping
                .get("group")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AppError::BadRequest("authorization group mappings require a group".to_string())
                })
                .and_then(|value| visible_text(value, 255, "authorization group"))?;
            let role = mapping
                .get("role")
                .ok_or_else(|| {
                    AppError::BadRequest("authorization group mappings require a role".to_string())
                })
                .and_then(&role_name)?;
            group_mappings.push(NormalizedGroupMapping { group, role });
        }
    }

    let mut organization_role_mappings = Vec::new();
    if let Some(value) = object.get("organization_role_mappings") {
        let mappings = value.as_object().ok_or_else(|| {
            AppError::BadRequest(
                "authorization organization_role_mappings must be an object".to_string(),
            )
        })?;
        if mappings.len() > 32 {
            return Err(AppError::BadRequest(
                "authorization organization_role_mappings is too large".to_string(),
            ));
        }
        for (organization_role, role) in mappings {
            organization_role_mappings.push(NormalizedOrganizationRoleMapping {
                organization_role: visible_text(organization_role, 64, "organization role")?,
                role: role_name(role)?,
            });
        }
    }

    for field in [
        "user_roles",
        "group_roles",
        "organization_roles",
        "user_assignments",
        "role_assignments",
        "user_role_assignments",
        "group_role_assignments",
        "organization_role_assignments",
        "assignments",
    ] {
        if object.contains_key(field) {
            return Err(AppError::BadRequest(
                "website authorization manifests cannot declare user role assignments".to_string(),
            ));
        }
    }

    Ok(NormalizedAuthorizationMappings {
        default_role,
        group_mappings,
        organization_role_mappings,
    })
}

fn redacted_payload(
    manifest: &ApplicationManifest,
    protocols: &Value,
    login_adapters: &Value,
    directory_sync: &Value,
    authorization: &Value,
    profiles: &BTreeMap<String, NormalizedProfile>,
) -> AppResult<Value> {
    let clients = manifest
        .clients
        .iter()
        .map(|client| {
            let mut value = serde_json::to_value(client).map_err(|_| {
                AppError::Internal("failed to encode discovery snapshot".to_string())
            })?;
            if let Some(object) = value.as_object_mut() {
                object.remove("client_secret");
            }
            Ok(value)
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(serde_json::json!({
        "format": FORMAT,
        "application_id": manifest.application_id,
        "revision": manifest.revision,
        "version": manifest.version,
        "iss": manifest.iss,
        "aud": manifest.aud,
        "iat": manifest.iat,
        "exp": manifest.exp,
        "clients": clients,
        "protocols": protocols,
        "login_adapters": login_adapters,
        "directory_sync": directory_sync,
        "authorization": authorization,
        "profiles": profiles,
    }))
}

fn normalize_profile_key(value: &str) -> AppResult<String> {
    visible_text(value, 255, "profile key")
}

fn normalize_permission_key(value: &str) -> AppResult<String> {
    let value = visible_text(value, 256, "permission key")?;
    if value.split(':').any(str::is_empty) {
        return Err(AppError::BadRequest(
            "permission key is invalid".to_string(),
        ));
    }
    Ok(value)
}

fn normalize_string_list(
    values: &[String],
    max_length: usize,
    field: &str,
) -> AppResult<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for value in values {
        normalized.insert(visible_text(value, max_length, field)?);
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_url_list(values: &[String], field: &str) -> AppResult<Vec<String>> {
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let value = visible_text(value, 2048, field)?;
        let parsed = url::Url::parse(&value)
            .map_err(|_| AppError::BadRequest(format!("{field} is invalid")))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || parsed.username().len() > 0
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AppError::BadRequest(format!("{field} is invalid")));
        }
        result.push(value);
    }
    Ok(result)
}

fn visible_optional_text(value: &str, max_length: usize, field: &str) -> AppResult<String> {
    if value.trim().is_empty() {
        return Ok(String::new());
    }
    visible_text(value, max_length, field)
}

/// Human-facing labels may contain spaces. They still cannot contain control
/// characters or be empty, because Signet stores them in the administrative
/// catalog and renders them in consent/role-management surfaces.
fn normalize_display_text(value: &str, max_length: usize, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_length || value.chars().any(|ch| ch.is_control()) {
        return Err(AppError::BadRequest(format!("{field} is invalid")));
    }
    Ok(value.to_string())
}

fn visible_text(value: &str, max_length: usize, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > max_length
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(AppError::BadRequest(format!("{field} is invalid")));
    }
    Ok(value.to_string())
}

fn normalize_description(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(1024).collect())
}

/// Fetches and applies one website-owned authorization snapshot. The
/// network/signature phase is deliberately outside the database transaction;
/// `Db::apply_website_manifest` only receives an already verified value and
/// reconciles it atomically.
pub async fn sync_application(
    state: &AppState,
    application_id: &str,
) -> AppResult<ApplicationDiscoveryRecord> {
    let discovery = state
        .db
        .find_application_discovery(application_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if discovery.management_mode != MANAGEMENT_MODE_WEBSITE {
        return Err(AppError::BadRequest(
            "application is not website-managed".to_string(),
        ));
    }
    if discovery.operator_disabled != 0 {
        return Err(AppError::Forbidden);
    }

    let result = match sync_application_once(state, &discovery).await {
        Ok(manifest) => {
            state
                .db
                .apply_website_manifest(application_id, manifest)
                .await
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(record) => Ok(record),
        Err(error) => {
            let status = if discovery.fetch_secret_ciphertext.is_empty()
                || discovery.signing_public_jwks.trim().is_empty()
                || matches!(&error, AppError::Configuration(_))
            {
                SYNC_UNCONFIGURED
            } else {
                SYNC_ERROR
            };
            state
                .db
                .mark_application_discovery_sync_error(
                    application_id,
                    status,
                    Some(error.to_string()),
                )
                .await?;
            Err(error)
        }
    }
}

async fn sync_application_once(
    state: &AppState,
    discovery: &ApplicationDiscoveryRecord,
) -> AppResult<VerifiedApplicationManifest> {
    if discovery.fetch_secret_ciphertext.trim().is_empty()
        || discovery.signing_public_jwks.trim().is_empty()
    {
        return Err(AppError::Configuration(
            "website-managed application discovery trust is not configured".to_string(),
        ));
    }
    if state.settings.discovery.encryption_key.trim().is_empty() {
        return Err(AppError::Configuration(
            "discovery encryption key is not configured".to_string(),
        ));
    }
    let fetch_secret = util::decrypt_discovery_secret(
        &state.settings.discovery.encryption_key,
        &discovery.fetch_secret_ciphertext,
    )?;
    let website_issuer = website_origin(&discovery.website_url)?;
    let discovery_url = default_discovery_url(&discovery.website_url)?;
    let expected_audience = state.settings.oidc.issuer.trim_end_matches('/').to_string();
    if expected_audience.is_empty() {
        return Err(AppError::Configuration(
            "oidc issuer is not configured".to_string(),
        ));
    }
    let application = state
        .db
        .find_application_by_id(&discovery.application_id)
        .await?
        .ok_or(AppError::NotFound)?;
    fetch_and_verify(
        &discovery_url,
        &fetch_secret,
        &discovery.signing_public_jwks,
        &website_issuer,
        &application.slug,
        &expected_audience,
        &application.organization_id,
        state.settings.discovery.allow_private_networks,
    )
    .await
}

/// Attempts all website-managed applications and keeps one failed website
/// from preventing the remaining applications from refreshing.
pub async fn sync_all(state: &AppState) -> AppResult<()> {
    for (application, discovery) in state.db.list_website_managed_discoveries().await? {
        if discovery.operator_disabled != 0 {
            continue;
        }
        if let Err(error) = sync_application(state, &application.id).await {
            tracing::warn!(
                application_id = %application.slug,
                error = %error,
                "website application discovery sync failed"
            );
        }
    }
    Ok(())
}

/// Starts the periodic refresh loop. The first refresh is performed during
/// startup by `main`; this task waits one full interval before its first tick
/// so startup never creates an avoidable duplicate request.
pub fn spawn_periodic_sync(state: AppState) {
    let interval_seconds = state.settings.discovery.sync_interval_seconds.max(30) as u64;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = sync_all(&state).await {
                tracing::warn!(error = %error, "website application discovery sweep failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::header, routing::get};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn signed_manifest() -> (Vec<u8>, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
                "kid": "key-1",
                "use": "sig",
                "alg": "EdDSA"
            }]
        })
        .to_string();
        let now = util::now_ts();
        let payload = serde_json::json!({
            "format": FORMAT,
            "application_id": "axon",
            "revision": 1,
            "version": "test-1",
            "iss": "https://axon.example",
            "aud": ["https://sso.example", "signet:application:axon"],
            "iat": now,
            "exp": now + 300,
            "protocols": {"oauth2_oidc": {"enabled": true, "client_ids": ["web"]}},
            "clients": [{
                "client_id": "web",
                "client_name": "Web",
                "scopes": ["openid"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "require_pkce": true,
                "redirect_uris": ["https://axon.example/callback"]
            }],
            "authorization": {
                "inherit_enterprise_roles": true,
                "default_role": "member",
                "claims": ["roles", "permissions", "groups"],
                "custom_roles": [
                    {"name": "member", "description": "Basic user", "permissions": ["axon.read:owned_resources"]},
                    {"name": "operator", "description": "Operator", "permissions": ["axon.read:owned_resources"]}
                ]
            },
            "profiles": {"default": {
                "permissions": [{"key": "axon.read:owned_resources", "label": "Owned resources"}],
                "roles": [
                    {"key": "member", "name": "Member", "permissions": ["axon.read:owned_resources"], "is_default": true},
                    {"key": "operator", "name": "Operator", "permissions": ["axon.read:owned_resources"]}
                ]
            }}
        });
        let header =
            URL_SAFE_NO_PAD.encode(serde_json::json!({"alg":"EdDSA","kid":"key-1"}).to_string());
        let encoded_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let input = format!("{header}.{encoded_payload}");
        let signature = signing_key.sign(input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        (token.into_bytes(), jwks)
    }

    #[test]
    fn ed25519_manifest_verifies_and_normalizes() {
        let (body, jwks) = signed_manifest();
        let verified = verify_and_normalize(
            &body,
            &jwks,
            "https://axon.example",
            "axon",
            "https://sso.example",
            "org-1",
        )
        .unwrap();
        assert_eq!(verified.revision, 1);
        assert_eq!(verified.clients[0].client_id, "web");
        assert_eq!(verified.profiles["default"].roles[0].key, "member");
        assert!(verified.authorization.get("custom_roles").is_some());
    }

    #[test]
    fn manifest_content_digest_ignores_short_lived_claims() {
        let first = serde_json::json!({
            "format": FORMAT,
            "application_id": "axon",
            "revision": 1,
            "version": "test-1",
            "iss": "https://axon.example",
            "aud": ["https://sso.example", "signet:application:axon"],
            "iat": 100,
            "exp": 400,
            "clients": [{"client_id": "web", "scopes": ["openid"]}],
        });
        let second = serde_json::json!({
            "format": FORMAT,
            "application_id": "axon",
            "revision": 1,
            "version": "test-1",
            "iss": "https://axon.example",
            "aud": ["https://sso.example", "signet:application:axon"],
            "iat": 200,
            "exp": 500,
            "clients": [{"client_id": "web", "scopes": ["openid"]}],
        });
        assert_eq!(
            manifest_content_digest(&serde_json::to_vec(&first).unwrap()).unwrap(),
            manifest_content_digest(&serde_json::to_vec(&second).unwrap()).unwrap()
        );

        let mut changed = second;
        changed["clients"][0]["scopes"] = serde_json::json!(["openid", "profile"]);
        assert_ne!(
            manifest_content_digest(&serde_json::to_vec(&first).unwrap()).unwrap(),
            manifest_content_digest(&serde_json::to_vec(&changed).unwrap()).unwrap()
        );
    }

    #[tokio::test]
    async fn authenticated_manifest_endpoint_round_trips_through_verifier() {
        let (body, jwks) = signed_manifest();
        let body = String::from_utf8(body).unwrap();
        let fetch_secret = "fetch-secret".to_string();
        let route_body = body.clone();
        let route_secret = fetch_secret.clone();
        let app = Router::new().route(
            DISCOVERY_PATH,
            get(move |headers: axum::http::HeaderMap| {
                let route_body = route_body.clone();
                let route_secret = route_secret.clone();
                async move {
                    let authorized = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        == Some(format!("Bearer {route_secret}").as_str());
                    if !authorized {
                        return (axum::http::StatusCode::UNAUTHORIZED, String::new());
                    }
                    (axum::http::StatusCode::OK, route_body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let verified = fetch_and_verify(
            &format!("http://127.0.0.1:{}{}", address.port(), DISCOVERY_PATH),
            &fetch_secret,
            &jwks,
            "https://axon.example",
            "axon",
            "https://sso.example",
            "org-1",
            true,
        )
        .await
        .unwrap();
        assert_eq!(verified.application_id, "axon");
        assert_eq!(verified.clients[0].client_id, "web");
        server.abort();
    }

    #[test]
    fn wrong_signature_is_rejected() {
        let (mut body, jwks) = signed_manifest();
        let last = body.len() - 1;
        body[last] = if body[last] == b'A' { b'B' } else { b'A' };
        assert!(
            verify_and_normalize(
                &body,
                &jwks,
                "https://axon.example",
                "axon",
                "https://sso.example",
                "org-1",
            )
            .is_err()
        );
    }

    #[test]
    fn extreme_manifest_timestamps_fail_closed_without_overflowing() {
        let manifest = ApplicationManifest {
            format: FORMAT.to_string(),
            application_id: "axon".to_string(),
            revision: 1,
            version: "test".to_string(),
            iss: "https://axon.example".to_string(),
            aud: serde_json::json!(["https://sso.example"]),
            iat: i64::MIN,
            exp: i64::MAX,
            clients: Vec::new(),
            protocols: Map::new(),
            login_adapters: Map::new(),
            directory_sync: Map::new(),
            authorization: Map::new(),
            profiles: BTreeMap::new(),
        };
        assert!(
            validate_claims(
                &manifest,
                "https://axon.example",
                "axon",
                "https://sso.example",
            )
            .is_err()
        );
    }
}
