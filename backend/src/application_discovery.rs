//! Website-owned application authentication discovery.
//!
//! The website publishes one complete, signed document. Signet verifies the
//! document against an operator-pinned Ed25519 key and turns it into a
//! normalized in-memory snapshot. Database reconciliation is intentionally
//! kept outside this module so signature/schema validation has no side
//! effects.

use crate::{
    AppState,
    application_contract::{ApplicationContract, ClientContract, IntegrationProfile},
    db::{ApplicationDiscoveryRecord, NewClient},
    error::{AppError, AppResult},
    util,
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

pub const FORMAT: &str = crate::application_contract::FORMAT;
pub const DISCOVERY_PATH: &str = "/.well-known/signet-authorization.json";
pub const MANAGEMENT_MODE_SIGNET: &str = "signet_managed";
pub const MANAGEMENT_MODE_WEBSITE: &str = "website_managed";
pub const SOURCE_WEBSITE: &str = "website_manifest";
pub const SOURCE_MANUAL: &str = "manual";
pub const SOURCE_MODE_MANUAL: &str = "manual";
pub const SOURCE_MODE_DISCOVERY: &str = "application_discovery";
pub const SYNC_STATUS_MANUAL: &str = "manual";
pub const SYNC_STATUS_SYNCED: &str = "synced";
pub const SYNC_STATUS_NO_PROFILE: &str = "no_profile";
pub const SYNC_STATUS_ERROR: &str = "error";
pub const SYNC_UNCONFIGURED: &str = "unconfigured";
pub const SYNC_PENDING: &str = "pending";
pub const SYNC_SYNCED: &str = "synced";
pub const SYNC_ERROR: &str = "error";
pub const SYNC_DISABLED: &str = "disabled";

const MAX_CLIENT_ID_LENGTH: usize = 255;
const MAX_SCOPE_LENGTH: usize = 256;
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
    pub revoke_removed_clients: bool,
    pub clients: Vec<NewClient>,
    pub client_protocols: BTreeMap<String, String>,
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

fn manifest_content_digest(payload: &[u8]) -> AppResult<String> {
    let mut value = serde_json::from_slice::<Value>(payload)
        .map_err(|_| AppError::BadRequest("application discovery schema is invalid".to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        AppError::BadRequest("application discovery schema is invalid".to_string())
    })?;
    object.remove("iat");
    object.remove("exp");
    let canonical = serde_json::to_string(&value)
        .map_err(|_| AppError::Internal("failed to encode application discovery digest".to_string()))?;
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
        .resolve(host, resolved_address)
        .build()
        .map_err(|_| AppError::Internal("failed to build discovery HTTP client".to_string()))?
        .get(discovery_url.as_str())
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {fetch_secret}"))
        .header(reqwest::header::ACCEPT, "application/jose, application/json")
        .send()
        .await
        .map_err(|_| AppError::BadRequest("application discovery request failed".to_string()))?;
    if !response.status().is_success() {
        return Err(AppError::BadRequest("application discovery returned an error".to_string()));
    }
    if response.content_length().is_some_and(|length| length > 512 * 1024) {
        return Err(AppError::BadRequest("application discovery response is too large".to_string()));
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::BadRequest("application discovery body failed".to_string()))?
    {
        if body.len().saturating_add(chunk.len()) > 512 * 1024 {
            return Err(AppError::BadRequest("application discovery response is too large".to_string()));
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
        let envelope = serde_json::from_str::<DiscoveryEnvelope>(text)
            .map_err(|_| AppError::BadRequest("application discovery envelope is invalid".to_string()))?;
        if envelope.format != FORMAT {
            return Err(AppError::BadRequest("application discovery format is unsupported".to_string()));
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
    #[derive(Deserialize)]
    struct JwsHeader {
        alg: String,
        #[serde(default)]
        kid: Option<String>,
    }
    #[derive(Deserialize)]
    struct PinnedJwks {
        keys: Vec<PinnedJwk>,
    }
    #[derive(Deserialize)]
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
    let header = serde_json::from_slice::<JwsHeader>(
        &URL_SAFE_NO_PAD.decode(encoded_header).map_err(|_| AppError::Unauthorized)?,
    )
    .map_err(|_| AppError::Unauthorized)?;
    if header.alg != "EdDSA" {
        return Err(AppError::Unauthorized);
    }
    let keys = serde_json::from_str::<PinnedJwks>(pinned_jwks)
        .map_err(|_| AppError::Unauthorized)?
        .keys;
    let candidates = keys
        .iter()
        .filter(|key| {
            key.kty == "OKP"
                && key.crv == "Ed25519"
                && key.use_.as_deref().is_none_or(|value| value == "sig")
                && key.alg.as_deref().is_none_or(|value| value == "EdDSA")
                && header.kid.as_deref().is_none_or(|kid| key.kid.as_deref() == Some(kid))
        })
        .collect::<Vec<_>>();
    let key = match (header.kid.as_deref(), candidates.as_slice()) {
        (_, []) => return Err(AppError::Unauthorized),
        (Some(_), [key, ..]) => *key,
        (None, [key]) => *key,
        (None, _) => return Err(AppError::Unauthorized),
    };
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&key.x)
        .map_err(|_| AppError::Unauthorized)?
        .try_into()
        .map_err(|_| AppError::Unauthorized)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| AppError::Unauthorized)?;
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|_| AppError::Unauthorized)?,
    )
    .map_err(|_| AppError::Unauthorized)?;
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AppError::Unauthorized)?;
    URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| AppError::Unauthorized)
}

fn normalize_application_contract(
    contract: &ApplicationContract,
    payload: &[u8],
    expected_issuer: &str,
    expected_application_id: &str,
    expected_audience: &str,
    organization_id: &str,
) -> AppResult<VerifiedApplicationManifest> {
    contract
        .validate(util::now_ts())
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    if contract.application_id != expected_application_id
        || website_origin(&contract.issuer)? != website_origin(expected_issuer)?
        || !audience_contains(&contract.audience, expected_audience)
    {
        return Err(AppError::Unauthorized);
    }
    let clients = contract
        .modules
        .clients
        .iter()
        .map(|client| normalize_contract_client(client, organization_id, &contract.modules.policies))
        .collect::<AppResult<Vec<_>>>()?;
    let client_protocols = contract
        .modules
        .clients
        .iter()
        .map(|client| {
            Ok((
                client.client_id.clone(),
                normalize_client_protocol(&client.protocol)?,
            ))
        })
        .collect::<AppResult<BTreeMap<_, _>>>()?;
    let profiles = normalize_contract_profiles(contract)?;
    let authorization = contract_authorization_module(&profiles)?;
    let authorization_mappings = normalize_authorization_bindings(&authorization, &profiles)?;
    let protocols = normalize_contract_protocols(
        &contract.modules.connections,
        &client_protocols,
        expected_issuer,
    )?;
    let login_adapters = normalize_module(
        "login_adapters",
        &serde_json::json!({"enabled": true, "allow_signet_password": true})
            .as_object()
            .cloned()
            .ok_or_else(|| AppError::Internal("failed to build login adapters".to_string()))?,
        expected_issuer,
    )?;
    let directory_sync = normalize_directory_sync(&contract.modules.connections, expected_issuer)?;
    validate_protocol_client_bindings(&protocols, &clients)?;
    let redacted_payload = serde_json::to_value(contract)
        .map_err(|_| AppError::Internal("failed to encode v3 contract snapshot".to_string()))?;
    Ok(VerifiedApplicationManifest {
        application_id: contract.application_id.clone(),
        revision: contract.revision,
        version: contract.version.clone(),
        digest: manifest_content_digest(payload)?,
        issued_at: contract.issued_at,
        expires_at: contract.expires_at,
        revoke_removed_clients: contract.modules.lifecycle.revoke_removed_clients,
        clients,
        client_protocols,
        protocols,
        login_adapters,
        directory_sync,
        authorization,
        authorization_mappings,
        profiles,
        redacted_payload,
    })
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
    let payload_value = serde_json::from_slice::<Value>(&payload)
        .map_err(|_| AppError::BadRequest("application discovery schema is invalid".to_string()))?;
    if payload_value.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(AppError::BadRequest(
            "only signet-application/v3 discovery contracts are supported".to_string(),
        ));
    }
    let contract = serde_json::from_value::<ApplicationContract>(payload_value).map_err(|_| {
        AppError::BadRequest("application v3 contract schema is invalid".to_string())
    })?;
    normalize_application_contract(
        &contract,
        &payload,
        expected_issuer,
        expected_application_id,
        expected_audience,
        organization_id,
    )
}

fn audience_contains(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn normalize_contract_client(
    client: &ClientContract,
    organization_id: &str,
    policies: &[crate::application_contract::PolicyContract],
) -> AppResult<NewClient> {
    let client_id = visible_text(&client.client_id, MAX_CLIENT_ID_LENGTH, "client_id")?;
    let client_name = if client.display_name.trim().is_empty() {
        client_id.clone()
    } else {
        normalize_display_text(&client.display_name, 160, "client_name")?
    };
    let auth_method = client.token_endpoint_auth_method.trim();
    if !matches!(auth_method, "none" | "private_key_jwt") {
        return Err(AppError::BadRequest(
            "v3 clients cannot transport shared secrets".to_string(),
        ));
    }
    let jwks = client
        .jwks
        .as_ref()
        .filter(|value| !value.is_null())
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| AppError::BadRequest("client jwks is invalid".to_string()))?
        .unwrap_or_default();
    let audiences = normalize_string_list(&client.audiences, 2048, "audience")?;
    let scopes = normalize_string_list(&client.scopes, MAX_SCOPE_LENGTH, "scope")?;
    let grant_types = normalize_string_list(&client.grant_types, 128, "grant_type")?;
    let response_types = normalize_string_list(&client.response_types, 128, "response_type")?;
    let service_account_enabled = client
        .profiles
        .contains(&IntegrationProfile::MachineIdentity);
    let service_account_permissions = policies
        .iter()
        .filter(|policy| policy.client_ids.iter().any(|id| id == &client.client_id))
        .flat_map(|policy| policy.permissions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let client_require_mfa = client.require_mfa
        || policies.iter().any(|policy| {
            policy.client_ids.iter().any(|id| id == &client.client_id) && policy.require_mfa
        });
    let client_require_dpop = client.require_dpop
        || policies.iter().any(|policy| {
            policy.client_ids.iter().any(|id| id == &client.client_id) && policy.require_dpop
        });
    let logo_uri = client
        .metadata
        .get("logo_uri")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(NewClient {
        client_id,
        client_secret_hash: None,
        client_name,
        logo_uri,
        organization_id: Some(organization_id.to_string()),
        redirect_uris: normalize_url_list(&client.redirect_uris, "redirect_uri")?,
        post_logout_redirect_uris: normalize_url_list(
            &client.post_logout_redirect_uris,
            "post_logout_redirect_uri",
        )?,
        scopes,
        audience: audiences.first().cloned().unwrap_or_default(),
        grant_types,
        response_types,
        token_endpoint_auth_method: auth_method.to_string(),
        require_pkce: client.require_pkce,
        require_mfa: client_require_mfa,
        require_pushed_authorization_requests: false,
        require_s256_pkce: client.require_s256_pkce,
        require_confidential_client: auth_method != "none",
        require_dpop: client_require_dpop,
        require_account_selection: false,
        trust_email_verified: false,
        authorization_details_types: Vec::new(),
        subject_type: if service_account_enabled {
            "pairwise".to_string()
        } else {
            "public".to_string()
        },
        sector_identifier_uri: String::new(),
        jwks_uri: client.jwks_uri.clone().unwrap_or_default(),
        jwks,
        backchannel_logout_uri: String::new(),
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: String::new(),
        frontchannel_logout_session_required: false,
        service_account_enabled,
        service_account_permissions,
        is_active: client.active,
    })
}

fn normalize_client_protocol(value: &str) -> AppResult<String> {
    let protocol = visible_text(value, 64, "client protocol")?.to_ascii_lowercase();
    if !matches!(
        protocol.as_str(),
        "oidc" | "saml" | "cas" | "jwt" | "iap" | "forward_auth"
    ) {
        return Err(AppError::BadRequest(
            "v3 client protocol is unsupported".to_string(),
        ));
    }
    Ok(protocol)
}

fn normalize_contract_profiles(
    contract: &ApplicationContract,
) -> AppResult<BTreeMap<String, NormalizedProfile>> {
    let all_permission_keys = contract
        .modules
        .policies
        .iter()
        .flat_map(|policy| policy.permissions.iter().cloned())
        .chain(
            contract
                .modules
                .roles
                .iter()
                .flat_map(|role| role.permissions.iter().cloned()),
        )
        .map(|permission| normalize_permission_key(&permission))
        .collect::<AppResult<BTreeSet<_>>>()?;
    let build_profile = |allowed_permissions: &BTreeSet<String>| -> AppResult<NormalizedProfile> {
        let permissions = allowed_permissions
            .iter()
            .map(|key| {
                Ok(NormalizedPermission {
                    key: key.clone(),
                    label: key.rsplit(':').next().unwrap_or(key).to_string(),
                    description: None,
                })
            })
            .collect::<AppResult<Vec<_>>>()?;
        let mut roles = Vec::new();
        for role in &contract.modules.roles {
            let normalized_role_permissions = role
                .permissions
                .iter()
                .map(|permission| normalize_permission_key(permission))
                .collect::<AppResult<Vec<_>>>()?;
            if normalized_role_permissions
                .iter()
                .any(|permission| !allowed_permissions.contains(permission))
            {
                continue;
            }
            let key = visible_text(&role.role_id, 128, "role_id")?;
            roles.push(NormalizedRole {
                key: key.clone(),
                name: key,
                description: None,
                permissions: normalized_role_permissions,
                is_default: role.default_role,
            });
        }
        Ok(NormalizedProfile { permissions, roles })
    };

    let application_profile = build_profile(&all_permission_keys)?;
    let mut profiles = BTreeMap::new();
    profiles.insert("default".to_string(), application_profile);
    for client in &contract.modules.clients {
        let is_machine_identity = client
            .profiles
            .contains(&IntegrationProfile::MachineIdentity);
        let mut allowed_permissions = if is_machine_identity {
            BTreeSet::new()
        } else {
            all_permission_keys.clone()
        };
        allowed_permissions.extend(
            contract
                .modules
                .policies
                .iter()
                .filter(|policy| {
                    policy
                        .client_ids
                        .iter()
                        .any(|client_id| client_id == &client.client_id)
                })
                .flat_map(|policy| policy.permissions.iter().cloned())
                .map(|permission| normalize_permission_key(&permission))
                .collect::<AppResult<BTreeSet<_>>>()?,
        );
        profiles.insert(client.client_id.clone(), build_profile(&allowed_permissions)?);
    }
    Ok(profiles)
}

fn contract_authorization_module(
    profiles: &BTreeMap<String, NormalizedProfile>,
) -> AppResult<Value> {
    let profile = profiles
        .get("default")
        .ok_or_else(|| AppError::BadRequest("v3 must declare a default profile".to_string()))?;
    let mut object = serde_json::Map::new();
    object.insert(
        "default_role".to_string(),
        profile
            .roles
            .iter()
            .find(|role| role.is_default)
            .map(|role| Value::String(role.key.clone()))
            .unwrap_or(Value::Null),
    );
    object.insert(
        "roles".to_string(),
        Value::Array(
            profile
                .roles
                .iter()
                .map(|role| {
                    serde_json::json!({
                        "role_id": role.key,
                        "permissions": role.permissions,
                        "default_role": role.is_default
                    })
                })
                .collect(),
        ),
    );
    object.insert(
        "custom_roles".to_string(),
        Value::Array(
            profile
                .roles
                .iter()
                .map(|role| {
                    serde_json::json!({
                        "name": role.key,
                        "description": role.description.clone().unwrap_or_default(),
                        "permissions": role.permissions
                    })
                })
                .collect(),
        ),
    );
    normalize_module("authorization", &object, "")
}

fn normalize_contract_protocols(
    connections: &[crate::application_contract::ConnectionContract],
    client_protocols: &BTreeMap<String, String>,
    expected_issuer: &str,
) -> AppResult<Value> {
    let mut protocols = serde_json::Map::new();
    let mut clients_by_protocol = BTreeMap::<String, Vec<String>>::new();
    for (client_id, protocol) in client_protocols {
        let module_key = protocol_module_key(protocol);
        clients_by_protocol
            .entry(module_key.to_string())
            .or_default()
            .push(client_id.clone());
    }
    for (module_key, client_ids) in clients_by_protocol {
        protocols.insert(
            module_key,
            serde_json::json!({"enabled": true, "client_ids": client_ids}),
        );
    }
    for connection in connections {
        let key = match connection.kind.as_str() {
            "saml2" => "saml2",
            "cas" => "cas",
            "jwt" => "jwt",
            "scim" | "ldap" => continue,
            other if connection.required => {
                return Err(AppError::BadRequest(format!(
                    "v3 connection kind {other} is not supported"
                )))
            }
            _ => continue,
        };
        let mut value = connection.settings.clone();
        value.insert("enabled".to_string(), Value::Bool(true));
        value.insert(
            "connection_id".to_string(),
            Value::String(connection.connection_id.clone()),
        );
        let protocol = protocols
            .entry(key.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(protocol) = protocol.as_object_mut() else {
            return Err(AppError::Internal(
                "protocol module entry is not an object".to_string(),
            ));
        };
        for (field, field_value) in value {
            protocol.insert(field, field_value);
        }
    }
    normalize_module("protocols", &protocols, expected_issuer)
}

fn protocol_module_key(protocol: &str) -> &str {
    match protocol {
        "oidc" => "oauth2_oidc",
        "saml" => "saml2",
        other => other,
    }
}

fn normalize_directory_sync(
    connections: &[crate::application_contract::ConnectionContract],
    expected_issuer: &str,
) -> AppResult<Value> {
    let scim = connections.iter().filter(|connection| connection.kind == "scim").collect::<Vec<_>>();
    let ldap = connections.iter().filter(|connection| connection.kind == "ldap").collect::<Vec<_>>();
    if scim.len() > 1 {
        return Err(AppError::BadRequest("v3 declares more than one SCIM connection".to_string()));
    }
    let object = serde_json::json!({
        "enabled": !scim.is_empty() || !ldap.is_empty(),
        "scim_enabled": !scim.is_empty(),
        "ldap_provider_ids": ldap.iter().filter_map(|connection| connection.settings.get("provider_id").and_then(Value::as_str)).collect::<Vec<_>>(),
        "scim_audience": scim.first().and_then(|connection| connection.settings.get("audience")).and_then(Value::as_str).unwrap_or_default()
    });
    normalize_module(
        "directory_sync",
        object.as_object().ok_or_else(|| AppError::Internal("failed to build directory sync".to_string()))?,
        expected_issuer,
    )
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
    let Some(protocols) = protocols.as_object() else {
        return Err(AppError::BadRequest(
            "protocols module must be an object".to_string(),
        ));
    };
    for protocol in protocols.values() {
        let Some(client_ids) = protocol
            .as_object()
            .and_then(|object| object.get("client_ids"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for client_id in client_ids.iter().filter_map(Value::as_str) {
            if !known.contains(client_id) {
                return Err(AppError::BadRequest(
                    "protocols references an undeclared client".to_string(),
                ));
            }
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
                "v3 authorization contracts cannot declare user role assignments".to_string(),
            ));
        }
    }

    Ok(NormalizedAuthorizationMappings {
        default_role,
        group_mappings,
        organization_role_mappings,
    })
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

/// Fetches and applies one website-owned authorization snapshot. The
/// network/signature phase is deliberately outside the database transaction;
/// `Db::apply_application_contract` only receives an already verified value and
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
        Ok(contract) => {
            state
                .db
                .apply_application_contract(application_id, contract)
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

    fn signed_contract() -> (Vec<u8>, String) {
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
            "format": crate::application_contract::FORMAT,
            "application_id": "axon",
            "revision": 2,
            "version": "v3-test",
            "iss": "https://axon.example",
            "aud": ["https://sso.example", "signet:application:axon"],
            "iat": now,
            "exp": now + 300,
            "modules": {
                "clients": [{
                    "client_id": "web",
                    "protocol": "oidc",
                    "display_name": "Web",
                    "profiles": ["web_oidc"],
                    "redirect_uris": ["https://axon.example/callback"],
                    "scopes": ["openid", "axon.read"],
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "require_pkce": true,
                    "require_s256_pkce": true
                }, {
                    "client_id": "worker",
                    "protocol": "oidc",
                    "display_name": "Worker",
                    "profiles": ["machine_identity", "api_resource"],
                    "scopes": ["axon.read"],
                    "audiences": ["https://axon.example/api"],
                    "grant_types": ["client_credentials"],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": {"keys": [{
                        "kty": "RSA",
                        "kid": "worker-1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "smj1yrPFDZ2_dU44RmLcdAgTfrGY2leozoOhP4li6X4Xcc89yvH3vDtNU7aEshwmu8UBUI698JXDAmQE8sjeV_ZermfSHwmt72HfTInCX-4X_O2h07BBx5N7Kno7YAWaQrcfHzJRFlQa6wbkIrGxzdaRzNVKVyE628_j_jBI_W-KdIK9P96AtBStkcB48WI7M_tKpe4AxvVnAQzex0M_XX04MwyZ3v07Bb7kr-KWUM-A6cDMwtoc3qoQUdcjLh5hRl3iOwJ3wPHElQPyrxRQknWtbwJF0Fw1v25rATNFGqvO4Ddr9CkIg1njpxpG8NxfUbFzGq3GHQYxgUaxZmPBcw",
                        "e": "AQAB"
                    }]}
                }],
                "connections": [{"connection_id": "sso-saml", "kind": "saml2", "settings": {}}],
                "policies": [{
                    "policy_id": "read",
                    "client_ids": ["web"],
                    "permissions": ["axon.read"]
                }, {
                    "policy_id": "worker-read",
                    "client_ids": ["worker"],
                    "audiences": ["https://axon.example/api"],
                    "permissions": ["axon.read"],
                    "require_dpop": true
                }],
                "roles": [{
                    "role_id": "member",
                    "permissions": ["axon.read"],
                    "default_role": true
                }, {
                    "role_id": "operator",
                    "permissions": ["axon.admin"]
                }],
                "lifecycle": {"mode": "replace", "fail_closed": true, "revoke_removed_clients": true}
            }
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
        let (body, jwks) = signed_contract();
        let verified = verify_and_normalize(
            &body,
            &jwks,
            "https://axon.example",
            "axon",
            "https://sso.example",
            "org-1",
        )
        .unwrap();
        assert_eq!(verified.revision, 2);
        assert_eq!(verified.clients[0].client_id, "web");
        assert_eq!(verified.client_protocols["worker"], "oidc");
        assert_eq!(verified.profiles["default"].roles[0].key, "member");
        assert!(verified.authorization.get("custom_roles").is_some());
    }

    #[test]
    fn ed25519_v3_contract_verifies_and_normalizes_to_local_snapshot() {
        let (body, jwks) = signed_contract();
        let verified = verify_and_normalize(
            &body,
            &jwks,
            "https://axon.example",
            "axon",
            "https://sso.example",
            "org-1",
        )
        .unwrap();
        assert_eq!(verified.revision, 2);
        assert_eq!(verified.clients[0].client_id, "web");
        assert_eq!(verified.clients[0].require_s256_pkce, true);
        let worker = verified
            .clients
            .iter()
            .find(|client| client.client_id == "worker")
            .unwrap();
        assert!(worker.require_dpop);
        assert_eq!(worker.service_account_permissions, vec!["axon.read"]);
        assert!(verified.profiles["worker"]
            .permissions
            .iter()
            .all(|permission| permission.key != "axon.admin"));
        assert_eq!(
            verified.protocols["saml2"]["enabled"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(verified.profiles["default"].roles[0].key, "member");
        assert!(verified.profiles["default"]
            .permissions
            .iter()
            .any(|permission| permission.key == "axon.read"));
    }

    #[test]
    fn v3_connections_reject_unknown_adapters_instead_of_persisting_dead_config() {
        let error = normalize_contract_protocols(
            &[crate::application_contract::ConnectionContract {
                connection_id: "unknown".to_string(),
                kind: "unsupported".to_string(),
                required: true,
                settings: Map::new(),
            }],
            &BTreeMap::new(),
            "https://axon.example",
        )
        .unwrap_err();
        assert!(error.to_string().contains("not supported"));
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
        let (body, jwks) = signed_contract();
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
        let (mut body, jwks) = signed_contract();
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


}
