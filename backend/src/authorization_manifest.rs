//! Signed website authorization manifests.
//!
//! A manifest describes a website's permission vocabulary and role catalog;
//! it never contains user assignments.  Signet stores the last verified
//! snapshot and evaluates it locally so login and token issuance do not
//! depend on the website being reachable.

use crate::{
    AppState,
    client_assertion,
    db::{
        ApplicationPermissionDefinitionRecord, ApplicationProfileRoleRecord,
        ClientRecord, NewApplicationPermissionDefinition, NewApplicationProfileRole,
    },
    error::{AppError, AppResult},
    util,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};
use url::Url;

pub const MANIFEST_FORMAT: &str = "signet-authorization/v1";
pub const DEFAULT_MANIFEST_PATH: &str = "/.well-known/signet-authorization.json";
pub const SOURCE_MANIFEST: &str = "manifest";
pub const SOURCE_MANUAL: &str = "manual";
pub const SOURCE_MODE_MANUAL: &str = "manual";
pub const SOURCE_MODE_SIGNED: &str = "signed_manifest";
pub const SYNC_STATUS_MANUAL: &str = "manual";
pub const SYNC_STATUS_SYNCED: &str = "synced";
pub const SYNC_STATUS_NO_PROFILE: &str = "no_profile";
pub const SYNC_STATUS_ERROR: &str = "error";

const MAX_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_PERMISSION_DEFINITIONS: usize = 4096;
const MAX_ROLES: usize = 512;
const MAX_ROLE_PERMISSIONS: usize = 512;
const MAX_PERMISSION_KEY_LENGTH: usize = 256;
const MAX_ROLE_KEY_LENGTH: usize = 128;
const MAX_LABEL_LENGTH: usize = 160;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEnvelope {
    pub format: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPermission {
    pub key: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRole {
    pub key: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestProfile {
    #[serde(default)]
    pub permissions: Vec<ManifestPermission>,
    #[serde(default)]
    pub roles: Vec<ManifestRole>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestClaims {
    iss: String,
    #[allow(dead_code)]
    aud: Value,
    iat: i64,
    #[allow(dead_code)]
    exp: i64,
    version: String,
    profiles: BTreeMap<String, ManifestProfile>,
}

#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    pub version: String,
    pub digest: String,
    pub permissions: Vec<NewApplicationPermissionDefinition>,
    pub roles: Vec<NewApplicationProfileRole>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManifestProfileStatus {
    pub profile_key: String,
    pub source_mode: String,
    pub manifest_url: String,
    pub signer_client_id: Option<String>,
    pub remote_version: Option<String>,
    pub remote_digest: Option<String>,
    pub sync_status: String,
    pub last_synced_at: Option<i64>,
    pub last_error: Option<String>,
    pub permission_count: usize,
    pub role_count: usize,
}

pub fn website_origin(value: &str) -> AppResult<String> {
    let parsed = Url::parse(value.trim())
        .map_err(|_| AppError::BadRequest("website URL is invalid".to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AppError::BadRequest(
            "website URL must be an absolute http(s) URL without credentials, query, or fragment"
                .to_string(),
        ));
    }
    let mut origin = parsed;
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    Ok(origin.to_string().trim_end_matches('/').to_string())
}

pub fn default_manifest_url(website_url: &str) -> AppResult<String> {
    let origin = website_origin(website_url)?;
    Ok(format!("{origin}{DEFAULT_MANIFEST_PATH}"))
}

pub async fn discover_profile(
    _state: &AppState,
    signer_client: &ClientRecord,
    manifest_url: &str,
    expected_issuer: &str,
    audience: &str,
    profile_key: &str,
    profile_id: &str,
) -> AppResult<Option<VerifiedManifest>> {
    let manifest_url = validate_fetch_url(manifest_url)?;
    let expected_issuer = website_origin(expected_issuer)?;
    let mut response = Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| AppError::Internal(format!("failed to build manifest client: {err}")))?
        .get(&manifest_url)
        .header(reqwest::header::ACCEPT, "application/json, application/jwt")
        .send()
        .await
        .map_err(|err| AppError::BadRequest(format!("authorization manifest request failed: {err}")))?
        .error_for_status()
        .map_err(|err| AppError::BadRequest(format!("authorization manifest returned an error: {err}")))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MANIFEST_BYTES as u64)
    {
        return Err(AppError::BadRequest(
            "authorization manifest is too large".to_string(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| AppError::BadRequest(format!("authorization manifest body failed: {err}")))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_MANIFEST_BYTES {
            return Err(AppError::BadRequest(
                "authorization manifest is too large".to_string(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let token = manifest_token(&body)?;
    let claims = client_assertion::verify_signed_jwt_for_issuer::<ManifestClaims>(
        signer_client,
        &token,
        &[audience.to_string()],
        &expected_issuer,
        &["iss", "aud", "iat", "exp"],
    )
    .await
    .map_err(|_| AppError::BadRequest("authorization manifest signature is invalid".to_string()))?;
    if claims.iss != expected_issuer {
        return Err(AppError::BadRequest(
            "authorization manifest issuer does not match the website".to_string(),
        ));
    }
    if claims.version.trim().is_empty() || claims.version.len() > 128 {
        return Err(AppError::BadRequest(
            "authorization manifest version is invalid".to_string(),
        ));
    }
    if claims.iat > util::now_ts() + 60 {
        return Err(AppError::BadRequest(
            "authorization manifest issue time is in the future".to_string(),
        ));
    }
    let Some(profile) = claims.profiles.get(profile_key) else {
        return Ok(None);
    };
    let (permissions, roles) = normalize_profile(profile, profile_id)?;
    Ok(Some(VerifiedManifest {
        version: claims.version,
        digest: util::sha256_base64url(&token),
        permissions,
        roles,
    }))
}

fn manifest_token(body: &[u8]) -> AppResult<String> {
    let text = std::str::from_utf8(body)
        .map_err(|_| AppError::BadRequest("authorization manifest is not UTF-8".to_string()))?
        .trim();
    if text.is_empty() {
        return Err(AppError::BadRequest(
            "authorization manifest is empty".to_string(),
        ));
    }
    if text.starts_with('{') {
        let envelope = serde_json::from_str::<ManifestEnvelope>(text).map_err(|err| {
            AppError::BadRequest(format!("authorization manifest envelope is invalid: {err}"))
        })?;
        if envelope.format != MANIFEST_FORMAT {
            return Err(AppError::BadRequest(
                "authorization manifest format is unsupported".to_string(),
            ));
        }
        return Ok(envelope.token.trim().to_string());
    }
    Ok(text.to_string())
}

fn normalize_profile(
    profile: &ManifestProfile,
    profile_id: &str,
) -> AppResult<(
    Vec<NewApplicationPermissionDefinition>,
    Vec<NewApplicationProfileRole>,
)> {
    if profile.permissions.len() > MAX_PERMISSION_DEFINITIONS {
        return Err(AppError::BadRequest(
            "authorization manifest has too many permissions".to_string(),
        ));
    }
    if profile.roles.len() > MAX_ROLES {
        return Err(AppError::BadRequest(
            "authorization manifest has too many roles".to_string(),
        ));
    }
    let mut permission_keys = BTreeSet::new();
    let mut permissions = Vec::with_capacity(profile.permissions.len());
    for item in &profile.permissions {
        let key = normalize_permission_key(&item.key)?;
        if !permission_keys.insert(key.clone()) {
            return Err(AppError::BadRequest(format!(
                "authorization manifest repeats permission: {key}"
            )));
        }
        let label = item
            .label
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| key.rsplit(':').next().unwrap_or(&key))
            .to_string();
        validate_label(&label, "permission label")?;
        permissions.push(NewApplicationPermissionDefinition {
            profile_id: profile_id.to_string(),
            permission_key: key,
            label,
            description: normalize_optional_description(item.description.as_deref()),
            source: SOURCE_MANIFEST.to_string(),
            is_active: true,
        });
    }
    let mut role_keys = BTreeSet::new();
    let mut roles = Vec::with_capacity(profile.roles.len());
    for item in &profile.roles {
        let role_key = normalize_role_key(&item.key)?;
        if !role_keys.insert(role_key.clone()) {
            return Err(AppError::BadRequest(format!(
                "authorization manifest repeats role: {role_key}"
            )));
        }
        if item.permissions.len() > MAX_ROLE_PERMISSIONS {
            return Err(AppError::BadRequest(format!(
                "authorization role has too many permissions: {role_key}"
            )));
        }
        let mut role_permissions = BTreeSet::new();
        for permission in &item.permissions {
            let permission = normalize_permission_key(permission)?;
            if !permission_keys.contains(&permission) {
                return Err(AppError::BadRequest(format!(
                    "authorization role references an undefined permission: {permission}"
                )));
            }
            role_permissions.insert(permission);
        }
        let name = item
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&role_key)
            .to_string();
        validate_label(&name, "role name")?;
        roles.push(NewApplicationProfileRole {
            id: None,
            profile_id: profile_id.to_string(),
            role_key,
            name,
            description: normalize_optional_description(item.description.as_deref()),
            permissions: role_permissions.into_iter().collect(),
            source: SOURCE_MANIFEST.to_string(),
            is_default: false,
            is_active: true,
        });
    }
    Ok((permissions, roles))
}

fn normalize_permission_key(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_PERMISSION_KEY_LENGTH
        || value.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        || value.split(':').any(str::is_empty)
    {
        return Err(AppError::BadRequest(
            "authorization permission key is invalid".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn normalize_role_key(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_ROLE_KEY_LENGTH
        || value.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(AppError::BadRequest(
            "authorization role key is invalid".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn validate_label(value: &str, field: &str) -> AppResult<()> {
    if value.is_empty() || value.len() > MAX_LABEL_LENGTH || value.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!("{field} is invalid")));
    }
    Ok(())
}

fn normalize_optional_description(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(1024).collect())
}

fn validate_fetch_url(value: &str) -> AppResult<String> {
    let parsed = Url::parse(value.trim())
        .map_err(|_| AppError::BadRequest("manifest URL is invalid".to_string()))?;
    if !matches!(parsed.scheme(), "https" | "http")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AppError::BadRequest(
            "manifest URL must be an absolute http(s) URL without credentials or fragment"
                .to_string(),
        ));
    }
    let host = parsed.host_str().unwrap_or_default();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("127.0.0.1")
        || host == "::1";
    if parsed.scheme() == "http" && !loopback {
        return Err(AppError::BadRequest(
            "manifest URL must use HTTPS outside localhost".to_string(),
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>()
        && (ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(value) if value.is_private() || value.is_link_local()))
    {
        return Err(AppError::BadRequest(
            "manifest URL cannot target a private network address".to_string(),
        ));
    }
    Ok(parsed.to_string())
}

pub fn profile_status(
    profile: &crate::db::ApplicationAuthorizationProfileRecord,
    definitions: &[ApplicationPermissionDefinitionRecord],
    roles: &[ApplicationProfileRoleRecord],
) -> ManifestProfileStatus {
    ManifestProfileStatus {
        profile_key: profile.profile_key.clone(),
        source_mode: profile.source_mode.clone(),
        manifest_url: profile.manifest_url.clone(),
        signer_client_id: profile.signer_client_id.clone(),
        remote_version: profile.remote_version.clone(),
        remote_digest: profile.remote_digest.clone(),
        sync_status: profile.sync_status.clone(),
        last_synced_at: profile.last_synced_at,
        last_error: profile.last_error.clone(),
        permission_count: definitions.iter().filter(|item| item.is_active == 1).count(),
        role_count: roles.iter().filter(|item| item.is_active == 1).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_keys_keep_colon_segments_without_prefix_semantics() {
        assert_eq!(normalize_permission_key("admin:billing:invoice:approve").unwrap(), "admin:billing:invoice:approve");
        assert!(normalize_permission_key("admin:billing:").is_err());
        assert!(normalize_permission_key("admin billing").is_err());
    }

    #[test]
    fn profile_roles_must_reference_exactly_declared_permissions() {
        let profile = ManifestProfile {
            permissions: vec![ManifestPermission {
                key: "admin:billing:invoice".to_string(),
                label: Some("Invoice".to_string()),
                description: None,
            }],
            roles: vec![ManifestRole {
                key: "billing-admin".to_string(),
                name: None,
                description: None,
                permissions: vec!["admin:billing:invoice".to_string()],
            }],
        };
        let (_, roles) = normalize_profile(&profile, "profile-1").unwrap();
        assert_eq!(roles[0].permissions, vec!["admin:billing:invoice"]);

        let mut invalid = profile;
        invalid.roles[0].permissions.push("admin:billing".to_string());
        assert!(normalize_profile(&invalid, "profile-1").is_err());
    }

    #[test]
    fn manifest_fetch_rejects_insecure_public_urls_and_private_addresses() {
        assert!(validate_fetch_url("http://example.com/.well-known/signet-authorization.json").is_err());
        assert!(validate_fetch_url("https://127.0.0.1/.well-known/signet-authorization.json").is_err());
        assert!(validate_fetch_url("https://example.com/.well-known/signet-authorization.json").is_ok());
    }
}
