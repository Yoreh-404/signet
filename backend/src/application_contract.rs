use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use thiserror::Error;
use url::Url;

pub const FORMAT: &str = "signet-application/v3";
pub const MAX_CONTRACT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_CLIENTS: usize = 512;
pub const MAX_CONNECTIONS: usize = 128;
pub const MAX_POLICIES: usize = 512;
pub const MAX_ROLES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationContract {
    pub format: String,
    pub application_id: String,
    pub revision: i64,
    pub version: String,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: Value,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    pub modules: ContractModules,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ContractModules {
    #[serde(default)]
    pub clients: Vec<ClientContract>,
    #[serde(default)]
    pub connections: Vec<ConnectionContract>,
    #[serde(default)]
    pub policies: Vec<PolicyContract>,
    #[serde(default)]
    pub roles: Vec<RoleContract>,
    #[serde(default)]
    pub lifecycle: LifecycleContract,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientContract {
    pub client_id: String,
    pub protocol: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub profiles: Vec<IntegrationProfile>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default = "default_auth_method")]
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub credential_ref: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<Value>,
    #[serde(default)]
    pub require_pkce: bool,
    #[serde(default)]
    pub require_s256_pkce: bool,
    #[serde(default)]
    pub require_mfa: bool,
    #[serde(default)]
    pub require_dpop: bool,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub metadata: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionContract {
    pub connection_id: String,
    pub kind: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub settings: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyContract {
    pub policy_id: String,
    #[serde(default)]
    pub client_ids: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub require_mfa: bool,
    #[serde(default)]
    pub require_dpop: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleContract {
    pub role_id: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub default_role: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleContract {
    #[serde(default = "default_lifecycle_mode")]
    pub mode: String,
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    #[serde(default)]
    pub revoke_removed_clients: bool,
    #[serde(default)]
    pub allow_downgrade: bool,
}

impl Default for LifecycleContract {
    fn default() -> Self {
        Self {
            mode: default_lifecycle_mode(),
            fail_closed: true,
            revoke_removed_clients: true,
            allow_downgrade: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationProfile {
    LegacyProxy,
    WebOidc,
    SpaOidc,
    ApiResource,
    MachineIdentity,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractValidationError {
    #[error("{0}")]
    Invalid(String),
}

impl ApplicationContract {
    pub fn validate(&self, now: i64) -> Result<(), ContractValidationError> {
        if self.format != FORMAT {
            return invalid(format!("unsupported contract format: {}", self.format));
        }
        validate_identifier("application_id", &self.application_id)?;
        if self.revision <= 0 {
            return invalid("revision must be positive");
        }
        if self.version.trim().is_empty() {
            return invalid("version must not be empty");
        }
        if self.issuer.trim().is_empty() {
            return invalid("issuer must not be empty");
        }
        let issuer = Url::parse(self.issuer.trim())
            .map_err(|_| ContractValidationError::Invalid("issuer is invalid".to_string()))?;
        if !matches!(issuer.scheme(), "https" | "http")
            || issuer.host_str().is_none()
            || issuer.username() != ""
            || issuer.password().is_some()
            || (issuer.path() != "" && issuer.path() != "/")
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            return invalid("issuer must be an absolute HTTP(S) origin");
        }
        if self.issued_at <= 0 || self.expires_at <= self.issued_at {
            return invalid("issued_at and expires_at are invalid");
        }
        if self.expires_at - self.issued_at > MAX_CONTRACT_TTL_SECONDS {
            return invalid("contract lifetime exceeds the maximum allowed TTL");
        }
        if now > 0 && self.expires_at <= now {
            return invalid("contract has expired");
        }
        validate_public_entries(self.extensions.iter(), "extensions")?;
        validate_modules(&self.modules)
    }
}

fn validate_modules(modules: &ContractModules) -> Result<(), ContractValidationError> {
    if modules.clients.len() > MAX_CLIENTS {
        return invalid("too many clients");
    }
    if modules.connections.len() > MAX_CONNECTIONS {
        return invalid("too many connections");
    }
    if modules.policies.len() > MAX_POLICIES {
        return invalid("too many policies");
    }
    if modules.roles.len() > MAX_ROLES {
        return invalid("too many roles");
    }
    if modules.lifecycle.mode != "replace" {
        return invalid("lifecycle.mode must be replace until merge reconciliation is supported");
    }
    if !modules.lifecycle.fail_closed {
        return invalid("lifecycle.fail_closed must be true");
    }
    if modules.lifecycle.allow_downgrade {
        return invalid("lifecycle.allow_downgrade is not supported");
    }

    let mut client_ids = BTreeSet::new();
    for client in &modules.clients {
        validate_identifier("client_id", &client.client_id)?;
        if client.client_id == "default" {
            return invalid("client_id default is reserved for the application profile");
        }
        if !client_ids.insert(&client.client_id) {
            return invalid(format!("duplicate client_id: {}", client.client_id));
        }
        if client.profiles.is_empty() {
            return invalid(format!(
                "client {} must declare an integration profile",
                client.client_id
            ));
        }
        let mut profiles = BTreeSet::new();
        for profile in &client.profiles {
            if !profiles.insert(profile) {
                return invalid(format!(
                    "client {} declares a duplicate integration profile",
                    client.client_id
                ));
            }
        }
        let protocol = client.protocol.trim().to_ascii_lowercase();
        if !matches!(
            protocol.as_str(),
            "oidc" | "saml" | "cas" | "jwt" | "iap" | "forward_auth"
        ) {
            return invalid(format!(
                "client {} uses an unsupported protocol",
                client.client_id
            ));
        }
        if client.profiles.contains(&IntegrationProfile::LegacyProxy) && protocol != "forward_auth"
        {
            return invalid(format!(
                "legacy_proxy client {} must use forward_auth",
                client.client_id
            ));
        }
        if (client.profiles.contains(&IntegrationProfile::WebOidc)
            || client.profiles.contains(&IntegrationProfile::SpaOidc))
            && protocol != "oidc"
        {
            return invalid(format!("OIDC client {} must use oidc", client.client_id));
        }
        if client.credential_ref.is_some() {
            return invalid(format!(
                "client {} uses reserved credential_ref before a credential resolver is enabled",
                client.client_id
            ));
        }
        let auth_method = client.token_endpoint_auth_method.trim();
        if !matches!(auth_method, "none" | "private_key_jwt") {
            return invalid(format!(
                "client {} uses an unsupported token endpoint authentication method",
                client.client_id
            ));
        }
        let has_jwks_uri = client
            .jwks_uri
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if has_jwks_uri {
            validate_jwks_uri(client.jwks_uri.as_deref().unwrap_or(""))?;
        }
        let has_jwks = client.jwks.as_ref().is_some_and(|value| !value.is_null());
        if auth_method == "private_key_jwt" && !has_jwks_uri && !has_jwks {
            return invalid(format!(
                "private_key_jwt client {} must declare jwks_uri or jwks",
                client.client_id
            ));
        }
        if client.profiles.contains(&IntegrationProfile::WebOidc)
            || client.profiles.contains(&IntegrationProfile::SpaOidc)
        {
            if !client
                .grant_types
                .iter()
                .any(|value| value == "authorization_code")
                || !client.response_types.iter().any(|value| value == "code")
            {
                return invalid(format!(
                    "OIDC client {} must declare authorization_code and code",
                    client.client_id
                ));
            }
            if client.redirect_uris.is_empty() {
                return invalid(format!(
                    "OIDC client {} must declare redirect_uris",
                    client.client_id
                ));
            }
            for redirect_uri in &client.redirect_uris {
                validate_redirect_uri(redirect_uri)?;
            }
        }
        for redirect_uri in &client.post_logout_redirect_uris {
            validate_redirect_uri(redirect_uri)?;
        }
        if client.profiles.contains(&IntegrationProfile::ApiResource) && client.audiences.is_empty()
        {
            return invalid(format!(
                "API client {} must declare audiences",
                client.client_id
            ));
        }
        if client
            .profiles
            .contains(&IntegrationProfile::MachineIdentity)
            && client.token_endpoint_auth_method == "none"
        {
            return invalid(format!(
                "machine client {} cannot use token_endpoint_auth_method none",
                client.client_id
            ));
        }
        if client
            .profiles
            .contains(&IntegrationProfile::MachineIdentity)
            && !client
                .grant_types
                .iter()
                .any(|value| value == "client_credentials")
        {
            return invalid(format!(
                "machine client {} must declare client_credentials",
                client.client_id
            ));
        }
        if client.profiles.contains(&IntegrationProfile::SpaOidc)
            && (!client.require_pkce || !client.require_s256_pkce)
        {
            return invalid(format!(
                "SPA client {} must require S256 PKCE",
                client.client_id
            ));
        }
        if client.require_s256_pkce && !client.require_pkce {
            return invalid(format!(
                "client {} requires S256 PKCE without requiring PKCE",
                client.client_id
            ));
        }
        if client.require_dpop && !client.profiles.contains(&IntegrationProfile::ApiResource) {
            return invalid(format!(
                "client {} requires DPoP but is not an API resource",
                client.client_id
            ));
        }
        validate_public_entries(
            client.metadata.iter(),
            &format!("client {} metadata", client.client_id),
        )?;
    }

    validate_unique_ids(
        modules
            .connections
            .iter()
            .map(|item| item.connection_id.as_str()),
        "connection_id",
    )?;
    for connection in &modules.connections {
        validate_identifier("connection_id", &connection.connection_id)?;
        validate_identifier("connection kind", &connection.kind)?;
        validate_public_entries(
            connection.settings.iter(),
            &format!("connection {} settings", connection.connection_id),
        )?;
    }
    validate_unique_ids(
        modules.policies.iter().map(|item| item.policy_id.as_str()),
        "policy_id",
    )?;
    for policy in &modules.policies {
        validate_identifier("policy_id", &policy.policy_id)?;
        if policy.permissions.len() > 512 {
            return invalid(format!(
                "policy {} declares too many permissions",
                policy.policy_id
            ));
        }
        for client_id in &policy.client_ids {
            if !modules
                .clients
                .iter()
                .any(|client| client.client_id == *client_id)
            {
                return invalid(format!(
                    "policy {} references an undeclared client",
                    policy.policy_id
                ));
            }
        }
        if policy.scopes.is_empty() && policy.permissions.is_empty() {
            return invalid(format!(
                "policy {} must declare scopes or permissions",
                policy.policy_id
            ));
        }
        if policy.client_ids.is_empty()
            && (policy.require_mfa
                || policy.require_dpop
                || !policy.scopes.is_empty()
                || !policy.audiences.is_empty())
        {
            return invalid(format!(
                "policy {} client-scoped fields must name client_ids",
                policy.policy_id
            ));
        }
    }
    validate_unique_ids(
        modules.roles.iter().map(|item| item.role_id.as_str()),
        "role_id",
    )?;
    for role in &modules.roles {
        validate_identifier("role_id", &role.role_id)?;
        if role.permissions.is_empty() || role.permissions.len() > 512 {
            return invalid(format!("role {} must declare permissions", role.role_id));
        }
    }
    Ok(())
}

fn validate_unique_ids<'a>(
    values: impl Iterator<Item = &'a str>,
    field: &str,
) -> Result<(), ContractValidationError> {
    let mut ids = BTreeSet::new();
    for value in values {
        if !ids.insert(value) {
            return invalid(format!("duplicate {field}: {value}"));
        }
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), ContractValidationError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 255
        || trimmed.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':'))
        })
    {
        return invalid(format!("{field} is invalid"));
    }
    Ok(())
}

fn validate_public_value(value: &Value, path: &str) -> Result<(), ContractValidationError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = key.to_ascii_lowercase();
                let looks_secret = [
                    "secret",
                    "password",
                    "token",
                    "api_key",
                    "private_key",
                    "client_secret",
                ]
                .iter()
                .any(|needle| normalized == *needle || normalized.ends_with(&format!("_{needle}")));
                if looks_secret && !normalized.ends_with("_ref") {
                    return invalid(format!("{path}.{key} must be a reference, not a secret"));
                }
                validate_public_value(child, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_public_value(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_public_entries<'a>(
    entries: impl Iterator<Item = (&'a String, &'a Value)>,
    path: &str,
) -> Result<(), ContractValidationError> {
    for (key, value) in entries {
        let normalized = key.to_ascii_lowercase();
        let looks_secret = [
            "secret",
            "password",
            "token",
            "api_key",
            "private_key",
            "client_secret",
        ]
        .iter()
        .any(|needle| normalized == *needle || normalized.ends_with(&format!("_{needle}")));
        if looks_secret && !normalized.ends_with("_ref") {
            return invalid(format!("{path}.{key} must be a reference, not a secret"));
        }
        validate_public_value(value, &format!("{path}.{key}"))?;
    }
    Ok(())
}

fn validate_redirect_uri(value: &str) -> Result<(), ContractValidationError> {
    let parsed = Url::parse(value.trim())
        .map_err(|_| ContractValidationError::Invalid("redirect URI is invalid".to_string()))?;
    if parsed.fragment().is_some()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.host_str().is_none()
        || !matches!(parsed.scheme(), "https" | "http")
        || value.contains('*')
    {
        return invalid(format!("redirect URI is invalid: {value}"));
    }
    if parsed.scheme() == "http" && !is_local_development_host(parsed.host_str()) {
        return invalid(format!("non-local redirect URI must use HTTPS: {value}"));
    }
    Ok(())
}

fn validate_jwks_uri(value: &str) -> Result<(), ContractValidationError> {
    let parsed = Url::parse(value.trim())
        .map_err(|_| ContractValidationError::Invalid("jwks_uri is invalid".to_string()))?;
    let host = parsed.host_str();
    if parsed.username() != ""
        || parsed.password().is_some()
        || host.is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (parsed.scheme() != "https"
            && !(parsed.scheme() == "http" && is_local_development_host(host)))
    {
        return invalid("jwks_uri must be an HTTPS URL, or local HTTP for development");
    }
    Ok(())
}

fn is_local_development_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "[::1]" | "::1"))
}

fn invalid<T>(message: T) -> Result<(), ContractValidationError>
where
    T: Into<String>,
{
    Err(ContractValidationError::Invalid(message.into()))
}

fn default_auth_method() -> String {
    "none".to_string()
}

fn default_lifecycle_mode() -> String {
    "replace".to_string()
}

fn default_true() -> bool {
    true
}

impl fmt::Display for IntegrationProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LegacyProxy => "legacy_proxy",
            Self::WebOidc => "web_oidc",
            Self::SpaOidc => "spa_oidc",
            Self::ApiResource => "api_resource",
            Self::MachineIdentity => "machine_identity",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> ApplicationContract {
        ApplicationContract {
            format: FORMAT.to_string(),
            application_id: "legacy-site".to_string(),
            revision: 1,
            version: "2026-08-22".to_string(),
            issuer: "https://sso.example.com".to_string(),
            audience: Value::String("legacy-site".to_string()),
            issued_at: 1_000,
            expires_at: 1_300,
            modules: ContractModules {
                clients: vec![ClientContract {
                    client_id: "legacy-site-web".to_string(),
                    protocol: "oidc".to_string(),
                    display_name: "Legacy site".to_string(),
                    profiles: vec![IntegrationProfile::WebOidc],
                    redirect_uris: vec!["https://legacy.example.com/auth/callback".to_string()],
                    post_logout_redirect_uris: vec![],
                    scopes: vec!["openid".to_string(), "profile".to_string()],
                    audiences: vec![],
                    grant_types: vec!["authorization_code".to_string()],
                    response_types: vec!["code".to_string()],
                    token_endpoint_auth_method: "none".to_string(),
                    credential_ref: None,
                    jwks_uri: None,
                    jwks: None,
                    require_pkce: true,
                    require_s256_pkce: true,
                    require_mfa: false,
                    require_dpop: false,
                    active: true,
                    metadata: Map::new(),
                }],
                ..ContractModules::default()
            },
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn accepts_legacy_and_modern_profiles_in_one_contract() {
        assert!(contract().validate(1_100).is_ok());
    }

    #[test]
    fn serializes_envelope_claims_with_oidc_names() {
        let value = serde_json::to_value(contract()).unwrap();
        assert_eq!(
            value.get("iss").and_then(Value::as_str),
            Some("https://sso.example.com")
        );
        assert_eq!(value.get("iat").and_then(Value::as_i64), Some(1_000));
        assert!(value.get("issuer").is_none());
    }

    #[test]
    fn rejects_plaintext_secret_fields_by_schema_shape() {
        let value = serde_json::json!({
            "format": FORMAT,
            "application_id": "app",
            "revision": 1,
            "version": "1",
            "iss": "https://sso.example.com",
            "aud": "app",
            "iat": 1000,
            "exp": 1100,
            "modules": {"clients": [{"client_id": "app", "profiles": ["web_oidc"], "client_secret": "secret"}]}
        });
        assert!(serde_json::from_value::<ApplicationContract>(value).is_err());
    }

    #[test]
    fn rejects_plaintext_secrets_inside_connection_settings() {
        let mut value = contract();
        value.modules.connections.push(ConnectionContract {
            connection_id: "legacy-proxy".to_string(),
            kind: "forward_auth".to_string(),
            required: true,
            settings: Map::from_iter([(
                "password".to_string(),
                Value::String("do-not-publish".to_string()),
            )]),
        });
        assert!(value.validate(1_100).is_err());

        value.modules.connections[0].settings = Map::from_iter([(
            "password_ref".to_string(),
            Value::String("secret://legacy-proxy/password".to_string()),
        )]);
        assert!(value.validate(1_100).is_ok());
    }

    #[test]
    fn rejects_insecure_public_redirect_uri() {
        let mut value = contract();
        value.modules.clients[0].redirect_uris =
            vec!["http://legacy.example.com/callback".to_string()];
        assert!(value.validate(1_100).is_err());
    }

    #[test]
    fn rejects_insecure_jwks_uri_and_non_origin_issuer() {
        let mut value = contract();
        value.issuer = "https://sso.example.com/path".to_string();
        assert!(value.validate(1_100).is_err());

        let mut value = contract();
        value.modules.clients[0].token_endpoint_auth_method = "private_key_jwt".to_string();
        value.modules.clients[0].jwks_uri = Some("http://keys.example.com/jwks".to_string());
        assert!(value.validate(1_100).is_err());

        value.modules.clients[0].jwks_uri = Some("http://localhost:8080/jwks".to_string());
        assert!(value.validate(1_100).is_ok());
    }

    #[test]
    fn permits_local_http_for_development() {
        let mut value = contract();
        value.modules.clients[0].redirect_uris = vec!["http://localhost:3000/callback".to_string()];
        assert!(value.validate(1_100).is_ok());
    }

    #[test]
    fn rejects_machine_identity_without_client_authentication() {
        let mut value = contract();
        value.modules.clients[0].profiles = vec![IntegrationProfile::MachineIdentity];
        value.modules.clients[0].grant_types = vec!["client_credentials".to_string()];
        assert!(value.validate(1_100).is_err());
    }

    #[test]
    fn rejects_duplicate_profiles() {
        let mut value = contract();
        value.modules.clients[0].profiles =
            vec![IntegrationProfile::WebOidc, IntegrationProfile::WebOidc];
        assert!(value.validate(1_100).is_err());
    }

    #[test]
    fn rejects_expired_and_long_lived_contracts() {
        let mut value = contract();
        assert!(value.validate(1_301).is_err());
        value.expires_at = value.issued_at + MAX_CONTRACT_TTL_SECONDS + 1;
        assert!(value.validate(1_100).is_err());
    }

    #[test]
    fn rejects_lifecycle_modes_not_supported_by_reconciliation() {
        let mut value = contract();
        value.modules.lifecycle.mode = "merge".to_string();
        assert!(value.validate(1_100).is_err());

        let mut value = contract();
        value.modules.lifecycle.allow_downgrade = true;
        assert!(value.validate(1_100).is_err());
    }

    #[test]
    fn rejects_spa_without_s256_pkce() {
        let mut value = contract();
        value.modules.clients[0].profiles = vec![IntegrationProfile::SpaOidc];
        value.modules.clients[0].require_s256_pkce = false;
        assert!(value.validate(1_100).is_err());
    }

    #[test]
    fn rejects_unbound_policy_step_up_requirements() {
        let mut value = contract();
        value.modules.policies.push(PolicyContract {
            policy_id: "mfa".to_string(),
            client_ids: Vec::new(),
            scopes: vec!["openid".to_string()],
            audiences: Vec::new(),
            permissions: Vec::new(),
            require_mfa: true,
            require_dpop: false,
        });
        assert!(value.validate(1_100).is_err());
    }
}
