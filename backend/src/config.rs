use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{env, fs, net::SocketAddr, str::FromStr};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Settings {
    pub server: ServerSettings,
    pub database: DatabaseSettings,
    pub oidc: OidcSettings,
    pub security: SecuritySettings,
    pub registration: RegistrationSettings,
    pub verification: VerificationSettings,
    pub i18n: I18nSettings,
    #[serde(default)]
    pub external_oidc_providers: Vec<ExternalOidcProviderSettings>,
    pub cors: CorsSettings,
    pub bootstrap: BootstrapSettings,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
    pub public_base_url: String,
    #[serde(default)]
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseSettings {
    pub kind: DatabaseKind,
    pub url: String,
    pub pool_size: u32,
    pub run_migrations: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseKind {
    Sqlite,
    Postgres,
    Mysql,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcSettings {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    pub access_token_ttl_seconds: i64,
    pub id_token_ttl_seconds: i64,
    pub authorization_code_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub supported_scopes: Vec<String>,
    pub skip_consent: bool,
    pub allow_dynamic_client_registration: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecuritySettings {
    pub cookie_name: String,
    pub cookie_domain: String,
    pub cookie_secure: bool,
    pub cookie_same_site: SameSiteSetting,
    #[serde(default)]
    pub disable_csrf_origin_check: bool,
    pub session_ttl_seconds: i64,
    pub password_min_length: usize,
    pub rsa_private_key_pem: String,
    pub key_id: String,
    /// Optional SAML IdP signing key. When empty, the active JWT signing key
    /// is reused; the certificate must still match the selected private key.
    #[serde(default)]
    pub saml_private_key_pem: String,
    /// X.509 certificate corresponding to `saml_private_key_pem` (or the
    /// active JWT signing key when that field is empty).
    #[serde(default)]
    pub saml_signing_certificate_pem: String,
    pub admin_api_prefix: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum SameSiteSetting {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorsSettings {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub allow_credentials: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistrationSettings {
    pub allow_password_registration: bool,
    pub require_email_verification: bool,
    pub require_phone_verification: bool,
    pub allow_external_oidc_registration: bool,
    pub require_invitation: bool,
    pub first_user_direct_admin: bool,
    pub default_user_active: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationSettings {
    pub email: VerificationChannelSettings,
    pub phone: VerificationChannelSettings,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationChannelSettings {
    pub enabled: bool,
    pub delivery: VerificationDelivery,
    pub code_ttl_seconds: i64,
    pub resend_interval_seconds: i64,
    pub max_attempts: i32,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub webhook_timeout_seconds: Option<u64>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from: Option<String>,
    pub smtp_starttls: Option<bool>,
    pub sms_provider: Option<String>,
    pub sms_api_key: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDelivery {
    DevLog,
    Smtp,
    SmsProvider,
    Webhook,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct I18nSettings {
    pub default_locale: String,
    pub supported_locales: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalOidcProviderSettings {
    pub slug: String,
    pub display_name: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub redirect_path: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub email_domains: Vec<String>,
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub allow_login: bool,
    pub allow_registration: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BootstrapSettings {
    pub admin: BootstrapAdmin,
    #[serde(default)]
    pub clients: Vec<BootstrapClient>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BootstrapAdmin {
    pub create_on_startup: bool,
    pub email: String,
    pub username: String,
    pub display_name: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BootstrapClient {
    pub client_id: String,
    pub client_name: String,
    #[serde(default)]
    pub logo_uri: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
}

impl Settings {
    pub fn load() -> Result<Self> {
        let path = env::var("SSO_CONFIG").unwrap_or_else(|_| "config/default.toml".to_string());
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read configuration file: {path}"))?;
        let mut settings: Settings = toml::from_str(&raw)
            .with_context(|| format!("failed to parse configuration file: {path}"))?;
        settings.apply_env_overrides();
        settings.validate()?;
        Ok(settings)
    }

    pub fn socket_addr(&self) -> Result<SocketAddr> {
        SocketAddr::from_str(&format!("{}:{}", self.server.host, self.server.port))
            .context("invalid server host/port")
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(value) = env::var("SSO_PUBLIC_BASE_URL") {
            self.server.public_base_url = value;
            if env::var("SSO_ISSUER").is_err() {
                self.oidc.issuer = self.server.public_base_url.clone();
            }
        }
        if let Ok(value) = env::var("SSO_ISSUER") {
            self.oidc.issuer = value;
        }
        if let Ok(value) = env::var("SSO_TRUST_PROXY_HEADERS") {
            self.server.trust_proxy_headers = matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Ok(value) = env::var("SSO_DISABLE_CSRF_ORIGIN_CHECK") {
            self.security.disable_csrf_origin_check = matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Ok(value) = env::var("SSO_DATABASE_KIND") {
            self.database.kind = match value.to_ascii_lowercase().as_str() {
                "postgres" | "postgresql" => DatabaseKind::Postgres,
                "mysql" | "mariadb" => DatabaseKind::Mysql,
                _ => DatabaseKind::Sqlite,
            };
        }
        if let Ok(value) = env::var("SSO_DATABASE_URL") {
            self.database.url = value;
        }
        if let Ok(value) = env::var("SSO_RSA_PRIVATE_KEY_PEM") {
            self.security.rsa_private_key_pem = value;
        }
        if let Ok(value) = env::var("SSO_SAML_PRIVATE_KEY_PEM") {
            self.security.saml_private_key_pem = value;
        }
        if let Ok(value) = env::var("SSO_SAML_SIGNING_CERTIFICATE_PEM") {
            self.security.saml_signing_certificate_pem = value;
        }
        if let Ok(value) = env::var("SSO_BOOTSTRAP_ADMIN_PASSWORD") {
            self.bootstrap.admin.password = value;
        }
    }

    fn validate(&self) -> Result<()> {
        if self.oidc.issuer.trim().is_empty() {
            anyhow::bail!("oidc.issuer cannot be empty");
        }
        if !self
            .oidc
            .supported_scopes
            .iter()
            .any(|scope| scope == "openid")
        {
            anyhow::bail!("oidc.supported_scopes must include openid");
        }
        if self.security.password_min_length < 8 {
            anyhow::bail!("security.password_min_length must be at least 8");
        }
        if self.security.cookie_same_site == SameSiteSetting::None && !self.security.cookie_secure {
            anyhow::bail!("security.cookie_secure must be true when cookie_same_site is None");
        }
        if self.cors.allow_credentials
            && self
                .cors
                .allowed_origins
                .iter()
                .any(|origin| origin.trim() == "*")
        {
            anyhow::bail!("credentialed CORS cannot use a wildcard allowed origin");
        }
        if self.bootstrap.admin.create_on_startup
            && self.bootstrap.admin.password.len() < self.security.password_min_length
        {
            anyhow::bail!(
                "bootstrap.admin.password must be at least {} characters",
                self.security.password_min_length
            );
        }
        if !self
            .i18n
            .supported_locales
            .iter()
            .any(|locale| locale == &self.i18n.default_locale)
        {
            anyhow::bail!("i18n.supported_locales must include i18n.default_locale");
        }
        if self.verification.email.code_ttl_seconds <= 0
            || self.verification.phone.code_ttl_seconds <= 0
        {
            anyhow::bail!("verification code TTL must be positive");
        }
        if self.verification.email.resend_interval_seconds <= 0
            || self.verification.phone.resend_interval_seconds <= 0
        {
            anyhow::bail!("verification resend interval must be positive");
        }
        if self.verification.email.max_attempts <= 0 || self.verification.phone.max_attempts <= 0 {
            anyhow::bail!("verification max_attempts must be positive");
        }
        validate_verification_channel("email", &self.verification.email)?;
        validate_verification_channel("phone", &self.verification.phone)?;
        for client in &self.bootstrap.clients {
            validate_bootstrap_client_logo_uri(&client.client_id, &client.logo_uri)?;
            if !matches!(
                client.token_endpoint_auth_method.as_str(),
                "client_secret_basic"
                    | "client_secret_post"
                    | "client_secret_jwt"
                    | "private_key_jwt"
                    | "none"
            ) {
                anyhow::bail!(
                    "bootstrap client {} has unsupported token_endpoint_auth_method",
                    client.client_id
                );
            }
            if matches!(
                client.token_endpoint_auth_method.as_str(),
                "client_secret_basic" | "client_secret_post" | "client_secret_jwt"
            ) && client.client_secret.is_empty()
            {
                anyhow::bail!(
                    "bootstrap client {} requires client_secret for secret-based authentication",
                    client.client_id
                );
            }
            if !client.scopes.iter().any(|scope| scope == "openid") {
                anyhow::bail!(
                    "bootstrap client {} must include openid scope",
                    client.client_id
                );
            }
            let uses_authorization_code = client
                .grant_types
                .iter()
                .any(|value| value == "authorization_code");
            if uses_authorization_code && !client.response_types.iter().any(|value| value == "code")
            {
                anyhow::bail!(
                    "bootstrap client {} must support code response type",
                    client.client_id
                );
            }
        }
        for provider in &self.external_oidc_providers {
            if provider.slug.trim().is_empty() {
                anyhow::bail!("external OIDC provider slug cannot be empty");
            }
            if provider.enabled
                && (provider.client_id.trim().is_empty()
                    || provider.authorization_endpoint.trim().is_empty()
                    || provider.token_endpoint.trim().is_empty()
                    || provider.userinfo_endpoint.trim().is_empty())
            {
                anyhow::bail!(
                    "enabled external OIDC provider {} is missing required endpoints/client_id",
                    provider.slug
                );
            }
        }
        Ok(())
    }
}

fn validate_verification_channel(name: &str, channel: &VerificationChannelSettings) -> Result<()> {
    if let Some(timeout) = channel.webhook_timeout_seconds
        && timeout == 0
    {
        anyhow::bail!("verification.{name}.webhook_timeout_seconds must be positive");
    }
    match channel.delivery {
        VerificationDelivery::Webhook => {
            let url = channel
                .webhook_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "verification.{name}.webhook_url is required for webhook delivery"
                    )
                })?;
            validate_http_delivery_url(&format!("verification.{name}.webhook_url"), url)?;
        }
        VerificationDelivery::SmsProvider => {
            let url = channel
                .sms_provider
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "verification.{name}.sms_provider is required for sms_provider delivery"
                    )
                })?;
            validate_http_delivery_url(&format!("verification.{name}.sms_provider"), url)?;
        }
        VerificationDelivery::Smtp => {
            if name != "email" {
                anyhow::bail!("verification.{name}.delivery=smtp is only valid for email");
            }
            required_nonempty(
                &channel.smtp_host,
                &format!("verification.{name}.smtp_host is required for smtp delivery"),
            )?;
            required_nonempty(
                &channel.smtp_from,
                &format!("verification.{name}.smtp_from is required for smtp delivery"),
            )?;
            let has_username = optional_nonempty(&channel.smtp_username).is_some();
            let has_password = optional_nonempty(&channel.smtp_password).is_some();
            if has_username != has_password {
                anyhow::bail!(
                    "verification.{name}.smtp_username and smtp_password must be configured together"
                );
            }
        }
        VerificationDelivery::DevLog => {}
    }
    Ok(())
}

fn required_nonempty<'a>(value: &'a Option<String>, message: &str) -> Result<&'a str> {
    optional_nonempty(value).ok_or_else(|| anyhow::anyhow!(message.to_string()))
}

fn optional_nonempty(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn validate_http_delivery_url(label: &str, value: &str) -> Result<()> {
    let parsed =
        url::Url::parse(value).with_context(|| format!("{label} must be an absolute URL"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => anyhow::bail!("{label} must use http or https"),
    }
    if parsed.fragment().is_some() {
        anyhow::bail!("{label} cannot contain a fragment");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("{label} cannot include user info");
    }
    Ok(())
}

fn validate_bootstrap_client_logo_uri(client_id: &str, value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 2048 {
        anyhow::bail!("bootstrap client {client_id} logo_uri exceeds 2048 characters");
    }
    let label = format!("bootstrap client {client_id} logo_uri");
    let parsed =
        url::Url::parse(value).with_context(|| format!("{label} must be an absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        anyhow::bail!("{label} must be an absolute http(s) URL");
    }
    if parsed.fragment().is_some() {
        anyhow::bail!("{label} cannot contain a fragment");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("{label} cannot include user info");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_settings() -> Settings {
        toml::from_str(include_str!("../../config/default.toml")).unwrap()
    }

    fn verification_channel(delivery: VerificationDelivery) -> VerificationChannelSettings {
        VerificationChannelSettings {
            enabled: true,
            delivery,
            code_ttl_seconds: 600,
            resend_interval_seconds: 60,
            max_attempts: 5,
            webhook_url: Some("https://notify.example/sso".to_string()),
            webhook_secret: None,
            webhook_timeout_seconds: Some(5),
            smtp_host: Some("smtp.example.com".to_string()),
            smtp_port: Some(587),
            smtp_username: None,
            smtp_password: None,
            smtp_from: Some("SSO <sso@example.com>".to_string()),
            smtp_starttls: Some(true),
            sms_provider: Some("https://sms.example/send".to_string()),
            sms_api_key: None,
        }
    }

    #[test]
    fn smtp_verification_requires_email_channel_and_sender() {
        let mut email = verification_channel(VerificationDelivery::Smtp);
        assert!(validate_verification_channel("email", &email).is_ok());

        assert!(validate_verification_channel("phone", &email).is_err());

        email.smtp_from = None;
        assert!(validate_verification_channel("email", &email).is_err());
    }

    #[test]
    fn smtp_verification_credentials_must_be_configured_together() {
        let mut email = verification_channel(VerificationDelivery::Smtp);
        email.smtp_username = Some("sso".to_string());
        assert!(validate_verification_channel("email", &email).is_err());

        email.smtp_password = Some("secret".to_string());
        assert!(validate_verification_channel("email", &email).is_ok());
    }

    #[test]
    fn same_site_none_requires_secure_session_cookies() {
        let mut settings = default_settings();
        settings.security.cookie_same_site = SameSiteSetting::None;
        settings.security.cookie_secure = false;
        assert!(settings.validate().is_err());

        settings.security.cookie_secure = true;
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn credentialed_cors_rejects_wildcard_origins() {
        let mut settings = default_settings();
        settings.cors.allow_credentials = true;
        settings.cors.allowed_origins = vec!["*".to_string()];
        assert!(settings.validate().is_err());

        settings.cors.allowed_origins = vec!["https://console.example".to_string()];
        assert!(settings.validate().is_ok());
    }
}
