use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, env, fs, net::SocketAddr, str::FromStr};
use url::Url;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Settings {
    pub server: ServerSettings,
    pub database: DatabaseSettings,
    pub oidc: OidcSettings,
    pub security: SecuritySettings,
    pub registration: RegistrationSettings,
    pub verification: VerificationSettings,
    #[serde(default)]
    pub discovery: DiscoverySettings,
    #[serde(default)]
    pub billing: BillingSettings,
    pub i18n: I18nSettings,
    #[serde(default)]
    pub external_oidc_providers: Vec<ExternalOidcProviderSettings>,
    pub cors: CorsSettings,
    pub bootstrap: BootstrapSettings,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoverySettings {
    #[serde(default = "default_discovery_sync_interval_seconds")]
    pub sync_interval_seconds: i64,
    /// Development-only escape hatch for a Compose edge whose DNS name
    /// resolves to a private container address. Production deployments must
    /// keep this false so a website-managed application cannot turn Signet
    /// into an SSRF primitive.
    #[serde(default)]
    pub allow_private_networks: bool,
    /// Base64url/base64 encoded 32-byte key used only to encrypt discovery
    /// fetch secrets before they are persisted. It is deliberately separate
    /// from Signet's JWT/SAML signing material.
    #[serde(default)]
    pub encryption_key: String,
    /// Shared secret used to authenticate one-request discovery challenges.
    /// It is never persisted and is required when challenge-based automatic
    /// registration is enabled.
    #[serde(default)]
    pub challenge_secret: String,
    /// Allow Signet to discover and provision applications whose exact origin
    /// is explicitly mapped to an organization and manifest application ID.
    /// The whitelist is intentionally deployment-owned; a website can never
    /// add itself to this list through the discovery document.
    #[serde(default)]
    pub auto_registration: AutoRegistrationSettings,
}

impl Default for DiscoverySettings {
    fn default() -> Self {
        Self {
            sync_interval_seconds: default_discovery_sync_interval_seconds(),
            allow_private_networks: false,
            encryption_key: String::new(),
            challenge_secret: String::new(),
            auto_registration: AutoRegistrationSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AutoRegistrationSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub startup_scan: bool,
    #[serde(default = "default_discovery_challenge_ttl_seconds")]
    pub challenge_ttl_seconds: i64,
    #[serde(default = "default_discovery_concurrency")]
    pub max_concurrency: usize,
    #[serde(default)]
    pub allowlist: Vec<AutoRegistrationAllowlistEntry>,
}

impl Default for AutoRegistrationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            startup_scan: true,
            challenge_ttl_seconds: default_discovery_challenge_ttl_seconds(),
            max_concurrency: default_discovery_concurrency(),
            allowlist: Vec::new(),
        }
    }
}

fn default_discovery_challenge_ttl_seconds() -> i64 {
    300
}

fn default_discovery_concurrency() -> usize {
    4
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AutoRegistrationAllowlistEntry {
    pub id: String,
    /// Exact canonical origin. Wildcard matching is deliberately not enabled
    /// in v1 because the scheduler cannot safely enumerate wildcard hosts.
    pub origin: String,
    pub organization_id: String,
    pub application_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub auto_activate: bool,
}

fn default_discovery_sync_interval_seconds() -> i64 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BillingSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_billing_currency")]
    pub default_currency: String,
    #[serde(default = "default_billing_currencies")]
    pub supported_currencies: Vec<CurrencySettings>,
    #[serde(default = "default_reservation_ttl_seconds")]
    pub reservation_ttl_seconds: i64,
    /// Delay between durable reconciliation sweeps. The first worker sweep
    /// is intentionally delayed by this interval after startup.
    #[serde(default = "default_billing_reconcile_interval_seconds")]
    pub reconcile_interval_seconds: i64,
    /// Maximum number of payment orders claimed by one sweep on one instance.
    #[serde(default = "default_billing_reconcile_batch_size")]
    pub reconcile_batch_size: usize,
    /// How long an instance owns a claimed order before another instance may
    /// fence and recover it. This must cover the normal provider timeout.
    #[serde(
        default = "default_billing_reconcile_lease_seconds",
        alias = "reconcile_lease_ttl_seconds"
    )]
    pub reconcile_lease_seconds: i64,
    /// Base delay for an unknown provider outcome before the next query.
    #[serde(default = "default_billing_reconcile_retry_base_seconds")]
    pub reconcile_retry_base_seconds: i64,
    /// Upper bound for exponential retry delay.
    #[serde(default = "default_billing_reconcile_retry_max_seconds")]
    pub reconcile_retry_max_seconds: i64,
    #[serde(default)]
    pub providers: Vec<PaymentProviderSettings>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CurrencySettings {
    pub code: String,
    pub minor_unit: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaymentProviderSettings {
    pub slug: String,
    pub kind: String,
    pub enabled: bool,
    #[serde(default)]
    pub gateway_url: String,
    #[serde(default)]
    pub app_id: String,
    #[serde(default = "default_epay_channel")]
    pub payment_channel: String,
    #[serde(default)]
    pub merchant_id: String,
    #[serde(default)]
    pub merchant_secret: String,
    #[serde(default)]
    pub merchant_secret_env: Option<String>,
    #[serde(default)]
    pub private_key_pem: String,
    #[serde(default)]
    pub private_key_env: Option<String>,
    #[serde(default)]
    pub alipay_public_key_pem: String,
    #[serde(default)]
    pub alipay_public_key_env: Option<String>,
    #[serde(default)]
    pub certificate_serial_no: String,
    #[serde(default)]
    pub api_v3_key: String,
    #[serde(default)]
    pub api_v3_key_env: Option<String>,
    #[serde(default)]
    pub platform_certificate_pem: String,
    #[serde(default)]
    pub platform_certificate_env: Option<String>,
    #[serde(default)]
    pub notify_url: Option<String>,
}

impl Default for BillingSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            default_currency: default_billing_currency(),
            supported_currencies: default_billing_currencies(),
            reservation_ttl_seconds: default_reservation_ttl_seconds(),
            reconcile_interval_seconds: default_billing_reconcile_interval_seconds(),
            reconcile_batch_size: default_billing_reconcile_batch_size(),
            reconcile_lease_seconds: default_billing_reconcile_lease_seconds(),
            reconcile_retry_base_seconds: default_billing_reconcile_retry_base_seconds(),
            reconcile_retry_max_seconds: default_billing_reconcile_retry_max_seconds(),
            providers: Vec::new(),
        }
    }
}

fn default_billing_currency() -> String {
    "CNY".to_string()
}

fn default_billing_currencies() -> Vec<CurrencySettings> {
    vec![CurrencySettings {
        code: "CNY".to_string(),
        minor_unit: 2,
    }]
}

fn default_reservation_ttl_seconds() -> i64 {
    900
}

fn default_billing_reconcile_interval_seconds() -> i64 {
    30
}

fn default_billing_reconcile_batch_size() -> usize {
    32
}

fn default_billing_reconcile_lease_seconds() -> i64 {
    120
}

fn default_billing_reconcile_retry_base_seconds() -> i64 {
    10
}

fn default_billing_reconcile_retry_max_seconds() -> i64 {
    900
}

fn default_epay_channel() -> String {
    "alipay".to_string()
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
pub struct DelegatedAllowlistEntry {
    /// The confidential OAuth client that is allowed to perform the
    /// delegation.  Omitting this field is a wildcard, but production
    /// configuration should always bind a rule to a concrete client.
    #[serde(default)]
    pub client_id: Option<String>,
    /// RFC 8707 resource or RFC 8693 audience accepted by the rule.
    #[serde(default, alias = "resource")]
    pub audience: Option<String>,
    /// Optional source client binding.  This is useful when a single
    /// delegating client accepts subject tokens issued to more than one RP.
    #[serde(default)]
    pub subject_client_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Accept the singular spelling as well as the more convenient TOML
    /// array form.
    #[serde(default)]
    pub scope: Option<String>,
}

impl DelegatedAllowlistEntry {
    pub fn normalized_scopes(&self) -> Vec<String> {
        let mut scopes = BTreeSet::new();
        scopes.extend(
            self.scopes
                .iter()
                .map(String::as_str)
                .filter(|scope| !scope.trim().is_empty())
                .map(|scope| scope.trim().to_string()),
        );
        if let Some(scope) = self.scope.as_deref().map(str::trim) {
            if !scope.is_empty() {
                scopes.insert(scope.to_string());
            }
        }
        scopes.into_iter().collect()
    }
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
    /// Explicit resource-owner delegation policy for RFC 8693 token
    /// exchange.  This is intentionally separate from a client's ordinary
    /// scope list: a user token can only be delegated where an operator has
    /// declared both the target audience and the delegated scope.
    #[serde(default, alias = "delegated_scope_allowlist")]
    pub delegated_allowlist: Vec<DelegatedAllowlistEntry>,
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
    /// Base64/base64url encoded 32-byte key used to encrypt recoverable
    /// authentication secrets such as TOTP seeds. It must be supplied by the
    /// deployment and is never stored in the database.
    #[serde(default)]
    pub totp_encryption_key: String,
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
    pub applications: Vec<BootstrapApplication>,
    #[serde(default)]
    pub clients: Vec<BootstrapClient>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BootstrapApplication {
    /// Public stable application identifier. This maps to applications.slug;
    /// the database UUID remains an internal foreign key.
    pub application_id: String,
    pub name: String,
    pub website_url: String,
    #[serde(default = "default_management_mode")]
    pub management_mode: String,
    #[serde(default = "default_true")]
    pub is_active: bool,
    /// Optional environment variable names used to enroll Discovery trust
    /// material without putting secrets in TOML. These fields are not
    /// authentication policy; they only establish the fetch/signing trust
    /// root for a website-managed application.
    #[serde(default)]
    pub fetch_secret_env: Option<String>,
    #[serde(default)]
    pub signing_public_jwks_env: Option<String>,
    #[serde(skip)]
    pub fetch_secret: String,
    #[serde(skip)]
    pub signing_public_jwks: String,
}

fn default_management_mode() -> String {
    "signet_managed".to_string()
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
    #[serde(default)]
    pub client_secret: String,
    #[serde(default, alias = "secret_env")]
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub require_pkce: bool,
    #[serde(default)]
    pub require_confidential_client: bool,
    #[serde(default, alias = "service_account")]
    pub service_account_enabled: bool,
    #[serde(default, alias = "permissions")]
    pub service_account_permissions: Vec<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default, alias = "rotate_client_secret", alias = "rotate")]
    pub rotate_secret: bool,
}

impl Settings {
    pub fn load() -> Result<Self> {
        let path = env::var("SSO_CONFIG").unwrap_or_else(|_| "config/default.toml".to_string());
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read configuration file: {path}"))?;
        let mut settings: Settings = toml::from_str(&raw)
            .with_context(|| format!("failed to parse configuration file: {path}"))?;
        settings.apply_env_overrides()?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn socket_addr(&self) -> Result<SocketAddr> {
        SocketAddr::from_str(&format!("{}:{}", self.server.host, self.server.port))
            .context("invalid server host/port")
    }

    fn apply_env_overrides(&mut self) -> Result<()> {
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
        if let Ok(value) = env::var("SSO_BILLING_RECONCILE_INTERVAL_SECONDS") {
            self.billing.reconcile_interval_seconds = value
                .parse()
                .with_context(|| "SSO_BILLING_RECONCILE_INTERVAL_SECONDS must be an integer")?;
        }
        if let Ok(value) = env::var("SSO_BILLING_RECONCILE_BATCH_SIZE") {
            self.billing.reconcile_batch_size = value
                .parse()
                .with_context(|| "SSO_BILLING_RECONCILE_BATCH_SIZE must be an integer")?;
        }
        if let Ok(value) = env::var("SSO_BILLING_RECONCILE_LEASE_SECONDS") {
            self.billing.reconcile_lease_seconds = value
                .parse()
                .with_context(|| "SSO_BILLING_RECONCILE_LEASE_SECONDS must be an integer")?;
        }
        if let Ok(value) = env::var("SSO_BILLING_RECONCILE_RETRY_BASE_SECONDS") {
            self.billing.reconcile_retry_base_seconds = value
                .parse()
                .with_context(|| "SSO_BILLING_RECONCILE_RETRY_BASE_SECONDS must be an integer")?;
        }
        if let Ok(value) = env::var("SSO_BILLING_RECONCILE_RETRY_MAX_SECONDS") {
            self.billing.reconcile_retry_max_seconds = value
                .parse()
                .with_context(|| "SSO_BILLING_RECONCILE_RETRY_MAX_SECONDS must be an integer")?;
        }
        if let Ok(value) = env::var("SSO_RSA_PRIVATE_KEY_PEM") {
            self.security.rsa_private_key_pem = value;
        }
        if let Ok(value) = env::var("SSO_TOTP_ENCRYPTION_KEY") {
            self.security.totp_encryption_key = value;
        }
        if let Ok(value) = env::var("SSO_SAML_PRIVATE_KEY_PEM") {
            self.security.saml_private_key_pem = value;
        }
        if let Ok(value) = env::var("SSO_SAML_SIGNING_CERTIFICATE_PEM") {
            self.security.saml_signing_certificate_pem = value;
        }
        if let Ok(value) = env::var("SSO_DISCOVERY_ENCRYPTION_KEY") {
            self.discovery.encryption_key = value;
        }
        if let Ok(value) = env::var("SSO_DISCOVERY_CHALLENGE_SECRET") {
            self.discovery.challenge_secret = value;
        }
        if let Ok(value) = env::var("SSO_DISCOVERY_ALLOW_PRIVATE_NETWORKS") {
            self.discovery.allow_private_networks = matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Ok(value) = env::var("SSO_AUTO_REGISTRATION_ALLOWLIST_JSON")
            && !value.trim().is_empty()
        {
            self.discovery.auto_registration.allowlist = serde_json::from_str(&value)
                .with_context(|| "SSO_AUTO_REGISTRATION_ALLOWLIST_JSON must be a JSON array")?;
        }
        if let Ok(value) = env::var("SSO_AUTO_REGISTRATION_ENABLED") {
            self.discovery.auto_registration.enabled = matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Ok(value) = env::var("SSO_AUTO_REGISTRATION_STARTUP_SCAN") {
            self.discovery.auto_registration.startup_scan = matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Ok(value) = env::var("SSO_AUTO_REGISTRATION_CHALLENGE_TTL_SECONDS") {
            self.discovery.auto_registration.challenge_ttl_seconds = value.parse().with_context(
                || "SSO_AUTO_REGISTRATION_CHALLENGE_TTL_SECONDS must be an integer",
            )?;
        }
        if let Ok(value) = env::var("SSO_AUTO_REGISTRATION_MAX_CONCURRENCY") {
            self.discovery.auto_registration.max_concurrency = value
                .parse()
                .with_context(|| "SSO_AUTO_REGISTRATION_MAX_CONCURRENCY must be an integer")?;
        }
        if let Ok(value) = env::var("SSO_BOOTSTRAP_ADMIN_PASSWORD") {
            self.bootstrap.admin.password = value;
        }
        for client in &mut self.bootstrap.clients {
            let Some(env_name) = client
                .client_secret_env
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
            else {
                continue;
            };
            resolve_bootstrap_client_secret(client, env::var(&env_name))?;
        }
        for application in &mut self.bootstrap.applications {
            if let Some(env_name) = application
                .fetch_secret_env
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                // Missing trust material leaves the application explicitly
                // unconfigured. Signet must still boot so an operator can
                // enroll the website later through deployment secrets or the
                // admin API; the runtime application gate remains fail-closed
                // until a verified snapshot exists.
                application.fetch_secret = env::var(env_name).unwrap_or_default();
            }
            if let Some(env_name) = application
                .signing_public_jwks_env
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                application.signing_public_jwks = env::var(env_name).unwrap_or_default();
            }
        }
        for provider in &mut self.billing.providers {
            if !provider.enabled {
                continue;
            }
            resolve_optional_secret(
                &mut provider.merchant_secret,
                provider.merchant_secret_env.as_deref(),
            )?;
            resolve_optional_secret(
                &mut provider.private_key_pem,
                provider.private_key_env.as_deref(),
            )?;
            resolve_optional_secret(
                &mut provider.alipay_public_key_pem,
                provider.alipay_public_key_env.as_deref(),
            )?;
            resolve_optional_secret(&mut provider.api_v3_key, provider.api_v3_key_env.as_deref())?;
            resolve_optional_secret(
                &mut provider.platform_certificate_pem,
                provider.platform_certificate_env.as_deref(),
            )?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        validate_public_origin(&self.server.public_base_url, "server.public_base_url")?;
        validate_public_origin(&self.oidc.issuer, "oidc.issuer")?;
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
        validate_billing_settings(&self.billing)?;
        if self.discovery.sync_interval_seconds < 30 {
            anyhow::bail!("discovery.sync_interval_seconds must be at least 30");
        }
        if self.discovery.auto_registration.challenge_ttl_seconds <= 0
            || self.discovery.auto_registration.challenge_ttl_seconds > 900
        {
            anyhow::bail!(
                "discovery.auto_registration.challenge_ttl_seconds must be between 1 and 900"
            );
        }
        if self.discovery.auto_registration.max_concurrency == 0
            || self.discovery.auto_registration.max_concurrency > 32
        {
            anyhow::bail!("discovery.auto_registration.max_concurrency must be between 1 and 32");
        }
        let mut allowlist_ids = BTreeSet::new();
        let mut allowlist_origins = BTreeSet::new();
        for entry in &self.discovery.auto_registration.allowlist {
            let id = entry.id.trim();
            if id.is_empty() || !allowlist_ids.insert(id.to_string()) {
                anyhow::bail!(
                    "discovery.auto_registration allowlist IDs must be unique and non-empty"
                );
            }
            let origin = entry.origin.trim();
            let parsed = url::Url::parse(origin).map_err(|_| {
                anyhow::anyhow!(
                    "discovery.auto_registration.allowlist {} has an invalid origin",
                    entry.id
                )
            })?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || !matches!(parsed.path(), "" | "/")
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || !allowlist_origins.insert(origin.trim_end_matches('/').to_ascii_lowercase())
            {
                anyhow::bail!(
                    "discovery.auto_registration.allowlist {} must contain a unique HTTPS origin",
                    entry.id
                );
            }
            if entry.organization_id.trim().is_empty() || entry.application_ids.is_empty() {
                anyhow::bail!(
                    "discovery.auto_registration.allowlist {} requires organization_id and application_ids",
                    entry.id
                );
            }
            let mut application_ids = BTreeSet::new();
            if entry.application_ids.iter().any(|application_id| {
                let application_id = application_id.trim();
                application_id.is_empty()
                    || crate::applications::normalize_application_slug(application_id)
                        .ok()
                        .as_deref()
                        != Some(application_id)
                    || !application_ids.insert(application_id.to_string())
            }) {
                anyhow::bail!(
                    "discovery.auto_registration.allowlist {} contains an invalid or duplicate application ID",
                    entry.id
                );
            }
        }
        if self.discovery.auto_registration.enabled
            && !self.discovery.auto_registration.allowlist.is_empty()
            && self.discovery.challenge_secret.trim().len() < 32
        {
            anyhow::bail!(
                "discovery.challenge_secret must contain at least 32 characters when automatic registration is enabled"
            );
        }
        if !self.discovery.encryption_key.trim().is_empty() {
            validate_discovery_encryption_key(&self.discovery.encryption_key)?;
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
        if !(300..=600).contains(&self.oidc.access_token_ttl_seconds) {
            anyhow::bail!("oidc.access_token_ttl_seconds must be between 300 and 600 seconds");
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
        let mut application_ids = BTreeSet::new();
        for application in &self.bootstrap.applications {
            validate_bootstrap_application(application)?;
            if !application_ids.insert(application.application_id.trim().to_string()) {
                anyhow::bail!(
                    "bootstrap application_id must be unique: {}",
                    application.application_id
                );
            }
            if application.management_mode == "website_managed"
                && !application.fetch_secret.trim().is_empty()
                && self.discovery.encryption_key.trim().is_empty()
            {
                anyhow::bail!(
                    "website-managed bootstrap application {} requires discovery.encryption_key or SSO_DISCOVERY_ENCRYPTION_KEY",
                    application.application_id
                );
            }
        }
        for client in &self.bootstrap.clients {
            validate_bootstrap_client_logo_uri(&client.client_id, &client.logo_uri)?;
            if client.client_id.trim().is_empty() {
                anyhow::bail!("bootstrap client_id cannot be empty");
            }
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
            let uses_authorization_code = client
                .grant_types
                .iter()
                .any(|value| value == "authorization_code");
            if uses_authorization_code && !client.scopes.iter().any(|scope| scope == "openid") {
                anyhow::bail!(
                    "bootstrap client {} must include openid scope",
                    client.client_id
                );
            }
            if uses_authorization_code && !client.response_types.iter().any(|value| value == "code")
            {
                anyhow::bail!(
                    "bootstrap client {} must support code response type",
                    client.client_id
                );
            }
            if client.service_account_enabled
                && !client
                    .grant_types
                    .iter()
                    .any(|value| value == "client_credentials")
            {
                anyhow::bail!(
                    "bootstrap client {} service accounts require client_credentials grant",
                    client.client_id
                );
            }
            if client.require_confidential_client && client.token_endpoint_auth_method == "none" {
                anyhow::bail!(
                    "bootstrap client {} cannot require confidentiality with token_endpoint_auth_method=none",
                    client.client_id
                );
            }
            crate::service_accounts::normalize_permissions(
                client.service_account_permissions.clone(),
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "bootstrap client {} has invalid service_account_permissions: {error}",
                    client.client_id
                )
            })?;
            if let Some(audience) = client.audience.as_deref()
                && !audience.trim().is_empty()
            {
                if audience.len() > 2048 {
                    anyhow::bail!(
                        "bootstrap client {} audience must be at most 2048 characters",
                        client.client_id
                    );
                }
                if audience.chars().any(char::is_whitespace) {
                    anyhow::bail!(
                        "bootstrap client {} audience cannot contain whitespace",
                        client.client_id
                    );
                }
            }
            if client.rotate_secret {
                if !matches!(
                    client.token_endpoint_auth_method.as_str(),
                    "client_secret_basic" | "client_secret_post" | "client_secret_jwt"
                ) {
                    anyhow::bail!(
                        "bootstrap client {} rotate_secret requires secret-based authentication",
                        client.client_id
                    );
                }
                if client.client_secret.is_empty()
                    && !client
                        .client_secret_env
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                {
                    anyhow::bail!(
                        "bootstrap client {} rotate_secret requires client_secret or client_secret_env",
                        client.client_id
                    );
                }
            }
        }
        for (index, entry) in self.oidc.delegated_allowlist.iter().enumerate() {
            for (label, value) in [
                ("client_id", entry.client_id.as_deref()),
                ("audience", entry.audience.as_deref()),
                ("subject_client_id", entry.subject_client_id.as_deref()),
            ] {
                if value.is_some_and(|value| value.trim().is_empty()) {
                    anyhow::bail!("oidc.delegated_allowlist[{index}].{label} cannot be empty");
                }
            }
            let scopes = entry.normalized_scopes();
            if scopes.is_empty() {
                anyhow::bail!("oidc.delegated_allowlist[{index}] must contain at least one scope");
            }
            for scope in scopes {
                if scope.ends_with(".service") {
                    anyhow::bail!(
                        "oidc.delegated_allowlist[{index}] cannot delegate service scope {scope}"
                    );
                }
                if scope.len() > 256 || scope.chars().any(char::is_whitespace) {
                    anyhow::bail!("oidc.delegated_allowlist[{index}] contains an invalid scope");
                }
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

/// Validates the origin used to construct browser redirects, issuer claims
/// and WebAuthn origins.  Plain HTTP is intentionally limited to loopback
/// development hosts; accepting arbitrary HTTP here turns a runtime setting
/// into a transport-security downgrade.
pub fn validate_public_origin(value: &str, field: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('/');
    let url = Url::parse(value).map_err(|err| anyhow::anyhow!("{field} is invalid: {err}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("{field} has no host"))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.path() != "" && url.path() != "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("{field} must be an absolute HTTP(S) origin without credentials or path");
    }
    let loopback = matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    );
    if url.scheme() == "http" && !loopback {
        anyhow::bail!("{field} must use HTTPS outside localhost development");
    }
    Ok(value.to_string())
}

fn validate_bootstrap_application(application: &BootstrapApplication) -> Result<()> {
    let application_id = application.application_id.trim();
    if application_id.is_empty()
        || application_id.len() > 64
        || application_id
            .chars()
            .any(|ch| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'))
        || application_id.starts_with('-')
        || application_id.ends_with('-')
    {
        anyhow::bail!(
            "bootstrap application_id {} is invalid",
            application.application_id
        );
    }
    if application.name.trim().is_empty() || application.name.len() > 160 {
        anyhow::bail!(
            "bootstrap application {} name is invalid",
            application.application_id
        );
    }
    let parsed = url::Url::parse(application.website_url.trim()).with_context(|| {
        format!(
            "bootstrap application {} website_url must be an absolute URL",
            application.application_id
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!(
            "bootstrap application {} website_url must be an http(s) origin",
            application.application_id
        );
    }
    if !matches!(
        application.management_mode.as_str(),
        "signet_managed" | "website_managed"
    ) {
        anyhow::bail!(
            "bootstrap application {} has unsupported management_mode",
            application.application_id
        );
    }
    Ok(())
}

fn validate_discovery_encryption_key(value: &str) -> Result<()> {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    let decoded = URL_SAFE_NO_PAD
        .decode(value.trim())
        .or_else(|_| STANDARD.decode(value.trim()))
        .with_context(|| "discovery.encryption_key must be base64 encoded")?;
    if decoded.len() != 32 {
        anyhow::bail!("discovery.encryption_key must decode to exactly 32 bytes");
    }
    Ok(())
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

fn resolve_bootstrap_client_secret(
    client: &mut BootstrapClient,
    value: std::result::Result<String, env::VarError>,
) -> Result<()> {
    if client.client_secret_env.is_none() {
        return Ok(());
    }
    client.client_secret = value.with_context(|| {
        format!(
            "bootstrap client {} references missing client_secret_env",
            client.client_id
        )
    })?;
    Ok(())
}

fn resolve_optional_secret(value: &mut String, env_name: Option<&str>) -> Result<()> {
    let Some(env_name) = env_name.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    *value = env::var(env_name).with_context(|| {
        format!("billing provider references missing secret environment variable {env_name}")
    })?;
    Ok(())
}

fn validate_billing_settings(settings: &BillingSettings) -> Result<()> {
    if settings.default_currency.trim().is_empty() {
        anyhow::bail!("billing.default_currency cannot be empty");
    }
    let mut seen_currencies = BTreeSet::new();
    for currency in &settings.supported_currencies {
        let code = currency.code.trim().to_ascii_uppercase();
        if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_uppercase()) {
            anyhow::bail!("billing currency codes must be three uppercase ASCII letters");
        }
        if currency.minor_unit > 8 {
            anyhow::bail!("billing currency minor_unit must be between 0 and 8");
        }
        if !seen_currencies.insert(code) {
            anyhow::bail!("billing currency codes must be unique");
        }
    }
    if !seen_currencies.contains(&settings.default_currency.trim().to_ascii_uppercase()) {
        anyhow::bail!("billing.default_currency must be in billing.supported_currencies");
    }
    if settings.reservation_ttl_seconds <= 0 {
        anyhow::bail!("billing.reservation_ttl_seconds must be positive");
    }
    if settings.reconcile_interval_seconds <= 0 {
        anyhow::bail!("billing.reconcile_interval_seconds must be positive");
    }
    if settings.reconcile_batch_size == 0 || settings.reconcile_batch_size > 500 {
        anyhow::bail!("billing.reconcile_batch_size must be between 1 and 500");
    }
    if settings.reconcile_lease_seconds < settings.reconcile_interval_seconds {
        anyhow::bail!(
            "billing.reconcile_lease_seconds must be at least reconcile_interval_seconds"
        );
    }
    if settings.reconcile_retry_base_seconds <= 0 {
        anyhow::bail!("billing.reconcile_retry_base_seconds must be positive");
    }
    if settings.reconcile_retry_max_seconds < settings.reconcile_retry_base_seconds {
        anyhow::bail!(
            "billing.reconcile_retry_max_seconds must be at least reconcile_retry_base_seconds"
        );
    }
    if settings.reconcile_retry_max_seconds > 7 * 24 * 60 * 60 {
        anyhow::bail!("billing.reconcile_retry_max_seconds must be at most 604800 seconds");
    }
    let mut seen_providers = BTreeSet::new();
    for provider in &settings.providers {
        let slug = provider.slug.trim();
        if slug.is_empty() || slug.len() > 128 || !seen_providers.insert(slug.to_string()) {
            anyhow::bail!("billing provider slugs must be unique and non-empty");
        }
        if !matches!(
            provider.kind.as_str(),
            "epay_v1" | "alipay_page" | "wechat_native"
        ) {
            anyhow::bail!("unsupported billing provider kind: {}", provider.kind);
        }
        if provider.enabled && provider.gateway_url.trim().is_empty() {
            anyhow::bail!("enabled billing provider {slug} requires gateway_url");
        }
        if provider.enabled && provider.kind == "wechat_native" {
            for (name, value) in [
                ("app_id", provider.app_id.as_str()),
                ("merchant_id", provider.merchant_id.as_str()),
                (
                    "certificate_serial_no",
                    provider.certificate_serial_no.as_str(),
                ),
                ("api_v3_key", provider.api_v3_key.as_str()),
                ("private_key_pem", provider.private_key_pem.as_str()),
            ] {
                if value.trim().is_empty() {
                    anyhow::bail!("enabled WeChat billing provider {slug} requires {name}");
                }
            }
        }
        if provider.enabled && provider.kind == "alipay_page" {
            for (name, value) in [
                ("app_id", provider.app_id.as_str()),
                ("private_key_pem", provider.private_key_pem.as_str()),
                (
                    "alipay_public_key_pem",
                    provider.alipay_public_key_pem.as_str(),
                ),
            ] {
                if value.trim().is_empty() {
                    anyhow::bail!("enabled Alipay billing provider {slug} requires {name}");
                }
            }
        }
        if provider.enabled && provider.kind == "epay_v1" {
            for (name, value) in [
                ("merchant_id", provider.merchant_id.as_str()),
                ("merchant_secret", provider.merchant_secret.as_str()),
            ] {
                if value.trim().is_empty() {
                    anyhow::bail!("enabled EPay billing provider {slug} requires {name}");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_settings() -> Settings {
        toml::from_str(include_str!("../../config/default.toml")).unwrap()
    }

    fn sample_bootstrap_client() -> BootstrapClient {
        BootstrapClient {
            client_id: "sample-client".to_string(),
            client_name: "Sample Client".to_string(),
            logo_uri: String::new(),
            client_secret: "sample-secret".to_string(),
            client_secret_env: None,
            redirect_uris: vec!["https://example.test/callback".to_string()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            require_pkce: true,
            require_confidential_client: true,
            service_account_enabled: false,
            service_account_permissions: Vec::new(),
            audience: None,
            rotate_secret: false,
        }
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
    fn public_origins_require_https_outside_loopback() {
        let mut settings = default_settings();
        settings.server.public_base_url = "http://signet.example.test".to_string();
        assert!(settings.validate().is_err());

        settings.server.public_base_url = "https://signet.example.test".to_string();
        settings.oidc.issuer = "https://signet.example.test".to_string();
        assert!(settings.validate().is_ok());

        assert!(validate_public_origin("http://localhost:8080", "origin").is_ok());
        assert!(validate_public_origin("http://127.0.0.1:8080", "origin").is_ok());
        assert!(validate_public_origin("http://example.test", "origin").is_err());
        assert!(validate_public_origin("https://example.test/path", "origin").is_err());
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

    #[test]
    fn billing_reconcile_settings_require_safe_retry_and_lease_bounds() {
        let mut settings = default_settings();
        settings.billing.reconcile_batch_size = 0;
        assert!(settings.validate().is_err());

        let mut settings = default_settings();
        settings.billing.reconcile_lease_seconds = settings.billing.reconcile_interval_seconds - 1;
        assert!(settings.validate().is_err());

        let mut settings = default_settings();
        settings.billing.reconcile_retry_max_seconds =
            settings.billing.reconcile_retry_base_seconds - 1;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn auto_registration_allowlist_rejects_embedded_user_info() {
        let mut settings = default_settings();
        settings
            .discovery
            .auto_registration
            .allowlist
            .push(AutoRegistrationAllowlistEntry {
                id: "example".to_string(),
                origin: "https://user:password@example.test".to_string(),
                organization_id: "org-1".to_string(),
                application_ids: vec!["example".to_string()],
                auto_activate: true,
            });
        assert!(settings.validate().is_err());

        settings.discovery.auto_registration.allowlist[0].origin =
            "https://user@example.test".to_string();
        assert!(settings.validate().is_err());
    }

    #[test]
    fn auto_registration_allowlist_requires_unique_application_slugs() {
        let mut settings = default_settings();
        settings
            .discovery
            .auto_registration
            .allowlist
            .push(AutoRegistrationAllowlistEntry {
                id: "example".to_string(),
                origin: "https://example.test".to_string(),
                organization_id: "org-1".to_string(),
                application_ids: vec!["Bad_ID".to_string()],
                auto_activate: true,
            });
        assert!(settings.validate().is_err());

        settings.discovery.auto_registration.allowlist[0].application_ids =
            vec!["example".to_string(), "example".to_string()];
        assert!(settings.validate().is_err());
    }

    #[test]
    fn billing_provider_validation_requires_enabled_provider_credentials() {
        let mut settings = default_settings();
        settings.billing.providers[0].enabled = true;
        assert!(settings.validate().is_err());

        settings.billing.providers[0].merchant_id = "merchant-1".to_string();
        settings.billing.providers[0].merchant_secret = "secret".to_string();
        assert!(settings.validate().is_ok());

        settings
            .billing
            .supported_currencies
            .push(CurrencySettings {
                code: "CNY".to_string(),
                minor_unit: 2,
            });
        assert!(settings.validate().is_err());
    }

    #[test]
    fn bootstrap_client_supports_service_accounts_without_openid_scope() {
        let mut settings = default_settings();
        settings.bootstrap.clients.push(sample_bootstrap_client());
        {
            let client = settings.bootstrap.clients.first_mut().unwrap();
            client.scopes = vec!["memory.service".to_string()];
            client.grant_types = vec!["client_credentials".to_string()];
            client.response_types.clear();
            client.service_account_enabled = true;
            client.service_account_permissions = vec![" users.read ".to_string()];
            client.audience = Some("memory-atlas".to_string());
        }

        assert!(settings.validate().is_ok());

        settings.bootstrap.clients[0].service_account_permissions =
            vec!["not-a-permission".to_string()];
        assert!(settings.validate().is_err());
    }

    #[test]
    fn bootstrap_client_secret_env_replaces_literal_secret() {
        let mut settings = default_settings();
        settings.bootstrap.clients.push(sample_bootstrap_client());
        let client = settings.bootstrap.clients.first_mut().unwrap();
        client.client_secret = "literal-secret".to_string();
        client.client_secret_env = Some("SIGNET_TEST_CLIENT_SECRET".to_string());

        resolve_bootstrap_client_secret(client, Ok("env-secret".to_string())).unwrap();
        assert_eq!(client.client_secret, "env-secret");
    }

    #[test]
    fn bootstrap_client_secret_can_be_omitted_for_existing_clients() {
        let mut settings = default_settings();
        settings.bootstrap.clients.push(sample_bootstrap_client());
        settings.bootstrap.clients[0].client_secret.clear();
        assert!(settings.validate().is_ok());

        settings.bootstrap.clients[0].rotate_secret = true;
        assert!(settings.validate().is_err());

        settings.bootstrap.clients[0].client_secret = "secret".to_string();
        settings.bootstrap.clients[0].token_endpoint_auth_method = "none".to_string();
        assert!(settings.validate().is_err());
    }

    #[test]
    fn bootstrap_client_aliases_support_secret_env_and_rotate() {
        let client: BootstrapClient = toml::from_str(
            r#"
            client_id = "worker"
            client_name = "Worker"
            secret_env = "WORKER_SECRET"
            scopes = ["memory.service"]
            grant_types = ["client_credentials"]
            token_endpoint_auth_method = "client_secret_basic"
            service_account = true
            permissions = ["users.read"]
            audience = "memory-atlas-api"
            rotate_client_secret = true
            "#,
        )
        .unwrap();

        assert_eq!(client.client_secret_env.as_deref(), Some("WORKER_SECRET"));
        assert!(client.redirect_uris.is_empty());
        assert!(client.post_logout_redirect_uris.is_empty());
        assert!(client.response_types.is_empty());
        assert!(!client.require_pkce);
        assert!(client.service_account_enabled);
        assert_eq!(client.service_account_permissions, vec!["users.read"]);
        assert_eq!(client.audience.as_deref(), Some("memory-atlas-api"));
        assert!(client.rotate_secret);
    }
}
