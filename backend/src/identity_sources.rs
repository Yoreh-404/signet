use crate::error::{AppError, AppResult};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, time::Duration};
use url::Url;

const DISCOVERY_TIMEOUT_SECONDS: u64 = 8;
const MAX_DISCOVERY_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct OidcProviderTemplate {
    pub id: &'static str,
    pub slug: &'static str,
    pub display_name: &'static str,
    pub issuer: &'static str,
    pub scopes: &'static [&'static str],
}

#[derive(Debug, Clone, Serialize)]
pub struct OidcDiscoveryResult {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenIdConfiguration {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
    scopes_supported: Option<Vec<String>>,
}

#[allow(async_fn_in_trait)]
trait OidcDiscoveryClient {
    async fn fetch(&self, url: &str) -> AppResult<OpenIdConfiguration>;
}

#[derive(Debug, Clone)]
struct HttpOidcDiscoveryClient {
    client: Client,
}

impl HttpOidcDiscoveryClient {
    fn new() -> AppResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DISCOVERY_TIMEOUT_SECONDS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| {
                AppError::Internal(format!("failed to build discovery client: {err}"))
            })?;
        Ok(Self { client })
    }

    async fn fetch_jwks(&self, url: &str) -> AppResult<JwkSet> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| AppError::BadRequest(format!("OIDC JWKS request failed: {err}")))?;
        if !response.status().is_success() {
            return Err(AppError::BadRequest(format!(
                "OIDC JWKS returned HTTP {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|err| AppError::BadRequest(format!("OIDC JWKS body failed: {err}")))?;
        if bytes.len() > MAX_DISCOVERY_BYTES {
            return Err(AppError::BadRequest(
                "OIDC JWKS document is too large".to_string(),
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|err| AppError::BadRequest(format!("OIDC JWKS JSON is invalid: {err}")))
    }
}

impl OidcDiscoveryClient for HttpOidcDiscoveryClient {
    async fn fetch(&self, url: &str) -> AppResult<OpenIdConfiguration> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| AppError::BadRequest(format!("OIDC discovery request failed: {err}")))?;
        if !response.status().is_success() {
            return Err(AppError::BadRequest(format!(
                "OIDC discovery returned HTTP {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|err| AppError::BadRequest(format!("OIDC discovery body failed: {err}")))?;
        if bytes.len() > MAX_DISCOVERY_BYTES {
            return Err(AppError::BadRequest(
                "OIDC discovery document is too large".to_string(),
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|err| AppError::BadRequest(format!("OIDC discovery JSON is invalid: {err}")))
    }
}

pub fn oidc_provider_templates() -> Vec<OidcProviderTemplate> {
    vec![
        OidcProviderTemplate {
            id: "google",
            slug: "google",
            display_name: "Google",
            issuer: "https://accounts.google.com",
            scopes: &["openid", "profile", "email"],
        },
        OidcProviderTemplate {
            id: "microsoft_entra",
            slug: "microsoft",
            display_name: "Microsoft Entra ID",
            issuer: "https://login.microsoftonline.com/common/v2.0",
            scopes: &["openid", "profile", "email"],
        },
        OidcProviderTemplate {
            id: "keycloak",
            slug: "keycloak",
            display_name: "Keycloak",
            issuer: "https://keycloak.example.com/realms/example",
            scopes: &["openid", "profile", "email"],
        },
        OidcProviderTemplate {
            id: "authentik",
            slug: "authentik",
            display_name: "authentik",
            issuer: "https://auth.example.com/application/o/example/",
            scopes: &["openid", "profile", "email"],
        },
        OidcProviderTemplate {
            id: "zitadel",
            slug: "zitadel",
            display_name: "ZITADEL",
            issuer: "https://example.zitadel.cloud",
            scopes: &["openid", "profile", "email"],
        },
        OidcProviderTemplate {
            id: "logto",
            slug: "logto",
            display_name: "Logto",
            issuer: "https://example.logto.app/oidc",
            scopes: &["openid", "profile", "email"],
        },
    ]
}

pub async fn discover_oidc_provider(
    issuer_or_discovery_url: &str,
) -> AppResult<OidcDiscoveryResult> {
    discover_oidc_provider_with_client(issuer_or_discovery_url, &HttpOidcDiscoveryClient::new()?)
        .await
}

/// Fetches the provider's public signing keys after validating the configured
/// issuer/discovery URL.  Keeping this in the identity-source adapter gives
/// external login and the admin discovery flow the same URL and payload
/// bounds, and deliberately disables redirects to avoid turning discovery
/// into an SSRF hop.
pub async fn fetch_oidc_jwks(jwks_uri: &str) -> AppResult<JwkSet> {
    let normalized = normalize_http_url(jwks_uri.to_string(), "jwks_uri", false)?;
    if normalized.is_empty() {
        return Err(AppError::BadRequest(
            "OIDC provider jwks_uri is required".to_string(),
        ));
    }
    HttpOidcDiscoveryClient::new()?
        .fetch_jwks(&normalized)
        .await
}

async fn discover_oidc_provider_with_client<C: OidcDiscoveryClient>(
    issuer_or_discovery_url: &str,
    client: &C,
) -> AppResult<OidcDiscoveryResult> {
    let candidates = discovery_url_candidates(issuer_or_discovery_url)?;
    let mut last_error = None;
    for url in candidates {
        match client.fetch(&url).await {
            Ok(document) => return normalize_discovery_document(document),
            Err(err) => last_error = Some(err.to_string()),
        }
    }
    Err(AppError::BadRequest(format!(
        "OIDC discovery failed{}",
        last_error
            .map(|message| format!(": {message}"))
            .unwrap_or_default()
    )))
}

fn normalize_discovery_document(document: OpenIdConfiguration) -> AppResult<OidcDiscoveryResult> {
    let issuer = normalize_http_url(document.issuer, "issuer", true)?;
    let authorization_endpoint = normalize_http_url(
        document.authorization_endpoint,
        "authorization_endpoint",
        false,
    )?;
    let token_endpoint = normalize_http_url(document.token_endpoint, "token_endpoint", false)?;
    let userinfo_endpoint = normalize_http_url(
        document.userinfo_endpoint.unwrap_or_default(),
        "userinfo_endpoint",
        false,
    )?;
    if userinfo_endpoint.is_empty() {
        return Err(AppError::BadRequest(
            "OIDC discovery document does not include userinfo_endpoint".to_string(),
        ));
    }
    let jwks_uri = normalize_http_url(document.jwks_uri, "jwks_uri", false)?;
    if jwks_uri.is_empty() {
        return Err(AppError::BadRequest(
            "OIDC discovery document does not include jwks_uri".to_string(),
        ));
    }
    let scopes = normalize_discovered_scopes(document.scopes_supported)?;
    Ok(OidcDiscoveryResult {
        issuer,
        authorization_endpoint,
        token_endpoint,
        userinfo_endpoint,
        jwks_uri,
        scopes,
    })
}

fn normalize_discovered_scopes(scopes: Option<Vec<String>>) -> AppResult<Vec<String>> {
    let Some(scopes) = scopes else {
        return Ok(vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]);
    };
    let supported = scopes
        .into_iter()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    let supported_set = supported.iter().map(String::as_str).collect::<HashSet<_>>();
    if !supported_set.contains("openid") {
        return Err(AppError::BadRequest(
            "OIDC discovery scopes_supported must include openid".to_string(),
        ));
    }
    let mut selected = Vec::new();
    for scope in ["openid", "profile", "email"] {
        if supported_set.contains(scope) {
            selected.push(scope.to_string());
        }
    }
    if selected.is_empty() {
        selected.push("openid".to_string());
    }
    Ok(selected)
}

fn discovery_url_candidates(value: &str) -> AppResult<Vec<String>> {
    let normalized = normalize_http_url(value.to_string(), "issuer", true)?;
    let parsed = Url::parse(&normalized)
        .map_err(|err| AppError::BadRequest(format!("issuer is invalid: {err}")))?;
    if parsed.path().ends_with("/.well-known/openid-configuration") {
        return Ok(vec![normalized]);
    }
    let append = format!("{}/.well-known/openid-configuration", normalized);
    let mut candidates = vec![append];
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() && path != "/" {
        let mut spec = parsed.clone();
        spec.set_path(&format!("/.well-known/openid-configuration{}", path));
        spec.set_query(None);
        spec.set_fragment(None);
        let spec = spec.to_string().trim_end_matches('/').to_string();
        if !candidates.iter().any(|candidate| candidate == &spec) {
            candidates.push(spec);
        }
    }
    Ok(candidates)
}

fn normalize_http_url(value: String, field: &str, trim_trailing_slash: bool) -> AppResult<String> {
    let value = if trim_trailing_slash {
        value.trim().trim_end_matches('/').to_string()
    } else {
        value.trim().to_string()
    };
    if value.is_empty() {
        return Ok(String::new());
    }
    let parsed = Url::parse(&value)
        .map_err(|err| AppError::BadRequest(format!("{field} is invalid: {err}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::BadRequest(format!(
            "{field} must be an absolute http(s) URL"
        )));
    }
    if parsed.fragment().is_some() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::BadRequest(format!(
            "{field} cannot include credentials or fragment"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct StaticDiscoveryClient {
        fail_first: bool,
    }

    impl OidcDiscoveryClient for StaticDiscoveryClient {
        async fn fetch(&self, url: &str) -> AppResult<OpenIdConfiguration> {
            if self.fail_first
                && url == "https://idp.example.com/tenant/.well-known/openid-configuration"
            {
                return Err(AppError::BadRequest("not found".to_string()));
            }
            Ok(OpenIdConfiguration {
                issuer: "https://idp.example.com/tenant".to_string(),
                authorization_endpoint: "https://idp.example.com/tenant/authorize".to_string(),
                token_endpoint: "https://idp.example.com/tenant/token".to_string(),
                userinfo_endpoint: Some("https://idp.example.com/tenant/userinfo".to_string()),
                jwks_uri: "https://idp.example.com/tenant/jwks".to_string(),
                scopes_supported: Some(vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                    "offline_access".to_string(),
                ]),
            })
        }
    }

    #[test]
    fn discovery_url_candidates_support_append_and_spec_paths() {
        assert_eq!(
            discovery_url_candidates("https://idp.example.com").unwrap(),
            vec!["https://idp.example.com/.well-known/openid-configuration"]
        );
        assert_eq!(
            discovery_url_candidates("https://idp.example.com/tenant/").unwrap(),
            vec![
                "https://idp.example.com/tenant/.well-known/openid-configuration",
                "https://idp.example.com/.well-known/openid-configuration/tenant",
            ]
        );
    }

    #[tokio::test]
    async fn discovery_uses_later_candidate_when_provider_uses_spec_path() {
        let result = discover_oidc_provider_with_client(
            "https://idp.example.com/tenant",
            &StaticDiscoveryClient { fail_first: true },
        )
        .await
        .unwrap();

        assert_eq!(result.issuer, "https://idp.example.com/tenant");
        assert_eq!(
            result.authorization_endpoint,
            "https://idp.example.com/tenant/authorize"
        );
        assert_eq!(
            result.scopes,
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string()
            ]
        );
    }

    #[test]
    fn discovered_scopes_require_openid_and_prefer_standard_profile_email() {
        assert!(matches!(
            normalize_discovered_scopes(Some(vec!["profile".to_string()])),
            Err(AppError::BadRequest(_))
        ));
        assert_eq!(
            normalize_discovered_scopes(None).unwrap(),
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string()
            ]
        );
    }

    #[test]
    fn templates_include_common_enterprise_oidc_sources() {
        let ids = oidc_provider_templates()
            .into_iter()
            .map(|template| template.id)
            .collect::<Vec<_>>();
        assert!(ids.contains(&"google"));
        assert!(ids.contains(&"microsoft_entra"));
        assert!(ids.contains(&"keycloak"));
        assert!(ids.contains(&"authentik"));
    }
}
