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
    config::AutoRegistrationAllowlistEntry,
    db::{ApplicationDiscoveryRecord, NewApplication, NewClient},
    error::{AppError, AppResult},
    util,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::net::lookup_host;
use tokio::{
    sync::{Semaphore, oneshot},
    task::JoinHandle,
    time::Instant,
};
use url::{Host, Url};

pub const FORMAT: &str = crate::application_contract::FORMAT;
pub const DISCOVERY_PATH: &str = "/.well-known/signet-authorization.json";
pub use crate::application_discovery_contract::{
    MANAGEMENT_MODE_SIGNET, MANAGEMENT_MODE_WEBSITE, SOURCE_MANUAL, SOURCE_MODE_DISCOVERY,
    SOURCE_MODE_MANUAL, SOURCE_WEBSITE, SYNC_ACCEPTED, SYNC_DISABLED, SYNC_ERROR, SYNC_PENDING,
    SYNC_REJECTED, SYNC_STATUS_ERROR, SYNC_STATUS_MANUAL, SYNC_STATUS_NO_PROFILE,
    SYNC_STATUS_SYNCED, SYNC_SYNCED, SYNC_UNCONFIGURED, SYNC_UNKNOWN,
    website_discovery_runtime_active,
};

const MAX_CLIENT_ID_LENGTH: usize = 255;
const MAX_SCOPE_LENGTH: usize = 256;
const MAX_DISCOVERY_SWEEP_APPLICATIONS: usize = 10_000;
const MAX_DISCOVERY_CHALLENGE_TTL_SECONDS: i64 = 900;
const DISCOVERY_CHALLENGE_VERSION: &str = "v1";
const DISCOVERY_CHALLENGE_LABEL: &[u8] = b"signet:application-discovery-challenge:v1:";
const REGISTRATION_PROOF_EXTENSION: &str = "registration_proof";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncFailureStatus {
    Rejected,
    Unknown,
}

impl SyncFailureStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => SYNC_REJECTED,
            Self::Unknown => SYNC_UNKNOWN,
        }
    }
}

#[derive(Debug)]
struct SyncFailure {
    status: SyncFailureStatus,
    error: AppError,
}

impl SyncFailure {
    fn rejected(error: AppError) -> Self {
        Self {
            status: SyncFailureStatus::Rejected,
            error,
        }
    }

    fn unknown(error: AppError) -> Self {
        Self {
            status: SyncFailureStatus::Unknown,
            error,
        }
    }
}

#[derive(Debug, Clone)]
struct DiscoveryLease {
    application_id: String,
    owner_token: String,
    lease_generation: i64,
    commit_gate: Arc<tokio::sync::Mutex<()>>,
}

type DiscoveryCommitGates = HashMap<String, Arc<tokio::sync::Mutex<()>>>;

static DISCOVERY_COMMIT_GATES: OnceLock<Mutex<DiscoveryCommitGates>> = OnceLock::new();

fn discovery_commit_gate(application_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    DISCOVERY_COMMIT_GATES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(application_id.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Claims the durable database lease. The local gate is only shared by
/// commit/release calls in this process; ownership and fencing come from the
/// database owner token plus generation.
async fn acquire_discovery_lease(
    state: &AppState,
    application_id: &str,
) -> AppResult<Option<DiscoveryLease>> {
    let owner_token = util::random_token(24);
    let Some(lease) = state
        .db
        .claim_application_discovery_lease(application_id, &owner_token)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(DiscoveryLease {
        application_id: lease.application_id,
        owner_token: lease.owner_token,
        lease_generation: lease.lease_generation,
        commit_gate: discovery_commit_gate(application_id),
    }))
}

impl DiscoveryLease {
    async fn mark_status_if_owner(
        &self,
        state: &AppState,
        status: &str,
        error: Option<String>,
    ) -> AppResult<Option<ApplicationDiscoveryRecord>> {
        let _commit_guard = self.commit_gate.lock().await;
        state
            .db
            .mark_application_discovery_sync_error_if_owner(
                &self.application_id,
                &self.owner_token,
                self.lease_generation,
                status,
                error,
            )
            .await
    }

    async fn apply_if_owner(
        &self,
        state: &AppState,
        manifest: VerifiedApplicationManifest,
    ) -> AppResult<Option<ApplicationDiscoveryRecord>> {
        let _commit_guard = self.commit_gate.lock().await;
        if !state
            .db
            .renew_application_discovery_lease(
                &self.application_id,
                &self.owner_token,
                self.lease_generation,
            )
            .await?
        {
            return Ok(None);
        }
        state
            .db
            .commit_application_discovery_if_owner(
                &self.application_id,
                &self.owner_token,
                self.lease_generation,
                manifest.into(),
            )
            .await
            .map(Some)
    }

    async fn release(&self, state: &AppState) -> AppResult<bool> {
        let _commit_guard = self.commit_gate.lock().await;
        state
            .db
            .release_application_discovery_lease(
                &self.application_id,
                &self.owner_token,
                self.lease_generation,
            )
            .await
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RegistrationProof {
    purpose: String,
    origin: String,
    challenge: String,
}

#[derive(Debug, Clone, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    jwk: Option<PinnedJwk>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PinnedJwks {
    keys: Vec<PinnedJwk>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

impl From<VerifiedApplicationManifest> for crate::db::ApplicationDiscoveryManifest {
    fn from(manifest: VerifiedApplicationManifest) -> Self {
        Self {
            revision: manifest.revision,
            version: manifest.version,
            digest: manifest.digest,
            expires_at: manifest.expires_at,
            revoke_removed_clients: manifest.revoke_removed_clients,
            clients: manifest.clients,
            client_protocols: manifest.client_protocols,
            protocols: manifest.protocols,
            login_adapters: manifest.login_adapters,
            directory_sync: manifest.directory_sync,
            authorization: manifest.authorization,
            authorization_mappings: manifest.authorization_mappings.into(),
            profiles: manifest
                .profiles
                .into_iter()
                .map(|(key, profile)| (key, profile.into()))
                .collect(),
            redacted_payload: manifest.redacted_payload,
        }
    }
}

impl From<NormalizedAuthorizationMappings>
    for crate::db::ApplicationDiscoveryAuthorizationMappings
{
    fn from(mappings: NormalizedAuthorizationMappings) -> Self {
        Self {
            group_mappings: mappings
                .group_mappings
                .into_iter()
                .map(Into::into)
                .collect(),
            organization_role_mappings: mappings
                .organization_role_mappings
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<NormalizedGroupMapping> for crate::db::ApplicationDiscoveryGroupMapping {
    fn from(mapping: NormalizedGroupMapping) -> Self {
        Self {
            group: mapping.group,
            role: mapping.role,
        }
    }
}

impl From<NormalizedOrganizationRoleMapping>
    for crate::db::ApplicationDiscoveryOrganizationRoleMapping
{
    fn from(mapping: NormalizedOrganizationRoleMapping) -> Self {
        Self {
            organization_role: mapping.organization_role,
            role: mapping.role,
        }
    }
}

impl From<NormalizedProfile> for crate::db::ApplicationDiscoveryProfile {
    fn from(profile: NormalizedProfile) -> Self {
        Self {
            permissions: profile.permissions.into_iter().map(Into::into).collect(),
            roles: profile.roles.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<NormalizedPermission> for crate::db::ApplicationDiscoveryPermission {
    fn from(permission: NormalizedPermission) -> Self {
        Self {
            key: permission.key,
            label: permission.label,
            description: permission.description,
        }
    }
}

impl From<NormalizedRole> for crate::db::ApplicationDiscoveryRole {
    fn from(role: NormalizedRole) -> Self {
        Self {
            key: role.key,
            name: role.name,
            description: role.description,
            permissions: role.permissions,
            is_default: role.is_default,
        }
    }
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

/// Creates a short-lived capability for automatic registration. The website
/// must echo this value in the signed v3 `extensions.registration_proof`
/// object; a random header by itself is never enough to bootstrap trust.
pub fn new_discovery_challenge(secret: &str, origin: &str, ttl_seconds: i64) -> AppResult<String> {
    if secret.trim().len() < 32 || !(1..=MAX_DISCOVERY_CHALLENGE_TTL_SECONDS).contains(&ttl_seconds)
    {
        return Err(AppError::Configuration(
            "discovery challenge secret or TTL is invalid".to_string(),
        ));
    }
    let issued_at = util::now_ts();
    let nonce = util::random_token(32);
    let origin = website_origin(origin)?.to_ascii_lowercase();
    let timestamp = issued_at.to_string();
    let ttl = ttl_seconds.to_string();
    let mac = discovery_challenge_mac(secret, &origin, &timestamp, &ttl, &nonce)?;
    Ok(format!(
        "{DISCOVERY_CHALLENGE_VERSION}.{timestamp}.{ttl}.{nonce}.{mac}"
    ))
}

fn discovery_challenge_mac(
    secret: &str,
    origin: &str,
    issued_at: &str,
    ttl_seconds: &str,
    nonce: &str,
) -> AppResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::Configuration("invalid discovery challenge secret".into()))?;
    mac.update(DISCOVERY_CHALLENGE_LABEL);
    mac.update(origin.as_bytes());
    mac.update(b":");
    mac.update(issued_at.as_bytes());
    mac.update(b":");
    mac.update(ttl_seconds.as_bytes());
    mac.update(b":");
    mac.update(nonce.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn auto_registration_entry<'a>(
    state: &'a AppState,
    origin: &str,
) -> Option<&'a AutoRegistrationAllowlistEntry> {
    state
        .settings
        .discovery
        .auto_registration
        .allowlist
        .iter()
        .find(|entry| {
            website_origin(&entry.origin)
                .ok()
                .is_some_and(|value| value.eq_ignore_ascii_case(origin))
        })
}

fn validate_existing_auto_registration_binding(
    application: &crate::db::ApplicationRecord,
    entry: &AutoRegistrationAllowlistEntry,
) -> AppResult<()> {
    if application.organization_id != entry.organization_id {
        return Err(AppError::BadRequest(
            "allowlisted origin is bound to a different organization".to_string(),
        ));
    }
    if !entry
        .application_ids
        .iter()
        .any(|value| value.trim() == application.slug)
    {
        return Err(AppError::BadRequest(
            "allowlisted origin returned an unexpected application_id".to_string(),
        ));
    }
    Ok(())
}

fn application_to_new(application: &crate::db::ApplicationRecord) -> NewApplication {
    NewApplication {
        organization_id: application.organization_id.clone(),
        slug: application.slug.clone(),
        name: application.name.clone(),
        description: application.description.clone(),
        access_mode: application.access_mode.clone(),
        registration_mode: application.registration_mode.clone(),
        account_selection_mode: application.account_selection_mode.clone(),
        unique_identity_factors: application.unique_identity_factors().unwrap_or_default(),
        is_active: application.is_active == 1,
    }
}

/// A newly discovered application has no durable value until its verified
/// contract has been reconciled.  If the first database step after creating
/// the row fails, remove the provisional aggregate so a later retry cannot
/// mistake an empty discovery record for a usable website application.
async fn cleanup_failed_auto_registration(
    state: &AppState,
    application_id: &str,
    original_error: AppError,
) -> AppError {
    match state.db.delete_application(application_id).await {
        Ok(()) => original_error,
        Err(cleanup_error) => AppError::Internal(format!(
            "auto-registration failed: {original_error}; provisional application cleanup failed: {cleanup_error}"
        )),
    }
}

/// Discovers and provisions one explicitly allowlisted website. The
/// application row is inactive until the complete signed v3 contract has
/// been normalized and applied in one database reconciliation transaction.
pub async fn auto_register_application(
    state: &AppState,
    website_url: &str,
) -> AppResult<ApplicationDiscoveryRecord> {
    if !state.settings.discovery.auto_registration.enabled {
        return Err(AppError::Forbidden);
    }
    let origin = website_origin(website_url)?;
    let entry = auto_registration_entry(state, &origin).ok_or(AppError::Forbidden)?;
    let expected_audience = state.settings.oidc.issuer.trim_end_matches('/').to_string();
    if expected_audience.is_empty() {
        return Err(AppError::Configuration(
            "oidc issuer is not configured".to_string(),
        ));
    }
    let challenge = new_discovery_challenge(
        &state.settings.discovery.challenge_secret,
        &origin,
        state
            .settings
            .discovery
            .auto_registration
            .challenge_ttl_seconds,
    )?;
    let discovery_url = default_discovery_url(&origin)?;

    let existing = state
        .db
        .list_application_discoveries()
        .await?
        .into_iter()
        .find(|(_, discovery)| {
            website_origin(&discovery.website_url)
                .ok()
                .is_some_and(|value| value.eq_ignore_ascii_case(&origin))
        });
    if let Some((application, discovery)) = existing {
        validate_existing_auto_registration_binding(&application, entry)?;
        if discovery.operator_disabled != 0 {
            return Ok(discovery);
        }
        if discovery.management_mode != MANAGEMENT_MODE_WEBSITE {
            return Err(AppError::BadRequest(
                "allowlisted origin is owned by a Signet-managed application".to_string(),
            ));
        }
        if !discovery.signing_public_jwks.trim().is_empty() {
            let record = sync_application(state, &application.id).await?;
            if entry.auto_activate && application.is_active == 0 {
                state
                    .db
                    .update_application(
                        &application.id,
                        NewApplication {
                            is_active: true,
                            ..application_to_new(&application)
                        },
                    )
                    .await?;
            }
            return Ok(record);
        }

        let (contract, signing_public_jwks) =
            fetch_and_verify_auto_registration(DiscoveryAutoRegistrationRequest {
                discovery_url: &discovery_url,
                expected_issuer: &origin,
                expected_audience: &expected_audience,
                organization_id: &application.organization_id,
                challenge: &challenge,
                challenge_secret: &state.settings.discovery.challenge_secret,
                max_contract_ttl_seconds: state
                    .settings
                    .discovery
                    .auto_registration
                    .challenge_ttl_seconds,
                allow_private_networks: state.settings.discovery.allow_private_networks,
            })
            .await?;
        if contract.application_id != application.slug {
            return Err(AppError::BadRequest(
                "allowlisted origin returned an unexpected application_id".to_string(),
            ));
        }
        state
            .db
            .upsert_application_discovery(crate::db::NewApplicationDiscovery {
                application_id: discovery.application_id.clone(),
                management_mode: discovery.management_mode.clone(),
                website_url: discovery.website_url.clone(),
                fetch_secret_ciphertext: discovery.fetch_secret_ciphertext.clone(),
                signing_public_jwks,
                last_verified_revision: discovery.last_verified_revision,
                last_verified_version: discovery.last_verified_version.clone(),
                last_verified_digest: discovery.last_verified_digest.clone(),
                last_verified_expires_at: discovery.last_verified_expires_at,
                sync_status: SYNC_PENDING.to_string(),
                last_fetched_at: discovery.last_fetched_at,
                last_success_at: discovery.last_success_at,
                last_error: discovery.last_error.clone(),
                snapshot_json: discovery.snapshot_json.clone(),
                operator_disabled: discovery.operator_disabled != 0,
            })
            .await?;
        let record = state
            .db
            .apply_application_contract(&application.id, contract)
            .await?;
        if entry.auto_activate && application.is_active == 0 {
            state
                .db
                .update_application(
                    &application.id,
                    NewApplication {
                        is_active: true,
                        ..application_to_new(&application)
                    },
                )
                .await?;
        }
        return Ok(record);
    }

    let (contract, signing_public_jwks) =
        fetch_and_verify_auto_registration(DiscoveryAutoRegistrationRequest {
            discovery_url: &discovery_url,
            expected_issuer: &origin,
            expected_audience: &expected_audience,
            organization_id: &entry.organization_id,
            challenge: &challenge,
            challenge_secret: &state.settings.discovery.challenge_secret,
            max_contract_ttl_seconds: state
                .settings
                .discovery
                .auto_registration
                .challenge_ttl_seconds,
            allow_private_networks: state.settings.discovery.allow_private_networks,
        })
        .await?;
    if !entry
        .application_ids
        .iter()
        .any(|value| value.trim() == contract.application_id)
    {
        return Err(AppError::BadRequest(
            "allowlisted origin returned an unexpected application_id".to_string(),
        ));
    }

    if let Some(existing_application) = state
        .db
        .find_application_by_slug_in_organization(&entry.organization_id, &contract.application_id)
        .await?
    {
        if state
            .db
            .find_application_discovery(&existing_application.id)
            .await?
            .is_some_and(|value| {
                !website_origin(&value.website_url)
                    .ok()
                    .is_some_and(|value| value.eq_ignore_ascii_case(&origin))
            })
        {
            return Err(AppError::BadRequest(
                "application_id is already bound to another origin".to_string(),
            ));
        }
        return Err(AppError::BadRequest(
            "application_id already exists and cannot be auto-adopted".to_string(),
        ));
    }

    let application = state
        .db
        .insert_application(NewApplication {
            organization_id: entry.organization_id.clone(),
            slug: contract.application_id.clone(),
            name: crate::applications::normalize_application_name(&contract.application_id)?,
            description: None,
            access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: false,
        })
        .await?;
    if let Err(error) = state
        .db
        .upsert_application_discovery(crate::db::NewApplicationDiscovery {
            application_id: application.id.clone(),
            management_mode: MANAGEMENT_MODE_WEBSITE.to_string(),
            website_url: origin,
            fetch_secret_ciphertext: String::new(),
            signing_public_jwks,
            last_verified_revision: None,
            last_verified_version: None,
            last_verified_digest: None,
            last_verified_expires_at: None,
            sync_status: SYNC_PENDING.to_string(),
            last_fetched_at: None,
            last_success_at: None,
            last_error: None,
            snapshot_json: None,
            operator_disabled: false,
        })
        .await
    {
        return Err(cleanup_failed_auto_registration(state, &application.id, error).await);
    }
    let record = match state
        .db
        .apply_application_contract(&application.id, contract)
        .await
    {
        Ok(record) => record,
        Err(error) => {
            return Err(cleanup_failed_auto_registration(state, &application.id, error).await);
        }
    };
    state
        .db
        .update_application(
            &application.id,
            NewApplication {
                is_active: entry.auto_activate,
                ..application_to_new(&application)
            },
        )
        .await?;
    Ok(record)
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
    if let Some(extensions) = object.get_mut("extensions").and_then(Value::as_object_mut) {
        // The proof is bound to one challenge and therefore changes on every
        // bootstrap fetch. It must not make an unchanged contract revision
        // look like a content change.
        extensions.remove(REGISTRATION_PROOF_EXTENSION);
    }
    let canonical = serde_json::to_string(&value).map_err(|_| {
        AppError::Internal("failed to encode application discovery digest".to_string())
    })?;
    Ok(util::sha256_base64url(&canonical))
}

pub struct DiscoveryFetchRequest<'a> {
    pub discovery_url: &'a str,
    pub fetch_secret: &'a str,
    pub signing_public_jwks: &'a str,
    pub expected_issuer: &'a str,
    pub expected_application_id: &'a str,
    pub expected_audience: &'a str,
    pub organization_id: &'a str,
    pub allow_private_networks: bool,
}

pub struct DiscoveryChallengeRequest<'a> {
    pub discovery_url: &'a str,
    pub signing_public_jwks: &'a str,
    pub expected_issuer: &'a str,
    pub expected_application_id: &'a str,
    pub expected_audience: &'a str,
    pub organization_id: &'a str,
    pub challenge: &'a str,
    pub challenge_secret: &'a str,
    pub max_contract_ttl_seconds: i64,
    pub allow_private_networks: bool,
}

pub struct DiscoveryAutoRegistrationRequest<'a> {
    pub discovery_url: &'a str,
    pub expected_issuer: &'a str,
    pub expected_audience: &'a str,
    pub organization_id: &'a str,
    pub challenge: &'a str,
    pub challenge_secret: &'a str,
    pub max_contract_ttl_seconds: i64,
    pub allow_private_networks: bool,
}

pub async fn fetch_and_verify(
    request: DiscoveryFetchRequest<'_>,
) -> AppResult<VerifiedApplicationManifest> {
    if request.fetch_secret.trim().is_empty() {
        return Err(AppError::Configuration(
            "website-managed application has no fetch secret".to_string(),
        ));
    }
    let body = fetch_discovery_body(
        request.discovery_url,
        Some(request.fetch_secret),
        None,
        request.allow_private_networks,
    )
    .await?;
    verify_and_normalize(
        &body,
        request.signing_public_jwks,
        request.expected_issuer,
        request.expected_application_id,
        request.expected_audience,
        request.organization_id,
    )
}

/// Fetches a known application without a long-lived transport secret. The
/// signed v3 contract must echo the challenge in its registration proof.
pub async fn fetch_and_verify_challenge(
    request: DiscoveryChallengeRequest<'_>,
) -> AppResult<VerifiedApplicationManifest> {
    verify_discovery_challenge(
        request.challenge_secret,
        request.expected_issuer,
        request.challenge,
    )?;
    let body = fetch_discovery_body(
        request.discovery_url,
        None,
        Some(request.challenge),
        request.allow_private_networks,
    )
    .await?;
    let token = extract_jws(&body)?;
    let payload = verify_jws(&token, request.signing_public_jwks)?;
    let contract = parse_contract(&payload)?;
    validate_registration_contract(
        &contract,
        request.expected_issuer,
        request.expected_application_id,
        request.expected_audience,
        request.challenge,
        request.max_contract_ttl_seconds,
    )?;
    normalize_application_contract(
        &contract,
        &payload,
        request.expected_issuer,
        request.expected_application_id,
        request.expected_audience,
        request.organization_id,
    )
}

/// Performs the first fetch for an allowlisted application. Its signing key
/// is bootstrapped only from the protected JWS `jwk` header, after the origin,
/// audience, contract, and challenge proof have all been validated.
pub async fn fetch_and_verify_auto_registration(
    request: DiscoveryAutoRegistrationRequest<'_>,
) -> AppResult<(VerifiedApplicationManifest, String)> {
    verify_discovery_challenge(
        request.challenge_secret,
        request.expected_issuer,
        request.challenge,
    )?;
    let body = fetch_discovery_body(
        request.discovery_url,
        None,
        Some(request.challenge),
        request.allow_private_networks,
    )
    .await?;
    let token = extract_jws(&body)?;
    let (payload, key) = verify_jws_with_embedded_key(&token)?;
    let contract = parse_contract(&payload)?;
    validate_registration_contract(
        &contract,
        request.expected_issuer,
        &contract.application_id,
        request.expected_audience,
        request.challenge,
        request.max_contract_ttl_seconds,
    )?;
    let pinned_jwks = serde_json::to_string(&PinnedJwks { keys: vec![key] })
        .map_err(|_| AppError::Internal("failed to encode discovery signing key".to_string()))?;
    let verified = normalize_application_contract(
        &contract,
        &payload,
        request.expected_issuer,
        &contract.application_id,
        request.expected_audience,
        request.organization_id,
    )?;
    Ok((verified, pinned_jwks))
}

async fn fetch_discovery_body(
    discovery_url: &str,
    fetch_secret: Option<&str>,
    challenge: Option<&str>,
    allow_private_networks: bool,
) -> AppResult<Vec<u8>> {
    let discovery_url = validate_fetch_url(discovery_url, allow_private_networks)?;
    let resolved_address = resolve_public_host(&discovery_url, allow_private_networks).await?;
    let host = discovery_url
        .host_str()
        .ok_or_else(|| AppError::BadRequest("application discovery URL has no host".to_string()))?;
    let mut request = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        // Only private-network development endpoints may use a development
        // certificate. Public discovery always uses normal TLS validation.
        .danger_accept_invalid_certs(
            allow_private_networks && is_forbidden_ip(resolved_address.ip()),
        )
        // Pin the DNS result used for this request to close the common
        // DNS-rebinding gap between validation and connection.
        .resolve(host, resolved_address)
        .build()
        .map_err(|_| AppError::Internal("failed to build discovery HTTP client".to_string()))?
        .get(discovery_url.as_str())
        .header(
            reqwest::header::ACCEPT,
            "application/jose, application/json",
        )
        .header(reqwest::header::CACHE_CONTROL, "no-cache");
    if let Some(fetch_secret) = fetch_secret.filter(|value| !value.trim().is_empty()) {
        request = request.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {fetch_secret}"),
        );
    }
    if let Some(challenge) = challenge {
        let value = reqwest::header::HeaderValue::from_str(challenge)
            .map_err(|_| AppError::BadRequest("discovery challenge is invalid".to_string()))?;
        request = request.header("x-signet-discovery-challenge", value);
    }
    let response = request
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
    Ok(body)
}

fn validate_challenge(challenge: &str) -> AppResult<()> {
    let parts = challenge.split('.').collect::<Vec<_>>();
    if parts.len() != 5
        || parts[0] != DISCOVERY_CHALLENGE_VERSION
        || parts[1].parse::<i64>().ok().is_none_or(|value| value <= 0)
        || parts[2]
            .parse::<i64>()
            .ok()
            .is_none_or(|value| !(1..=MAX_DISCOVERY_CHALLENGE_TTL_SECONDS).contains(&value))
        || parts[3].len() < 16
        || parts[3].len() > 128
        || !parts[3]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || URL_SAFE_NO_PAD
            .decode(parts[4])
            .ok()
            .is_none_or(|value| value.len() != 32)
    {
        return Err(AppError::BadRequest(
            "discovery challenge is invalid".to_string(),
        ));
    }
    Ok(())
}

fn verify_discovery_challenge(
    secret: &str,
    expected_origin: &str,
    challenge: &str,
) -> AppResult<()> {
    validate_challenge(challenge)?;
    if secret.trim().len() < 32 {
        return Err(AppError::Configuration(
            "discovery challenge secret is not configured".to_string(),
        ));
    }
    let parts = challenge.split('.').collect::<Vec<_>>();
    let issued_at = parts[1]
        .parse::<i64>()
        .map_err(|_| AppError::BadRequest("discovery challenge is invalid".to_string()))?;
    let ttl_seconds = parts[2]
        .parse::<i64>()
        .map_err(|_| AppError::BadRequest("discovery challenge is invalid".to_string()))?;
    let now = util::now_ts();
    if issued_at > now.saturating_add(60)
        || issued_at
            .checked_add(ttl_seconds)
            .is_none_or(|expires_at| expires_at <= now)
    {
        return Err(AppError::Unauthorized);
    }
    let origin = website_origin(expected_origin)?.to_ascii_lowercase();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::Configuration("invalid discovery challenge secret".into()))?;
    mac.update(DISCOVERY_CHALLENGE_LABEL);
    mac.update(origin.as_bytes());
    mac.update(b":");
    mac.update(parts[1].as_bytes());
    mac.update(b":");
    mac.update(parts[2].as_bytes());
    mac.update(b":");
    mac.update(parts[3].as_bytes());
    let provided = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|_| AppError::BadRequest("discovery challenge is invalid".to_string()))?;
    mac.verify_slice(&provided)
        .map_err(|_| AppError::Unauthorized)
}

fn parse_contract(payload: &[u8]) -> AppResult<ApplicationContract> {
    let value = serde_json::from_slice::<Value>(payload)
        .map_err(|_| AppError::BadRequest("application discovery schema is invalid".to_string()))?;
    if value.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(AppError::BadRequest(
            "only signet-application/v3 discovery contracts are supported".to_string(),
        ));
    }
    serde_json::from_value::<ApplicationContract>(value)
        .map_err(|_| AppError::BadRequest("application v3 contract schema is invalid".to_string()))
}

fn validate_registration_contract(
    contract: &ApplicationContract,
    expected_issuer: &str,
    expected_application_id: &str,
    expected_audience: &str,
    challenge: &str,
    max_contract_ttl_seconds: i64,
) -> AppResult<()> {
    contract
        .validate(util::now_ts())
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    if crate::applications::normalize_application_slug(&contract.application_id)
        .ok()
        .as_deref()
        != Some(contract.application_id.as_str())
        || contract.application_id != expected_application_id
        || website_origin(&contract.issuer)? != website_origin(expected_issuer)?
        || !audience_contains(&contract.audience, expected_audience)
        || !audience_contains(
            &contract.audience,
            &format!("signet:application:{}", contract.application_id),
        )
    {
        return Err(AppError::Unauthorized);
    }
    validate_registration_proof(contract, expected_issuer, challenge)?;
    let lifetime = contract
        .expires_at
        .checked_sub(contract.issued_at)
        .ok_or_else(|| {
            AppError::BadRequest("application discovery lifetime is invalid".to_string())
        })?;
    if max_contract_ttl_seconds <= 0 || lifetime <= 0 || lifetime > max_contract_ttl_seconds {
        return Err(AppError::BadRequest(
            "application discovery contract lifetime exceeds the registration challenge TTL"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_registration_proof(
    contract: &ApplicationContract,
    expected_origin: &str,
    challenge: &str,
) -> AppResult<()> {
    let proof = contract
        .extensions
        .get(REGISTRATION_PROOF_EXTENSION)
        .ok_or(AppError::Unauthorized)
        .and_then(|value| {
            serde_json::from_value::<RegistrationProof>(value.clone())
                .map_err(|_| AppError::Unauthorized)
        })?;
    if proof.purpose != "application_registration"
        || proof.challenge != challenge
        || website_origin(&proof.origin).ok().as_deref() != Some(expected_origin)
    {
        return Err(AppError::Unauthorized);
    }
    Ok(())
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
    let (header, payload, signature, signing_input) = parse_jws(token)?;
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
    verify_signature(&header, key, &signing_input, &signature)?;
    Ok(payload)
}

fn verify_jws_with_embedded_key(token: &str) -> AppResult<(Vec<u8>, PinnedJwk)> {
    let (header, payload, signature, signing_input) = parse_jws(token)?;
    let key = header.jwk.clone().ok_or(AppError::Unauthorized)?;
    verify_signature(&header, &key, &signing_input, &signature)?;
    Ok((payload, key))
}

fn parse_jws(token: &str) -> AppResult<(JwsHeader, Vec<u8>, Signature, String)> {
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
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| AppError::Unauthorized)?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| AppError::Unauthorized)
        .and_then(|value| Signature::from_slice(&value).map_err(|_| AppError::Unauthorized))?;
    Ok((
        header,
        payload,
        signature,
        format!("{encoded_header}.{encoded_payload}"),
    ))
}

fn verify_signature(
    header: &JwsHeader,
    key: &PinnedJwk,
    signing_input: &str,
    signature: &Signature,
) -> AppResult<()> {
    if key.kty != "OKP"
        || key.crv != "Ed25519"
        || key.use_.as_deref().is_some_and(|value| value != "sig")
        || key.alg.as_deref().is_some_and(|value| value != "EdDSA")
        || header.kid.is_some() && header.kid.as_deref() != key.kid.as_deref()
    {
        return Err(AppError::Unauthorized);
    }
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&key.x)
        .map_err(|_| AppError::Unauthorized)?
        .try_into()
        .map_err(|_| AppError::Unauthorized)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AppError::Unauthorized)?;
    verifying_key
        .verify(signing_input.as_bytes(), signature)
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
        .map(|client| {
            normalize_contract_client(client, organization_id, &contract.modules.policies)
        })
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
    let mut redacted_payload = serde_json::to_value(contract)
        .map_err(|_| AppError::Internal("failed to encode v3 contract snapshot".to_string()))?;
    if let Some(extensions) = redacted_payload
        .get_mut("extensions")
        .and_then(Value::as_object_mut)
    {
        // A challenge is a short-lived capability, not durable application
        // configuration. Do not retain it in the verified snapshot.
        extensions.remove(REGISTRATION_PROOF_EXTENSION);
    }
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
        if roles.iter().filter(|role| role.is_default).count() > 1 {
            return Err(AppError::BadRequest(
                "v3 profile declares more than one default role".to_string(),
            ));
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
        profiles.insert(
            client.client_id.clone(),
            build_profile(&allowed_permissions)?,
        );
    }
    Ok(profiles)
}

fn contract_authorization_module(
    _profiles: &BTreeMap<String, NormalizedProfile>,
) -> AppResult<Value> {
    // Roles and their default flag are persisted in the physical profile
    // records. The module is only the non-role policy shell; serializing the
    // old `default_role`/`custom_roles` fields here would reintroduce the
    // removed application-wide role facade and is rejected by module
    // validation.
    let object = serde_json::json!({
        "inherit_enterprise_roles": true,
        "permissions": [],
        "denied_permissions": [],
        "claims": []
    })
    .as_object()
    .cloned()
    .ok_or_else(|| AppError::Internal("failed to build authorization module".to_string()))?;
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
                )));
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
    let scim = connections
        .iter()
        .filter(|connection| connection.kind == "scim")
        .collect::<Vec<_>>();
    let ldap = connections
        .iter()
        .filter(|connection| connection.kind == "ldap")
        .collect::<Vec<_>>();
    if scim.len() > 1 {
        return Err(AppError::BadRequest(
            "v3 declares more than one SCIM connection".to_string(),
        ));
    }
    let object = serde_json::json!({
        "enabled": !scim.is_empty() || !ldap.is_empty(),
        "scim_enabled": !scim.is_empty(),
        "ldap_provider_ids": ldap.iter().filter_map(|connection| connection.settings.get("provider_id").and_then(Value::as_str)).collect::<Vec<_>>(),
        "scim_audience": scim.first().and_then(|connection| connection.settings.get("audience")).and_then(Value::as_str).unwrap_or_default()
    });
    normalize_module(
        "directory_sync",
        object
            .as_object()
            .ok_or_else(|| AppError::Internal("failed to build directory sync".to_string()))?,
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
            || !parsed.username().is_empty()
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

async fn current_discovery_record(
    state: &AppState,
    application_id: &str,
) -> AppResult<ApplicationDiscoveryRecord> {
    state
        .db
        .find_application_discovery(application_id)
        .await?
        .ok_or(AppError::NotFound)
}

fn classify_apply_failure(error: &AppError) -> SyncFailureStatus {
    match error {
        // The database rejected a verified contract because it violated the
        // monotonic revision/content rules or a tenant-bound policy edge.
        // Keep the previous accepted snapshot, but expose that this revision
        // was rejected rather than making it look like a transport outage.
        AppError::BadRequest(_) | AppError::Unauthorized | AppError::Forbidden => {
            SyncFailureStatus::Rejected
        }
        // A missing application, database failure, or local configuration
        // problem leaves the outcome unknown to the reconciler.
        _ => SyncFailureStatus::Unknown,
    }
}

async fn fetch_and_verify_for_sync(
    request: DiscoveryFetchRequest<'_>,
) -> Result<VerifiedApplicationManifest, SyncFailure> {
    fetch_and_verify(request)
        .await
        .map_err(|error| match error {
            AppError::Configuration(_) => SyncFailure::unknown(error),
            error => SyncFailure::rejected(error),
        })
}

async fn fetch_and_verify_challenge_for_sync(
    request: DiscoveryChallengeRequest<'_>,
) -> Result<VerifiedApplicationManifest, SyncFailure> {
    fetch_and_verify_challenge(request)
        .await
        .map_err(|error| match error {
            AppError::Configuration(_) => SyncFailure::unknown(error),
            error => SyncFailure::rejected(error),
        })
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

    let Some(lease) = acquire_discovery_lease(state, application_id).await? else {
        return current_discovery_record(state, application_id).await;
    };

    let pending = lease.mark_status_if_owner(state, SYNC_PENDING, None).await;
    match pending {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = lease.release(state).await;
            return current_discovery_record(state, application_id).await;
        }
        Err(error) => {
            let _ = lease.release(state).await;
            return Err(error);
        }
    }

    match sync_application_once(state, &discovery).await {
        Ok(manifest) => match lease.apply_if_owner(state, manifest).await {
            Ok(Some(record)) => {
                let _ = lease.release(state).await;
                Ok(record)
            }
            Ok(None) => {
                let _ = lease.release(state).await;
                current_discovery_record(state, application_id).await
            }
            Err(error) => {
                let status = classify_apply_failure(&error);
                let marked = lease
                    .mark_status_if_owner(state, status.as_str(), Some(error.to_string()))
                    .await;
                let _ = lease.release(state).await;
                match marked {
                    Ok(Some(_)) => Err(error),
                    Ok(None) => current_discovery_record(state, application_id).await,
                    Err(mark_error) => Err(mark_error),
                }
            }
        },
        Err(failure) => {
            let SyncFailure { status, error } = failure;
            let marked = lease
                .mark_status_if_owner(state, status.as_str(), Some(error.to_string()))
                .await;
            let _ = lease.release(state).await;
            match marked {
                Ok(Some(_)) => Err(error),
                Ok(None) => current_discovery_record(state, application_id).await,
                Err(mark_error) => Err(mark_error),
            }
        }
    }
}

async fn sync_application_once(
    state: &AppState,
    discovery: &ApplicationDiscoveryRecord,
) -> Result<VerifiedApplicationManifest, SyncFailure> {
    if discovery.signing_public_jwks.trim().is_empty() {
        return Err(SyncFailure::unknown(AppError::Configuration(
            "website-managed application discovery trust is not configured".to_string(),
        )));
    }
    let website_issuer = website_origin(&discovery.website_url).map_err(SyncFailure::unknown)?;
    let discovery_url =
        default_discovery_url(&discovery.website_url).map_err(SyncFailure::unknown)?;
    let expected_audience = state.settings.oidc.issuer.trim_end_matches('/').to_string();
    if expected_audience.is_empty() {
        return Err(SyncFailure::unknown(AppError::Configuration(
            "oidc issuer is not configured".to_string(),
        )));
    }
    let application = state
        .db
        .find_application_by_id(&discovery.application_id)
        .await
        .map_err(SyncFailure::unknown)?
        .ok_or_else(|| SyncFailure::unknown(AppError::NotFound))?;
    if discovery.fetch_secret_ciphertext.trim().is_empty() {
        let challenge = new_discovery_challenge(
            &state.settings.discovery.challenge_secret,
            &website_issuer,
            state
                .settings
                .discovery
                .auto_registration
                .challenge_ttl_seconds,
        )
        .map_err(SyncFailure::unknown)?;
        fetch_and_verify_challenge_for_sync(DiscoveryChallengeRequest {
            discovery_url: &discovery_url,
            signing_public_jwks: &discovery.signing_public_jwks,
            expected_issuer: &website_issuer,
            expected_application_id: &application.slug,
            expected_audience: &expected_audience,
            organization_id: &application.organization_id,
            challenge: &challenge,
            challenge_secret: &state.settings.discovery.challenge_secret,
            max_contract_ttl_seconds: state
                .settings
                .discovery
                .auto_registration
                .challenge_ttl_seconds,
            allow_private_networks: state.settings.discovery.allow_private_networks,
        })
        .await
    } else {
        if state.settings.discovery.encryption_key.trim().is_empty() {
            return Err(SyncFailure::unknown(AppError::Configuration(
                "discovery encryption key is not configured".to_string(),
            )));
        }
        let fetch_secret = util::decrypt_discovery_secret(
            &state.settings.discovery.encryption_key,
            &discovery.fetch_secret_ciphertext,
        )
        .map_err(SyncFailure::unknown)?;
        fetch_and_verify_for_sync(DiscoveryFetchRequest {
            discovery_url: &discovery_url,
            fetch_secret: &fetch_secret,
            signing_public_jwks: &discovery.signing_public_jwks,
            expected_issuer: &website_issuer,
            expected_application_id: &application.slug,
            expected_audience: &expected_audience,
            organization_id: &application.organization_id,
            allow_private_networks: state.settings.discovery.allow_private_networks,
        })
        .await
    }
}

/// Attempts all website-managed applications and keeps one failed website
/// from preventing the remaining applications from refreshing.
pub async fn sync_all(state: &AppState) -> AppResult<()> {
    let mut auto_registered_applications = BTreeSet::new();
    if state.settings.discovery.auto_registration.enabled
        && state.settings.discovery.auto_registration.startup_scan
    {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            state.settings.discovery.auto_registration.max_concurrency,
        ));
        let mut tasks = Vec::new();
        for entry in state.settings.discovery.auto_registration.allowlist.clone() {
            let semaphore = semaphore.clone();
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                let origin = entry.origin.clone();
                let result = match semaphore.acquire_owned().await {
                    Ok(permit) => {
                        let _permit = permit;
                        auto_register_application(&state, &origin).await
                    }
                    Err(_) => Err(AppError::Internal(
                        "automatic discovery semaphore was closed".to_string(),
                    )),
                };
                (origin, result)
            }));
        }
        for task in tasks {
            match task.await {
                Ok((_origin, Ok(record))) => {
                    auto_registered_applications.insert(record.application_id);
                }
                Ok((origin, Err(error))) => {
                    tracing::warn!(
                        origin = %origin,
                        error = %error,
                        "automatic application discovery failed"
                    );
                }
                Err(error) => {
                    tracing::warn!(error = %error, "automatic discovery task panicked");
                }
            }
        }
    }
    let website_discoveries = state.db.list_website_managed_discoveries().await?;
    if website_discoveries.len() > MAX_DISCOVERY_SWEEP_APPLICATIONS {
        return Err(AppError::Internal(format!(
            "website application discovery sweep exceeds the safety limit of {MAX_DISCOVERY_SWEEP_APPLICATIONS} applications"
        )));
    }
    let semaphore = Arc::new(Semaphore::new(
        state
            .settings
            .discovery
            .auto_registration
            .max_concurrency
            .max(1),
    ));
    let mut tasks = Vec::new();
    for (application, discovery) in website_discoveries {
        if auto_registered_applications.contains(&application.id) {
            continue;
        }
        if discovery.operator_disabled != 0 {
            continue;
        }
        let semaphore = semaphore.clone();
        let state = state.clone();
        let application_id = application.id;
        let application_slug = application.slug;
        tasks.push(tokio::spawn(async move {
            let result = match semaphore.acquire_owned().await {
                Ok(permit) => {
                    let _permit = permit;
                    sync_application(&state, &application_id).await
                }
                Err(_) => Err(AppError::Internal(
                    "website discovery semaphore was closed".to_string(),
                )),
            };
            (application_slug, result)
        }));
    }
    for task in tasks {
        match task.await {
            Ok((_application_slug, Ok(_record))) => {}
            Ok((application_slug, Err(error))) => {
                tracing::warn!(
                    application_id = %application_slug,
                    error = %error,
                    "website application discovery sync failed"
                );
            }
            Err(error) => {
                tracing::warn!(error = %error, "website discovery sync task panicked");
            }
        }
    }
    Ok(())
}

/// Handle for the process-local discovery scheduler. Discovery ownership is
/// still durable in the database, but retaining the task handle lets graceful
/// shutdown stop future sweeps and wait for the current sweep to finish.
pub struct DiscoverySyncWorker {
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl DiscoverySyncWorker {
    pub async fn stop(mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        let _ = self.task.await;
    }
}

/// Starts the periodic refresh loop. The first refresh is performed during
/// startup by `main`; this task waits one full interval before its first tick
/// so startup never creates an avoidable duplicate request.
pub fn spawn_periodic_sync(state: AppState) -> DiscoverySyncWorker {
    let interval_seconds = state.settings.discovery.sync_interval_seconds.max(30) as u64;
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let interval = Duration::from_secs(interval_seconds);
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(Instant::now() + interval, interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                _ = interval.tick() => {
                    if let Err(error) = sync_all(&state).await {
                        tracing::warn!(error = %error, "website application discovery sweep failed");
                    }
                }
            }
        }
        tracing::debug!("website application discovery worker stopped");
    });
    DiscoverySyncWorker {
        stop_tx: Some(stop_tx),
        task,
    }
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
        assert_eq!(
            verified.authorization.get("inherit_enterprise_roles"),
            Some(&serde_json::Value::Bool(true))
        );
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
        assert!(verified.clients[0].require_s256_pkce);
        let worker = verified
            .clients
            .iter()
            .find(|client| client.client_id == "worker")
            .unwrap();
        assert!(worker.require_dpop);
        assert_eq!(worker.service_account_permissions, vec!["axon.read"]);
        assert!(
            verified.profiles["worker"]
                .permissions
                .iter()
                .all(|permission| permission.key != "axon.admin")
        );
        assert_eq!(
            verified.protocols["saml2"]["enabled"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(verified.profiles["default"].roles[0].key, "member");
        assert!(
            verified.profiles["default"]
                .permissions
                .iter()
                .any(|permission| permission.key == "axon.read")
        );
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

    #[test]
    fn website_runtime_gate_uses_canonical_management_mode() {
        assert!(!website_discovery_runtime_active(
            MANAGEMENT_MODE_WEBSITE,
            false,
            None,
            None,
            false,
            100,
        ));
        assert!(website_discovery_runtime_active(
            MANAGEMENT_MODE_WEBSITE,
            false,
            Some(1),
            Some(101),
            true,
            100,
        ));
        assert!(!website_discovery_runtime_active(
            MANAGEMENT_MODE_WEBSITE,
            false,
            Some(1),
            Some(100),
            true,
            100,
        ));
        // `website` was an incorrect caller-side spelling. It must not
        // accidentally turn an unverified website-managed record into a
        // fail-closed record through a second, divergent policy.
        assert!(website_discovery_runtime_active(
            "website", false, None, None, false, 100,
        ));
    }

    #[test]
    fn v3_registration_proof_binds_the_challenge_and_origin() {
        let secret = "01234567890123456789012345678901";
        let origin = "https://axon.example";
        let challenge = new_discovery_challenge(secret, origin, 300).unwrap();
        let now = util::now_ts();
        let contract: ApplicationContract = serde_json::from_value(serde_json::json!({
            "format": FORMAT,
            "application_id": "axon",
            "revision": 1,
            "version": "v3-registration",
            "iss": origin,
            "aud": ["https://sso.example", "signet:application:axon"],
            "iat": now,
            "exp": now + 300,
            "modules": {
                "lifecycle": {
                    "mode": "replace",
                    "fail_closed": true,
                    "revoke_removed_clients": true,
                    "allow_downgrade": false
                }
            },
            "extensions": {
                "registration_proof": {
                    "purpose": "application_registration",
                    "origin": "HTTPS://Axon.Example/",
                    "challenge": challenge
                }
            }
        }))
        .unwrap();

        assert!(
            verify_discovery_challenge(secret, origin, &challenge).is_ok(),
            "generated challenge must verify"
        );
        assert!(verify_discovery_challenge(secret, "https://other.example", &challenge).is_err());
        assert!(
            validate_registration_contract(
                &contract,
                origin,
                "axon",
                "https://sso.example",
                &challenge,
                300,
            )
            .is_ok()
        );

        let mut wrong_proof = contract.clone();
        wrong_proof
            .extensions
            .get_mut(REGISTRATION_PROOF_EXTENSION)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "challenge".to_string(),
                Value::String("wrong-challenge".to_string()),
            );
        assert!(
            validate_registration_contract(
                &wrong_proof,
                origin,
                "axon",
                "https://sso.example",
                &challenge,
                300,
            )
            .is_err()
        );
    }

    #[test]
    fn registration_proof_does_not_change_the_v3_content_digest() {
        let base = serde_json::json!({
            "format": FORMAT,
            "application_id": "axon",
            "revision": 1,
            "version": "v3-registration",
            "iss": "https://axon.example",
            "aud": ["https://sso.example", "signet:application:axon"],
            "iat": 100,
            "exp": 400,
            "modules": {},
            "extensions": {
                "registration_proof": {
                    "purpose": "application_registration",
                    "origin": "https://axon.example",
                    "challenge": "challenge-a"
                }
            }
        });
        let mut changed = base.clone();
        changed["extensions"][REGISTRATION_PROOF_EXTENSION]["challenge"] =
            serde_json::json!("challenge-b");
        assert_eq!(
            manifest_content_digest(&serde_json::to_vec(&base).unwrap()).unwrap(),
            manifest_content_digest(&serde_json::to_vec(&changed).unwrap()).unwrap()
        );
    }

    #[test]
    fn embedded_v3_signing_key_can_bootstrap_auto_registration() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let payload = serde_json::json!({
            "format": FORMAT,
            "application_id": "axon"
        });
        let encoded_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "EdDSA",
                "kid": "key-1",
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                    "kid": "key-1",
                    "use": "sig",
                    "alg": "EdDSA"
                }
            }))
            .unwrap(),
        );
        let encoded_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );

        let (decoded, pinned_key) = verify_jws_with_embedded_key(&token).unwrap();
        assert_eq!(decoded, serde_json::to_vec(&payload).unwrap());
        assert_eq!(pinned_key.kid.as_deref(), Some("key-1"));
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

        let verified = fetch_and_verify(DiscoveryFetchRequest {
            discovery_url: &format!("http://127.0.0.1:{}{}", address.port(), DISCOVERY_PATH),
            fetch_secret: &fetch_secret,
            signing_public_jwks: &jwks,
            expected_issuer: "https://axon.example",
            expected_application_id: "axon",
            expected_audience: "https://sso.example",
            organization_id: "org-1",
            allow_private_networks: true,
        })
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

    #[test]
    fn sync_outcomes_have_explicit_runtime_statuses() {
        assert_eq!(SyncFailureStatus::Rejected.as_str(), SYNC_REJECTED);
        assert_eq!(SyncFailureStatus::Unknown.as_str(), SYNC_UNKNOWN);
        assert_eq!(SYNC_SYNCED, SYNC_ACCEPTED);
        assert_eq!(
            classify_apply_failure(&AppError::BadRequest("stale".into())).as_str(),
            SYNC_REJECTED
        );
    }

    #[test]
    fn application_commit_gate_is_shared_only_as_a_local_optimization() {
        let application_id = format!("lease-test-{}", uuid::Uuid::new_v4());
        let first = discovery_commit_gate(&application_id);
        let second = discovery_commit_gate(&application_id);
        assert!(Arc::ptr_eq(&first, &second));
    }
}
