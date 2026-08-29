//! Application-domain policy.
//!
//! An OIDC client is an integration endpoint, while an application is the
//! tenant-owned authorization domain.  Keeping the policy here prevents a
//! UI-only account picker from becoming the security boundary.

use crate::{
    AppState,
    auth_domain::ClientBinding,
    db::{
        ApplicationClientBindingRecord, ApplicationModuleRecord, ApplicationRecord,
        AuthorizationPolicySnapshot, ClientRecord, UserRecord,
    },
    error::{AppError, AppResult},
    organizations::normalize_slug,
};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};

pub const ACCESS_ASSIGNED_ACCOUNTS: &str = "assigned_accounts";
pub const ACCESS_ORGANIZATION_MEMBERS: &str = "organization_members";
/// Product default: a website application is available to every active
/// account in Signet.  Application membership is not required for login.
pub const ACCESS_ALL_SIGNET_USERS: &str = "all_users";
/// Compatibility setting for pre-application clients. New applications may
/// not be created with this mode.
pub const ACCESS_LEGACY_ALL_USERS: &str = "legacy_all_users";

pub const REGISTRATION_DISABLED: &str = "disabled";
pub const REGISTRATION_INVITATION: &str = "invitation";
pub const REGISTRATION_ORGANIZATION_MEMBERS: &str = "organization_members";
pub const REGISTRATION_LEGACY: &str = "legacy";

pub const ACCOUNT_SELECTION_OPTIONAL: &str = "optional";
pub const ACCOUNT_SELECTION_REQUIRED: &str = "required";

pub const FACTOR_EMAIL: &str = "email";
pub const FACTOR_PHONE: &str = "phone";

/// A provider with no organization is a platform-managed shared connector;
/// an owned connector may only be consumed by the same enterprise as the
/// website application. Keeping this rule as a small pure policy function
/// makes every binding path (write-time validation and runtime defense) use
/// the same semantics.
pub fn organization_binding_is_allowed(
    application_organization_id: &str,
    resource_organization_id: Option<&str>,
) -> bool {
    resource_organization_id
        .is_none_or(|organization_id| organization_id == application_organization_id)
}

/// Validates the stable shape shared by the management UI and the runtime
/// adapters while preserving unknown keys for forward-compatible module
/// extensions. The application module table is deliberately generic, but it
/// must not become an untyped escape hatch for malformed configuration.
pub fn normalize_module_config(module_key: &str, value: Value) -> AppResult<Value> {
    let object = value.as_object().ok_or_else(|| {
        AppError::BadRequest(format!(
            "application module {module_key} config must be a JSON object"
        ))
    })?;

    match module_key {
        "protocols" => {
            validate_string_field(object, "website_url")?;
            validate_protocol_config(object, "oauth2_oidc", &["client_ids"])?;
            validate_protocol_config(object, "saml2", &[])?;
            validate_saml_protocol_config(object)?;
            validate_protocol_config(object, "cas", &["service_urls", "proxy_callback_urls"])?;
            validate_cas_protocol_config(object)?;
            validate_protocol_config(object, "jwt", &["redirect_uris"])?;
            validate_protocol_config(object, "iap", &["client_ids"])?;
            validate_protocol_config(object, "forward_auth", &["client_ids"])?;
            validate_jwt_client_type(object)?;
        }
        "login_adapters" => {
            validate_bool_field(object, "enabled")?;
            validate_bool_field(object, "allow_signet_password")?;
            validate_string_list_field(object, "provider_ids")?;
        }
        "directory_sync" => {
            validate_bool_field(object, "enabled")?;
            validate_bool_field(object, "scim_enabled")?;
            validate_bool_field(object, "sync_groups")?;
            validate_bool_field(object, "reactivate_users")?;
            validate_string_field(object, "scim_audience")?;
            validate_string_list_field(object, "ldap_provider_ids")?;
            validate_directory_sync_config(object)?;
            validate_scim_config(object)?;
        }
        "authorization" => {
            validate_bool_field(object, "inherit_enterprise_roles")?;
            validate_string_list_field(object, "claims")?;
            validate_string_list_field(object, "permissions")?;
            validate_string_list_field(object, "denied_permissions")?;
            for field in [
                "default_role",
                "custom_roles",
                "group_mappings",
                "organization_role_mappings",
            ] {
                if object.contains_key(field) {
                    return Err(AppError::BadRequest(format!(
                        "application authorization roles must be managed through profiles; remove {field} from the module config"
                    )));
                }
            }
        }
        _ => {
            return Err(AppError::BadRequest(format!(
                "unsupported application module: {module_key}"
            )));
        }
    }

    Ok(value)
}

fn validate_bool_field(object: &Map<String, Value>, field: &str) -> AppResult<()> {
    if object.get(field).is_some_and(|value| !value.is_boolean()) {
        return Err(AppError::BadRequest(format!(
            "application module field {field} must be a boolean"
        )));
    }
    Ok(())
}

fn validate_string_field(object: &Map<String, Value>, field: &str) -> AppResult<()> {
    if object.get(field).is_some_and(|value| !value.is_string()) {
        return Err(AppError::BadRequest(format!(
            "application module field {field} must be a string"
        )));
    }
    Ok(())
}

fn validate_string_list_field(object: &Map<String, Value>, field: &str) -> AppResult<()> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let Some(values) = value.as_array() else {
        return Err(AppError::BadRequest(format!(
            "application module field {field} must be a string list"
        )));
    };
    if values.iter().any(|value| !value.is_string()) {
        return Err(AppError::BadRequest(format!(
            "application module field {field} must be a string list"
        )));
    }
    Ok(())
}

fn validate_protocol_config(
    object: &Map<String, Value>,
    protocol: &str,
    string_list_fields: &[&str],
) -> AppResult<()> {
    let Some(value) = object.get(protocol) else {
        return Ok(());
    };
    let nested = value.as_object().ok_or_else(|| {
        AppError::BadRequest(format!(
            "application protocol {protocol} config must be a JSON object"
        ))
    })?;
    validate_bool_field(nested, "enabled")?;
    for field in string_list_fields {
        validate_string_list_field(nested, field)?;
    }
    for field in [
        "entity_id",
        "acs_url",
        "service_validate_url",
        "audience",
        "client_id",
        "client_type",
    ] {
        validate_string_field(nested, field)?;
    }
    if nested
        .get("token_ttl_seconds")
        .is_some_and(|value| !(value.is_u64() || value.is_i64()))
    {
        return Err(AppError::BadRequest(
            "application protocol token_ttl_seconds must be an integer".to_string(),
        ));
    }
    Ok(())
}

fn validate_jwt_client_type(object: &Map<String, Value>) -> AppResult<()> {
    let Some(jwt) = object.get("jwt").and_then(Value::as_object) else {
        return Ok(());
    };
    if let Some(client_type) = jwt.get("client_type").and_then(Value::as_str)
        && !matches!(client_type.trim(), "public" | "confidential")
    {
        return Err(AppError::BadRequest(
            "application JWT client_type must be public or confidential".to_string(),
        ));
    }
    Ok(())
}

fn validate_cas_protocol_config(object: &Map<String, Value>) -> AppResult<()> {
    let Some(cas) = object.get("cas").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_bool_field(cas, "allow_proxy")?;
    for field in ["ticket_ttl_seconds", "pgt_ttl_seconds"] {
        if cas
            .get(field)
            .is_some_and(|value| !(value.is_u64() || value.is_i64()))
        {
            return Err(AppError::BadRequest(format!(
                "application CAS {field} must be an integer"
            )));
        }
    }
    Ok(())
}

const DIRECTORY_SYNC_MAX_ENTRIES: u64 = 100_000;
const DIRECTORY_SYNC_MAX_FILTER_LENGTH: usize = 4_096;
const DIRECTORY_SYNC_MAX_BASE_DN_LENGTH: usize = 2_048;
const DIRECTORY_SYNC_MAX_ATTRIBUTE_LENGTH: usize = 128;

fn validate_directory_sync_config(object: &Map<String, Value>) -> AppResult<()> {
    for field in [
        "user_sync_filter",
        "group_base_dn",
        "group_filter",
        "group_id_attribute",
        "group_name_attribute",
        "group_member_attribute",
        "deprovision_action",
    ] {
        validate_string_field(object, field)?;
    }
    validate_ldap_filter_field(object, "user_sync_filter")?;
    validate_ldap_filter_field(object, "group_filter")?;
    validate_bounded_text_field(object, "group_base_dn", DIRECTORY_SYNC_MAX_BASE_DN_LENGTH)?;
    for field in [
        "group_id_attribute",
        "group_name_attribute",
        "group_member_attribute",
    ] {
        validate_ldap_attribute_field(object, field)?;
    }

    if let Some(value) = object.get("ldap_provider_ids") {
        let values = value.as_array().ok_or_else(|| {
            AppError::BadRequest(
                "application module field ldap_provider_ids must be a string list".to_string(),
            )
        })?;
        if values.len() > 128
            || values.iter().any(|value| {
                value
                    .as_str()
                    .is_none_or(|value| value.trim().is_empty() || value.len() > 128)
            })
        {
            return Err(AppError::BadRequest(
                "application directory sync provider ids are invalid".to_string(),
            ));
        }
    }

    if let Some(value) = object.get("max_entries") {
        let Some(max_entries) = value.as_u64() else {
            return Err(AppError::BadRequest(
                "application directory sync max_entries must be an unsigned integer".to_string(),
            ));
        };
        if !(1..=DIRECTORY_SYNC_MAX_ENTRIES).contains(&max_entries) {
            return Err(AppError::BadRequest(format!(
                "application directory sync max_entries must be between 1 and {DIRECTORY_SYNC_MAX_ENTRIES}"
            )));
        }
    }

    if let Some(action) = object.get("deprovision_action").and_then(Value::as_str)
        && action.trim() != "remove_membership"
    {
        return Err(AppError::BadRequest(
            "application directory sync currently supports only remove_membership deprovisioning"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_ldap_filter_field(object: &Map<String, Value>, field: &str) -> AppResult<()> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let filter = value.as_str().map(str::trim).ok_or_else(|| {
        AppError::BadRequest(format!(
            "application directory sync {field} must be a string"
        ))
    })?;
    // An empty application override deliberately means “use the provider's
    // safe default” (or the built-in group filter). The connector expands
    // that default before issuing an LDAP query.
    if filter.is_empty() {
        return Ok(());
    }
    if filter.len() > DIRECTORY_SYNC_MAX_FILTER_LENGTH
        || !filter.starts_with('(')
        || !filter.ends_with(')')
        || filter.bytes().any(|byte| byte == 0 || byte < 0x20)
    {
        return Err(AppError::BadRequest(format!(
            "application directory sync {field} is invalid"
        )));
    }

    let mut depth = 0usize;
    let mut escaped = false;
    for byte in filter.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'(' => depth += 1,
            b')' => {
                if depth == 0 {
                    return Err(AppError::BadRequest(format!(
                        "application directory sync {field} is invalid"
                    )));
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    if escaped || depth != 0 {
        return Err(AppError::BadRequest(format!(
            "application directory sync {field} is invalid"
        )));
    }
    Ok(())
}

fn validate_bounded_text_field(
    object: &Map<String, Value>,
    field: &str,
    max_length: usize,
) -> AppResult<()> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let text = value.as_str().map(str::trim).ok_or_else(|| {
        AppError::BadRequest(format!(
            "application directory sync {field} must be a string"
        ))
    })?;
    if text.len() > max_length || text.bytes().any(|byte| byte == 0 || byte < 0x20) {
        return Err(AppError::BadRequest(format!(
            "application directory sync {field} is invalid"
        )));
    }
    Ok(())
}

fn validate_ldap_attribute_field(object: &Map<String, Value>, field: &str) -> AppResult<()> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let attribute = value.as_str().map(str::trim).ok_or_else(|| {
        AppError::BadRequest(format!(
            "application directory sync {field} must be a string"
        ))
    })?;
    if attribute.is_empty() || attribute.len() > DIRECTORY_SYNC_MAX_ATTRIBUTE_LENGTH {
        return Err(AppError::BadRequest(format!(
            "application directory sync {field} is invalid"
        )));
    }
    if attribute.eq_ignore_ascii_case("dn") {
        return Ok(());
    }
    let mut chars = attribute.chars();
    let valid_first = chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch.is_ascii_digit());
    let valid_rest = chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | ';' | '.'));
    if !valid_first || !valid_rest {
        return Err(AppError::BadRequest(format!(
            "application directory sync {field} is invalid"
        )));
    }
    Ok(())
}

fn validate_scim_config(object: &Map<String, Value>) -> AppResult<()> {
    if object.get("scim_enabled").and_then(Value::as_bool) != Some(true) {
        return Ok(());
    }
    let audience = object
        .get("scim_audience")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::BadRequest(
                "enabled application SCIM requires an explicit audience".to_string(),
            )
        })?;
    let parsed = url::Url::parse(audience).map_err(|_| {
        AppError::BadRequest("application SCIM audience must be an absolute URL".to_string())
    })?;
    if !matches!(parsed.scheme(), "https" | "http")
        || parsed.host_str().is_none()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(AppError::BadRequest(
            "application SCIM audience must be an absolute URL without credentials or fragment"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_saml_protocol_config(object: &Map<String, Value>) -> AppResult<()> {
    let Some(saml) = object.get("saml2").and_then(Value::as_object) else {
        return Ok(());
    };
    for field in [
        "idp_entity_id",
        "sp_entity_id",
        "entity_id",
        "acs_url",
        "slo_url",
        "name_id_claim",
        "name_id_format",
        "response_binding",
        "sp_metadata_xml",
        "sp_signing_certificate",
    ] {
        validate_string_field(saml, field)?;
    }
    for field in [
        "require_signed_requests",
        "want_assertions_signed",
        "require_signed_logout",
        "want_logout_responses_signed",
    ] {
        validate_bool_field(saml, field)?;
    }
    if let Some(index) = saml.get("acs_index")
        && index.as_u64().is_none_or(|value| value > u16::MAX as u64)
    {
        return Err(AppError::BadRequest(
            "application SAML acs_index must be an unsigned 16-bit integer".to_string(),
        ));
    }
    if let Some(binding) = saml.get("response_binding").and_then(Value::as_str)
        && !matches!(binding.trim().to_ascii_lowercase().as_str(), "post")
    {
        return Err(AppError::BadRequest(
            "application SAML response_binding must be post".to_string(),
        ));
    }
    if let Some(metadata) = saml.get("sp_metadata_xml").and_then(Value::as_str)
        && metadata.len() > 512 * 1024
    {
        return Err(AppError::BadRequest(
            "application SAML SP metadata is too large".to_string(),
        ));
    }
    let Some(attributes) = saml.get("attributes") else {
        return Ok(());
    };
    let attributes = attributes.as_array().ok_or_else(|| {
        AppError::BadRequest("application SAML attributes must be a list".to_string())
    })?;
    if attributes.len() > 128 {
        return Err(AppError::BadRequest(
            "application SAML attributes are limited to 128 entries".to_string(),
        ));
    }
    for attribute in attributes {
        let attribute = attribute.as_object().ok_or_else(|| {
            AppError::BadRequest("application SAML attribute entries must be objects".to_string())
        })?;
        for field in ["name", "claim", "name_format", "value_type"] {
            validate_string_field(attribute, field)?;
        }
    }
    Ok(())
}

async fn application_module(
    state: &AppState,
    application_id: &str,
    module_key: &str,
) -> AppResult<Option<ApplicationModuleRecord>> {
    state
        .db
        .find_application_module(application_id, module_key)
        .await
}

/// Returns the validated configuration of an enabled application module.
///
/// Runtime adapters use this boundary instead of decoding
/// `application_modules.config_json` themselves.  Keeping the enabled-state
/// check here makes a module disable immediately effective for every protocol
/// and prevents one handler from accidentally retaining a stale configuration
/// path.
pub async fn enabled_module_config(
    state: &AppState,
    application_id: &str,
    module_key: &str,
) -> AppResult<Option<Map<String, Value>>> {
    let Some(module) = application_module(state, application_id, module_key).await? else {
        return Ok(None);
    };
    if module.is_enabled != 1 {
        return Ok(None);
    }
    let config = module_config(&module)?;
    let normalized = normalize_module_config(module_key, Value::Object(config))?;
    Ok(Some(normalized.as_object().cloned().ok_or_else(|| {
        AppError::Internal("application module config is not an object".to_string())
    })?))
}

/// Immutable request boundary for an application-owned protocol connection.
/// The control-plane binding and application row are resolved together before
/// any data-plane authorization decision is made; callers must not reuse this
/// value across requests.
#[derive(Debug, Clone)]
pub struct ApplicationBoundarySnapshot {
    pub application: ApplicationRecord,
    pub binding: ApplicationClientBindingRecord,
}

/// Transactionally materialized application/client runtime boundary.
/// `policy` is intentionally retained so a user-bearing authorization path can
/// hand the exact database snapshot forward without reopening the pool.  When
/// loaded without a user it is a runtime-only projection; callers must not use
/// it as a user authorization decision.
#[derive(Debug, Clone)]
pub struct ApplicationRuntimeSnapshot {
    pub policy: AuthorizationPolicySnapshot,
    pub application: ApplicationRecord,
    pub binding: ApplicationClientBindingRecord,
}

impl ApplicationRuntimeSnapshot {
    pub async fn load(
        state: &AppState,
        client: &ClientRecord,
        required_protocol: Option<&str>,
    ) -> AppResult<Self> {
        let policy = state
            .db
            .load_client_runtime_snapshot(&client.id, required_protocol)
            .await?;
        let runtime_active = if required_protocol.is_some() {
            policy.is_interactive_client_runtime_active()
        } else {
            policy.is_application_client_runtime_active()
        };
        if !runtime_active
            || policy.client_id.as_deref() != Some(client.id.as_str())
            || policy.client_organization_id.as_deref() != client.organization_id.as_deref()
        {
            return Err(AppError::Forbidden);
        }
        let application = policy.application.clone().ok_or(AppError::Forbidden)?;
        let binding = policy.binding.clone().ok_or(AppError::Forbidden)?;
        Ok(Self {
            policy,
            application,
            binding,
        })
    }

    pub fn require_interactive(&self) -> AppResult<()> {
        if self.policy.is_interactive_client_runtime_active() {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    pub fn require_service(&self) -> AppResult<()> {
        if self.policy.is_application_client_runtime_active() {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

pub async fn resolve_application_boundary(
    state: &AppState,
    client: &ClientRecord,
) -> AppResult<ApplicationBoundarySnapshot> {
    let runtime = ApplicationRuntimeSnapshot::load(state, client, None).await?;
    Ok(ApplicationBoundarySnapshot {
        application: runtime.application,
        binding: runtime.binding,
    })
}

/// Control-plane deletion preflight.  The actual destructive operation still
/// belongs to `Db::delete_application`; the database layer must accept this
/// expected organization/application revision in one transaction before a
/// handler can claim deletion is fully TOCTOU-safe.
pub async fn application_deletion_boundary(
    state: &AppState,
    application_id: &str,
    expected_organization_id: &str,
) -> AppResult<ApplicationRecord> {
    let application = state
        .db
        .find_application_by_id(application_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if application.organization_id != expected_organization_id {
        return Err(AppError::Forbidden);
    }
    Ok(application)
}

/// Applies the live lifecycle gate shared by every application-owned runtime
/// adapter. Configuration reads are intentionally not enough: a disabled
/// enterprise must immediately disable all of its websites, even when a
/// caller already has a cached ApplicationRecord.
pub async fn ensure_application_runtime_active(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<()> {
    if application.is_active != 1 {
        return Err(AppError::Forbidden);
    }
    let organization = state
        .db
        .find_organization_by_id(&application.organization_id)
        .await?
        .ok_or(AppError::Forbidden)?;
    if organization.is_active != 1 {
        return Err(AppError::Forbidden);
    }
    if let Some(discovery) = state.db.find_application_discovery(&application.id).await?
        && !crate::application_discovery::website_discovery_runtime_active(
            &discovery.management_mode,
            discovery.operator_disabled != 0,
            discovery.last_verified_revision,
            discovery.last_verified_expires_at,
            discovery.snapshot_json.is_some(),
            crate::util::now_ts(),
        )
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Returns the validated protocol-specific configuration for an application.
/// Protocol handlers use this accessor instead of reaching into the generic
/// module record themselves, which keeps the module table out of the public
/// runtime contract and gives every protocol the same enabled-state rules.
pub async fn enabled_protocol_config(
    state: &AppState,
    application_id: &str,
    protocol: &str,
) -> AppResult<Option<Map<String, Value>>> {
    let Some(config) = enabled_module_config(state, application_id, "protocols").await? else {
        return Ok(None);
    };
    let Some(protocol_config) = config.get(protocol).and_then(Value::as_object) else {
        return Ok(None);
    };
    if protocol_config.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    Ok(Some(protocol_config.clone()))
}

/// Validates database-backed references before a generic application module
/// is persisted. JSON shape validation alone cannot establish tenant
/// ownership, and allowing an organization administrator to smuggle another
/// organization's client/provider id into a module would bypass the UI's
/// filtering.
pub async fn validate_module_bindings(
    state: &AppState,
    application: &ApplicationRecord,
    module_key: &str,
    config: &Map<String, Value>,
) -> AppResult<()> {
    match module_key {
        "protocols" => {
            let client_ids = config
                .values()
                .filter_map(Value::as_object)
                .filter_map(|protocol| protocol.get("client_ids"))
                .filter_map(Value::as_array)
                .flatten()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>();
            if !client_ids.is_empty() {
                let bound_clients = state.db.list_application_clients(&application.id).await?;
                let mut bound_ids = BTreeSet::new();
                for client in &bound_clients {
                    if client_ids.contains(&client.id) {
                        if client.organization_id.as_deref()
                            != Some(application.organization_id.as_str())
                        {
                            return Err(AppError::Forbidden);
                        }
                        bound_ids.insert(client.id.clone());
                    }
                }
                let missing_client_ids = client_ids
                    .difference(&bound_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                if !missing_client_ids.is_empty() {
                    let existing_clients =
                        state.db.list_clients_by_ids(&missing_client_ids).await?;
                    let existing_clients = existing_clients
                        .into_iter()
                        .map(|client| (client.id.clone(), client))
                        .collect::<HashMap<_, _>>();
                    for client_id in missing_client_ids {
                        let client = existing_clients.get(&client_id).ok_or_else(|| {
                            AppError::BadRequest("protocol client does not exist".to_string())
                        })?;
                        if client.organization_id.as_deref()
                            != Some(application.organization_id.as_str())
                        {
                            return Err(AppError::Forbidden);
                        }
                    }
                    return Err(AppError::Forbidden);
                }
            }
        }
        "login_adapters" => {
            let provider_ids = config
                .get("provider_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            let provider_ids = provider_ids.map(ToOwned::to_owned).collect::<BTreeSet<_>>();
            let providers = state
                .db
                .list_external_oidc_providers_by_ids(
                    &provider_ids.iter().cloned().collect::<Vec<_>>(),
                )
                .await?
                .into_iter()
                .map(|provider| (provider.id.clone(), provider))
                .collect::<HashMap<_, _>>();
            for provider_id in provider_ids {
                let provider = providers.get(&provider_id).ok_or_else(|| {
                    AppError::BadRequest("external OIDC provider does not exist".to_string())
                })?;
                if !organization_binding_is_allowed(
                    &application.organization_id,
                    provider.organization_id.as_deref(),
                ) {
                    return Err(AppError::Forbidden);
                }
            }
        }
        "directory_sync" => {
            let provider_ids = config
                .get("ldap_provider_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>();
            if !provider_ids.is_empty() {
                let providers = state
                    .db
                    .list_ldap_providers_by_ids(&provider_ids.iter().cloned().collect::<Vec<_>>())
                    .await?
                    .into_iter()
                    .map(|provider| (provider.id.clone(), provider))
                    .collect::<HashMap<_, _>>();
                for provider_id in provider_ids {
                    let provider = providers.get(&provider_id).ok_or_else(|| {
                        AppError::BadRequest("LDAP provider does not exist".to_string())
                    })?;
                    if !organization_binding_is_allowed(
                        &application.organization_id,
                        provider.organization_id.as_deref(),
                    ) {
                        return Err(AppError::Forbidden);
                    }
                }
            }
        }
        "authorization" => {}
        _ => {
            return Err(AppError::BadRequest(format!(
                "unsupported application module: {module_key}"
            )));
        }
    }
    Ok(())
}

pub async fn application_website_url(
    state: &AppState,
    application_id: &str,
) -> AppResult<Option<String>> {
    let Some(module) = application_module(state, application_id, "protocols").await? else {
        return Ok(None);
    };
    let config = module_config(&module)?;
    Ok(config
        .get("website_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned))
}

fn module_config(module: &ApplicationModuleRecord) -> AppResult<Map<String, Value>> {
    serde_json::from_str::<Value>(&module.config_json)
        .map_err(|err| AppError::Internal(format!("application module config is invalid: {err}")))?
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::Internal("application module config is not an object".to_string()))
}

/// Returns whether a protocol connection is enabled by the application's
/// protocol module. Applications created before modules existed keep the
/// historical behavior until an administrator explicitly configures a module.
pub async fn application_protocol_enabled(
    state: &AppState,
    application_id: &str,
    protocol: &str,
) -> AppResult<bool> {
    let Some(module) = application_module(state, application_id, "protocols").await? else {
        return Ok(true);
    };
    if module.is_enabled != 1 {
        return Ok(false);
    }
    let config = module_config(&module)?;
    let config = normalize_module_config("protocols", Value::Object(config))?;
    let protocol_key = match protocol {
        "oidc" => "oauth2_oidc",
        "saml" => "saml2",
        other => other,
    };
    let Some(protocol_config) = config.get(protocol_key).and_then(Value::as_object) else {
        return Ok(false);
    };
    Ok(protocol_config
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true))
}

/// Returns whether an external OIDC provider was explicitly selected by the
/// application's login-adapter module. A missing module is retained as a
/// compatibility path for applications created before module configuration
/// existed; once the module is present, an empty provider list means none are
/// allowed through that website.
pub async fn application_login_adapter_enabled(
    state: &AppState,
    application_id: &str,
    provider_id: &str,
) -> AppResult<bool> {
    let Some(application) = state.db.find_application_by_id(application_id).await? else {
        return Ok(false);
    };
    let Some(module) = application_module(state, application_id, "login_adapters").await? else {
        return Ok(true);
    };
    if module.is_enabled != 1 {
        return Ok(false);
    }
    let config = module_config(&module)?;
    let selected = config
        .get("provider_ids")
        .and_then(Value::as_array)
        .is_some_and(|provider_ids| {
            provider_ids
                .iter()
                .filter_map(Value::as_str)
                .any(|id| id == provider_id)
        });
    if !selected {
        return Ok(false);
    }
    let Some(provider) = state
        .db
        .find_external_oidc_provider_by_id(provider_id)
        .await?
    else {
        return Ok(false);
    };
    Ok(organization_binding_is_allowed(
        &application.organization_id,
        provider.organization_id.as_deref(),
    ))
}

/// Returns whether the website allows Signet's local password adapter for a
/// login interaction. A missing module preserves the compatibility behavior
/// for applications created before website-owned discovery existed. Once a
/// website publishes the module, its enabled flag and explicit boolean are
/// the runtime boundary; the admin login endpoint must not silently fall back
/// to a global password policy for that application.
pub async fn application_signet_password_enabled(
    state: &AppState,
    application_id: &str,
) -> AppResult<bool> {
    let Some(module) = application_module(state, application_id, "login_adapters").await? else {
        return Ok(true);
    };
    if module.is_enabled != 1 {
        return Ok(false);
    }
    let config = module_config(&module)?;
    let config = normalize_module_config("login_adapters", Value::Object(config))?;
    Ok(config
        .get("allow_signet_password")
        .and_then(Value::as_bool)
        .unwrap_or(true))
}

/// Returns whether an LDAP/AD source is bound to the website's directory
/// module. A configured module is an explicit allowlist: an empty list or a
/// disabled module means that directory source is not usable for this
/// application's login flow. Applications created before the module existed
/// retain the compatibility behavior of allowing the globally configured
/// directory sources until an administrator saves the module.
pub async fn application_directory_provider_enabled(
    state: &AppState,
    application_id: &str,
    provider_id: &str,
) -> AppResult<bool> {
    let Some(application) = state.db.find_application_by_id(application_id).await? else {
        return Ok(false);
    };
    let Some(provider) = state.db.find_ldap_provider_by_id(provider_id).await? else {
        return Ok(false);
    };
    if !organization_binding_is_allowed(
        &application.organization_id,
        provider.organization_id.as_deref(),
    ) {
        return Ok(false);
    }
    let Some(module) = application_module(state, application_id, "directory_sync").await? else {
        return Ok(true);
    };
    if module.is_enabled != 1 {
        return Ok(false);
    }
    let config = module_config(&module)?;
    Ok(config
        .get("ldap_provider_ids")
        .and_then(Value::as_array)
        .is_some_and(|provider_ids| {
            provider_ids
                .iter()
                .filter_map(Value::as_str)
                .any(|id| id == provider_id)
        }))
}

pub async fn application_directory_provider_allowlist(
    state: &AppState,
    application_id: &str,
) -> AppResult<Option<BTreeSet<String>>> {
    let Some(module) = application_module(state, application_id, "directory_sync").await? else {
        return Ok(None);
    };
    if module.is_enabled != 1 {
        return Ok(Some(BTreeSet::new()));
    }
    let config = module_config(&module)?;
    Ok(Some(
        config
            .get("ldap_provider_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
    ))
}

pub fn normalize_application_name(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 160 {
        return Err(AppError::BadRequest(
            "application name must be 1-160 characters".to_string(),
        ));
    }
    Ok(value.to_string())
}

pub fn normalize_application_slug(value: &str) -> AppResult<String> {
    normalize_slug(value).map_err(|_| {
        AppError::BadRequest(
            "application slug must be 2-64 lowercase letters, digits, and single hyphens"
                .to_string(),
        )
    })
}

pub fn normalize_access_mode(value: &str, allow_legacy: bool) -> AppResult<String> {
    match value.trim() {
        ACCESS_ASSIGNED_ACCOUNTS | ACCESS_ORGANIZATION_MEMBERS | ACCESS_ALL_SIGNET_USERS => {
            Ok(value.trim().to_string())
        }
        ACCESS_LEGACY_ALL_USERS if allow_legacy => Ok(ACCESS_LEGACY_ALL_USERS.to_string()),
        other => Err(AppError::BadRequest(format!(
            "unsupported application access mode: {other}"
        ))),
    }
}

pub fn normalize_registration_mode(value: &str, allow_legacy: bool) -> AppResult<String> {
    match value.trim() {
        REGISTRATION_DISABLED | REGISTRATION_INVITATION | REGISTRATION_ORGANIZATION_MEMBERS => {
            Ok(value.trim().to_string())
        }
        REGISTRATION_LEGACY if allow_legacy => Ok(REGISTRATION_LEGACY.to_string()),
        other => Err(AppError::BadRequest(format!(
            "unsupported application registration mode: {other}"
        ))),
    }
}

pub fn normalize_account_selection_mode(value: &str) -> AppResult<String> {
    match value.trim() {
        ACCOUNT_SELECTION_OPTIONAL | ACCOUNT_SELECTION_REQUIRED => Ok(value.trim().to_string()),
        other => Err(AppError::BadRequest(format!(
            "unsupported account selection mode: {other}"
        ))),
    }
}

pub fn normalize_unique_identity_factors(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for value in values {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => {}
            FACTOR_EMAIL => {
                normalized.insert(FACTOR_EMAIL.to_string());
            }
            FACTOR_PHONE => {
                normalized.insert(FACTOR_PHONE.to_string());
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "unsupported application identity factor: {other}"
                )));
            }
        }
    }
    Ok(normalized.into_iter().collect())
}

impl ApplicationRecord {
    pub fn unique_identity_factors(&self) -> AppResult<Vec<String>> {
        normalize_unique_identity_factors(crate::util::from_json(&self.unique_identity_factors)?)
    }

    pub fn requires_account_selection(&self) -> bool {
        self.account_selection_mode == ACCOUNT_SELECTION_REQUIRED
    }
}

pub async fn resolve_application_for_client(
    state: &AppState,
    client: &ClientRecord,
) -> AppResult<(ApplicationRecord, ClientBinding)> {
    let boundary = resolve_application_boundary(state, client).await?;
    let application = boundary.application;
    let binding = client_binding_from_record(boundary.binding);
    Ok((application, binding))
}

fn client_binding_from_record(record: ApplicationClientBindingRecord) -> ClientBinding {
    ClientBinding {
        application_id: record.application_id,
        client_db_id: record.client_db_id,
        protocol: record.protocol,
        authorization_profile_id: record.authorization_profile_id,
        auth_domain_id: record.auth_domain_id,
        is_active: record.is_active == 1,
    }
}

pub async fn authorize_user_for_application(
    state: &AppState,
    client: &ClientRecord,
    user: &UserRecord,
) -> AppResult<(ApplicationRecord, ClientBinding)> {
    let snapshot = state
        .db
        .load_client_policy_snapshot_for_protocol(&client.id, &user.id, "oauth2_oidc")
        .await?;
    if !snapshot.is_authorizable
        || snapshot.client_id.as_deref() != Some(client.id.as_str())
        || snapshot.user_id != user.id
    {
        return Err(AppError::Forbidden);
    }
    let application = snapshot.application.ok_or(AppError::Forbidden)?;
    let binding = snapshot.binding.ok_or(AppError::Forbidden)?;
    Ok((application, client_binding_from_record(binding)))
}

/// Enforces the live website boundary for grants that do not have a user
/// subject (for example client credentials). Every active client is expected
/// to have an explicit application aggregate; a missing binding is data
/// corruption and fails closed rather than becoming an ungoverned legacy
/// client.
pub async fn authorize_application_client(
    state: &AppState,
    client: &ClientRecord,
    protocol: &str,
) -> AppResult<ApplicationRecord> {
    let runtime = ApplicationRuntimeSnapshot::load(state, client, Some(protocol)).await?;
    runtime.require_interactive()?;
    Ok(runtime.application)
}

/// Authorizes an application-owned machine client for the OAuth
/// `client_credentials` grant. Service-only applications such as Memory
/// Atlas can disable interactive OIDC while still issuing narrowly scoped
/// tokens to explicitly declared service accounts.
pub async fn authorize_client_for_service_token(
    state: &AppState,
    client: &ClientRecord,
) -> AppResult<ApplicationRecord> {
    let runtime = ApplicationRuntimeSnapshot::load(state, client, None).await?;
    runtime.require_service()?;
    if client.service_account_enabled != 1
        || !client
            .grant_types()
            .map_err(|_| AppError::Forbidden)?
            .iter()
            .any(|value| value == "client_credentials")
    {
        return Err(AppError::Forbidden);
    }
    Ok(runtime.application)
}

/// Side-effect-free eligibility probe for account chooser rendering. The
/// authorization path still calls `authorize_user_for_application` afterwards to
/// make the final reservation atomically.
pub async fn user_can_authorize_client(
    state: &AppState,
    client: &ClientRecord,
    user: &UserRecord,
) -> AppResult<bool> {
    let snapshot = state
        .db
        .load_client_policy_snapshot_for_protocol(&client.id, &user.id, "oauth2_oidc")
        .await?;
    Ok(snapshot.is_authorizable)
}

/// Creates or refreshes the current user's application-local factor locks.
/// Missing verification is intentionally a hard denial when the app opted in
/// to that factor: otherwise a user could bypass a "phone unique" rule by
/// simply omitting their phone number.
pub async fn reserve_verified_identity_factors(
    state: &AppState,
    application: &ApplicationRecord,
    user: &UserRecord,
) -> AppResult<()> {
    let digests = verified_identity_factor_digests(state, application, user)?;
    if digests.is_empty() {
        return Ok(());
    }
    state
        .db
        .replace_application_identity_bindings(&application.id, &user.id, digests)
        .await
}

fn verified_identity_factor_digests(
    state: &AppState,
    application: &ApplicationRecord,
    user: &UserRecord,
) -> AppResult<Vec<(String, String)>> {
    let factors = application.unique_identity_factors()?;
    let mut digests = Vec::with_capacity(factors.len());
    for factor in factors {
        let value = match factor.as_str() {
            FACTOR_EMAIL if user.email_verified_at.is_some() => {
                user.email.trim().to_ascii_lowercase()
            }
            FACTOR_PHONE if user.phone_verified_at.is_some() => {
                normalize_phone(user.phone.as_deref().ok_or(AppError::Forbidden)?)?
            }
            FACTOR_EMAIL | FACTOR_PHONE => return Err(AppError::Forbidden),
            _ => {
                return Err(AppError::Internal(
                    "application identity factor is invalid".to_string(),
                ));
            }
        };
        digests.push((
            factor.clone(),
            crate::util::identity_factor_digest(
                &state.settings.security.rsa_private_key_pem,
                &factor,
                &value,
            ),
        ));
    }
    Ok(digests)
}

pub fn normalize_phone(value: &str) -> AppResult<String> {
    let value = value.trim();
    let mut normalized = String::with_capacity(value.len());
    for (index, ch) in value.chars().enumerate() {
        if ch.is_ascii_digit() || (ch == '+' && index == 0) {
            normalized.push(ch);
        } else if !matches!(ch, ' ' | '-' | '(' | ')' | '.') {
            return Err(AppError::BadRequest("phone is invalid".to_string()));
        }
    }
    if normalized.len() < 7 || normalized.len() > 20 || normalized == "+" {
        return Err(AppError::BadRequest("phone is invalid".to_string()));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_factors_are_deduplicated_and_validated() {
        assert_eq!(
            normalize_unique_identity_factors(vec!["PHONE".into(), "email".into(), "phone".into()])
                .unwrap(),
            vec!["email", "phone"]
        );
        assert!(normalize_unique_identity_factors(vec!["passport".into()]).is_err());
    }

    #[test]
    fn website_applications_allow_all_active_signet_accounts() {
        assert_eq!(
            normalize_access_mode(ACCESS_ALL_SIGNET_USERS, false).unwrap(),
            ACCESS_ALL_SIGNET_USERS
        );
        assert!(normalize_access_mode(ACCESS_LEGACY_ALL_USERS, false).is_err());
    }

    #[test]
    fn provider_bindings_allow_shared_sources_but_reject_other_enterprises() {
        assert!(organization_binding_is_allowed("org-a", None));
        assert!(organization_binding_is_allowed("org-a", Some("org-a")));
        assert!(!organization_binding_is_allowed("org-a", Some("org-b")));
    }

    #[test]
    fn module_config_accepts_known_shapes_and_rejects_malformed_fields() {
        let config = serde_json::json!({
            "website_url": "https://app.example.test",
            "oauth2_oidc": {
                "enabled": true,
                "client_ids": ["client-db-id"]
            },
            "future_extension": {"kept": true}
        });
        let normalized = normalize_module_config("protocols", config.clone()).unwrap();
        assert_eq!(normalized, config);

        assert!(
            normalize_module_config(
                "protocols",
                serde_json::json!({"oauth2_oidc": {"client_ids": [42]}})
            )
            .is_err()
        );
        assert!(
            normalize_module_config(
                "authorization",
                serde_json::json!({"custom_roles": ["owner"]})
            )
            .is_err()
        );
        assert!(normalize_module_config("authorization", serde_json::json!(null)).is_err());
    }

    #[test]
    fn directory_sync_config_requires_safe_filters_and_attributes() {
        let config = serde_json::json!({
            "enabled": true,
            "ldap_provider_ids": ["ldap-provider"],
            "user_sync_filter": "(&(objectClass=person)(mail=*))",
            "group_base_dn": "ou=groups,dc=example,dc=test",
            "group_filter": "(objectClass=group)",
            "group_id_attribute": "entryUUID",
            "group_name_attribute": "cn",
            "group_member_attribute": "member",
            "max_entries": 5000,
            "deprovision_action": "remove_membership"
        });
        assert!(normalize_module_config("directory_sync", config).is_ok());
        assert!(
            normalize_module_config(
                "directory_sync",
                serde_json::json!({"user_sync_filter": "", "group_filter": ""})
            )
            .is_ok()
        );
        assert!(
            normalize_module_config(
                "directory_sync",
                serde_json::json!({"user_sync_filter": "uid=*"})
            )
            .is_err()
        );
        assert!(
            normalize_module_config(
                "directory_sync",
                serde_json::json!({"group_member_attribute": "member_name"})
            )
            .is_err()
        );
        assert!(
            normalize_module_config("directory_sync", serde_json::json!({"max_entries": 0}))
                .is_err()
        );
        assert!(
            normalize_module_config(
                "directory_sync",
                serde_json::json!({"deprovision_action": "archive"})
            )
            .is_err()
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn module_bindings_are_tenant_scoped_and_shared_sources_are_reusable() {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-application-binding-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.pool_size = 1;
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        let state = crate::AppState {
            jwt: crate::jwt::JwtManager::new(&settings).unwrap(),
            settings,
            db,
        };

        let organization_a = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "binding-org-a".to_string(),
                name: "Binding Org A".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let organization_b = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "binding-org-b".to_string(),
                name: "Binding Org B".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application_a = state
            .db
            .insert_application(crate::db::NewApplication {
                organization_id: organization_a.id.clone(),
                slug: "binding-website-a".to_string(),
                name: "Binding Website A".to_string(),
                description: None,
                access_mode: ACCESS_ALL_SIGNET_USERS.to_string(),
                registration_mode: REGISTRATION_DISABLED.to_string(),
                account_selection_mode: ACCOUNT_SELECTION_OPTIONAL.to_string(),
                unique_identity_factors: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application_b = state
            .db
            .insert_application(crate::db::NewApplication {
                organization_id: organization_b.id.clone(),
                slug: "binding-website-b".to_string(),
                name: "Binding Website B".to_string(),
                description: None,
                access_mode: ACCESS_ALL_SIGNET_USERS.to_string(),
                registration_mode: REGISTRATION_DISABLED.to_string(),
                account_selection_mode: ACCOUNT_SELECTION_OPTIONAL.to_string(),
                unique_identity_factors: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();

        let client_a_input = crate::db::NewClient {
            client_id: "binding-client-a".to_string(),
            client_secret_hash: None,
            client_name: "Binding Client A".to_string(),
            logo_uri: String::new(),
            organization_id: Some(organization_a.id.clone()),
            redirect_uris: vec!["https://binding.example.test/callback".to_string()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".to_string()],
            audience: String::new(),
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: true,
            require_mfa: false,
            require_pushed_authorization_requests: false,
            require_s256_pkce: false,
            require_confidential_client: false,
            require_dpop: false,
            require_account_selection: false,
            trust_email_verified: false,
            authorization_details_types: Vec::new(),
            subject_type: crate::subject::SUBJECT_TYPE_PUBLIC.to_string(),
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
        };
        let mut client_b_input = client_a_input.clone();
        client_b_input.client_id = "binding-client-b".to_string();
        client_b_input.client_name = "Binding Client B".to_string();
        client_b_input.organization_id = Some(organization_b.id.clone());
        let client_a = state
            .db
            .insert_client_for_application(&application_a.id, client_a_input)
            .await
            .unwrap();
        let client_b = state
            .db
            .insert_client_for_application(&application_b.id, client_b_input)
            .await
            .unwrap();

        let shared_oidc = state
            .db
            .insert_external_oidc_provider(crate::db::NewExternalOidcProvider {
                slug: "binding-shared-oidc".to_string(),
                display_name: "Shared OIDC".to_string(),
                organization_id: None,
                issuer: "https://shared-idp.example.test".to_string(),
                client_id: "shared-client".to_string(),
                client_secret: "shared-secret".to_string(),
                authorization_endpoint: "https://shared-idp.example.test/authorize".to_string(),
                token_endpoint: "https://shared-idp.example.test/token".to_string(),
                userinfo_endpoint: "https://shared-idp.example.test/userinfo".to_string(),
                redirect_path: "/api/register/oidc/binding-shared-oidc/callback".to_string(),
                scopes: vec!["openid".to_string()],
                email_domains: Vec::new(),
                is_active: true,
                allow_login: true,
                allow_registration: true,
            })
            .await
            .unwrap();
        let foreign_oidc = state
            .db
            .insert_external_oidc_provider(crate::db::NewExternalOidcProvider {
                slug: "binding-foreign-oidc".to_string(),
                display_name: "Foreign OIDC".to_string(),
                organization_id: Some(organization_b.id.clone()),
                issuer: "https://foreign-idp.example.test".to_string(),
                client_id: "foreign-client".to_string(),
                client_secret: "foreign-secret".to_string(),
                authorization_endpoint: "https://foreign-idp.example.test/authorize".to_string(),
                token_endpoint: "https://foreign-idp.example.test/token".to_string(),
                userinfo_endpoint: "https://foreign-idp.example.test/userinfo".to_string(),
                redirect_path: "/api/register/oidc/binding-foreign-oidc/callback".to_string(),
                scopes: vec!["openid".to_string()],
                email_domains: Vec::new(),
                is_active: true,
                allow_login: true,
                allow_registration: true,
            })
            .await
            .unwrap();
        let shared_ldap = state
            .db
            .insert_ldap_provider(crate::db::NewLdapProvider {
                slug: "binding-shared-ldap".to_string(),
                display_name: "Shared LDAP".to_string(),
                organization_id: None,
                url: "ldaps://shared-ldap.example.test".to_string(),
                starttls: false,
                bind_dn: "cn=reader,dc=example,dc=test".to_string(),
                bind_password: Some("secret".to_string()),
                base_dn: "dc=example,dc=test".to_string(),
                user_filter: "(uid={login})".to_string(),
                user_id_attribute: "uid".to_string(),
                email_attribute: "mail".to_string(),
                username_attribute: "uid".to_string(),
                display_name_attribute: "cn".to_string(),
                phone_attribute: "telephoneNumber".to_string(),
                is_active: true,
                allow_login: true,
                allow_registration: true,
            })
            .await
            .unwrap();
        let foreign_ldap = state
            .db
            .insert_ldap_provider(crate::db::NewLdapProvider {
                slug: "binding-foreign-ldap".to_string(),
                display_name: "Foreign LDAP".to_string(),
                organization_id: Some(organization_b.id.clone()),
                url: "ldaps://foreign-ldap.example.test".to_string(),
                starttls: false,
                bind_dn: "cn=reader,dc=example,dc=test".to_string(),
                bind_password: Some("secret".to_string()),
                base_dn: "dc=example,dc=test".to_string(),
                user_filter: "(uid={login})".to_string(),
                user_id_attribute: "uid".to_string(),
                email_attribute: "mail".to_string(),
                username_attribute: "uid".to_string(),
                display_name_attribute: "cn".to_string(),
                phone_attribute: "telephoneNumber".to_string(),
                is_active: true,
                allow_login: true,
                allow_registration: true,
            })
            .await
            .unwrap();

        let client_config = serde_json::json!({
            "oauth2_oidc": {"enabled": true, "client_ids": [client_b.id]}
        });
        assert!(matches!(
            validate_module_bindings(
                &state,
                &application_a,
                "protocols",
                client_config.as_object().unwrap(),
            )
            .await,
            Err(AppError::Forbidden)
        ));
        let provider_config =
            serde_json::json!({"enabled": true, "provider_ids": [foreign_oidc.id]});
        assert!(matches!(
            validate_module_bindings(
                &state,
                &application_a,
                "login_adapters",
                provider_config.as_object().unwrap(),
            )
            .await,
            Err(AppError::Forbidden)
        ));
        let directory_config = serde_json::json!({
            "enabled": true,
            "ldap_provider_ids": [foreign_ldap.id]
        });
        assert!(matches!(
            validate_module_bindings(
                &state,
                &application_a,
                "directory_sync",
                directory_config.as_object().unwrap(),
            )
            .await,
            Err(AppError::Forbidden)
        ));

        for application in [&application_a, &application_b] {
            let config = serde_json::json!({
                "enabled": true,
                "provider_ids": [shared_oidc.id]
            });
            validate_module_bindings(
                &state,
                application,
                "login_adapters",
                config.as_object().unwrap(),
            )
            .await
            .unwrap();
            state
                .db
                .upsert_application_module(
                    &application.id,
                    "login_adapters",
                    &config.to_string(),
                    true,
                )
                .await
                .unwrap();
        }
        assert_eq!(
            state
                .db
                .list_application_modules(&application_a.id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            state
                .db
                .list_application_modules(&application_b.id)
                .await
                .unwrap()
                .len(),
            1
        );

        // OIDC connections are exclusive to one application, and a failed
        // cross-enterprise move must leave the existing binding untouched.
        let client_a_profile_id = state
            .db
            .find_application_client_binding(&client_a.id)
            .await
            .unwrap()
            .unwrap()
            .authorization_profile_id;
        state
            .db
            .link_client_to_application(
                &application_a.id,
                &client_a.id,
                "oidc",
                &client_a_profile_id,
            )
            .await
            .unwrap();
        assert!(
            state
                .db
                .link_client_to_application(&application_b.id, &client_a.id, "oidc", "default")
                .await
                .is_err()
        );
        assert_eq!(
            state
                .db
                .find_application_for_client(&client_a.id)
                .await
                .unwrap()
                .unwrap()
                .id,
            application_a.id
        );

        // The shared connector can be bound to both enterprises, while the
        // enterprise-owned connector can only be used by its own application.
        let shared_directory_config = serde_json::json!({
            "enabled": true,
            "ldap_provider_ids": [shared_ldap.id]
        });
        validate_module_bindings(
            &state,
            &application_a,
            "directory_sync",
            shared_directory_config.as_object().unwrap(),
        )
        .await
        .unwrap();
        validate_module_bindings(
            &state,
            &application_b,
            "directory_sync",
            shared_directory_config.as_object().unwrap(),
        )
        .await
        .unwrap();

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn runtime_authorization_snapshot_fails_closed_on_boundary_mismatch() {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-runtime-boundary-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.pool_size = 1;
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        let state = crate::AppState {
            jwt: crate::jwt::JwtManager::new(&settings).unwrap(),
            settings,
            db,
        };

        let organization_a = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "runtime-boundary-org-a".to_string(),
                name: "Runtime Boundary Org A".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let organization_b = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "runtime-boundary-org-b".to_string(),
                name: "Runtime Boundary Org B".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application_input = crate::db::NewApplication {
            organization_id: organization_a.id.clone(),
            slug: "runtime-boundary-app".to_string(),
            name: "Runtime Boundary App".to_string(),
            description: None,
            access_mode: ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: REGISTRATION_DISABLED.to_string(),
            account_selection_mode: ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        };
        let application = state
            .db
            .insert_application(application_input.clone())
            .await
            .unwrap();
        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "runtime-boundary-user@example.test".to_string(),
                username: "runtime-boundary-user".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: None,
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let client_input = crate::db::NewClient {
            client_id: "runtime-boundary-client".to_string(),
            client_secret_hash: None,
            client_name: "Runtime Boundary Client".to_string(),
            logo_uri: String::new(),
            organization_id: Some(organization_a.id.clone()),
            redirect_uris: vec!["https://runtime-boundary.example/callback".to_string()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".to_string()],
            audience: String::new(),
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: true,
            require_mfa: false,
            require_pushed_authorization_requests: false,
            require_s256_pkce: false,
            require_confidential_client: false,
            require_dpop: false,
            require_account_selection: false,
            trust_email_verified: false,
            authorization_details_types: Vec::new(),
            subject_type: crate::subject::SUBJECT_TYPE_PUBLIC.to_string(),
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
        };
        let client = state
            .db
            .insert_client_for_application(&application.id, client_input.clone())
            .await
            .unwrap();

        assert!(
            ApplicationRuntimeSnapshot::load(&state, &client, Some("oauth2_oidc"))
                .await
                .is_ok()
        );
        assert!(
            state
                .db
                .load_client_policy_snapshot_for_protocol(&client.id, &user.id, "oauth2_oidc")
                .await
                .unwrap()
                .is_authorizable
        );

        // The client is still bound to application A, but its live tenant
        // identity points at organization B. Both runtime and user policy
        // snapshots must reject this split boundary.
        let mut foreign_client = client_input.clone();
        foreign_client.organization_id = Some(organization_b.id.clone());
        state
            .db
            .update_client(&client.id, foreign_client)
            .await
            .unwrap();
        assert!(
            ApplicationRuntimeSnapshot::load(&state, &client, Some("oauth2_oidc"))
                .await
                .is_err()
        );
        assert!(
            !state
                .db
                .load_client_policy_snapshot_for_protocol(&client.id, &user.id, "oauth2_oidc")
                .await
                .unwrap()
                .is_authorizable
        );
        state
            .db
            .update_client(&client.id, client_input.clone())
            .await
            .unwrap();

        let mut inactive_application = application_input.clone();
        inactive_application.is_active = false;
        state
            .db
            .update_application(&application.id, inactive_application)
            .await
            .unwrap();
        assert!(
            ApplicationRuntimeSnapshot::load(&state, &client, Some("oauth2_oidc"))
                .await
                .is_err()
        );
        state
            .db
            .update_application(&application.id, application_input.clone())
            .await
            .unwrap();

        let organization_a_record = state
            .db
            .find_organization_by_id(&organization_a.id)
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .update_organization(
                &organization_a.id,
                crate::db::NewOrganization {
                    slug: organization_a_record.slug,
                    name: organization_a_record.name,
                    kind: organization_a_record.kind,
                    description: organization_a_record.description,
                    allowed_email_domains: crate::util::from_json(
                        &organization_a_record.allowed_email_domains,
                    )
                    .unwrap(),
                    is_active: false,
                },
            )
            .await
            .unwrap();
        assert!(
            ApplicationRuntimeSnapshot::load(&state, &client, Some("oauth2_oidc"))
                .await
                .is_err()
        );

        state
            .db
            .update_organization(
                &organization_a.id,
                crate::db::NewOrganization {
                    slug: "runtime-boundary-org-a".to_string(),
                    name: "Runtime Boundary Org A".to_string(),
                    kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                    description: None,
                    allowed_email_domains: Vec::new(),
                    is_active: true,
                },
            )
            .await
            .unwrap();

        state
            .db
            .upsert_application_discovery(crate::db::NewApplicationDiscovery {
                application_id: application.id.clone(),
                management_mode: crate::application_discovery::MANAGEMENT_MODE_WEBSITE.to_string(),
                website_url: "https://runtime-boundary.example".to_string(),
                fetch_secret_ciphertext: "ciphertext".to_string(),
                signing_public_jwks: "{}".to_string(),
                last_verified_revision: None,
                last_verified_version: None,
                last_verified_digest: None,
                last_verified_expires_at: None,
                sync_status: crate::application_discovery::SYNC_PENDING.to_string(),
                last_fetched_at: None,
                last_success_at: None,
                last_error: None,
                snapshot_json: None,
                operator_disabled: false,
            })
            .await
            .unwrap();
        assert!(
            ApplicationRuntimeSnapshot::load(&state, &client, Some("oauth2_oidc"))
                .await
                .is_err()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
