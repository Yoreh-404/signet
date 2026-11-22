//! Explicit opt-in verifier for future transactional reconciliation.
//! It has no live caller and never treats TOFU, public DCR, or v1 as approval.
use super::*;
use crate::application_contract::ClientContract;

pub(crate) struct ApprovedAxonDeclaration<'a> {
    pub organization_id: &'a str,
    pub application_id: &'a str,
    pub revision: i64,
    pub website_origin: &'a str,
    pub discovery_issuer: &'a str,
    pub discovery_audience: &'a str,
    pub client_id: &'a str,
    pub resource_audience: &'a str,
    pub pinned_jwks: &'a str,
    pub catalog: &'a [String],
}

pub(crate) struct VerifiedAxonDeclaration {
    manifest: VerifiedApplicationManifest,
    organization_id: String,
    website_origin: String,
    withdrawal: bool,
}

impl VerifiedAxonDeclaration {
    pub(crate) fn manifest(&self) -> &VerifiedApplicationManifest { &self.manifest }
    pub(crate) fn organization_id(&self) -> &str { &self.organization_id }
    pub(crate) fn website_origin(&self) -> &str { &self.website_origin }
    pub(crate) fn is_withdrawal(&self) -> bool { self.withdrawal }
}

#[derive(Deserialize)]
struct RawDeclaration {
    format: String,
    application_id: String,
    revision: i64,
    iss: String,
    aud: Value,
    iat: i64,
    exp: i64,
    modules: RawModules,
}

#[derive(Deserialize)]
struct RawModules {
    clients: Vec<ClientContract>,
    axon_admin_mapping: Option<V2Mapping>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct V2Mapping {
    version: u8,
    source: String,
    claim: String,
    output: String,
    client_id: String,
    audience: String,
    permissions: Vec<String>,
}

/// Callers must supply trusted enrolled identities from the discovery row.
/// A verified snapshot is not activation: commit it only under the independent
/// durable reservation transaction, and never pass it to the v1 issuer path.
pub(crate) fn verify_approved_axon_v2(
    body: &[u8],
    enrolled_org: &str,
    enrolled_website: &str,
    approved: &ApprovedAxonDeclaration<'_>,
) -> AppResult<VerifiedAxonDeclaration> {
    verify(body, enrolled_org, enrolled_website, approved, false)
}

/// Requires explicit trusted approval of this higher omission revision.
/// Does not accept null, v1 or a malformed mapping as withdrawal.
pub(crate) fn verify_approved_axon_v2_withdrawal(
    body: &[u8],
    enrolled_org: &str,
    enrolled_website: &str,
    approved: &ApprovedAxonDeclaration<'_>,
) -> AppResult<VerifiedAxonDeclaration> {
    verify(body, enrolled_org, enrolled_website, approved, true)
}

fn verify(
    body: &[u8],
    enrolled_org: &str,
    enrolled_website: &str,
    approved: &ApprovedAxonDeclaration<'_>,
    withdrawal: bool,
) -> AppResult<VerifiedAxonDeclaration> {
    if body.is_empty() || body.len() > 512 * 1024 {
        return Err(AppError::BadRequest("invalid discovery body size".into()));
    }
    if enrolled_org.is_empty()
        || enrolled_org != approved.organization_id
        || website_origin(enrolled_website)? != approved.website_origin
        || website_origin(approved.discovery_issuer)? != approved.website_origin
    {
        return Err(AppError::Unauthorized);
    }
    let pin = axon_signer_pin(approved.pinned_jwks).ok_or(AppError::Unauthorized)?;
    let payload = verify_jws(&extract_jws(body)?, approved.pinned_jwks)?;
    let wire = parse_approved_mapping(&payload, approved, withdrawal)?;

    // Decode all ordinary v3 modules via the existing normalizer, but only
    // after the raw serde pass checked duplicates in the authority boundary.
    let mut value: Value = serde_json::from_slice(&payload).map_err(|_| bad_mapping())?;
    let raw_mapping = value["modules"].as_object_mut().ok_or_else(bad_mapping)?.remove("axon_admin_mapping");
    if withdrawal && raw_mapping.is_some() {
        return Err(bad_mapping());
    }
    let base = serde_json::from_value::<ApplicationContract>(value).map_err(|_| bad_mapping())?;
    let mut verified = normalize_application_contract(
        &base,
        &payload,
        approved.discovery_issuer,
        approved.application_id,
        approved.discovery_audience,
        approved.organization_id,
    )?;
    if let Some(wire) = wire {
        verified.redacted_payload["modules"]["axon_admin_mapping"] =
            serde_json::to_value(wire).map_err(|_| bad_mapping())?;
    }
    verified.redacted_payload["_signet_axon_verified_signer"] = Value::String(pin);
    Ok(VerifiedAxonDeclaration {
        manifest: verified,
        organization_id: enrolled_org.to_owned(),
        website_origin: approved.website_origin.to_owned(),
        withdrawal,
    })
}

fn bad_mapping() -> AppError {
    AppError::BadRequest("invalid approved Axon v2 admin declaration".into())
}

fn parse_approved_mapping(
    payload: &[u8],
    approved: &ApprovedAxonDeclaration<'_>,
    withdrawal: bool,
) -> AppResult<Option<V2Mapping>> {
    let raw = serde_json::from_slice::<RawDeclaration>(payload).map_err(|_| bad_mapping())?;
    if raw.format != FORMAT || raw.application_id != approved.application_id
        || raw.revision <= 0 || raw.revision != approved.revision || raw.iss != approved.discovery_issuer
        || !audience_contains(&raw.aud, approved.discovery_audience)
        || raw.iat >= raw.exp
    {
        return Err(bad_mapping());
    }
    if withdrawal {
        return raw.modules.axon_admin_mapping.is_none().then_some(None).ok_or_else(bad_mapping);
    }
    let mapping = raw.modules.axon_admin_mapping.ok_or_else(bad_mapping)?;
    if mapping.version != 2 || mapping.source != "signet.is_admin"
        || mapping.claim != crate::claim_mapper::AXON_ADMIN_AUTHORITY_CLAIM
        || mapping.output != "access_token" || approved.client_id.is_empty()
        || approved.resource_audience.is_empty() || mapping.client_id != approved.client_id
        || mapping.audience != approved.resource_audience
        || approved.catalog.is_empty() || !approved.catalog.windows(2).all(|p| p[0] < p[1])
        || !approved.catalog.iter().all(|p| p.starts_with("admin:") && !p.contains('*'))
        || mapping.permissions != approved.catalog
        || !raw.modules.clients.iter().any(|client| {
            client.active && client.protocol == "oidc" && client.client_id == approved.client_id
                && client.audiences == [approved.resource_audience]
                && client.scopes == ["openid"]
                && client.grant_types == ["authorization_code"]
                && client.response_types == ["code"]
                && client.require_pkce && client.require_s256_pkce
        })
    {
        return Err(bad_mapping());
    }
    Ok(Some(mapping))
}
