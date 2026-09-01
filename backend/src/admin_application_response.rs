use super::{
    admin_application_authorization_read::ApplicationAuthorizationProfileResponse,
    admin_client_response::public_client_from_context,
};
use crate::{
    AppState,
    db::{
        ApplicationGraphRecordSet, ApplicationModuleRecord, ApplicationRecord, PublicClient,
        PublicClientClaimMapper,
    },
    error::{AppError, AppResult},
};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Serialize)]
pub(crate) struct ApplicationModuleResponse {
    module_key: String,
    config: serde_json::Value,
    is_enabled: bool,
    created_at: i64,
    updated_at: i64,
}

pub(crate) fn application_module_response(
    module: ApplicationModuleRecord,
) -> AppResult<ApplicationModuleResponse> {
    let config = serde_json::from_str(&module.config_json).map_err(|err| {
        AppError::Internal(format!("application module config is invalid: {err}"))
    })?;
    Ok(ApplicationModuleResponse {
        module_key: module.module_key,
        config,
        is_enabled: module.is_enabled == 1,
        created_at: module.created_at,
        updated_at: module.updated_at,
    })
}

#[derive(Debug, Serialize)]
pub(crate) struct ApplicationResponse {
    id: String,
    organization_id: String,
    slug: String,
    name: String,
    description: Option<String>,
    account_selection_mode: String,
    unique_identity_factors: Vec<String>,
    is_active: bool,
    client_bindings: Vec<ApplicationClientBindingResponse>,
    modules: Vec<ApplicationModuleResponse>,
    authorization_profiles: Vec<ApplicationAuthorizationProfileResponse>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ApplicationClientBindingResponse {
    #[serde(flatten)]
    pub(crate) client: PublicClient,
    protocol: String,
    authorization_profile_id: String,
    auth_domain_id: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum MissingApplicationClientPolicy {
    Skip,
    NotFound,
}

/// Assemble application client bindings from the aggregate read projection.
///
/// The graph is loaded by `Db::read_application_graph` with bounded queries
/// for every relation. Keeping this assembler synchronous makes the read
/// model boundary explicit: once the graph is available, a binding list must
/// never open a connection for a client, mapper, or organization.
pub(crate) fn application_client_binding_responses_from_graph(
    graph: &ApplicationGraphRecordSet,
    protocol: Option<&str>,
    missing_client_policy: MissingApplicationClientPolicy,
) -> AppResult<Vec<ApplicationClientBindingResponse>> {
    let clients_by_id = graph
        .clients
        .iter()
        .map(|client| (client.id.as_str(), client))
        .collect::<HashMap<_, _>>();
    let mut mappers_by_client = HashMap::<String, Vec<PublicClientClaimMapper>>::new();
    for mapper in &graph.claim_mappers {
        mappers_by_client
            .entry(mapper.client_db_id.clone())
            .or_default()
            .push(mapper.clone().public());
    }
    for mappers in mappers_by_client.values_mut() {
        // Match list_client_claim_mappers' ORDER BY. The graph query groups
        // by client first, so restore the per-client created_at tie-breaker
        // before exposing the public projection.
        mappers.sort_by_key(|mapper| (mapper.sort_order, mapper.created_at));
    }
    let organizations_by_id = graph
        .organizations
        .iter()
        .map(|organization| (organization.id.as_str(), organization))
        .collect::<HashMap<_, _>>();

    let mut response = Vec::with_capacity(graph.bindings.len());
    for binding in &graph.bindings {
        if protocol.is_some_and(|expected| binding.protocol != expected) {
            continue;
        }
        let Some(client) = clients_by_id.get(binding.client_db_id.as_str()) else {
            if matches!(
                missing_client_policy,
                MissingApplicationClientPolicy::NotFound
            ) {
                return Err(AppError::NotFound);
            }
            continue;
        };

        let public = public_client_from_context(
            client,
            client
                .organization_id
                .as_deref()
                .and_then(|id| organizations_by_id.get(id))
                .map(|organization| (organization.slug.as_str(), organization.name.as_str())),
            mappers_by_client
                .get(&binding.client_db_id)
                .cloned()
                .unwrap_or_default(),
        )?;
        response.push(ApplicationClientBindingResponse {
            client: public,
            protocol: binding.protocol.clone(),
            authorization_profile_id: binding.authorization_profile_id.clone(),
            auth_domain_id: binding.auth_domain_id.clone(),
        });
    }
    Ok(response)
}

pub(crate) async fn application_response(
    state: &AppState,
    application: ApplicationRecord,
) -> AppResult<ApplicationResponse> {
    let graph = state.db.read_application_graph(&application.id).await?;
    application_response_from_graph(application, graph)
}

pub(crate) fn application_response_from_graph(
    application: ApplicationRecord,
    graph: ApplicationGraphRecordSet,
) -> AppResult<ApplicationResponse> {
    let client_bindings = application_client_binding_responses_from_graph(
        &graph,
        None,
        MissingApplicationClientPolicy::Skip,
    )?;
    let ApplicationGraphRecordSet {
        modules,
        profiles,
        permission_definitions,
        profile_roles,
        ..
    } = graph;
    let unique_identity_factors = application.unique_identity_factors()?;
    let modules = modules
        .into_iter()
        .map(application_module_response)
        .collect::<AppResult<Vec<_>>>()?;
    // A representation read must not repair or mutate the aggregate.  Profile
    // creation belongs to the explicit client/application write transaction;
    // otherwise a harmless GET can leave a partial profile graph behind when
    // a later query or response conversion fails.
    let mut permission_counts = BTreeMap::<String, usize>::new();
    for definition in permission_definitions {
        if definition.is_active == 1 {
            *permission_counts.entry(definition.profile_id).or_default() += 1;
        }
    }
    let mut role_counts = BTreeMap::<String, usize>::new();
    for role in profile_roles {
        if role.is_active == 1 {
            *role_counts.entry(role.profile_id).or_default() += 1;
        }
    }
    let mut authorization_profiles = Vec::with_capacity(profiles.len());
    for profile in profiles {
        authorization_profiles.push(ApplicationAuthorizationProfileResponse {
            id: profile.id.clone(),
            profile_key: profile.profile_key.clone(),
            connection_kind: profile.connection_kind.clone(),
            connection_id: profile.connection_id.clone(),
            source_mode: profile.source_mode.clone(),
            remote_version: profile.remote_version.clone(),
            remote_digest: profile.remote_digest.clone(),
            sync_status: profile.sync_status.clone(),
            last_synced_at: profile.last_synced_at,
            last_error: profile.last_error.clone(),
            permission_count: permission_counts.get(&profile.id).copied().unwrap_or(0),
            role_count: role_counts.get(&profile.id).copied().unwrap_or(0),
            created_at: profile.created_at,
            updated_at: profile.updated_at,
        });
    }
    Ok(ApplicationResponse {
        id: application.id,
        organization_id: application.organization_id,
        slug: application.slug,
        name: application.name,
        description: application.description,
        account_selection_mode: application.account_selection_mode,
        unique_identity_factors,
        is_active: application.is_active == 1,
        client_bindings,
        modules,
        authorization_profiles,
        created_at: application.created_at,
        updated_at: application.updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(config_json: &str, is_enabled: i32) -> ApplicationModuleRecord {
        ApplicationModuleRecord {
            application_id: "application-id".to_string(),
            module_key: "authorization".to_string(),
            config_json: config_json.to_string(),
            is_enabled,
            created_at: 10,
            updated_at: 20,
        }
    }

    #[test]
    fn application_module_response_decodes_config_and_flags() {
        let response = application_module_response(module(r#"{"mode":"strict"}"#, 1))
            .expect("valid module config should map");

        assert_eq!(response.module_key, "authorization");
        assert_eq!(response.config["mode"], "strict");
        assert!(response.is_enabled);
        assert_eq!(response.created_at, 10);
        assert_eq!(response.updated_at, 20);
    }

    #[test]
    fn application_module_response_rejects_invalid_config() {
        let error = application_module_response(module("not-json", 1))
            .expect_err("invalid module config must fail");

        assert!(matches!(error, AppError::Internal(message) if message.contains("invalid")));
    }

    #[test]
    fn application_module_response_maps_disabled_modules() {
        let response = application_module_response(module("{}", 0))
            .expect("empty object is valid module config");

        assert!(!response.is_enabled);
    }
}
