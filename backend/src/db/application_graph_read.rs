//! Read persistence for application response graphs.

use super::{
    ApplicationAuthorizationProfileRecord, ApplicationClientBindingRecord,
    ApplicationGraphRecordSet, ApplicationModuleRecord, ApplicationPermissionDefinitionRecord,
    ApplicationProfileRoleRecord, ClientClaimMapperRecord, ClientRecord, Db, OrganizationRecord,
    bind_text_list, blocking, ph, placeholders, select_application_authorization_profile_sql,
    select_application_module_sql, select_application_permission_definition_sql,
    select_application_profile_role_sql, select_client_claim_mapper_sql, select_client_sql,
    select_organization_sql,
};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
};
use diesel::sql_query;
use diesel::{Connection, RunQueryDsl};
use std::collections::{BTreeMap, BTreeSet};

impl Db {
    /// Loads the application response graph with a fixed number of queries.
    /// The subqueries preserve the application boundary while avoiding the
    /// per-binding and per-profile round trips used by the old response
    /// assembler.
    pub async fn read_application_graph(
        &self,
        application_id: &str,
    ) -> AppResult<ApplicationGraphRecordSet> {
        let application_id = application_id.to_string();
        let mut graphs = self
            .read_application_graph_batch(std::slice::from_ref(&application_id))
            .await?;
        Ok(graphs
            .remove(&application_id)
            .unwrap_or_else(|| ApplicationGraphRecordSet {
                bindings: Vec::new(),
                clients: Vec::new(),
                claim_mappers: Vec::new(),
                organizations: Vec::new(),
                modules: Vec::new(),
                profiles: Vec::new(),
                permission_definitions: Vec::new(),
                profile_roles: Vec::new(),
            }))
    }
}

impl Db {
    /// Loads only the relations needed to render an application's client
    /// bindings. The full application graph also reads modules and
    /// authorization profiles, which are unrelated to this projection.
    pub async fn read_application_client_binding_graph(
        &self,
        application_id: &str,
    ) -> AppResult<ApplicationGraphRecordSet> {
        let application_id = application_id.to_string();
        let application_ids = vec![application_id];
        with_conn!(self, |conn, kind| {
            let application_placeholder = ph(kind, 1);
            let bindings_sql = format!(
                "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE application_id = {} ORDER BY created_at ASC",
                application_placeholder
            );
            let bindings = bind_text_list(&mut conn, sql_query(bindings_sql), &application_ids)
                .load::<ApplicationClientBindingRecord>(&mut conn)
                .map_err(AppError::from)?;

            let clients_sql = format!(
                "{} WHERE id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id = {}) ORDER BY created_at ASC",
                select_client_sql(),
                application_placeholder
            );
            let clients = bind_text_list(&mut conn, sql_query(clients_sql), &application_ids)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)?;

            let mappers_sql = format!(
                "{} WHERE client_db_id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id = {}) ORDER BY client_db_id ASC, sort_order ASC",
                select_client_claim_mapper_sql(),
                application_placeholder
            );
            let claim_mappers = bind_text_list(&mut conn, sql_query(mappers_sql), &application_ids)
                .load::<ClientClaimMapperRecord>(&mut conn)
                .map_err(AppError::from)?;

            let organizations_sql = format!(
                "{} WHERE id IN (SELECT organization_id FROM clients WHERE id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id = {}) AND organization_id IS NOT NULL) ORDER BY slug ASC",
                select_organization_sql(),
                application_placeholder
            );
            let organizations =
                bind_text_list(&mut conn, sql_query(organizations_sql), &application_ids)
                    .load::<OrganizationRecord>(&mut conn)
                    .map_err(AppError::from)?;

            Ok(ApplicationGraphRecordSet {
                bindings,
                clients,
                claim_mappers,
                organizations,
                modules: Vec::new(),
                profiles: Vec::new(),
                permission_definitions: Vec::new(),
                profile_roles: Vec::new(),
            })
        })
    }

    /// Loads the response graphs for a set of applications with one bounded
    /// query per relation instead of one graph (and eight queries) per
    /// application.  The aggregate assembler groups the rows back by the
    /// application/client/profile foreign keys after the connection has
    /// completed all reads.
    pub async fn read_application_graph_batch(
        &self,
        application_ids: &[String],
    ) -> AppResult<BTreeMap<String, ApplicationGraphRecordSet>> {
        let mut application_ids = application_ids.to_vec();
        application_ids.sort_unstable();
        application_ids.dedup();
        if application_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        with_conn!(self, |conn, kind| {
            conn.transaction::<BTreeMap<String, ApplicationGraphRecordSet>, AppError, _>(|conn| {
            let application_placeholders = placeholders(kind, 1, application_ids.len());
            let bindings_sql = format!(
                "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE application_id IN ({}) ORDER BY application_id ASC, created_at ASC",
                application_placeholders
            );
            let bindings = bind_text_list(conn, sql_query(bindings_sql), &application_ids)
                .load::<ApplicationClientBindingRecord>(conn)
                .map_err(AppError::from)?;

            let clients_sql = format!(
                "{} WHERE id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id IN ({})) ORDER BY created_at ASC",
                select_client_sql(),
                application_placeholders
            );
            let clients = bind_text_list(conn, sql_query(clients_sql), &application_ids)
                .load::<ClientRecord>(conn)
                .map_err(AppError::from)?;

            let mappers_sql = format!(
                "{} WHERE client_db_id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id IN ({})) ORDER BY client_db_id ASC, sort_order ASC",
                select_client_claim_mapper_sql(),
                application_placeholders
            );
            let claim_mappers = bind_text_list(conn, sql_query(mappers_sql), &application_ids)
                .load::<ClientClaimMapperRecord>(conn)
                .map_err(AppError::from)?;

            let organizations_sql = format!(
                "{} WHERE id IN (SELECT organization_id FROM clients WHERE id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id IN ({})) AND organization_id IS NOT NULL) ORDER BY slug ASC",
                select_organization_sql(),
                application_placeholders
            );
            let organizations =
                bind_text_list(conn, sql_query(organizations_sql), &application_ids)
                    .load::<OrganizationRecord>(conn)
                    .map_err(AppError::from)?;

            let modules_sql = format!(
                "{} WHERE application_id IN ({}) ORDER BY application_id ASC, module_key ASC",
                select_application_module_sql(),
                application_placeholders
            );
            let modules = bind_text_list(conn, sql_query(modules_sql), &application_ids)
                .load::<ApplicationModuleRecord>(conn)
                .map_err(AppError::from)?;

            let profiles_sql = format!(
                "{} WHERE application_id IN ({}) ORDER BY application_id ASC, profile_key ASC",
                select_application_authorization_profile_sql(),
                application_placeholders
            );
            let profiles = bind_text_list(conn, sql_query(profiles_sql), &application_ids)
                .load::<ApplicationAuthorizationProfileRecord>(conn)
                .map_err(AppError::from)?;

            let definitions_sql = format!(
                "{} WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE application_id IN ({})) ORDER BY profile_id ASC, permission_key ASC",
                select_application_permission_definition_sql(),
                application_placeholders
            );
            let permission_definitions =
                bind_text_list(conn, sql_query(definitions_sql), &application_ids)
                    .load::<ApplicationPermissionDefinitionRecord>(conn)
                    .map_err(AppError::from)?;

            let roles_sql = format!(
                "{} WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE application_id IN ({})) ORDER BY profile_id ASC, is_active DESC, name ASC",
                select_application_profile_role_sql(),
                application_placeholders
            );
            let profile_roles = bind_text_list(conn, sql_query(roles_sql), &application_ids)
                .load::<ApplicationProfileRoleRecord>(conn)
                .map_err(AppError::from)?;

            let mut graphs = application_ids
                .iter()
                .map(|application_id| {
                    (
                        application_id.clone(),
                        ApplicationGraphRecordSet {
                            bindings: Vec::new(),
                            clients: Vec::new(),
                            claim_mappers: Vec::new(),
                            organizations: Vec::new(),
                            modules: Vec::new(),
                            profiles: Vec::new(),
                            permission_definitions: Vec::new(),
                            profile_roles: Vec::new(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();

            let client_application_ids = bindings
                .iter()
                .map(|binding| (binding.client_db_id.clone(), binding.application_id.clone()))
                .collect::<BTreeMap<_, _>>();
            let profile_application_ids = profiles
                .iter()
                .map(|profile| (profile.id.clone(), profile.application_id.clone()))
                .collect::<BTreeMap<_, _>>();
            let mut organization_application_ids = BTreeMap::<String, BTreeSet<String>>::new();

            for binding in bindings {
                if let Some(graph) = graphs.get_mut(&binding.application_id) {
                    graph.bindings.push(binding);
                }
            }
            for client in clients {
                if let Some(application_id) = client_application_ids.get(&client.id) {
                    if let Some(organization_id) = client.organization_id.as_ref() {
                        organization_application_ids
                            .entry(organization_id.clone())
                            .or_default()
                            .insert(application_id.clone());
                    }
                    if let Some(graph) = graphs.get_mut(application_id) {
                        graph.clients.push(client);
                    }
                }
            }
            for mapper in claim_mappers {
                if let Some(application_id) = client_application_ids.get(&mapper.client_db_id)
                    && let Some(graph) = graphs.get_mut(application_id)
                {
                    graph.claim_mappers.push(mapper);
                }
            }
            for organization in organizations {
                if let Some(application_ids) = organization_application_ids.get(&organization.id) {
                    for application_id in application_ids {
                        if let Some(graph) = graphs.get_mut(application_id) {
                            graph.organizations.push(organization.clone());
                        }
                    }
                }
            }
            for module in modules {
                if let Some(graph) = graphs.get_mut(&module.application_id) {
                    graph.modules.push(module);
                }
            }
            for profile in profiles {
                if let Some(graph) = graphs.get_mut(&profile.application_id) {
                    graph.profiles.push(profile);
                }
            }
            for definition in permission_definitions {
                if let Some(application_id) = profile_application_ids.get(&definition.profile_id)
                    && let Some(graph) = graphs.get_mut(application_id)
                {
                    graph.permission_definitions.push(definition);
                }
            }
            for role in profile_roles {
                if let Some(application_id) = profile_application_ids.get(&role.profile_id)
                    && let Some(graph) = graphs.get_mut(application_id)
                {
                    graph.profile_roles.push(role);
                }
            }
            Ok(graphs)
        })
        })
    }
}
