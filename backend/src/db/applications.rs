//! Persistence for application-owned protocol graphs, modules, discovery, and bindings.
//!
//! The public methods remain inherent on Db; this module only owns their
//! physical implementation so callers and transaction semantics are unchanged.

use super::*;

/// Creates the locked compatibility aggregate for a protocol client while
/// the owning application deletion transaction is still open. Keeping this
/// primitive on the same connection makes the "client is never unowned"
/// invariant durable across process crashes and avoids post-commit repair
/// races.
macro_rules! insert_locked_compatibility_application_on_conn {
    ($conn:expr, $kind:expr, $client:expr, $organization_id:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let client = $client;
        let organization_id = $organization_id;
        let now = $now;
        let slug = allocate_application_slug_on_conn!(
            conn,
            kind,
            organization_id,
            &client.client_id,
        );
        let application_id = uuid::Uuid::new_v4().to_string();
        let application = NewApplication {
            organization_id: organization_id.to_string(),
            slug,
            name: client.client_name.clone(),
            description: Some(format!(
                "Locked compatibility application for OIDC client {}.",
                client.client_id
            )),
            access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: if client.require_account_selection == 1 {
                crate::applications::ACCOUNT_SELECTION_REQUIRED.to_string()
            } else {
                crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string()
            },
            unique_identity_factors: Vec::new(),
            is_active: true,
        };
        let created = insert_application_on_conn!(conn, kind, &application_id, application, now)?;
        let auth_domain_id = format!("auth-domain:{application_id}");
        let auth_domain_sql = format!(
            "INSERT INTO application_auth_domains (id, application_id, assurance_policy, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6)
        );
        sql_query(auth_domain_sql)
            .bind::<Text, _>(&auth_domain_id)
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>("default")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(conn)
            .map_err(AppError::from)?;
        let binding_sql = format!(
            "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6),
            ph(kind, 7),
            ph(kind, 8)
        );
        sql_query(binding_sql)
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>(&client.id)
            .bind::<Text, _>("oidc")
            .bind::<Text, _>("default")
            .bind::<Text, _>(&auth_domain_id)
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(conn)
            .map_err(AppError::from)?;
        Ok::<ApplicationRecord, AppError>(created)
    }};
}

impl Db {
    pub async fn create_application_oidc_client_graph(
        &self,
        application_id: &str,
        client: NewClient,
        mappers: Vec<NewClientClaimMapper>,
    ) -> AppResult<ClientRecord> {
        let application_id = application_id.to_string();
        let organization_id = client.organization_id.clone().ok_or_else(|| {
            AppError::BadRequest("OIDC client organization is required".to_string())
        })?;
        let profile_key = client.client_id.clone();
        let client_db_id = uuid::Uuid::new_v4().to_string();
        let profile_id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ClientRecord, AppError, _>(|conn| {
                let application_sql = format!(
                    "SELECT COUNT(*) AS count FROM applications WHERE id = {} AND organization_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if sql_query(application_sql)
                    .bind::<Text, _>(application_id.clone())
                    .bind::<Text, _>(organization_id.clone())
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let created = insert_client_on_conn!(
                    conn,
                    kind,
                    &client_db_id,
                    client,
                    now,
                )?;
                write_application_profile_on_conn!(
                    conn,
                    kind,
                    NewApplicationAuthorizationProfile {
                        id: profile_id.clone(),
                        application_id: application_id.clone(),
                        profile_key,
                        connection_kind: "oidc".to_string(),
                        connection_id: Some(created.id.clone()),
                        source_mode: crate::application_discovery::SOURCE_MODE_MANUAL.to_string(),
                        remote_version: None,
                        remote_digest: None,
                        sync_status: crate::application_discovery::SYNC_STATUS_MANUAL.to_string(),
                        last_synced_at: None,
                        last_error: None,
                    },
                    now,
                )?;
                ensure_application_client_binding_on_conn!(
                    conn,
                    kind,
                    &application_id,
                    &created.id,
                    "oidc",
                    &profile_id,
                    now,
                )?;
                replace_client_claim_mappers_on_conn!(conn, kind, &created.id, mappers, now)?;
                Ok(created)
            })
        })
    }

    /// Registers a dynamic OIDC connection and all of the policy rows that
    /// make it usable as one aggregate. Dynamic registration historically
    /// inserted the client first and then created its compatibility
    /// application on separate pooled connections; a failure between those
    /// steps left an active client with no application boundary. Keep the
    /// fallback application locked to the platform account boundary, but
    /// create the client, application, physical profile, binding, and
    /// registration credential in one transaction.
    pub async fn register_dynamic_client_graph(
        &self,
        mut client: NewClient,
        registration_access_token_hash: String,
    ) -> AppResult<ClientRecord> {
        if registration_access_token_hash.trim().is_empty() {
            return Err(AppError::BadRequest(
                "dynamic registration access token is required".to_string(),
            ));
        }
        // DCR does not accept an organization selector. This is the same
        // fallback used by the legacy compatibility path, now resolved before
        // the first row is written so every aggregate member sees one owner.
        client.organization_id = Some(SIGNET_ORGANIZATION_ID.to_string());
        let client_db_id = uuid::Uuid::new_v4().to_string();
        let application_id = uuid::Uuid::new_v4().to_string();
        let profile_id = uuid::Uuid::new_v4().to_string();
        let profile_key = client.client_id.clone();
        let now = util::now_ts();

        with_conn!(self, |conn, kind| {
            conn.transaction::<ClientRecord, AppError, _>(|conn| {
                let organization_sql = format!(
                    "SELECT COUNT(*) AS count FROM organizations WHERE id = {} AND is_active = 1",
                    ph(kind, 1)
                );
                if sql_query(organization_sql)
                    .bind::<Text, _>(SIGNET_ORGANIZATION_ID)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::Internal(
                        "Signet system organization is unavailable for dynamic registration"
                            .to_string(),
                    ));
                }

                let created = insert_client_on_conn!(
                    conn,
                    kind,
                    &client_db_id,
                    client,
                    now,
                )?;

                let application_slug = allocate_application_slug_on_conn!(
                    conn,
                    kind,
                    SIGNET_ORGANIZATION_ID,
                    &created.client_id,
                );
                let application_sql = format!(
                    "INSERT INTO applications (id, organization_id, slug, name, description, access_mode, registration_mode, account_selection_mode, unique_identity_factors, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10),
                    ph(kind, 11),
                    ph(kind, 12)
                );
                sql_query(application_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(SIGNET_ORGANIZATION_ID)
                    .bind::<Text, _>(application_slug)
                    .bind::<Text, _>(&created.client_name)
                    .bind::<Nullable<Text>, _>(Some(format!(
                        "Website application created for OIDC client {}.",
                        created.client_id
                    )))
                    .bind::<Text, _>(crate::applications::ACCESS_ALL_SIGNET_USERS)
                    .bind::<Text, _>(crate::applications::REGISTRATION_DISABLED)
                    .bind::<Text, _>(if created.require_account_selection == 1 {
                        crate::applications::ACCOUNT_SELECTION_REQUIRED
                    } else {
                        crate::applications::ACCOUNT_SELECTION_OPTIONAL
                    })
                    .bind::<Text, _>("[]")
                    .bind::<Integer, _>(1)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let _ = ensure_application_default_profile_on_conn!(conn, kind, &application_id, now);

                write_application_profile_on_conn!(
                    conn,
                    kind,
                    NewApplicationAuthorizationProfile {
                        id: profile_id.clone(),
                        application_id: application_id.clone(),
                        profile_key,
                        connection_kind: "oidc".to_string(),
                        connection_id: Some(created.id.clone()),
                        source_mode: crate::application_discovery::SOURCE_MODE_MANUAL.to_string(),
                        remote_version: None,
                        remote_digest: None,
                        sync_status: crate::application_discovery::SYNC_STATUS_MANUAL.to_string(),
                        last_synced_at: None,
                        last_error: None,
                    },
                    now,
                )?;
                ensure_application_client_binding_on_conn!(
                    conn,
                    kind,
                    &application_id,
                    &created.id,
                    "oidc",
                    &profile_id,
                    now,
                )?;

                let registration_sql = format!(
                    "INSERT INTO client_registrations (client_db_id, registration_access_token_hash, created_at, updated_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(registration_sql)
                    .bind::<Text, _>(&created.id)
                    .bind::<Text, _>(registration_access_token_hash)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(created)
            })
        })
    }

    /// Updates the client, its profile identity, binding, and claim mappers
    /// atomically.  Legacy `default` bindings are upgraded to a physical
    /// profile ID during the same transition.
    pub async fn update_application_oidc_client_graph(
        &self,
        application_id: &str,
        client_db_id: &str,
        client: NewClient,
        mappers: Vec<NewClientClaimMapper>,
    ) -> AppResult<ClientRecord> {
        let application_id = application_id.to_string();
        let client_db_id = client_db_id.to_string();
        let organization_id = client.organization_id.clone().ok_or_else(|| {
            AppError::BadRequest("OIDC client organization is required".to_string())
        })?;
        let profile_key = client.client_id.clone();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ClientRecord, AppError, _>(|conn| {
                let binding_sql = format!(
                    "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE client_db_id = {}",
                    ph(kind, 1)
                );
                let binding = sql_query(binding_sql)
                    .bind::<Text, _>(client_db_id.clone())
                    .get_result::<ApplicationClientBindingRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .filter(|binding| {
                        binding.application_id == application_id && binding.protocol == "oidc"
                    })
                    .ok_or(AppError::NotFound)?;
                let existing_sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(client_db_id.clone())
                    .get_result::<ClientRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                let application_sql = format!(
                    "SELECT COUNT(*) AS count FROM applications WHERE id = {} AND organization_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if sql_query(application_sql)
                    .bind::<Text, _>(application_id.clone())
                    .bind::<Text, _>(organization_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::BadRequest(
                        "OIDC client must belong to the application's organization".to_string(),
                    ));
                }

                let profile_id = if binding.authorization_profile_id == "default" {
                    let by_connection_sql = format!(
                        "{} WHERE application_id = {} AND connection_id = {}",
                        select_application_authorization_profile_sql(),
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    let by_connection = sql_query(by_connection_sql)
                        .bind::<Text, _>(application_id.clone())
                        .bind::<Text, _>(client_db_id.clone())
                        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                    let profile = if by_connection.is_some() {
                        by_connection
                    } else {
                            let by_key_sql = format!(
                                "{} WHERE application_id = {} AND profile_key = {}",
                                select_application_authorization_profile_sql(),
                                ph(kind, 1),
                                ph(kind, 2)
                            );
                            sql_query(by_key_sql)
                                .bind::<Text, _>(application_id.clone())
                                .bind::<Text, _>(existing.client_id.clone())
                                .get_result::<ApplicationAuthorizationProfileRecord>(conn)
                                .optional()
                                .map_err(AppError::from)?
                    };
                    profile
                        .map(|profile| profile.id)
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
                } else {
                    let profile_count_sql = format!(
                        "SELECT COUNT(*) AS count FROM application_authorization_profiles WHERE id = {} AND application_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    if sql_query(profile_count_sql)
                        .bind::<Text, _>(binding.authorization_profile_id.clone())
                        .bind::<Text, _>(application_id.clone())
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        == 0
                    {
                        return Err(AppError::BadRequest(
                            "authorization profile must belong to the application".to_string(),
                        ));
                    }
                    binding.authorization_profile_id.clone()
                };
                let updated = update_client_on_conn!(conn, kind, &client_db_id, client, now)?;
                write_application_profile_on_conn!(
                    conn,
                    kind,
                    NewApplicationAuthorizationProfile {
                        id: profile_id.clone(),
                        application_id: application_id.clone(),
                        profile_key,
                        connection_kind: "oidc".to_string(),
                        connection_id: Some(updated.id.clone()),
                        source_mode: crate::application_discovery::SOURCE_MODE_MANUAL.to_string(),
                        remote_version: None,
                        remote_digest: None,
                        sync_status: crate::application_discovery::SYNC_STATUS_MANUAL.to_string(),
                        last_synced_at: None,
                        last_error: None,
                    },
                    now,
                )?;
                ensure_application_client_binding_on_conn!(
                    conn,
                    kind,
                    &application_id,
                    &updated.id,
                    "oidc",
                    &profile_id,
                    now,
                )?;
                replace_client_claim_mappers_on_conn!(conn, kind, &updated.id, mappers, now)?;
                Ok(updated)
            })
        })
    }

    /// Deletes an Application/OIDC connection and every profile-owned policy
    /// row in one transaction.  This prevents a deleted connection from
    /// leaving an unreachable authorization profile graph behind.
    pub async fn delete_application_oidc_client_graph(
        &self,
        application_id: &str,
        client_db_id: &str,
    ) -> AppResult<ClientRecord> {
        let application_id = application_id.to_string();
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ClientRecord, AppError, _>(|conn| {
                let binding_sql = format!(
                    "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE client_db_id = {}",
                    ph(kind, 1)
                );
                let binding = sql_query(binding_sql)
                    .bind::<Text, _>(client_db_id.clone())
                    .get_result::<ApplicationClientBindingRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .filter(|binding| {
                        binding.application_id == application_id && binding.protocol == "oidc"
                    })
                    .ok_or(AppError::NotFound)?;
                let profile_selector = format!(
                    "application_id = {} AND (connection_id = {} OR id = {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                for table in [
                    "application_profile_permission_overrides",
                    "application_profile_user_roles",
                    "application_profile_group_roles",
                    "application_profile_organization_roles",
                    "application_permission_definitions",
                    "application_profile_roles",
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE {profile_selector})"
                    );
                    sql_query(sql)
                        .bind::<Text, _>(application_id.clone())
                        .bind::<Text, _>(client_db_id.clone())
                        .bind::<Text, _>(binding.authorization_profile_id.clone())
                        .execute(&mut *conn)
                        .map_err(AppError::from)?;
                }
                let profile_sql = format!(
                    "DELETE FROM application_authorization_profiles WHERE {}",
                    profile_selector
                );
                sql_query(profile_sql)
                    .bind::<Text, _>(application_id.clone())
                    .bind::<Text, _>(client_db_id.clone())
                    .bind::<Text, _>(binding.authorization_profile_id)
                    .execute(&mut *conn)
                    .map_err(AppError::from)?;
                delete_client_on_conn!(conn, kind, &client_db_id)
            })
        })
    }
}
impl Db {
    pub async fn list_applications(
        &self,
        organization_id: Option<&str>,
    ) -> AppResult<Vec<ApplicationRecord>> {
        let organization_id = organization_id.map(ToOwned::to_owned);
        with_conn!(self, |conn, kind| {
            if let Some(organization_id) = organization_id {
                let sql = format!(
                    "{} WHERE organization_id = {} ORDER BY is_active DESC, name ASC",
                    select_application_sql(),
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(organization_id)
                    .load::<ApplicationRecord>(&mut conn)
                    .map_err(AppError::from)
            } else {
                let sql = format!(
                    "{} ORDER BY organization_id ASC, is_active DESC, name ASC",
                    select_application_sql()
                );
                sql_query(sql)
                    .load::<ApplicationRecord>(&mut conn)
                    .map_err(AppError::from)
            }
        })
    }

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

    /// Loads the response graphs for a set of applications with one bounded
    /// query per relation instead of one graph (and eight queries) per
    /// application.  The aggregate assembler groups the rows back by the
    /// application/client/profile foreign keys after the connection has
    /// completed all reads.
    pub async fn read_application_graph_batch(
        &self,
        application_ids: &[String],
    ) -> AppResult<BTreeMap<String, ApplicationGraphRecordSet>> {
        if application_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let application_ids = application_ids.to_vec();
        with_conn!(self, |conn, kind| {
            conn.transaction::<BTreeMap<String, ApplicationGraphRecordSet>, AppError, _>(|conn| {
                let bindings_sql = format!(
                "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE application_id IN ({}) ORDER BY application_id ASC, created_at ASC",
                (1..=application_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let bindings = bind_text_list(conn, sql_query(bindings_sql), &application_ids)
                .load::<ApplicationClientBindingRecord>(conn)
                .map_err(AppError::from)?;

            let clients_sql = format!(
                "{} WHERE id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id IN ({})) ORDER BY created_at ASC",
                select_client_sql(),
                (1..=application_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let clients = bind_text_list(conn, sql_query(clients_sql), &application_ids)
                .load::<ClientRecord>(conn)
                .map_err(AppError::from)?;

            let mappers_sql = format!(
                "{} WHERE client_db_id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id IN ({})) ORDER BY client_db_id ASC, sort_order ASC",
                select_client_claim_mapper_sql(),
                (1..=application_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let claim_mappers = bind_text_list(conn, sql_query(mappers_sql), &application_ids)
                .load::<ClientClaimMapperRecord>(conn)
                .map_err(AppError::from)?;

            let organizations_sql = format!(
                "{} WHERE id IN (SELECT organization_id FROM clients WHERE id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id IN ({})) AND organization_id IS NOT NULL) ORDER BY slug ASC",
                select_organization_sql(),
                (1..=application_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let organizations =
                bind_text_list(conn, sql_query(organizations_sql), &application_ids)
                    .load::<OrganizationRecord>(conn)
                    .map_err(AppError::from)?;

            let modules_sql = format!(
                "{} WHERE application_id IN ({}) ORDER BY application_id ASC, module_key ASC",
                select_application_module_sql(),
                (1..=application_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let modules = bind_text_list(conn, sql_query(modules_sql), &application_ids)
                .load::<ApplicationModuleRecord>(conn)
                .map_err(AppError::from)?;

            let profiles_sql = format!(
                "{} WHERE application_id IN ({}) ORDER BY application_id ASC, profile_key ASC",
                select_application_authorization_profile_sql(),
                (1..=application_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let profiles = bind_text_list(conn, sql_query(profiles_sql), &application_ids)
                .load::<ApplicationAuthorizationProfileRecord>(conn)
                .map_err(AppError::from)?;

            let definitions_sql = format!(
                "{} WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE application_id IN ({})) ORDER BY profile_id ASC, permission_key ASC",
                select_application_permission_definition_sql(),
                (1..=application_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let permission_definitions =
                bind_text_list(conn, sql_query(definitions_sql), &application_ids)
                    .load::<ApplicationPermissionDefinitionRecord>(conn)
                    .map_err(AppError::from)?;

            let roles_sql = format!(
                "{} WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE application_id IN ({})) ORDER BY profile_id ASC, is_active DESC, name ASC",
                select_application_profile_role_sql(),
                (1..=application_ids.len())
                    .map(|index| ph(kind, index))
                    .collect::<Vec<_>>()
                    .join(", ")
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

    pub async fn list_application_modules(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationModuleRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} ORDER BY module_key ASC",
                select_application_module_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationModuleRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_module(
        &self,
        application_id: &str,
        module_key: &str,
    ) -> AppResult<Option<ApplicationModuleRecord>> {
        let application_id = application_id.to_string();
        let module_key = module_key.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} AND module_key = {}",
                select_application_module_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(module_key)
                .get_result::<ApplicationModuleRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_application_module(
        &self,
        application_id: &str,
        module_key: &str,
        config_json: &str,
        is_enabled: bool,
    ) -> AppResult<ApplicationModuleRecord> {
        let application_id = application_id.to_string();
        let module_key = module_key.to_string();
        let config_json = config_json.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            upsert_application_module_on_conn!(
                conn,
                kind,
                &application_id,
                &module_key,
                &config_json,
                is_enabled,
                now,
            )
        })
    }

    /// Upserts one application module and its audit record atomically.
    pub async fn upsert_application_module_with_audit(
        &self,
        application_id: &str,
        module_key: &str,
        config_json: &str,
        is_enabled: bool,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationModuleRecord> {
        let application_id = application_id.to_string();
        let module_key = module_key.to_string();
        let config_json = config_json.to_string();
        let now = util::now_ts();
        let webhook_db = self.clone();
        let (module, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationModuleRecord, AuditEventRecord), AppError, _>(|conn| {
                let module = upsert_application_module_on_conn!(
                    conn,
                    kind,
                    &application_id,
                    &module_key,
                    &config_json,
                    is_enabled,
                    now,
                )?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((module, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(module)
    }

    pub async fn delete_application_module(
        &self,
        application_id: &str,
        module_key: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let module_key = module_key.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let lock_sql = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(lock_sql)
                    .bind::<Text, _>(&application_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let sql = format!(
                    "DELETE FROM application_modules WHERE application_id = {} AND module_key = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&module_key)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }
}

impl Db {
    pub async fn find_application_by_slug_in_organization(
        &self,
        organization_id: &str,
        slug: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        let organization_id = organization_id.to_string();
        let slug = slug.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE organization_id = {} AND slug = {}",
                select_application_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .bind::<Text, _>(slug)
                .get_result::<ApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_by_id(&self, id: &str) -> AppResult<Option<ApplicationRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_application_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_discovery(
        &self,
        application_id: &str,
    ) -> AppResult<Option<ApplicationDiscoveryRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {}",
                select_application_discovery_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .get_result::<ApplicationDiscoveryRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_website_managed_discoveries(
        &self,
    ) -> AppResult<Vec<(ApplicationRecord, ApplicationDiscoveryRecord)>> {
        Ok(self
            .list_application_discoveries()
            .await?
            .into_iter()
            .filter(|(_, discovery)| {
                discovery.management_mode == crate::application_discovery::MANAGEMENT_MODE_WEBSITE
            })
            .collect())
    }

    pub async fn list_application_discoveries(
        &self,
    ) -> AppResult<Vec<(ApplicationRecord, ApplicationDiscoveryRecord)>> {
        let rows = with_conn!(self, |conn, _kind| {
            // The inner join intentionally preserves the old behavior for an
            // orphan discovery row: it is ignored rather than handed to the
            // reconciler as an application that no longer exists.  Unlike the
            // former per-row lookups, this is one query for the whole set.
            let sql = "SELECT applications.id AS id,
                              applications.organization_id AS organization_id,
                              applications.slug AS slug,
                              applications.name AS name,
                              applications.description AS description,
                              applications.access_mode AS access_mode,
                              applications.registration_mode AS registration_mode,
                              applications.account_selection_mode AS account_selection_mode,
                              COALESCE(applications.unique_identity_factors, '[]') AS unique_identity_factors,
                              applications.is_active AS is_active,
                              applications.created_at AS created_at,
                              applications.updated_at AS updated_at,
                              application_discovery.management_mode AS discovery_management_mode,
                              application_discovery.website_url AS discovery_website_url,
                              application_discovery.fetch_secret_ciphertext AS fetch_secret_ciphertext,
                              application_discovery.signing_public_jwks AS signing_public_jwks,
                              application_discovery.last_verified_revision AS last_verified_revision,
                              application_discovery.last_verified_version AS last_verified_version,
                              application_discovery.last_verified_digest AS last_verified_digest,
                              application_discovery.last_verified_expires_at AS last_verified_expires_at,
                              application_discovery.sync_status AS discovery_sync_status,
                              application_discovery.last_fetched_at AS last_fetched_at,
                              application_discovery.last_success_at AS last_success_at,
                              application_discovery.last_error AS discovery_last_error,
                              application_discovery.snapshot_json AS snapshot_json,
                              application_discovery.operator_disabled AS operator_disabled,
                              application_discovery.created_at AS discovery_created_at,
                              application_discovery.updated_at AS discovery_updated_at,
                              application_discovery.lease_owner AS discovery_lease_owner,
                              application_discovery.lease_expires_at AS discovery_lease_expires_at,
                              application_discovery.lease_generation AS discovery_lease_generation
                       FROM application_discovery
                       INNER JOIN applications
                         ON applications.id = application_discovery.application_id
                       ORDER BY applications.id ASC";
            sql_query(sql)
                .load::<ApplicationDiscoveryJoinRecord>(&mut conn)
                .map_err(AppError::from)
        })?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let application_id = row.id.clone();
                (
                    ApplicationRecord {
                        id: row.id,
                        organization_id: row.organization_id,
                        slug: row.slug,
                        name: row.name,
                        description: row.description,
                        access_mode: row.access_mode,
                        registration_mode: row.registration_mode,
                        account_selection_mode: row.account_selection_mode,
                        unique_identity_factors: row.unique_identity_factors,
                        is_active: row.is_active,
                        created_at: row.created_at,
                        updated_at: row.updated_at,
                    },
                    ApplicationDiscoveryRecord {
                        application_id,
                        management_mode: row.discovery_management_mode,
                        website_url: row.discovery_website_url,
                        fetch_secret_ciphertext: row.fetch_secret_ciphertext,
                        signing_public_jwks: row.signing_public_jwks,
                        last_verified_revision: row.last_verified_revision,
                        last_verified_version: row.last_verified_version,
                        last_verified_digest: row.last_verified_digest,
                        last_verified_expires_at: row.last_verified_expires_at,
                        sync_status: row.discovery_sync_status,
                        last_fetched_at: row.last_fetched_at,
                        last_success_at: row.last_success_at,
                        last_error: row.discovery_last_error,
                        snapshot_json: row.snapshot_json,
                        operator_disabled: row.operator_disabled,
                        created_at: row.discovery_created_at,
                        updated_at: row.discovery_updated_at,
                        lease_owner: row.discovery_lease_owner,
                        lease_expires_at: row.discovery_lease_expires_at,
                        lease_generation: row.discovery_lease_generation,
                    },
                )
            })
            .collect())
    }

    pub async fn upsert_application_discovery(
        &self,
        discovery: NewApplicationDiscovery,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let existing = format!(
                "SELECT COUNT(*) AS count FROM application_discovery WHERE application_id = {}",
                ph(kind, 1)
            );
            let exists = sql_query(existing)
                .bind::<Text, _>(&discovery.application_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                > 0;
            if exists {
                let sql = format!(
                    "UPDATE application_discovery SET management_mode = {}, website_url = {}, fetch_secret_ciphertext = {}, signing_public_jwks = {}, last_verified_revision = {}, last_verified_version = {}, last_verified_digest = {}, last_verified_expires_at = {}, sync_status = {}, last_fetched_at = {}, last_success_at = {}, last_error = {}, snapshot_json = {}, operator_disabled = {}, updated_at = {} WHERE application_id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10),
                    ph(kind, 11),
                    ph(kind, 12),
                    ph(kind, 13),
                    ph(kind, 14),
                    ph(kind, 15),
                    ph(kind, 16)
                );
                sql_query(sql)
                    .bind::<Text, _>(&discovery.management_mode)
                    .bind::<Text, _>(&discovery.website_url)
                    .bind::<Text, _>(&discovery.fetch_secret_ciphertext)
                    .bind::<Text, _>(&discovery.signing_public_jwks)
                    .bind::<Nullable<BigInt>, _>(discovery.last_verified_revision)
                    .bind::<Nullable<Text>, _>(&discovery.last_verified_version)
                    .bind::<Nullable<Text>, _>(&discovery.last_verified_digest)
                    .bind::<Nullable<BigInt>, _>(discovery.last_verified_expires_at)
                    .bind::<Text, _>(&discovery.sync_status)
                    .bind::<Nullable<BigInt>, _>(discovery.last_fetched_at)
                    .bind::<Nullable<BigInt>, _>(discovery.last_success_at)
                    .bind::<Nullable<Text>, _>(&discovery.last_error)
                    .bind::<Nullable<Text>, _>(&discovery.snapshot_json)
                    .bind::<Integer, _>(i32::from(discovery.operator_disabled))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&discovery.application_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            } else {
                let sql = format!(
                    "INSERT INTO application_discovery (application_id, management_mode, website_url, fetch_secret_ciphertext, signing_public_jwks, last_verified_revision, last_verified_version, last_verified_digest, last_verified_expires_at, sync_status, last_fetched_at, last_success_at, last_error, snapshot_json, operator_disabled, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10),
                    ph(kind, 11),
                    ph(kind, 12),
                    ph(kind, 13),
                    ph(kind, 14),
                    ph(kind, 15),
                    ph(kind, 16),
                    ph(kind, 17)
                );
                sql_query(sql)
                    .bind::<Text, _>(&discovery.application_id)
                    .bind::<Text, _>(&discovery.management_mode)
                    .bind::<Text, _>(&discovery.website_url)
                    .bind::<Text, _>(&discovery.fetch_secret_ciphertext)
                    .bind::<Text, _>(&discovery.signing_public_jwks)
                    .bind::<Nullable<BigInt>, _>(discovery.last_verified_revision)
                    .bind::<Nullable<Text>, _>(&discovery.last_verified_version)
                    .bind::<Nullable<Text>, _>(&discovery.last_verified_digest)
                    .bind::<Nullable<BigInt>, _>(discovery.last_verified_expires_at)
                    .bind::<Text, _>(&discovery.sync_status)
                    .bind::<Nullable<BigInt>, _>(discovery.last_fetched_at)
                    .bind::<Nullable<BigInt>, _>(discovery.last_success_at)
                    .bind::<Nullable<Text>, _>(&discovery.last_error)
                    .bind::<Nullable<Text>, _>(&discovery.snapshot_json)
                    .bind::<Integer, _>(i32::from(discovery.operator_disabled))
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!(
                "{} WHERE application_id = {}",
                select_application_discovery_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&discovery.application_id)
                .get_result::<ApplicationDiscoveryRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Claims a durable discovery lease. `None` means another process still
    /// owns a non-expired lease; a missing discovery row is reported as
    /// `NotFound` so callers cannot silently skip an application.
    pub async fn claim_application_discovery_lease(
        &self,
        application_id: &str,
        owner_token: &str,
    ) -> AppResult<Option<ApplicationDiscoveryLease>> {
        if owner_token.trim().is_empty() {
            return Err(AppError::BadRequest(
                "application discovery lease owner is required".to_string(),
            ));
        }
        let application_id = application_id.to_string();
        let owner_token = owner_token.to_string();
        let now = util::now_ts();
        let lease_expires_at = now + APPLICATION_DISCOVERY_LEASE_TTL_SECONDS;
        with_conn!(self, |conn, kind| {
            let exists_sql = format!(
                "SELECT COUNT(*) AS count FROM application_discovery WHERE application_id = {}",
                ph(kind, 1)
            );
            if sql_query(exists_sql)
                .bind::<Text, _>(&application_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                == 0
            {
                return Err(AppError::NotFound);
            }
            let claim_sql = format!(
                "UPDATE application_discovery SET lease_owner = {}, lease_expires_at = {}, lease_generation = COALESCE(lease_generation, 0) + 1, updated_at = {} WHERE application_id = {} AND (lease_owner IS NULL OR lease_expires_at IS NULL OR lease_expires_at <= {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
            );
            let claimed = sql_query(claim_sql)
                .bind::<Nullable<Text>, _>(Some(owner_token.clone()))
                .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&application_id)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if claimed != 1 {
                return Ok(None);
            }

            #[derive(Debug, diesel::QueryableByName)]
            struct LeaseRow {
                #[diesel(sql_type = Nullable<Text>)]
                lease_owner: Option<String>,
                #[diesel(sql_type = Nullable<BigInt>)]
                lease_expires_at: Option<i64>,
                #[diesel(sql_type = BigInt)]
                lease_generation: i64,
            }
            let select_sql = format!(
                "SELECT lease_owner, lease_expires_at, lease_generation FROM application_discovery WHERE application_id = {}",
                ph(kind, 1)
            );
            let lease = sql_query(select_sql)
                .bind::<Text, _>(&application_id)
                .get_result::<LeaseRow>(&mut conn)
                .map_err(AppError::from)?;
            Ok(Some(ApplicationDiscoveryLease {
                application_id,
                owner_token: lease.lease_owner.unwrap_or(owner_token),
                lease_expires_at: lease.lease_expires_at.unwrap_or(lease_expires_at),
                lease_generation: lease.lease_generation,
            }))
        })
    }

    pub async fn renew_application_discovery_lease(
        &self,
        application_id: &str,
        owner_token: &str,
        lease_generation: i64,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        let owner_token = owner_token.to_string();
        let now = util::now_ts();
        let lease_expires_at = now + APPLICATION_DISCOVERY_LEASE_TTL_SECONDS;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery SET lease_expires_at = {}, updated_at = {} WHERE application_id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at IS NOT NULL AND lease_expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
            );
            sql_query(sql)
                .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(owner_token)
                .bind::<BigInt, _>(lease_generation)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    pub async fn release_application_discovery_lease(
        &self,
        application_id: &str,
        owner_token: &str,
        lease_generation: i64,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        let owner_token = owner_token.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery SET lease_owner = {}, lease_expires_at = {}, updated_at = {} WHERE application_id = {} AND lease_owner = {} AND lease_generation = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
            );
            sql_query(sql)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(util::now_ts())
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(owner_token)
                .bind::<BigInt, _>(lease_generation)
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    /// Publishes only a result that still owns the durable lease.  The
    /// existing contract reconciler is intentionally kept as the
    /// compatibility/non-leased entry point; the discovery module can switch
    /// to this method without changing its manifest model.
    pub async fn commit_application_discovery_if_owner(
        &self,
        application_id: &str,
        owner_token: &str,
        lease_generation: i64,
        manifest: crate::application_discovery::VerifiedApplicationManifest,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        self.apply_application_contract_with_lease(
            application_id,
            manifest,
            Some((owner_token.to_string(), lease_generation)),
        )
        .await
    }

    pub async fn mark_application_discovery_sync_error_if_owner(
        &self,
        application_id: &str,
        owner_token: &str,
        lease_generation: i64,
        sync_status: &str,
        last_error: Option<String>,
    ) -> AppResult<Option<ApplicationDiscoveryRecord>> {
        let application_id = application_id.to_string();
        let owner_token = owner_token.to_string();
        let sync_status = sync_status.to_string();
        let last_error = last_error.map(|value| value.chars().take(512).collect::<String>());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery SET sync_status = {}, last_fetched_at = {}, last_error = {}, updated_at = {} WHERE application_id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at IS NOT NULL AND lease_expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(&sync_status)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(&last_error)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&owner_token)
                .bind::<BigInt, _>(lease_generation)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected != 1 {
                return Ok(None);
            }
            let select_sql = format!(
                "{} WHERE application_id = {}",
                select_application_discovery_sql(),
                ph(kind, 1)
            );
            sql_query(select_sql)
                .bind::<Text, _>(&application_id)
                .get_result::<ApplicationDiscoveryRecord>(&mut conn)
                .map(Some)
                .map_err(AppError::from)
        })
    }

    /// Claims one administrative auto-registration request. The claim is
    /// durable so retries and concurrent Signet processes share the same
    /// result instead of repeating the website challenge and provisioning
    /// sequence. Completed keys are retained for one day; an abandoned
    /// in-progress claim may be taken over after a bounded lease.
    pub async fn claim_application_discovery_idempotency(
        &self,
        organization_id: &str,
        idempotency_key: &str,
        request_hash: &str,
        origin: &str,
    ) -> AppResult<ApplicationDiscoveryIdempotencyClaim> {
        const COMPLETED_RETENTION_SECONDS: i64 = 24 * 60 * 60;
        const CLAIM_LEASE_SECONDS: i64 = 15 * 60;
        let organization_id = organization_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let request_hash = request_hash.to_string();
        let origin = origin.to_string();
        let now = util::now_ts();
        let claim_token = util::random_token(24);
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM application_discovery_idempotency WHERE status <> {} AND updated_at <= {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(cleanup_sql)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now.saturating_sub(COMPLETED_RETENTION_SECONDS))
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let insert_sql = match kind {
                DatabaseKind::Mysql => format!(
                    "INSERT IGNORE INTO application_discovery_idempotency (organization_id, idempotency_key, request_hash, origin, application_id, claim_token, status, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                ),
                _ => format!(
                    "INSERT INTO application_discovery_idempotency (organization_id, idempotency_key, request_hash, origin, application_id, claim_token, status, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}) ON CONFLICT (organization_id, idempotency_key) DO NOTHING",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                ),
            };
            let inserted = sql_query(insert_sql)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>(&request_hash)
                .bind::<Text, _>(&origin)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Text, _>(&claim_token)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if inserted == 1 {
                return Ok(ApplicationDiscoveryIdempotencyClaim::Claimed { claim_token });
            }

            let select_sql = format!(
                "SELECT request_hash, origin, application_id, status, updated_at FROM application_discovery_idempotency WHERE organization_id = {} AND idempotency_key = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            let record = sql_query(select_sql)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .get_result::<ApplicationDiscoveryIdempotencyRecord>(&mut conn)
                .map_err(AppError::from)?;
            if record.request_hash != request_hash || record.origin != origin {
                return Err(AppError::BadRequest(
                    "idempotency_key was already used for another discovery request".to_string(),
                ));
            }
            if record.status == "completed" {
                if let Some(application_id) = record.application_id {
                    return Ok(ApplicationDiscoveryIdempotencyClaim::Completed { application_id });
                }
            }
            if record.status == "in_progress"
                && record.updated_at > now.saturating_sub(CLAIM_LEASE_SECONDS)
            {
                return Ok(ApplicationDiscoveryIdempotencyClaim::InProgress);
            }

            let update_sql = format!(
                "UPDATE application_discovery_idempotency SET application_id = {}, claim_token = {}, status = {}, updated_at = {} WHERE organization_id = {} AND idempotency_key = {} AND (status <> {} OR updated_at <= {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
            );
            let affected = sql_query(update_sql)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Text, _>(&claim_token)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now.saturating_sub(CLAIM_LEASE_SECONDS))
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 1 {
                Ok(ApplicationDiscoveryIdempotencyClaim::Claimed { claim_token })
            } else {
                Ok(ApplicationDiscoveryIdempotencyClaim::InProgress)
            }
        })
    }

    pub async fn complete_application_discovery_idempotency(
        &self,
        organization_id: &str,
        idempotency_key: &str,
        claim_token: &str,
        application_id: &str,
    ) -> AppResult<()> {
        let organization_id = organization_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let claim_token = claim_token.to_string();
        let application_id = application_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery_idempotency SET application_id = {}, status = {}, updated_at = {} WHERE organization_id = {} AND idempotency_key = {} AND claim_token = {} AND status = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>("completed")
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>(&claim_token)
                .bind::<Text, _>("in_progress")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected != 1 {
                return Err(AppError::Database(
                    "application discovery idempotency claim is no longer active".to_string(),
                ));
            }
            Ok(())
        })
    }

    pub async fn fail_application_discovery_idempotency(
        &self,
        organization_id: &str,
        idempotency_key: &str,
        claim_token: &str,
    ) -> AppResult<()> {
        let organization_id = organization_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let claim_token = claim_token.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery_idempotency SET application_id = {}, status = {}, updated_at = {} WHERE organization_id = {} AND idempotency_key = {} AND claim_token = {} AND status = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
            );
            sql_query(sql)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Text, _>("failed")
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>(&claim_token)
                .bind::<Text, _>("in_progress")
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    /// Records a failed discovery attempt without touching the last verified
    /// snapshot.  Runtime authorization deliberately reads the verified
    /// revision/snapshot fields, so a transient website outage only changes
    /// operator-visible status and diagnostics.
    pub async fn mark_application_discovery_sync_error(
        &self,
        application_id: &str,
        sync_status: &str,
        last_error: Option<String>,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        let application_id = application_id.to_string();
        let sync_status = sync_status.to_string();
        let last_error = last_error.map(|value| value.chars().take(512).collect::<String>());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery SET sync_status = {}, last_fetched_at = {}, last_error = {}, updated_at = {} WHERE application_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(&sync_status)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(&last_error)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&application_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            let sql = format!(
                "{} WHERE application_id = {}",
                select_application_discovery_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&application_id)
                .get_result::<ApplicationDiscoveryRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Applies one already verified website snapshot atomically. Network
    /// fetching and signature validation happen before this method; this
    /// transaction only reconciles the normalized result and the snapshot
    /// metadata. Client secrets are already hashed by the verifier.
    pub async fn apply_application_contract(
        &self,
        application_id: &str,
        manifest: crate::application_discovery::VerifiedApplicationManifest,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        self.apply_application_contract_with_lease(application_id, manifest, None)
            .await
    }

    async fn apply_application_contract_with_lease(
        &self,
        application_id: &str,
        manifest: crate::application_discovery::VerifiedApplicationManifest,
        lease: Option<(String, i64)>,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        let application_id = application_id.to_string();
        let snapshot_json = util::to_json(&manifest.redacted_payload)?;
        let manifest = manifest.clone();
        let application_organization_id = self
            .find_application_by_id(&application_id)
            .await?
            .ok_or(AppError::NotFound)?
            .organization_id;
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationDiscoveryRecord, AppError, _>(|conn| {
                // Discovery role/profile reconciliation and manual role
                // writes share the application row as their serialization
                // point. This prevents two concurrent writers from both
                // materializing a default role in the same profile.
                let lock_sql = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(lock_sql)
                    .bind::<Text, _>(&application_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let current_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_discovery_sql(),
                    ph(kind, 1)
                );
                let current = sql_query(current_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<ApplicationDiscoveryRecord>(conn)
                    .map_err(AppError::from)?;
                if let Some((owner_token, lease_generation)) = lease.as_ref()
                    && (current.lease_owner.as_deref() != Some(owner_token.as_str())
                        || current.lease_generation != *lease_generation
                        || current.lease_expires_at.is_none_or(|expires_at| expires_at <= util::now_ts()))
                {
                    return Err(AppError::BadRequest(
                        "application discovery lease conflict".to_string(),
                    ));
                }
                if current.management_mode != crate::application_discovery::MANAGEMENT_MODE_WEBSITE {
                    return Err(AppError::BadRequest(
                        "application is not website-managed".to_string(),
                    ));
                }
                if let Some(previous_revision) = current.last_verified_revision {
                    if manifest.revision < previous_revision {
                        return Err(AppError::BadRequest(
                            "application discovery revision moved backwards".to_string(),
                        ));
                    }
                    if manifest.revision == previous_revision {
                    if current.last_verified_digest.as_deref() == Some(manifest.digest.as_str()) {
                            // A verified website manifest is a short-lived
                            // JWS. Refresh its lease and clear a transient
                            // sync error even when the revision/content digest
                            // is unchanged; otherwise the persisted expiry
                            // would age out while periodic verification keeps
                            // succeeding.
                            let now = util::now_ts();
                            let refresh_sql = format!(
                                "UPDATE application_discovery SET last_verified_expires_at = {}, sync_status = {}, last_fetched_at = {}, last_success_at = {}, last_error = {}, snapshot_json = {}, updated_at = {} WHERE application_id = {}",
                                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                            );
                            sql_query(refresh_sql)
                                .bind::<BigInt, _>(manifest.expires_at)
                                .bind::<Text, _>(crate::application_discovery::SYNC_SYNCED)
                                .bind::<BigInt, _>(now)
                                .bind::<BigInt, _>(now)
                                .bind::<Nullable<Text>, _>(None::<String>)
                                .bind::<Nullable<Text>, _>(Some(snapshot_json.clone()))
                                .bind::<BigInt, _>(now)
                                .bind::<Text, _>(&application_id)
                                .execute(conn)
                                .map_err(AppError::from)?;
                            let result_sql = format!(
                                "{} WHERE application_id = {}",
                                select_application_discovery_sql(),
                                ph(kind, 1)
                            );
                            return sql_query(result_sql)
                                .bind::<Text, _>(&application_id)
                                .get_result::<ApplicationDiscoveryRecord>(conn)
                                .map_err(AppError::from);
                        }
                        return Err(AppError::BadRequest(
                            "application discovery revision was reused with different content".to_string(),
                        ));
                    }
                }

                let client_ids = manifest
                    .clients
                    .iter()
                    .map(|client| client.client_id.clone())
                    .collect::<BTreeSet<_>>();
                let mut client_db_ids = BTreeMap::new();
                let mut profile_db_ids = BTreeMap::new();
                for client in &manifest.clients {
                    let protocol = manifest
                        .client_protocols
                        .get(&client.client_id)
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "application contract is missing a client protocol".to_string(),
                            )
                        })?;
                    let existing_sql = format!(
                        "{} WHERE client_id = {}",
                        select_client_sql(),
                        ph(kind, 1)
                    );
                    let existing = sql_query(existing_sql)
                        .bind::<Text, _>(&client.client_id)
                        .get_result::<ClientRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                    let client_db_id = if let Some(existing) = existing {
                        let owner_sql = format!(
                            "SELECT COUNT(*) AS count FROM application_client_bindings WHERE client_db_id = {} AND application_id <> {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        let owned_elsewhere = sql_query(owner_sql)
                            .bind::<Text, _>(&existing.id)
                            .bind::<Text, _>(&application_id)
                            .get_result::<CountRow>(conn)
                            .map_err(AppError::from)?
                            .count
                            > 0;
                        if owned_elsewhere {
                            return Err(AppError::BadRequest(
                                "website-managed client belongs to another application".to_string(),
                            ));
                        }
                        if existing.organization_id.as_deref()
                            != Some(application_organization_id.as_str())
                        {
                            return Err(AppError::BadRequest(
                                "website-managed client belongs to another organization"
                                    .to_string(),
                            ));
                        }
                        conn.website_discovery_update_client(kind, &existing.id, client)?;
                        existing.id
                    } else {
                        conn.website_discovery_insert_client(kind, client)?
                    };
                    client_db_ids.insert(client.client_id.clone(), client_db_id.clone());
                    let link_count_sql = format!(
                        "SELECT COUNT(*) AS count FROM application_client_bindings WHERE application_id = {} AND client_db_id = {}",
                        ph(kind, 1), ph(kind, 2)
                    );
                    let linked = sql_query(link_count_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&client_db_id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        > 0;
                    if !linked {
                        let link_sql = format!(
                            "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                        );
                        sql_query(link_sql)
                            .bind::<Text, _>(&application_id)
                            .bind::<Text, _>(&client_db_id)
                            .bind::<Text, _>(protocol)
                            .bind::<Text, _>("default")
                            .bind::<Text, _>(&format!("auth-domain:{application_id}"))
                            .bind::<Integer, _>(1)
                            .bind::<BigInt, _>(util::now_ts())
                            .bind::<BigInt, _>(util::now_ts())
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                }
                let existing_clients_sql = format!(
                    "SELECT client_db_id FROM application_client_bindings WHERE application_id = {} AND is_active = 1",
                    ph(kind, 1)
                );
                #[derive(diesel::QueryableByName)]
                struct ClientIdRow {
                    #[diesel(sql_type = Text)]
                    client_db_id: String,
                }
                if manifest.revoke_removed_clients {
                    for row in sql_query(existing_clients_sql)
                        .bind::<Text, _>(&application_id)
                        .load::<ClientIdRow>(conn)
                        .map_err(AppError::from)?
                    {
                        let client_sql = format!(
                            "SELECT client_id FROM clients WHERE id = {}",
                            ph(kind, 1)
                        );
                        #[derive(diesel::QueryableByName)]
                        struct ClientNameRow {
                            #[diesel(sql_type = Text)]
                            client_id: String,
                        }
                        let current_client = sql_query(client_sql)
                            .bind::<Text, _>(&row.client_db_id)
                            .get_result::<ClientNameRow>(conn)
                            .map_err(AppError::from)?;
                        if !client_ids.contains(&current_client.client_id) {
                            let deactivate_sql = format!(
                                "UPDATE clients SET is_active = {}, updated_at = {} WHERE id = {}",
                                ph(kind, 1), ph(kind, 2), ph(kind, 3)
                            );
                            sql_query(deactivate_sql)
                                .bind::<Integer, _>(0)
                                .bind::<BigInt, _>(util::now_ts())
                                .bind::<Text, _>(&row.client_db_id)
                                .execute(conn)
                                .map_err(AppError::from)?;
                            let unlink_sql = format!(
                    "DELETE FROM application_client_bindings WHERE application_id = {} AND client_db_id = {}",
                                ph(kind, 1),
                                ph(kind, 2)
                            );
                            sql_query(unlink_sql)
                                .bind::<Text, _>(&application_id)
                                .bind::<Text, _>(&row.client_db_id)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        }
                    }
                }

                conn.website_discovery_upsert_module(
                    kind,
                    &application_id,
                    "protocols",
                    &manifest.protocols,
                )?;
                conn.website_discovery_upsert_module(
                    kind,
                    &application_id,
                    "login_adapters",
                    &manifest.login_adapters,
                )?;
                conn.website_discovery_upsert_module(
                    kind,
                    &application_id,
                    "directory_sync",
                    &manifest.directory_sync,
                )?;
                conn.website_discovery_upsert_module(
                    kind,
                    &application_id,
                    "authorization",
                    &manifest.authorization,
                )?;

                // The website document is a complete snapshot. Remove
                // profile records that disappeared from the new revision,
                // together with their assignments and role/permission rows;
                // otherwise a later reuse of the same client_id could revive
                // stale website entitlements.
                let existing_profiles_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_authorization_profile_sql(),
                    ph(kind, 1)
                );
                let existing_profiles = sql_query(existing_profiles_sql)
                    .bind::<Text, _>(&application_id)
                    .load::<ApplicationAuthorizationProfileRecord>(conn)
                    .map_err(AppError::from)?;
                for existing_profile in existing_profiles {
                    if manifest.profiles.contains_key(&existing_profile.profile_key) {
                        continue;
                    }
                    for table in [
                        "application_profile_permission_overrides",
                        "application_profile_user_roles",
                        "application_profile_group_roles",
                        "application_profile_organization_roles",
                        "application_permission_definitions",
                        "application_profile_roles",
                    ] {
                        let delete_sql = format!(
                            "DELETE FROM {table} WHERE profile_id = {}",
                            ph(kind, 1)
                        );
                        sql_query(delete_sql)
                            .bind::<Text, _>(&existing_profile.id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let delete_profile_sql = format!(
                        "DELETE FROM application_authorization_profiles WHERE id = {}",
                        ph(kind, 1)
                    );
                    sql_query(delete_profile_sql)
                        .bind::<Text, _>(&existing_profile.id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                for (profile_key, profile) in &manifest.profiles {
                    let connection_id = client_db_ids.get(profile_key).cloned();
                    let connection_kind = if profile_key == "default" {
                        "application".to_string()
                    } else {
                        manifest
                            .client_protocols
                            .get(profile_key)
                            .cloned()
                            .ok_or_else(|| {
                                AppError::BadRequest(
                                    "application contract profile has no client protocol"
                                        .to_string(),
                                )
                            })?
                    };
                    let profile_id = conn.website_discovery_upsert_profile(
                        kind,
                        &application_id,
                        profile_key,
                        connection_id.as_deref(),
                        &connection_kind,
                        &manifest.version,
                        &manifest.digest,
                    )?;
                    profile_db_ids.insert(profile_key.clone(), profile_id.clone());
                    conn.website_discovery_replace_permissions(kind, &profile_id, profile)?;
                    conn.website_discovery_replace_roles(kind, &profile_id, profile)?;
                }

                // Every verified v3 client receives an explicit
                // application/profile binding in the runtime authority.
                let now = util::now_ts();
                let auth_domain_id = format!("auth-domain:{application_id}");
                let auth_domain_count_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_auth_domains WHERE application_id = {}",
                    ph(kind, 1)
                );
                if sql_query(auth_domain_count_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    let auth_domain_sql = format!(
                        "INSERT INTO application_auth_domains (id, application_id, assurance_policy, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                    );
                    sql_query(auth_domain_sql)
                        .bind::<Text, _>(&auth_domain_id)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>("default")
                        .bind::<Integer, _>(1)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                for (client_id, client_db_id) in &client_db_ids {
                    let profile_id = profile_db_ids
                        .get(client_id)
                        .or_else(|| profile_db_ids.get("default"))
                        .map(String::as_str)
                        .unwrap_or("default");
                    let protocol = manifest
                        .client_protocols
                        .get(client_id)
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "application contract is missing a client protocol".to_string(),
                            )
                        })?;
                    let existing_binding_sql = format!(
                        "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE client_db_id = {}",
                        ph(kind, 1)
                    );
                    let existing_binding = sql_query(existing_binding_sql)
                        .bind::<Text, _>(client_db_id)
                        .get_result::<ApplicationClientBindingRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                    if let Some(existing_binding) = existing_binding {
                        if existing_binding.application_id != application_id {
                            return Err(AppError::BadRequest(
                                "website-managed client belongs to another application"
                                    .to_string(),
                            ));
                        }
                        let update_binding_sql = format!(
                            "UPDATE application_client_bindings SET protocol = {}, authorization_profile_id = {}, auth_domain_id = {}, is_active = {}, updated_at = {} WHERE application_id = {} AND client_db_id = {}",
                            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7)
                        );
                        sql_query(update_binding_sql)
                            .bind::<Text, _>(protocol)
                            .bind::<Text, _>(profile_id)
                            .bind::<Text, _>(&auth_domain_id)
                            .bind::<Integer, _>(1)
                            .bind::<BigInt, _>(now)
                            .bind::<Text, _>(&application_id)
                            .bind::<Text, _>(client_db_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    } else {
                        let binding_sql = format!(
                            "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                        );
                        sql_query(binding_sql)
                            .bind::<Text, _>(&application_id)
                            .bind::<Text, _>(client_db_id)
                            .bind::<Text, _>(protocol)
                            .bind::<Text, _>(profile_id)
                            .bind::<Text, _>(&auth_domain_id)
                            .bind::<Integer, _>(1)
                            .bind::<BigInt, _>(now)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                }

                if let Some(default_profile_id) = profile_db_ids.get("default") {
                    #[derive(Debug, diesel::QueryableByName)]
                    struct IdRow {
                        #[diesel(sql_type = Text)]
                        id: String,
                    }

                    // These mappings are website policy, so the complete set
                    // is replaced on every verified revision. User role
                    // assignments remain in the separate user-role table and
                    // are never present in the website manifest.
                    let profile_ids = profile_db_ids.values().cloned().collect::<Vec<_>>();
                    for profile_id in &profile_ids {
                        for table in [
                            "application_profile_group_roles",
                            "application_profile_organization_roles",
                        ] {
                            let delete_sql = format!(
                                "DELETE FROM {table} WHERE profile_id = {}",
                                ph(kind, 1)
                            );
                            sql_query(delete_sql)
                                .bind::<Text, _>(profile_id)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        }
                    }
                    for mapping in &manifest.authorization_mappings.group_mappings {
                        let group_sql = format!(
                            "SELECT id FROM access_groups WHERE id = {} OR name = {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        let group_id = sql_query(group_sql)
                            .bind::<Text, _>(&mapping.group)
                            .bind::<Text, _>(&mapping.group)
                            .get_result::<IdRow>(conn)
                            .optional()
                            .map_err(AppError::from)?
                            .ok_or_else(|| {
                                AppError::BadRequest(format!(
                                    "website authorization references unknown group: {}",
                                    mapping.group
                                ))
                            })?
                            .id;
                        for profile_id in &profile_ids {
                            let role_sql = format!(
                                "SELECT id FROM application_profile_roles WHERE profile_id = {} AND role_key = {} AND is_active = 1",
                                ph(kind, 1),
                                ph(kind, 2)
                            );
                            let role_id = sql_query(role_sql)
                                .bind::<Text, _>(profile_id)
                                .bind::<Text, _>(&mapping.role)
                                .get_result::<IdRow>(conn)
                                .optional()
                                .map_err(AppError::from)?;
                            let Some(role_id) = role_id else {
                                if profile_id == default_profile_id {
                                    return Err(AppError::BadRequest(format!(
                                        "website authorization references unknown role: {}",
                                        mapping.role
                                    )));
                                }
                                continue;
                            };
                            let insert_sql = format!(
                                "INSERT INTO application_profile_group_roles (profile_id, group_id, role_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, 1, {}, {})",
                                ph(kind, 1),
                                ph(kind, 2),
                                ph(kind, 3),
                                ph(kind, 4),
                                ph(kind, 5)
                            );
                            let now = util::now_ts();
                            sql_query(insert_sql)
                                .bind::<Text, _>(profile_id)
                                .bind::<Text, _>(group_id.clone())
                                .bind::<Text, _>(role_id.id)
                                .bind::<BigInt, _>(now)
                                .bind::<BigInt, _>(now)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        }
                    }
                    for mapping in &manifest.authorization_mappings.organization_role_mappings {
                        for profile_id in &profile_ids {
                            let role_sql = format!(
                                "SELECT id FROM application_profile_roles WHERE profile_id = {} AND role_key = {} AND is_active = 1",
                                ph(kind, 1),
                                ph(kind, 2)
                            );
                            let role_id = sql_query(role_sql)
                                .bind::<Text, _>(profile_id)
                                .bind::<Text, _>(&mapping.role)
                                .get_result::<IdRow>(conn)
                                .optional()
                                .map_err(AppError::from)?;
                            let Some(role_id) = role_id else {
                                if profile_id == default_profile_id {
                                    return Err(AppError::BadRequest(format!(
                                        "website authorization references unknown role: {}",
                                        mapping.role
                                    )));
                                }
                                continue;
                            };
                            let insert_sql = format!(
                                "INSERT INTO application_profile_organization_roles (profile_id, organization_role, role_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, 1, {}, {})",
                                ph(kind, 1),
                                ph(kind, 2),
                                ph(kind, 3),
                                ph(kind, 4),
                                ph(kind, 5)
                            );
                            let now = util::now_ts();
                            sql_query(insert_sql)
                                .bind::<Text, _>(profile_id)
                                .bind::<Text, _>(&mapping.organization_role)
                                .bind::<Text, _>(role_id.id)
                                .bind::<BigInt, _>(now)
                                .bind::<BigInt, _>(now)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        }
                    }
                }

                let now = util::now_ts();
                let affected = if let Some((owner_token, lease_generation)) = lease.as_ref() {
                    let update_sql = format!(
                        "UPDATE application_discovery SET last_verified_revision = {}, last_verified_version = {}, last_verified_digest = {}, last_verified_expires_at = {}, sync_status = {}, last_fetched_at = {}, last_success_at = {}, last_error = {}, snapshot_json = {}, updated_at = {}, lease_owner = {}, lease_expires_at = {} WHERE application_id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at IS NOT NULL AND lease_expires_at >= {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12), ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16)
                    );
                    sql_query(update_sql)
                        .bind::<BigInt, _>(manifest.revision)
                        .bind::<Text, _>(&manifest.version)
                        .bind::<Text, _>(&manifest.digest)
                        .bind::<BigInt, _>(manifest.expires_at)
                        .bind::<Text, _>(crate::application_discovery::SYNC_SYNCED)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<Text>, _>(Some(snapshot_json))
                        .bind::<BigInt, _>(now)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<BigInt>, _>(None::<i64>)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(owner_token)
                        .bind::<BigInt, _>(*lease_generation)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    let update_sql = format!(
                        "UPDATE application_discovery SET last_verified_revision = {}, last_verified_version = {}, last_verified_digest = {}, last_verified_expires_at = {}, sync_status = {}, last_fetched_at = {}, last_success_at = {}, last_error = {}, snapshot_json = {}, updated_at = {} WHERE application_id = {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11)
                    );
                    sql_query(update_sql)
                        .bind::<BigInt, _>(manifest.revision)
                        .bind::<Text, _>(&manifest.version)
                        .bind::<Text, _>(&manifest.digest)
                        .bind::<BigInt, _>(manifest.expires_at)
                        .bind::<Text, _>(crate::application_discovery::SYNC_SYNCED)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<Text>, _>(Some(snapshot_json))
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&application_id)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if lease.is_some() && affected != 1 {
                    return Err(AppError::BadRequest(
                        "application discovery lease conflict".to_string(),
                    ));
                }
                let result_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_discovery_sql(),
                    ph(kind, 1)
                );
                sql_query(result_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<ApplicationDiscoveryRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }
}

impl Db {
    pub async fn find_active_application_by_slug(
        &self,
        slug: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        let slug = slug.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE slug = {} AND is_active = 1 AND organization_id IN (SELECT id FROM organizations WHERE is_active = 1) ORDER BY organization_id ASC",
                select_application_sql(),
                ph(kind, 1)
            );
            let applications = sql_query(sql)
                .bind::<Text, _>(slug)
                .load::<ApplicationRecord>(&mut conn)
                .map_err(AppError::from)?;
            match applications.as_slice() {
                [] => Ok(None),
                [application] => Ok(Some(application.clone())),
                _ => Err(AppError::BadRequest(
                    "application slug is ambiguous; use an organization-specific URL".to_string(),
                )),
            }
        })
    }

    pub async fn find_application_for_client(
        &self,
        client_db_id: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id IN (SELECT application_id FROM application_client_bindings WHERE client_db_id = {} AND is_active = 1)",
                select_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .get_result::<ApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_auth_domain(
        &self,
        application_id: &str,
    ) -> AppResult<Option<ApplicationAuthDomainRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, application_id, assurance_policy, is_active, created_at, updated_at FROM application_auth_domains WHERE application_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .get_result::<ApplicationAuthDomainRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_auth_context(
        &self,
        auth_domain_id: &str,
        user_id: &str,
    ) -> AppResult<Option<ApplicationAuthContextRecord>> {
        let auth_domain_id = auth_domain_id.to_string();
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, auth_domain_id, user_id, acr, amr, authenticated_at, expires_at, revoked_at, created_at, updated_at FROM application_auth_contexts WHERE auth_domain_id = {} AND user_id = {} AND revoked_at IS NULL ORDER BY authenticated_at DESC LIMIT 1",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(auth_domain_id)
                .bind::<Text, _>(user_id)
                .get_result::<ApplicationAuthContextRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_application_auth_context(
        &self,
        context: NewApplicationAuthContext,
    ) -> AppResult<ApplicationAuthContextRecord> {
        let now = util::now_ts();
        let amr = serde_json::to_string(&context.amr)
            .map_err(|err| AppError::Internal(err.to_string()))?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO application_auth_contexts (id, auth_domain_id, user_id, acr, amr, authenticated_at, expires_at, revoked_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9),
                ph(kind, 10)
            );
            sql_query(sql)
                .bind::<Text, _>(&context.id)
                .bind::<Text, _>(&context.auth_domain_id)
                .bind::<Text, _>(&context.user_id)
                .bind::<Text, _>(&context.acr)
                .bind::<Text, _>(amr)
                .bind::<BigInt, _>(context.authenticated_at)
                .bind::<BigInt, _>(context.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let select_sql = format!(
                "SELECT id, auth_domain_id, user_id, acr, amr, authenticated_at, expires_at, revoked_at, created_at, updated_at FROM application_auth_contexts WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(select_sql)
                .bind::<Text, _>(context.id)
                .get_result::<ApplicationAuthContextRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_client_bindings(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationClientBindingRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE application_id = {} ORDER BY created_at ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationClientBindingRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_client_binding(
        &self,
        client_db_id: &str,
    ) -> AppResult<Option<ApplicationClientBindingRecord>> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE client_db_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .get_result::<ApplicationClientBindingRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_client_binding_by_public_client_id(
        &self,
        client_id: &str,
    ) -> AppResult<Option<ApplicationClientBindingRecord>> {
        let client_id = client_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT bindings.application_id, bindings.client_db_id, bindings.protocol, bindings.authorization_profile_id, bindings.auth_domain_id, bindings.is_active, bindings.created_at, bindings.updated_at FROM application_client_bindings bindings INNER JOIN clients ON clients.id = bindings.client_db_id WHERE clients.client_id = {} AND bindings.is_active = 1",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_id)
                .get_result::<ApplicationClientBindingRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    /// Resolves the single application that owns an enrollment invitation.
    /// The mapping is intentionally separate from invitation metadata so a
    /// generic enterprise invitation cannot be mistaken for an app-scoped
    /// admission capability.
    pub async fn find_application_for_enrollment_code(
        &self,
        invitation_id: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        let invitation_id = invitation_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id IN (SELECT application_id FROM application_enrollment_codes WHERE invitation_id = {})",
                select_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(invitation_id)
                .get_result::<ApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_client_ids(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<String>> {
        #[derive(diesel::QueryableByName)]
        struct ClientIdRow {
            #[diesel(sql_type = Text)]
            client_db_id: String,
        }

        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT client_db_id FROM application_client_bindings WHERE application_id = {} AND is_active = 1 ORDER BY created_at ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ClientIdRow>(&mut conn)
                .map(|rows| rows.into_iter().map(|row| row.client_db_id).collect())
                .map_err(AppError::from)
        })
    }

    /// Loads the client rows owned by an application in one bounded read.
    /// Enrollment-code creation needs the public client IDs and organization
    /// guard, so returning the rows here avoids one query per binding.
    pub async fn list_application_clients(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ClientRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id = {} AND is_active = 1) ORDER BY created_at ASC, id ASC",
                select_client_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// The invitation itself is the enrollment capability; this mapping gives
    /// it one tenant-owned application home for listing and revocation.
    pub async fn link_application_enrollment_code(
        &self,
        application_id: &str,
        invitation_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let invitation_id = invitation_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO application_enrollment_codes (application_id, invitation_id, created_at) VALUES ({}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(invitation_id)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_enrollment_codes(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<InvitationRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT invitation_records.* FROM ({}) AS invitation_records INNER JOIN application_enrollment_codes ON application_enrollment_codes.invitation_id = invitation_records.id WHERE application_enrollment_codes.application_id = {} ORDER BY invitation_records.created_at DESC",
                select_invitation_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<InvitationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn application_enrollment_code_belongs_to(
        &self,
        application_id: &str,
        invitation_id: &str,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        let invitation_id = invitation_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM application_enrollment_codes WHERE application_id = {} AND invitation_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(invitation_id)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count > 0)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_application(
        &self,
        application: NewApplication,
    ) -> AppResult<ApplicationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            insert_application_on_conn!(conn, kind, &id, &application, now)
        })
    }

    /// Creates an application and its management audit record atomically.
    /// The webhook is scheduled only after the transaction has committed.
    pub async fn insert_application_with_audit(
        &self,
        application: NewApplication,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let mut event = event;
        if event.target_id.is_none() {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let (application, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationRecord, AuditEventRecord), AppError, _>(|conn| {
                let application = insert_application_on_conn!(conn, kind, &id, &application, now,)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((application, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(application)
    }

    /// Creates an application and its initial module in one aggregate
    /// transaction. The admin UI uses this for the first `protocols` module so
    /// a lost response or module write cannot leave a half-created website.
    pub async fn insert_application_with_module_with_audit(
        &self,
        application: NewApplication,
        module_key: &str,
        config_json: &str,
        is_enabled: bool,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let module_key = module_key.to_string();
        let config_json = config_json.to_string();
        let mut event = event;
        if event.target_id.is_none() {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let (application, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationRecord, AuditEventRecord), AppError, _>(|conn| {
                let application = insert_application_on_conn!(conn, kind, &id, &application, now)?;
                upsert_application_module_on_conn!(
                    conn,
                    kind,
                    &id,
                    &module_key,
                    &config_json,
                    is_enabled,
                    now,
                )?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((application, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(application)
    }

    pub async fn update_application(
        &self,
        id: &str,
        application: NewApplication,
    ) -> AppResult<ApplicationRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            update_application_on_conn!(conn, kind, &id, &application, now)
        })
    }

    /// Updates an application and its management audit record atomically.
    pub async fn update_application_with_audit(
        &self,
        id: &str,
        application: NewApplication,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let webhook_db = self.clone();
        let (application, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationRecord, AuditEventRecord), AppError, _>(|conn| {
                let application = update_application_on_conn!(conn, kind, &id, &application, now,)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((application, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(application)
    }

    /// Deletes the complete application aggregate and its management audit
    /// event in one database transaction.
    ///
    /// `expected_organization_id` is deliberately checked on the same
    /// connection as every delete.  The handler may have loaded an
    /// application to authorize the request, but that read is not a
    /// sufficient ownership check for a destructive operation.
    pub async fn delete_application_with_expected_organization_and_audit(
        &self,
        id: &str,
        expected_organization_id: &str,
        event: crate::audit::AuditEvent,
    ) -> AppResult<()> {
        self.delete_application_aggregate(id, Some(expected_organization_id), Some(event))
            .await
    }

    /// Compatibility wrapper for internal callers that historically deleted
    /// an application without supplying an organization or audit event.
    /// New administrative code must use
    /// `delete_application_with_expected_organization_and_audit`.
    pub async fn delete_application(&self, id: &str) -> AppResult<()> {
        self.delete_application_aggregate(id, None, None).await
    }

    async fn delete_application_aggregate(
        &self,
        id: &str,
        expected_organization_id: Option<&str>,
        event: Option<crate::audit::AuditEvent>,
    ) -> AppResult<()> {
        #[derive(Debug, diesel::QueryableByName)]
        struct DetachedClientIdRow {
            #[diesel(sql_type = Text)]
            client_db_id: String,
        }
        #[derive(Debug, diesel::QueryableByName)]
        struct GroupIdRow {
            #[diesel(sql_type = Text)]
            group_id: String,
        }
        #[derive(Debug, diesel::QueryableByName)]
        struct ClientBindingCountRow {
            #[diesel(sql_type = Text)]
            client_db_id: String,
            #[diesel(sql_type = BigInt)]
            count: i64,
        }
        #[derive(Debug, diesel::QueryableByName)]
        struct OrganizationIdRow {
            #[diesel(sql_type = Text)]
            id: String,
        }
        #[derive(Debug, diesel::QueryableByName)]
        struct BillingActivityRow {
            #[diesel(sql_type = Integer)]
            has_activity: i32,
        }

        let id = id.to_string();
        let expected_organization_id = expected_organization_id.map(ToOwned::to_owned);
        let mut event = event;
        if let Some(event) = event.as_mut()
            && event.target_id.is_none()
        {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let audit_event = with_conn!(self, |conn, kind| {
            conn.transaction::<Option<AuditEventRecord>, AppError, _>(|conn| {
                // Serialize deletion against application-owned writers before
                // reading any child rows. The no-op UPDATE is portable across
                // SQLite, PostgreSQL and MySQL, and the organization predicate
                // keeps the destructive ownership check on the same lock.
                let lock_count = if let Some(expected_organization_id) =
                    expected_organization_id.as_deref()
                {
                    let lock_sql = format!(
                        "UPDATE applications SET updated_at = updated_at WHERE id = {} AND organization_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(lock_sql)
                        .bind::<Text, _>(&id)
                        .bind::<Text, _>(expected_organization_id)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    let lock_sql = format!(
                        "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                        ph(kind, 1)
                    );
                    sql_query(lock_sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if lock_count == 0 {
                    return Err(AppError::NotFound);
                }
                let application_sql = format!("{} WHERE id = {}", select_application_sql(), ph(kind, 1));
                let application = sql_query(application_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<ApplicationRecord>(conn)
                    .map_err(AppError::from)?;
                let application_organization_id = expected_organization_id
                    .clone()
                    .unwrap_or_else(|| application.organization_id.clone());

                // Monetary history is an immutable ledger, not disposable
                // application configuration. Refuse a hard delete once an
                // application wallet has participated in a transaction or
                // hold; otherwise deleting the application would orphan a
                // balance/entry with no ownership boundary. Empty wallet
                // accounts are removed below with the rest of the aggregate.
                let billing_activity_sql = format!(
                    "SELECT CASE WHEN EXISTS (SELECT 1 FROM wallet_transactions WHERE application_id = {p1} OR source_wallet_id IN (SELECT id FROM wallet_accounts WHERE application_id = {p2}) OR destination_wallet_id IN (SELECT id FROM wallet_accounts WHERE application_id = {p3})) OR EXISTS (SELECT 1 FROM wallet_holds WHERE application_id = {p4} OR wallet_id IN (SELECT id FROM wallet_accounts WHERE application_id = {p5})) OR EXISTS (SELECT 1 FROM wallet_entries WHERE wallet_id IN (SELECT id FROM wallet_accounts WHERE application_id = {p6})) THEN 1 ELSE 0 END AS has_activity",
                    p1 = ph(kind, 1),
                    p2 = ph(kind, 2),
                    p3 = ph(kind, 3),
                    p4 = ph(kind, 4),
                    p5 = ph(kind, 5),
                    p6 = ph(kind, 6),
                );
                let has_billing_activity = sql_query(billing_activity_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .get_result::<BillingActivityRow>(conn)
                    .map_err(AppError::from)?
                    .has_activity
                    != 0;
                if has_billing_activity {
                    return Err(AppError::BadRequest(
                        "application cannot be hard-deleted after billing activity; archive it instead"
                            .to_string(),
                    ));
                }

                // Capture every binding, including an inactive legacy row.
                // The rows are deleted below, and each surviving client must
                // either already have another owner or receive a fallback.
                let client_ids_sql = format!(
                    "SELECT client_db_id FROM application_client_bindings WHERE application_id = {} ORDER BY created_at ASC, client_db_id ASC",
                    ph(kind, 1)
                );
                let detached_client_ids = sql_query(client_ids_sql)
                    .bind::<Text, _>(&id)
                    .load::<DetachedClientIdRow>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|row| row.client_db_id)
                    .collect::<Vec<_>>();
                let scim_group_ids_sql = format!(
                    "SELECT group_id FROM application_scim_groups WHERE application_id = {}",
                    ph(kind, 1)
                );
                let scim_group_ids = sql_query(scim_group_ids_sql)
                    .bind::<Text, _>(&id)
                    .load::<GroupIdRow>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|row| row.group_id)
                    .collect::<BTreeSet<_>>();

                // Trial accounts are application-admission accounts. Revoke
                // their browser/session and pending authentication state
                // before revoking the enrollment itself. Normal registration
                // accounts remain global Signet accounts and are not deleted.
                let trial_users = format!(
                    "SELECT user_id FROM trial_enrollments WHERE invitation_id IN (SELECT invitation_id FROM application_enrollment_codes WHERE application_id = {})",
                    ph(kind, 1)
                );
                for table in ["session_credentials", "browser_context_accounts"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN ({trial_users}))"
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                for (table, column) in [
                    ("authorization_codes", "user_id"),
                    ("oidc_login_grants", "user_id"),
                    ("refresh_tokens", "user_id"),
                    ("device_authorizations", "authorized_user_id"),
                    ("webauthn_challenges", "user_id"),
                    ("client_grants", "user_id"),
                ] {
                    let sql = format!("DELETE FROM {table} WHERE {column} IN ({trial_users})");
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!("DELETE FROM sessions WHERE user_id IN ({trial_users})");
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "UPDATE trial_enrollments SET revoked_at = {} WHERE invitation_id IN (SELECT invitation_id FROM application_enrollment_codes WHERE application_id = {}) AND revoked_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(util::now_ts())
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                // A client survives application deletion for compatibility,
                // so revoke all client-keyed authorization state as well.
                // This covers legacy rows whose nullable application_id was
                // never backfilled.
                let client_public_id_subquery = format!(
                    "SELECT clients.client_id FROM clients INNER JOIN application_client_bindings ON application_client_bindings.client_db_id = clients.id WHERE application_client_bindings.application_id = {}",
                    ph(kind, 1)
                );
                for (table, column) in [
                    ("client_assertion_jtis", "client_id"),
                    ("pushed_authorization_requests", "client_id"),
                    ("device_authorizations", "client_id"),
                    ("authorization_codes", "client_id"),
                    ("refresh_tokens", "client_id"),
                    ("client_grants", "client_id"),
                    ("oidc_login_grants", "client_id"),
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE {column} IN ({client_public_id_subquery})"
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                for table in ["authorization_codes", "refresh_tokens"] {
                    let sql = format!("DELETE FROM {table} WHERE application_id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                // Delete the enrollment capability and its redemption rows
                // together. Trial enrollment history is retained, but is
                // explicitly revoked above, so it cannot grant a session.
                let enrollment_invitation_subquery = format!(
                    "SELECT invitation_id FROM application_enrollment_codes WHERE application_id = {}",
                    ph(kind, 1)
                );
                for table in ["oidc_login_grants", "invitation_redemptions"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE invitation_id IN ({enrollment_invitation_subquery})"
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "DELETE FROM invitations WHERE id IN ({enrollment_invitation_subquery})"
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                // Remove profile-owned policy before the profile itself, then
                // remove the application-level authorization graph. Keeping
                // this list explicit makes a newly added policy table fail
                // review visibly instead of silently becoming an orphan.
                for table in [
                    "application_profile_permission_overrides",
                    "application_profile_user_roles",
                    "application_profile_group_roles",
                    "application_profile_organization_roles",
                    "application_permission_definitions",
                    "application_profile_roles",
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE application_id = {})",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                // Authentication artifacts are deleted before their owning
                // domains/clients. These rows are all application state; the
                // generic client row itself is intentionally retained for the
                // compatibility fallback created before this transaction
                // commits.
                let sql = format!(
                    "DELETE FROM application_auth_contexts WHERE auth_domain_id IN (SELECT id FROM application_auth_domains WHERE application_id = {})",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "DELETE FROM application_jwt_client_secrets WHERE jwt_client_id IN (SELECT id FROM application_jwt_clients WHERE application_id = {})",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                // This table exists only on pre-binding deployments. New
                // databases intentionally omit it, so probe before deleting
                // to keep aggregate cleanup compatible with both schemas.
                let legacy_oidc_table_exists = match kind {
                    DatabaseKind::Sqlite => sql_query(
                        "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'application_oidc_clients'",
                    )
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                    DatabaseKind::Postgres => sql_query(format!(
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = {}",
                        ph(kind, 1)
                    ))
                    .bind::<Text, _>("application_oidc_clients")
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                    DatabaseKind::Mysql => sql_query(format!(
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = {}",
                        ph(kind, 1)
                    ))
                    .bind::<Text, _>("application_oidc_clients")
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                };
                if legacy_oidc_table_exists {
                    let sql = format!(
                        "DELETE FROM application_oidc_clients WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                for table in [
                    "wallet_accounts",
                    "application_authorization_profiles",
                    "application_jwt_clients",
                    "application_jwt_codes",
                    "application_auth_domains",
                    "application_modules",
                    "application_authorization_migration_state",
                    "application_billing_settings",
                    "application_identity_bindings",
                    "application_saml_interactions",
                    "application_saml_replays",
                    "application_saml_sessions",
                    "application_cas_tickets",
                    "application_scim_tokens",
                    "application_scim_groups",
                    "application_members",
                    "application_enrollment_codes",
                    "application_discovery",
                    "directory_sync_runs",
                    "directory_sync_leases",
                    "directory_sync_checkpoints",
                    "directory_sync_memberships",
                    "directory_sync_groups",
                    "iap_applications",
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                // SCIM groups are global authorization subjects. Find all
                // groups that have no surviving reference in one set-based
                // query, then remove their membership edges in bounded
                // batches. The previous group × table count loop amplified
                // deletion cost linearly with both dimensions.
                let scim_group_ids = scim_group_ids.into_iter().collect::<Vec<_>>();
                let mut orphan_scim_group_ids = Vec::new();
                for chunk in scim_group_ids.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = (1..=chunk.len())
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let orphan_sql = format!(
                        "SELECT id AS group_id FROM access_groups WHERE id IN ({placeholders}) AND NOT EXISTS (SELECT 1 FROM application_scim_groups WHERE group_id = access_groups.id) AND NOT EXISTS (SELECT 1 FROM application_profile_group_roles WHERE group_id = access_groups.id) AND NOT EXISTS (SELECT 1 FROM directory_sync_groups WHERE group_id = access_groups.id) AND NOT EXISTS (SELECT 1 FROM group_roles WHERE group_id = access_groups.id) AND NOT EXISTS (SELECT 1 FROM group_members WHERE group_id = access_groups.id)"
                    );
                    orphan_scim_group_ids.extend(
                        bind_text_list(conn, sql_query(orphan_sql), chunk)
                            .load::<GroupIdRow>(conn)
                            .map_err(AppError::from)?
                            .into_iter()
                            .map(|row| row.group_id),
                    );
                }
                for chunk in orphan_scim_group_ids.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = (1..=chunk.len())
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>()
                        .join(", ");
                    for table in ["group_members", "group_roles"] {
                        let sql = format!("DELETE FROM {table} WHERE group_id IN ({placeholders})");
                        bind_text_list(conn, sql_query(sql), chunk)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let sql = format!(
                        "DELETE FROM access_groups WHERE id IN ({placeholders})"
                    );
                    bind_text_list(conn, sql_query(sql), chunk)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                // Idempotency claims are tenant-scoped records. Match both
                // keys so a malformed/legacy row cannot be removed merely by
                // reusing an application ID in another organization.
                let idempotency_sql = format!(
                    "DELETE FROM application_discovery_idempotency WHERE organization_id = {} AND application_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(idempotency_sql)
                    .bind::<Text, _>(&application_organization_id)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let binding_sql = format!(
                    "DELETE FROM application_client_bindings WHERE application_id = {}",
                    ph(kind, 1)
                );
                sql_query(binding_sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                // The binding rows have now been detached. Hydrate all
                // surviving clients and their remaining ownership in bounded
                // batches, instead of issuing a client lookup and binding
                // count query for every edge below.
                let mut detached_clients = Vec::new();
                let mut active_detached_client_ids = BTreeSet::new();
                for chunk in detached_client_ids.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = (1..=chunk.len())
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let client_sql = format!(
                        "{} WHERE id IN ({placeholders})",
                        select_client_sql()
                    );
                    detached_clients.extend(
                        bind_text_list(conn, sql_query(client_sql), chunk)
                            .load::<ClientRecord>(conn)
                            .map_err(AppError::from)?,
                    );
                    let active_binding_sql = format!(
                        "SELECT client_db_id, COUNT(*) AS count FROM application_client_bindings WHERE client_db_id IN ({placeholders}) AND is_active = 1 GROUP BY client_db_id"
                    );
                    for row in bind_text_list(conn, sql_query(active_binding_sql), chunk)
                        .load::<ClientBindingCountRow>(conn)
                        .map_err(AppError::from)?
                    {
                        if row.count > 0 {
                            active_detached_client_ids.insert(row.client_db_id);
                        }
                    }
                }
                let organization_ids = detached_clients
                    .iter()
                    .filter_map(|client| client.organization_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut valid_organization_ids = BTreeSet::new();
                for chunk in organization_ids.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = (1..=chunk.len())
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let organization_sql = format!(
                        "SELECT id FROM organizations WHERE id IN ({placeholders})"
                    );
                    valid_organization_ids.extend(
                        bind_text_list(conn, sql_query(organization_sql), chunk)
                            .load::<OrganizationIdRow>(conn)
                            .map_err(AppError::from)?
                            .into_iter()
                            .map(|row| row.id),
                    );
                }

                let affected = if let Some(expected_organization_id) =
                    expected_organization_id.as_deref()
                {
                    let sql = format!(
                        "DELETE FROM applications WHERE id = {} AND organization_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .bind::<Text, _>(expected_organization_id)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    let sql = format!("DELETE FROM applications WHERE id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if affected == 0 {
                    return Err(AppError::NotFound);
                }

                // The old aggregate is gone only after every surviving
                // protocol client has received its locked compatibility
                // owner on this same connection. If any repair fails, the
                // whole deletion rolls back and no client is left unowned.
                for client in detached_clients {
                    if active_detached_client_ids.contains(&client.id) {
                        continue;
                    }
                    let organization_id = match client.organization_id.as_deref() {
                        Some(candidate) if valid_organization_ids.contains(candidate) => {
                            candidate.to_string()
                        }
                        _ => crate::organizations::SIGNET_ORGANIZATION_ID.to_string(),
                    };
                    if client.organization_id.as_deref() != Some(organization_id.as_str()) {
                        let update_client_sql = format!(
                            "UPDATE clients SET organization_id = {}, updated_at = {} WHERE id = {}",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3)
                        );
                        sql_query(update_client_sql)
                            .bind::<Text, _>(&organization_id)
                            .bind::<BigInt, _>(util::now_ts())
                            .bind::<Text, _>(&client.id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    insert_locked_compatibility_application_on_conn!(
                        conn,
                        kind,
                        &client,
                        &organization_id,
                        util::now_ts(),
                    )?;
                }

                let audit_event = event
                    .take()
                    .map(|event| insert_audit_event_on_conn!(conn, kind, event))
                    .transpose()?;
                Ok(audit_event)
            })
        })?;

        if let Some(audit_event) = audit_event {
            crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        }

        Ok(())
    }

    /// Links one protocol client to exactly one application and profile.
    /// Client configuration remains protocol-specific, while the application
    /// binding owns the authentication domain and authorization boundary.
    pub async fn link_client_to_application(
        &self,
        application_id: &str,
        client_db_id: &str,
        protocol: &str,
        authorization_profile_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let client_db_id = client_db_id.to_string();
        let protocol = protocol.to_string();
        let authorization_profile_id = authorization_profile_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let application_lock_sql = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(application_lock_sql)
                    .bind::<Text, _>(&application_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                if authorization_profile_id.is_empty() {
                    return Err(AppError::BadRequest(
                        "authorization profile is required".to_string(),
                    ));
                }
                // `default` is a compatibility profile key, not a physical
                // profile ID. The resolver intentionally looks it up by
                // (application_id, profile_key), and may fall back to the
                // legacy application-wide policy when older data has no
                // materialized default row.
                if authorization_profile_id != "default" {
                    // Non-default values are physical profile IDs.  Check
                    // ownership on the same transaction/connection as the
                    // binding write so a client can never reference another
                    // application's authorization policy.
                    let profile_count_sql = format!(
                        "SELECT COUNT(*) AS count FROM application_authorization_profiles WHERE id = {} AND application_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    if sql_query(profile_count_sql)
                        .bind::<Text, _>(&authorization_profile_id)
                        .bind::<Text, _>(&application_id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        == 0
                    {
                        return Err(AppError::BadRequest(
                            "authorization profile must belong to the application".to_string(),
                        ));
                    }
                }
                let same_organization_sql = format!(
                    "SELECT COUNT(*) AS count FROM applications INNER JOIN clients ON clients.id = {} WHERE applications.id = {} AND clients.organization_id = applications.organization_id",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if sql_query(same_organization_sql)
                    .bind::<Text, _>(&client_db_id)
                    .bind::<Text, _>(&application_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::BadRequest(
                        "OIDC client must belong to the application's organization".to_string(),
                    ));
                }
                let existing_binding_sql = format!(
                    "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE client_db_id = {}",
                    ph(kind, 1)
                );
                let existing_binding = sql_query(existing_binding_sql)
                    .bind::<Text, _>(&client_db_id)
                    .get_result::<ApplicationClientBindingRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                if let Some(existing_binding) = existing_binding.as_ref() {
                    if existing_binding.application_id != application_id {
                        return Err(AppError::BadRequest(
                            "OIDC client already belongs to another application".to_string(),
                        ));
                    }
                }
                let auth_domain_id = format!("auth-domain:{application_id}");
                let auth_domain_count_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_auth_domains WHERE application_id = {}",
                    ph(kind, 1)
                );
                if sql_query(auth_domain_count_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    let auth_domain_sql = format!(
                        "INSERT INTO application_auth_domains (id, application_id, assurance_policy, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                    );
                    sql_query(auth_domain_sql)
                        .bind::<Text, _>(&auth_domain_id)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>("default")
                        .bind::<Integer, _>(1)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                if existing_binding.is_some() {
                    let update_binding_sql = format!(
                        "UPDATE application_client_bindings SET protocol = {}, authorization_profile_id = {}, auth_domain_id = {}, is_active = {}, updated_at = {} WHERE application_id = {} AND client_db_id = {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7)
                    );
                    sql_query(update_binding_sql)
                        .bind::<Text, _>(&protocol)
                        .bind::<Text, _>(&authorization_profile_id)
                        .bind::<Text, _>(&auth_domain_id)
                        .bind::<Integer, _>(1)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&client_db_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                } else {
                    let binding_sql = format!(
                        "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                    );
                    sql_query(binding_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&client_db_id)
                        .bind::<Text, _>(&protocol)
                        .bind::<Text, _>(&authorization_profile_id)
                        .bind::<Text, _>(&auth_domain_id)
                        .bind::<Integer, _>(1)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    /// Detaches a client without leaving it ungoverned. The client immediately
    /// receives a locked fallback application.
    pub async fn unlink_client_from_application(&self, client_db_id: &str) -> AppResult<()> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let client_sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
                let client = sql_query(client_sql)
                    .bind::<Text, _>(&client_db_id)
                    .get_result::<ClientRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                let delete_sql = format!(
                    "DELETE FROM application_client_bindings WHERE client_db_id = {}",
                    ph(kind, 1)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&client_db_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let Some(client) = client else {
                    return Ok(());
                };
                let active_binding_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_client_bindings WHERE client_db_id = {} AND is_active = 1",
                    ph(kind, 1)
                );
                if sql_query(active_binding_sql)
                    .bind::<Text, _>(&client_db_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    > 0
                {
                    return Ok(());
                }
                let organization_id = if let Some(candidate) = client.organization_id.as_deref() {
                    let organization_sql = format!(
                        "SELECT COUNT(*) AS count FROM organizations WHERE id = {}",
                        ph(kind, 1)
                    );
                    if sql_query(organization_sql)
                        .bind::<Text, _>(candidate)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        > 0
                    {
                        candidate.to_string()
                    } else {
                        crate::organizations::SIGNET_ORGANIZATION_ID.to_string()
                    }
                } else {
                    crate::organizations::SIGNET_ORGANIZATION_ID.to_string()
                };
                if client.organization_id.as_deref() != Some(organization_id.as_str()) {
                    let update_client_sql = format!(
                        "UPDATE clients SET organization_id = {}, updated_at = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    sql_query(update_client_sql)
                        .bind::<Text, _>(&organization_id)
                        .bind::<BigInt, _>(util::now_ts())
                        .bind::<Text, _>(&client_db_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                insert_locked_compatibility_application_on_conn!(
                    conn,
                    kind,
                    &client,
                    &organization_id,
                    util::now_ts(),
                )?;
                Ok(())
            })
        })
    }

    /// Legacy compatibility reader. Application members are not a login
    /// roster; new runtime code must use organization membership and
    /// application entitlements instead.
    pub async fn list_application_members(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationMemberRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} ORDER BY is_active DESC, created_at ASC",
                select_application_member_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationMemberRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Legacy compatibility reader; retained for migration/audit tooling only.
    pub async fn list_application_members_with_users(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationMemberWithUserRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT application_members.application_id, application_members.user_id, application_members.role, application_members.is_active, application_members.created_at, application_members.updated_at, users.email, users.username, users.display_name, users.phone, users.email_verified_at, users.phone_verified_at FROM application_members INNER JOIN users ON users.id = application_members.user_id WHERE application_members.application_id = {} ORDER BY application_members.is_active DESC, users.email ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationMemberWithUserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Legacy compatibility writer for importing or repairing historical
    /// application_members rows. It is intentionally not used by any login,
    /// registration, or application-management runtime path.
    pub async fn replace_application_members(
        &self,
        application_id: &str,
        members: Vec<NewApplicationMember>,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let members = members
            .into_iter()
            .map(|member| (member.user_id.clone(), member))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect::<Vec<_>>();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let app_sql = format!("{} WHERE id = {}", select_application_sql(), ph(kind, 1));
                let application = sql_query(app_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<ApplicationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                for member in &members {
                    let user_sql = format!(
                        "SELECT COUNT(*) AS count FROM users WHERE id = {} AND is_active = 1 AND archived_at IS NULL",
                        ph(kind, 1)
                    );
                    if sql_query(user_sql)
                        .bind::<Text, _>(&member.user_id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        == 0
                    {
                        return Err(AppError::BadRequest(format!(
                            "active user does not exist: {}",
                            member.user_id
                        )));
                    }
                }
                let active_member_ids = members
                    .iter()
                    .filter(|member| member.is_active)
                    .map(|member| member.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let blocked_member_ids = members
                    .iter()
                    .filter(|member| !member.is_active)
                    .map(|member| member.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let binding_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_identity_binding_sql(),
                    ph(kind, 1)
                );
                let bound_user_ids = sql_query(binding_sql)
                    .bind::<Text, _>(&application_id)
                    .load::<ApplicationIdentityBindingRecord>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|binding| binding.user_id)
                    .collect::<BTreeSet<_>>();
                let users_losing_access = match application.access_mode.as_str() {
                    crate::applications::ACCESS_ASSIGNED_ACCOUNTS => bound_user_ids
                        .difference(&active_member_ids)
                        .cloned()
                        .collect::<Vec<_>>(),
                    crate::applications::ACCESS_ORGANIZATION_MEMBERS => bound_user_ids
                        .intersection(&blocked_member_ids)
                        .cloned()
                        .collect::<Vec<_>>(),
                    crate::applications::ACCESS_ALL_SIGNET_USERS
                    | crate::applications::ACCESS_LEGACY_ALL_USERS => Vec::new(),
                    _ => {
                        return Err(AppError::Internal(
                            "application access mode is invalid".to_string(),
                        ));
                    }
                };
                // Replacing a roster must release leases only for accounts
                // that no longer have application access. Existing eligible
                // accounts keep their reservations throughout the update.
                for user_id in users_losing_access {
                    clear_application_identity_bindings_for_user_for_conn!(
                        conn,
                        kind,
                        &application_id,
                        &user_id
                    )?;
                }

                let delete_sql = format!(
                    "DELETE FROM application_members WHERE application_id = {}",
                    ph(kind, 1)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&application_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for member in members {
                    let insert_sql = format!(
                        "INSERT INTO application_members (application_id, user_id, role, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                    );
                    sql_query(insert_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(member.user_id)
                        .bind::<Text, _>(member.role)
                        .bind::<Integer, _>(i32::from(member.is_active))
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    pub async fn user_can_access_application(
        &self,
        application: &ApplicationRecord,
        user_id: &str,
    ) -> AppResult<bool> {
        Ok(self
            .users_can_access_application(application, &[user_id.to_string()])
            .await?
            .contains(user_id))
    }

    /// Resolves the account/application admission gate for a complete chooser
    /// page in one bounded query set.  Browser account selection commonly has
    /// several remembered accounts; doing the same two existence queries for
    /// every account turns that page into an avoidable O(N) round-trip fan-out.
    /// The final select/activate endpoint still re-checks one account
    /// transactionally, so this is only a read-model optimization.
    pub async fn users_can_access_application(
        &self,
        application: &ApplicationRecord,
        user_ids: &[String],
    ) -> AppResult<BTreeSet<String>> {
        #[derive(diesel::QueryableByName)]
        struct UserIdRow {
            #[diesel(sql_type = Text)]
            id: String,
        }

        const BATCH_SIZE: usize = 400;
        if application.is_active != 1 || user_ids.is_empty() {
            return Ok(BTreeSet::new());
        }
        let user_ids = user_ids.to_vec();
        let organization_id = application.organization_id.clone();
        let user_ids = user_ids.to_vec();
        with_conn!(self, |conn, kind| {
            let organization_sql = format!(
                "SELECT COUNT(*) AS count FROM organizations WHERE id = {} AND is_active = 1",
                ph(kind, 1)
            );
            if sql_query(organization_sql)
                .bind::<Text, _>(&organization_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                == 0
            {
                return Ok(BTreeSet::new());
            }

            let mut accessible = BTreeSet::new();
            for chunk in user_ids.chunks(BATCH_SIZE) {
                if chunk.is_empty() {
                    continue;
                }
                let user_sql = format!(
                    "SELECT id FROM users WHERE id IN ({}) AND is_active = 1 AND archived_at IS NULL",
                    (1..=chunk.len())
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                accessible.extend(
                    bind_text_list(&mut conn, sql_query(user_sql), chunk)
                        .load::<UserIdRow>(&mut conn)
                        .map_err(AppError::from)?
                        .into_iter()
                        .map(|row| row.id),
                );
            }
            // An application is a website integration, not a membership
            // roster. Once the global account and tenant are active, every
            // active Signet account is eligible to authenticate. Application
            // roles and directory mappings are evaluated after this gate.
            let _ = organization_id;
            Ok(accessible)
        })
    }

    /// Atomically replaces this user's application-scoped factor reservations.
    /// The primary key on `(application_id, factor_type, factor_digest)` is
    /// the final concurrent enforcement point, not the management UI.
    pub async fn replace_application_identity_bindings(
        &self,
        application_id: &str,
        user_id: &str,
        factors: Vec<(String, String)>,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let user_id = user_id.to_string();
        let factors = factors
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let delete_sql = format!(
                    "DELETE FROM application_identity_bindings WHERE application_id = {} AND user_id = {}",
                    ph(kind, 1), ph(kind, 2)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&user_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for (factor_type, factor_digest) in factors {
                    let insert_sql = format!(
                        "INSERT INTO application_identity_bindings (application_id, factor_type, factor_digest, user_id, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                    );
                    sql_query(insert_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(factor_type)
                        .bind::<Text, _>(factor_digest)
                        .bind::<Text, _>(&user_id)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(|err| AppError::BadRequest(format!(
                            "the verified identity factor is already used by another application account: {err}"
                        )))?;
                }
                Ok(())
            })
        })
    }

    pub async fn application_identity_factor_is_available(
        &self,
        application_id: &str,
        factor_type: &str,
        factor_digest: &str,
        user_id: &str,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        let factor_type = factor_type.to_string();
        let factor_digest = factor_digest.to_string();
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} AND factor_type = {} AND factor_digest = {}",
                select_application_identity_binding_sql(),
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(factor_type)
                .bind::<Text, _>(factor_digest)
                .get_result::<ApplicationIdentityBindingRecord>(&mut conn)
                .optional()
                .map(|binding| binding.is_none_or(|binding| binding.user_id == user_id))
                .map_err(AppError::from)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sqlite")]
    async fn sqlite_test_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-application-delete-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let db = connect_sqlite(&DatabaseSettings {
            kind: DatabaseKind::Sqlite,
            url: path.to_string_lossy().into_owned(),
            pool_size: 1,
            run_migrations: true,
        })
        .unwrap();
        db.migrate().await.unwrap();
        (db, path)
    }

    #[cfg(feature = "sqlite")]
    fn tenant(slug: &str) -> NewOrganization {
        NewOrganization {
            slug: slug.to_string(),
            name: format!("{slug} organization"),
            kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn application(organization_id: &str, slug: &str) -> NewApplication {
        NewApplication {
            organization_id: organization_id.to_string(),
            slug: slug.to_string(),
            name: format!("{slug} application"),
            description: None,
            access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: crate::applications::REGISTRATION_INVITATION.to_string(),
            account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn application_enrollment_invitation(organization_id: &str) -> NewInvitation {
        NewInvitation {
            code_type: AuthorizationCodeType::Registration,
            login_code_level: LoginCodeLevel::AccountRecovery,
            allowed_client_ids: vec!["application-delete-client".to_string()],
            organization_id: Some(organization_id.to_string()),
            organization_role: Some(crate::organizations::ROLE_MEMBER.to_string()),
            description: Some("application delete test".to_string()),
            authorized_email: None,
            authorized_username: None,
            authorized_user_id: None,
            authorized_display_name: None,
            expires_at: Some(util::now_ts() + 300),
            max_uses: Some(1),
            is_active: true,
            created_by: None,
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_delete_rechecks_expected_organization_without_deleting() {
        let (db, path) = sqlite_test_db().await;
        let owner = db
            .insert_organization(tenant("application-delete-owner"))
            .await
            .unwrap();
        let wrong_owner = db
            .insert_organization(tenant("application-delete-wrong-owner"))
            .await
            .unwrap();
        let application = db
            .insert_application(application(&owner.id, "delete-organization-guard"))
            .await
            .unwrap();

        let result = db
            .delete_application_with_expected_organization_and_audit(
                &application.id,
                &wrong_owner.id,
                crate::audit::management_event(
                    "application-delete-test-actor",
                    "application.delete",
                    "application",
                    Some(application.id.clone()),
                    serde_json::json!({ "organization_id": wrong_owner.id }),
                ),
            )
            .await;
        assert!(matches!(result, Err(AppError::NotFound)));
        assert!(
            db.find_application_by_id(&application.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            !db.list_audit_events(100)
                .await
                .unwrap()
                .into_iter()
                .any(|event| {
                    event.action == "application.delete"
                        && event.target_id.as_deref() == Some(application.id.as_str())
                })
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_delete_removes_enrollment_invitation_and_writes_audit() {
        let (db, path) = sqlite_test_db().await;
        let owner = db
            .insert_organization(tenant("application-delete-success"))
            .await
            .unwrap();
        let application = db
            .insert_application(application(&owner.id, "delete-success"))
            .await
            .unwrap();
        let (invitation, _) = db
            .insert_invitation(application_enrollment_invitation(&owner.id))
            .await
            .unwrap();
        db.link_application_enrollment_code(&application.id, &invitation.id)
            .await
            .unwrap();

        db.delete_application_with_expected_organization_and_audit(
            &application.id,
            &owner.id,
            crate::audit::management_event(
                "application-delete-test-actor",
                "application.delete",
                "application",
                Some(application.id.clone()),
                serde_json::json!({ "organization_id": owner.id }),
            ),
        )
        .await
        .unwrap();

        assert!(
            db.find_application_by_id(&application.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_application_enrollment_codes(&application.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.find_invitation_by_id(&invitation.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_audit_events(100)
                .await
                .unwrap()
                .into_iter()
                .any(|event| {
                    event.action == "application.delete"
                        && event.target_id.as_deref() == Some(application.id.as_str())
                })
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
