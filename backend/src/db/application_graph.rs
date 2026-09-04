//! Persistence for application-owned OIDC client graphs.

use super::{
    AppError, AppResult, ApplicationAuthorizationProfileRecord, ApplicationClientBindingRecord,
    ClientClaimMapperRecord, ClientRecord, CountRow, DatabaseKind, Db,
    NewApplicationAuthorizationProfile, NewClient, NewClientClaimMapper, application_slug_base,
    application_slug_collision_candidate, blocking, ph,
    select_application_authorization_profile_sql, select_application_client_binding_sql,
    select_client_claim_mapper_sql, select_client_sql,
};
use crate::{
    application_discovery_contract::{SOURCE_MODE_MANUAL, SYNC_STATUS_MANUAL},
    organizations::SIGNET_ORGANIZATION_ID,
    util,
};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};

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
                        source_mode: SOURCE_MODE_MANUAL.to_string(),
                        remote_version: None,
                        remote_digest: None,
                        sync_status: SYNC_STATUS_MANUAL.to_string(),
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
                        source_mode: SOURCE_MODE_MANUAL.to_string(),
                        remote_version: None,
                        remote_digest: None,
                        sync_status: SYNC_STATUS_MANUAL.to_string(),
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
                    "{} WHERE application_id = {} AND client_db_id = {} AND protocol = {}",
                    select_application_client_binding_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let binding = sql_query(binding_sql)
                    .bind::<Text, _>(application_id.clone())
                    .bind::<Text, _>(client_db_id.clone())
                    .bind::<Text, _>("oidc")
                    .get_result::<ApplicationClientBindingRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                let existing_sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(client_db_id.clone())
                    .get_result::<ClientRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                if existing.organization_id.as_deref() != Some(organization_id.as_str()) {
                    return Err(AppError::BadRequest(
                        "OIDC client must belong to the application's organization".to_string(),
                    ));
                }
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
                        source_mode: SOURCE_MODE_MANUAL.to_string(),
                        remote_version: None,
                        remote_digest: None,
                        sync_status: SYNC_STATUS_MANUAL.to_string(),
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
                    "{} WHERE application_id = {} AND client_db_id = {} AND protocol = {}",
                    select_application_client_binding_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let binding = sql_query(binding_sql)
                    .bind::<Text, _>(application_id.clone())
                    .bind::<Text, _>(client_db_id.clone())
                    .bind::<Text, _>("oidc")
                    .get_result::<ApplicationClientBindingRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
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
