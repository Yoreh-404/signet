use super::*;
macro_rules! insert_client_in_connection {
    ($conn:expr, $kind:expr, $client:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let client = $client;
    let id = uuid::Uuid::new_v4().to_string();
    let now = util::now_ts();
    let redirect_uris = util::to_json(&client.redirect_uris)?;
    let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
    let scopes = util::to_json(&client.scopes)?;
    let grant_types = util::to_json(&client.grant_types)?;
    let response_types = util::to_json(&client.response_types)?;
    let authorization_details_types = util::to_json(&client.authorization_details_types)?;
    let service_account_permissions = util::to_json(&client.service_account_permissions)?;
    let sql = format!(
        "INSERT INTO clients (id, client_id, client_secret_hash, client_name, logo_uri, organization_id, redirect_uris, post_logout_redirect_uris, scopes, audience, grant_types, response_types, token_endpoint_auth_method, require_pkce, require_mfa, require_pushed_authorization_requests, require_s256_pkce, require_confidential_client, require_dpop, require_account_selection, trust_email_verified, authorization_details_types, subject_type, sector_identifier_uri, jwks_uri, jwks, backchannel_logout_uri, backchannel_logout_session_required, frontchannel_logout_uri, frontchannel_logout_session_required, service_account_enabled, service_account_permissions, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
        ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
        ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16), ph(kind, 17), ph(kind, 18),
        ph(kind, 19), ph(kind, 20), ph(kind, 21), ph(kind, 22), ph(kind, 23), ph(kind, 24),
        ph(kind, 25), ph(kind, 26), ph(kind, 27), ph(kind, 28), ph(kind, 29), ph(kind, 30),
        ph(kind, 31), ph(kind, 32), ph(kind, 33), ph(kind, 34), ph(kind, 35)
    );
    sql_query(sql)
        .bind::<Text, _>(&id)
        .bind::<Text, _>(&client.client_id)
        .bind::<Nullable<Text>, _>(&client.client_secret_hash)
        .bind::<Text, _>(&client.client_name)
        .bind::<Text, _>(&client.logo_uri)
        .bind::<Nullable<Text>, _>(&client.organization_id)
        .bind::<Text, _>(redirect_uris)
        .bind::<Text, _>(post_logout_redirect_uris)
        .bind::<Text, _>(scopes)
        .bind::<Text, _>(client.audience.trim())
        .bind::<Text, _>(grant_types)
        .bind::<Text, _>(response_types)
        .bind::<Text, _>(&client.token_endpoint_auth_method)
        .bind::<Integer, _>(i32::from(client.require_pkce))
        .bind::<Integer, _>(i32::from(client.require_mfa))
        .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
        .bind::<Integer, _>(i32::from(client.require_s256_pkce))
        .bind::<Integer, _>(i32::from(client.require_confidential_client))
        .bind::<Integer, _>(i32::from(client.require_dpop))
        .bind::<Integer, _>(i32::from(client.require_account_selection))
        .bind::<Integer, _>(i32::from(client.trust_email_verified))
        .bind::<Text, _>(authorization_details_types)
        .bind::<Text, _>(&client.subject_type)
        .bind::<Text, _>(&client.sector_identifier_uri)
        .bind::<Text, _>(&client.jwks_uri)
        .bind::<Text, _>(&client.jwks)
        .bind::<Text, _>(&client.backchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
        .bind::<Text, _>(&client.frontchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
        .bind::<Integer, _>(i32::from(client.service_account_enabled))
        .bind::<Text, _>(service_account_permissions)
        .bind::<Integer, _>(i32::from(client.is_active))
        .bind::<BigInt, _>(now)
        .bind::<BigInt, _>(now)
        .execute(conn)
        .map_err(AppError::from)?;
        Ok(id)
    }};
}

macro_rules! update_client_in_connection {
    ($conn:expr, $kind:expr, $id:expr, $client:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let id = $id;
        let client = $client;
    let now = util::now_ts();
    let redirect_uris = util::to_json(&client.redirect_uris)?;
    let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
    let scopes = util::to_json(&client.scopes)?;
    let grant_types = util::to_json(&client.grant_types)?;
    let response_types = util::to_json(&client.response_types)?;
    let authorization_details_types = util::to_json(&client.authorization_details_types)?;
    let service_account_permissions = util::to_json(&client.service_account_permissions)?;
    let sql = format!(
        "UPDATE clients SET client_id = {}, client_secret_hash = {}, client_name = {}, logo_uri = {}, organization_id = {}, redirect_uris = {}, post_logout_redirect_uris = {}, scopes = {}, audience = {}, grant_types = {}, response_types = {}, token_endpoint_auth_method = {}, require_pkce = {}, require_mfa = {}, require_pushed_authorization_requests = {}, require_s256_pkce = {}, require_confidential_client = {}, require_dpop = {}, require_account_selection = {}, trust_email_verified = {}, authorization_details_types = {}, subject_type = {}, sector_identifier_uri = {}, jwks_uri = {}, jwks = {}, backchannel_logout_uri = {}, backchannel_logout_session_required = {}, frontchannel_logout_uri = {}, frontchannel_logout_session_required = {}, service_account_enabled = {}, service_account_permissions = {}, is_active = {}, updated_at = {} WHERE id = {}",
        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
        ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
        ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16), ph(kind, 17), ph(kind, 18),
        ph(kind, 19), ph(kind, 20), ph(kind, 21), ph(kind, 22), ph(kind, 23), ph(kind, 24),
        ph(kind, 25), ph(kind, 26), ph(kind, 27), ph(kind, 28), ph(kind, 29), ph(kind, 30),
        ph(kind, 31), ph(kind, 32), ph(kind, 33), ph(kind, 34)
    );
    let affected = sql_query(sql)
        .bind::<Text, _>(&client.client_id)
        .bind::<Nullable<Text>, _>(&client.client_secret_hash)
        .bind::<Text, _>(&client.client_name)
        .bind::<Text, _>(&client.logo_uri)
        .bind::<Nullable<Text>, _>(&client.organization_id)
        .bind::<Text, _>(redirect_uris)
        .bind::<Text, _>(post_logout_redirect_uris)
        .bind::<Text, _>(scopes)
        .bind::<Text, _>(client.audience.trim())
        .bind::<Text, _>(grant_types)
        .bind::<Text, _>(response_types)
        .bind::<Text, _>(&client.token_endpoint_auth_method)
        .bind::<Integer, _>(i32::from(client.require_pkce))
        .bind::<Integer, _>(i32::from(client.require_mfa))
        .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
        .bind::<Integer, _>(i32::from(client.require_s256_pkce))
        .bind::<Integer, _>(i32::from(client.require_confidential_client))
        .bind::<Integer, _>(i32::from(client.require_dpop))
        .bind::<Integer, _>(i32::from(client.require_account_selection))
        .bind::<Integer, _>(i32::from(client.trust_email_verified))
        .bind::<Text, _>(authorization_details_types)
        .bind::<Text, _>(&client.subject_type)
        .bind::<Text, _>(&client.sector_identifier_uri)
        .bind::<Text, _>(&client.jwks_uri)
        .bind::<Text, _>(&client.jwks)
        .bind::<Text, _>(&client.backchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
        .bind::<Text, _>(&client.frontchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
        .bind::<Integer, _>(i32::from(client.service_account_enabled))
        .bind::<Text, _>(service_account_permissions)
        .bind::<Integer, _>(i32::from(client.is_active))
        .bind::<BigInt, _>(now)
        .bind::<Text, _>(id)
        .execute(conn)
        .map_err(AppError::from)?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
        Ok(())
    }};
}

macro_rules! upsert_application_module_in_connection {
    ($conn:expr, $kind:expr, $application_id:expr, $module_key:expr, $config:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let application_id = $application_id;
        let module_key = $module_key;
        let config = $config;
    let object = config
        .as_object()
        .ok_or_else(|| AppError::Internal("discovery module is not an object".to_string()))?;
    let config_json = util::to_json(config)?;
    let enabled = object
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(!object.is_empty());
    let now = util::now_ts();
    let count_sql = format!(
        "SELECT COUNT(*) AS count FROM application_modules WHERE application_id = {} AND module_key = {}",
        ph(kind, 1), ph(kind, 2)
    );
    let exists = sql_query(count_sql)
        .bind::<Text, _>(application_id)
        .bind::<Text, _>(module_key)
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        > 0;
    if exists {
        let sql = format!(
            "UPDATE application_modules SET config_json = {}, is_enabled = {}, updated_at = {} WHERE application_id = {} AND module_key = {}",
            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5)
        );
        sql_query(sql)
            .bind::<Text, _>(config_json)
            .bind::<Integer, _>(i32::from(enabled))
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(module_key)
            .execute(conn)
            .map_err(AppError::from)?;
    } else {
        let sql = format!(
            "INSERT INTO application_modules (application_id, module_key, config_json, is_enabled, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
        );
        sql_query(sql)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(module_key)
            .bind::<Text, _>(config_json)
            .bind::<Integer, _>(i32::from(enabled))
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(conn)
            .map_err(AppError::from)?;
    }
        Ok(())
    }};
}

macro_rules! upsert_website_profile_in_connection {
    ($conn:expr, $kind:expr, $application_id:expr, $profile_key:expr, $connection_id:expr, $connection_kind:expr, $version:expr, $digest:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let application_id = $application_id;
        let profile_key = $profile_key;
        let connection_id = $connection_id;
        let connection_kind = $connection_kind;
        let version = $version;
        let digest = $digest;
    let now = util::now_ts();
    let existing_sql = format!(
        "{} WHERE application_id = {} AND profile_key = {}",
        select_application_authorization_profile_sql(),
        ph(kind, 1),
        ph(kind, 2)
    );
    let existing = sql_query(existing_sql)
        .bind::<Text, _>(application_id)
        .bind::<Text, _>(profile_key)
        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
        .optional()
        .map_err(AppError::from)?;
    let profile_id = existing
        .as_ref()
        .map(|profile| profile.id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if existing.is_some() {
        let sql = format!(
            "UPDATE application_authorization_profiles SET connection_kind = {}, connection_id = {}, source_mode = {}, remote_version = {}, remote_digest = {}, sync_status = {}, last_synced_at = {}, last_error = {}, updated_at = {} WHERE id = {}",
            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10)
        );
        sql_query(sql)
            .bind::<Text, _>(connection_kind)
            .bind::<Nullable<Text>, _>(&connection_id)
            .bind::<Text, _>(SOURCE_MODE_DISCOVERY)
            .bind::<Nullable<Text>, _>(Some(version.to_string()))
            .bind::<Nullable<Text>, _>(Some(digest.to_string()))
            .bind::<Text, _>(SYNC_SYNCED)
            .bind::<Nullable<BigInt>, _>(Some(now))
            .bind::<Nullable<Text>, _>(None::<String>)
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(&profile_id)
            .execute(conn)
            .map_err(AppError::from)?;
    } else {
        let sql = format!(
            "INSERT INTO application_authorization_profiles (id, application_id, profile_key, connection_kind, connection_id, source_mode, remote_version, remote_digest, sync_status, last_synced_at, last_error, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12), ph(kind, 13)
        );
        sql_query(sql)
            .bind::<Text, _>(&profile_id)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(profile_key)
            .bind::<Text, _>(connection_kind)
            .bind::<Nullable<Text>, _>(&connection_id)
            .bind::<Text, _>(SOURCE_MODE_DISCOVERY)
            .bind::<Nullable<Text>, _>(Some(version.to_string()))
            .bind::<Nullable<Text>, _>(Some(digest.to_string()))
            .bind::<Text, _>(SYNC_SYNCED)
            .bind::<Nullable<BigInt>, _>(Some(now))
            .bind::<Nullable<Text>, _>(None::<String>)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(conn)
            .map_err(AppError::from)?;
    }
        Ok(profile_id)
    }};
}

macro_rules! replace_website_profile_permissions_in_connection {
    ($conn:expr, $kind:expr, $profile_id:expr, $profile:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let profile_id = $profile_id;
        let profile = $profile;
    let now = util::now_ts();
    let deactivate_sql = format!(
        "UPDATE application_permission_definitions SET is_active = {}, source = {}, updated_at = {} WHERE profile_id = {}",
        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
    );
    sql_query(deactivate_sql)
        .bind::<Integer, _>(0)
        .bind::<Text, _>(SOURCE_WEBSITE)
        .bind::<BigInt, _>(now)
        .bind::<Text, _>(profile_id)
        .execute(conn)
        .map_err(AppError::from)?;
    for permission in &profile.permissions {
        let count_sql = format!(
            "SELECT COUNT(*) AS count FROM application_permission_definitions WHERE profile_id = {} AND permission_key = {}",
            ph(kind, 1), ph(kind, 2)
        );
        let exists = sql_query(count_sql)
            .bind::<Text, _>(profile_id)
            .bind::<Text, _>(&permission.key)
            .get_result::<CountRow>(conn)
            .map_err(AppError::from)?
            .count
            > 0;
        if exists {
            let sql = format!(
                "UPDATE application_permission_definitions SET label = {}, description = {}, source = {}, is_active = {}, updated_at = {} WHERE profile_id = {} AND permission_key = {}",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(&permission.label)
                .bind::<Nullable<Text>, _>(&permission.description)
                .bind::<Text, _>(SOURCE_WEBSITE)
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(profile_id)
                .bind::<Text, _>(&permission.key)
                .execute(conn)
                .map_err(AppError::from)?;
        } else {
            let sql = format!(
                "INSERT INTO application_permission_definitions (profile_id, permission_key, label, description, source, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
            );
            sql_query(sql)
                .bind::<Text, _>(profile_id)
                .bind::<Text, _>(&permission.key)
                .bind::<Text, _>(&permission.label)
                .bind::<Nullable<Text>, _>(&permission.description)
                .bind::<Text, _>(SOURCE_WEBSITE)
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(conn)
                .map_err(AppError::from)?;
        }
    }
        Ok(())
    }};
}

macro_rules! replace_website_profile_roles_in_connection {
    ($conn:expr, $kind:expr, $profile_id:expr, $profile:expr) => {{
        let conn = $conn;
        let kind = $kind;
        let profile_id = $profile_id;
        let profile = $profile;
    let now = util::now_ts();
    let deactivate_sql = format!(
        "UPDATE application_profile_roles SET is_active = {}, is_default = 0, source = {}, updated_at = {} WHERE profile_id = {}",
        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
    );
    sql_query(deactivate_sql)
        .bind::<Integer, _>(0)
        .bind::<Text, _>(SOURCE_WEBSITE)
        .bind::<BigInt, _>(now)
        .bind::<Text, _>(profile_id)
        .execute(conn)
        .map_err(AppError::from)?;
    for role in &profile.roles {
        let permissions = util::to_json(&role.permissions)?;
        if role.is_default {
            let clear_default_sql = format!(
                "UPDATE application_profile_roles SET is_default = 0, updated_at = {} WHERE profile_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(clear_default_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(profile_id)
                .execute(conn)
                .map_err(AppError::from)?;
        }
        let existing_sql = format!(
            "{} WHERE profile_id = {} AND role_key = {}",
            select_application_profile_role_sql(),
            ph(kind, 1),
            ph(kind, 2)
        );
        let existing = sql_query(existing_sql)
            .bind::<Text, _>(profile_id)
            .bind::<Text, _>(&role.key)
            .get_result::<ApplicationProfileRoleRecord>(conn)
            .optional()
            .map_err(AppError::from)?;
        if let Some(existing) = existing {
            let sql = format!(
                "UPDATE application_profile_roles SET name = {}, description = {}, permissions = {}, source = {}, is_default = {}, is_active = {}, updated_at = {} WHERE profile_id = {} AND id = {}",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9)
            );
            sql_query(sql)
                .bind::<Text, _>(&role.name)
                .bind::<Nullable<Text>, _>(&role.description)
                .bind::<Text, _>(permissions)
                .bind::<Text, _>(SOURCE_WEBSITE)
                .bind::<Integer, _>(i32::from(role.is_default))
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(profile_id)
                .bind::<Text, _>(&existing.id)
                .execute(conn)
                .map_err(AppError::from)?;
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let sql = format!(
                "INSERT INTO application_profile_roles (id, profile_id, role_key, name, description, permissions, source, is_default, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(profile_id)
                .bind::<Text, _>(&role.key)
                .bind::<Text, _>(&role.name)
                .bind::<Nullable<Text>, _>(&role.description)
                .bind::<Text, _>(permissions)
                .bind::<Text, _>(SOURCE_WEBSITE)
                .bind::<Integer, _>(i32::from(role.is_default))
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(conn)
                .map_err(AppError::from)?;
        }
    }
        Ok(())
    }};
}

pub(crate) trait WebsiteDiscoveryConnection {
    fn website_discovery_insert_client(
        &mut self,
        kind: DatabaseKind,
        client: &NewClient,
    ) -> AppResult<String>;

    fn website_discovery_update_client(
        &mut self,
        kind: DatabaseKind,
        id: &str,
        client: &NewClient,
    ) -> AppResult<()>;

    fn website_discovery_upsert_module(
        &mut self,
        kind: DatabaseKind,
        application_id: &str,
        module_key: &str,
        config: &serde_json::Value,
    ) -> AppResult<()>;

    fn website_discovery_upsert_profile(
        &mut self,
        kind: DatabaseKind,
        profile: WebsiteDiscoveryProfileInput<'_>,
    ) -> AppResult<String>;

    fn website_discovery_replace_permissions(
        &mut self,
        kind: DatabaseKind,
        profile_id: &str,
        profile: &ApplicationDiscoveryProfile,
    ) -> AppResult<()>;

    fn website_discovery_replace_roles(
        &mut self,
        kind: DatabaseKind,
        profile_id: &str,
        profile: &ApplicationDiscoveryProfile,
    ) -> AppResult<()>;
}

pub(crate) struct WebsiteDiscoveryProfileInput<'a> {
    pub(crate) application_id: &'a str,
    pub(crate) profile_key: &'a str,
    pub(crate) connection_id: Option<&'a str>,
    pub(crate) connection_kind: &'a str,
    pub(crate) version: &'a str,
    pub(crate) digest: &'a str,
}

macro_rules! impl_website_discovery_connection {
    ($connection:ty) => {
        impl WebsiteDiscoveryConnection for $connection {
            fn website_discovery_insert_client(
                &mut self,
                kind: DatabaseKind,
                client: &NewClient,
            ) -> AppResult<String> {
                insert_client_in_connection!(self, kind, client)
            }

            fn website_discovery_update_client(
                &mut self,
                kind: DatabaseKind,
                id: &str,
                client: &NewClient,
            ) -> AppResult<()> {
                update_client_in_connection!(self, kind, id, client)
            }

            fn website_discovery_upsert_module(
                &mut self,
                kind: DatabaseKind,
                application_id: &str,
                module_key: &str,
                config: &serde_json::Value,
            ) -> AppResult<()> {
                upsert_application_module_in_connection!(
                    self,
                    kind,
                    application_id,
                    module_key,
                    config
                )
            }

            fn website_discovery_upsert_profile(
                &mut self,
                kind: DatabaseKind,
                profile: WebsiteDiscoveryProfileInput<'_>,
            ) -> AppResult<String> {
                upsert_website_profile_in_connection!(
                    self,
                    kind,
                    profile.application_id,
                    profile.profile_key,
                    profile.connection_id,
                    profile.connection_kind,
                    profile.version,
                    profile.digest
                )
            }

            fn website_discovery_replace_permissions(
                &mut self,
                kind: DatabaseKind,
                profile_id: &str,
                profile: &ApplicationDiscoveryProfile,
            ) -> AppResult<()> {
                replace_website_profile_permissions_in_connection!(self, kind, profile_id, profile)
            }

            fn website_discovery_replace_roles(
                &mut self,
                kind: DatabaseKind,
                profile_id: &str,
                profile: &ApplicationDiscoveryProfile,
            ) -> AppResult<()> {
                replace_website_profile_roles_in_connection!(self, kind, profile_id, profile)
            }
        }
    };
}

#[cfg(feature = "sqlite")]
impl_website_discovery_connection!(SqliteConnection);
#[cfg(feature = "postgres")]
impl_website_discovery_connection!(PgConnection);
#[cfg(feature = "mysql")]
impl_website_discovery_connection!(MysqlConnection);
