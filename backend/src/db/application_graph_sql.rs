macro_rules! insert_client_on_conn {
    ($conn:expr, $kind:expr, $id:expr, $client:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let id = $id;
        let client = $client;
        let now = $now;
    let redirect_uris = util::to_json(&client.redirect_uris)?;
    let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
    let scopes = util::to_json(&client.scopes)?;
    let audience = client.audience.trim().to_string();
    let grant_types = util::to_json(&client.grant_types)?;
    let response_types = util::to_json(&client.response_types)?;
    let authorization_details_types = util::to_json(&client.authorization_details_types)?;
    let service_account_permissions = util::to_json(&client.service_account_permissions)?;
    let sql = format!(
        "INSERT INTO clients (id, client_id, client_secret_hash, client_name, logo_uri, organization_id, redirect_uris, post_logout_redirect_uris, scopes, audience, grant_types, response_types, token_endpoint_auth_method, require_pkce, require_mfa, require_pushed_authorization_requests, require_s256_pkce, require_confidential_client, require_dpop, require_account_selection, trust_email_verified, authorization_details_types, subject_type, sector_identifier_uri, jwks_uri, jwks, backchannel_logout_uri, backchannel_logout_session_required, frontchannel_logout_uri, frontchannel_logout_session_required, service_account_enabled, service_account_permissions, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
        ph(kind, 17),
        ph(kind, 18),
        ph(kind, 19),
        ph(kind, 20),
        ph(kind, 21),
        ph(kind, 22),
        ph(kind, 23),
        ph(kind, 24),
        ph(kind, 25),
        ph(kind, 26),
        ph(kind, 27),
        ph(kind, 28),
        ph(kind, 29),
        ph(kind, 30),
        ph(kind, 31),
        ph(kind, 32),
        ph(kind, 33),
        ph(kind, 34),
        ph(kind, 35)
    );
    sql_query(sql)
        .bind::<Text, _>(id.to_string())
        .bind::<Text, _>(client.client_id)
        .bind::<Nullable<Text>, _>(client.client_secret_hash)
        .bind::<Text, _>(client.client_name)
        .bind::<Text, _>(client.logo_uri)
        .bind::<Nullable<Text>, _>(client.organization_id)
        .bind::<Text, _>(redirect_uris)
        .bind::<Text, _>(post_logout_redirect_uris)
        .bind::<Text, _>(scopes)
        .bind::<Text, _>(audience)
        .bind::<Text, _>(grant_types)
        .bind::<Text, _>(response_types)
        .bind::<Text, _>(client.token_endpoint_auth_method)
        .bind::<Integer, _>(i32::from(client.require_pkce))
        .bind::<Integer, _>(i32::from(client.require_mfa))
        .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
        .bind::<Integer, _>(i32::from(client.require_s256_pkce))
        .bind::<Integer, _>(i32::from(client.require_confidential_client))
        .bind::<Integer, _>(i32::from(client.require_dpop))
        .bind::<Integer, _>(i32::from(client.require_account_selection))
        .bind::<Integer, _>(i32::from(client.trust_email_verified))
        .bind::<Text, _>(authorization_details_types)
        .bind::<Text, _>(client.subject_type)
        .bind::<Text, _>(client.sector_identifier_uri)
        .bind::<Text, _>(client.jwks_uri)
        .bind::<Text, _>(client.jwks)
        .bind::<Text, _>(client.backchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
        .bind::<Text, _>(client.frontchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
        .bind::<Integer, _>(i32::from(client.service_account_enabled))
        .bind::<Text, _>(service_account_permissions)
        .bind::<Integer, _>(i32::from(client.is_active))
        .bind::<BigInt, _>(now)
        .bind::<BigInt, _>(now)
        .execute(conn)
        .map_err(AppError::from)?;

    let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
    sql_query(sql)
        .bind::<Text, _>(id.to_string())
        .get_result::<ClientRecord>(conn)
        .map_err(AppError::from)
    }};
}

macro_rules! update_client_on_conn {
    ($conn:expr, $kind:expr, $id:expr, $client:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let id = $id;
        let client = $client;
        let now = $now;
    let redirect_uris = util::to_json(&client.redirect_uris)?;
    let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
    let scopes = util::to_json(&client.scopes)?;
    let audience = client.audience.trim().to_string();
    let grant_types = util::to_json(&client.grant_types)?;
    let response_types = util::to_json(&client.response_types)?;
    let authorization_details_types = util::to_json(&client.authorization_details_types)?;
    let service_account_permissions = util::to_json(&client.service_account_permissions)?;
    let sql = format!(
        "UPDATE clients SET client_id = {}, client_secret_hash = {}, client_name = {}, logo_uri = {}, organization_id = {}, redirect_uris = {}, post_logout_redirect_uris = {}, scopes = {}, audience = {}, grant_types = {}, response_types = {}, token_endpoint_auth_method = {}, require_pkce = {}, require_mfa = {}, require_pushed_authorization_requests = {}, require_s256_pkce = {}, require_confidential_client = {}, require_dpop = {}, require_account_selection = {}, trust_email_verified = {}, authorization_details_types = {}, subject_type = {}, sector_identifier_uri = {}, jwks_uri = {}, jwks = {}, backchannel_logout_uri = {}, backchannel_logout_session_required = {}, frontchannel_logout_uri = {}, frontchannel_logout_session_required = {}, service_account_enabled = {}, service_account_permissions = {}, is_active = {}, updated_at = {} WHERE id = {}",
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
        ph(kind, 17),
        ph(kind, 18),
        ph(kind, 19),
        ph(kind, 20),
        ph(kind, 21),
        ph(kind, 22),
        ph(kind, 23),
        ph(kind, 24),
        ph(kind, 25),
        ph(kind, 26),
        ph(kind, 27),
        ph(kind, 28),
        ph(kind, 29),
        ph(kind, 30),
        ph(kind, 31),
        ph(kind, 32),
        ph(kind, 33),
        ph(kind, 34)
    );
    let affected = sql_query(sql)
        .bind::<Text, _>(client.client_id)
        .bind::<Nullable<Text>, _>(client.client_secret_hash)
        .bind::<Text, _>(client.client_name)
        .bind::<Text, _>(client.logo_uri)
        .bind::<Nullable<Text>, _>(client.organization_id)
        .bind::<Text, _>(redirect_uris)
        .bind::<Text, _>(post_logout_redirect_uris)
        .bind::<Text, _>(scopes)
        .bind::<Text, _>(audience)
        .bind::<Text, _>(grant_types)
        .bind::<Text, _>(response_types)
        .bind::<Text, _>(client.token_endpoint_auth_method)
        .bind::<Integer, _>(i32::from(client.require_pkce))
        .bind::<Integer, _>(i32::from(client.require_mfa))
        .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
        .bind::<Integer, _>(i32::from(client.require_s256_pkce))
        .bind::<Integer, _>(i32::from(client.require_confidential_client))
        .bind::<Integer, _>(i32::from(client.require_dpop))
        .bind::<Integer, _>(i32::from(client.require_account_selection))
        .bind::<Integer, _>(i32::from(client.trust_email_verified))
        .bind::<Text, _>(authorization_details_types)
        .bind::<Text, _>(client.subject_type)
        .bind::<Text, _>(client.sector_identifier_uri)
        .bind::<Text, _>(client.jwks_uri)
        .bind::<Text, _>(client.jwks)
        .bind::<Text, _>(client.backchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
        .bind::<Text, _>(client.frontchannel_logout_uri)
        .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
        .bind::<Integer, _>(i32::from(client.service_account_enabled))
        .bind::<Text, _>(service_account_permissions)
        .bind::<Integer, _>(i32::from(client.is_active))
        .bind::<BigInt, _>(now)
        .bind::<Text, _>(id.to_string())
        .execute(conn)
        .map_err(AppError::from)?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
    sql_query(sql)
        .bind::<Text, _>(id.to_string())
        .get_result::<ClientRecord>(conn)
        .map_err(AppError::from)
    }};
}

macro_rules! replace_client_claim_mappers_on_conn {
    ($conn:expr, $kind:expr, $client_db_id:expr, $mappers:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let client_db_id = $client_db_id;
        let mappers = $mappers;
        let now = $now;
    let sql = format!(
        "DELETE FROM client_claim_mappers WHERE client_db_id = {}",
        ph(kind, 1)
    );
    sql_query(sql)
        .bind::<Text, _>(client_db_id.to_string())
        .execute(&mut *conn)
        .map_err(AppError::from)?;
    for mapper in mappers {
        let sql = format!(
            "INSERT INTO client_claim_mappers (id, client_db_id, claim_name, source, source_value, value_type, include_in_id_token, include_in_access_token, include_in_userinfo, is_active, sort_order, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
            ph(kind, 13)
        );
        sql_query(sql)
            .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
            .bind::<Text, _>(client_db_id.to_string())
            .bind::<Text, _>(mapper.claim_name)
            .bind::<Text, _>(mapper.source)
            .bind::<Text, _>(mapper.source_value)
            .bind::<Text, _>(mapper.value_type)
            .bind::<Integer, _>(i32::from(mapper.include_in_id_token))
            .bind::<Integer, _>(i32::from(mapper.include_in_access_token))
            .bind::<Integer, _>(i32::from(mapper.include_in_userinfo))
            .bind::<Integer, _>(i32::from(mapper.is_active))
            .bind::<Integer, _>(mapper.sort_order)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    let sql = format!(
        "{} WHERE client_db_id = {} ORDER BY sort_order ASC, created_at ASC",
        select_client_claim_mapper_sql(),
        ph(kind, 1)
    );
    sql_query(sql)
        .bind::<Text, _>(client_db_id.to_string())
        .load::<ClientClaimMapperRecord>(conn)
        .map_err(AppError::from)
    }};
}

macro_rules! write_application_profile_on_conn {
    ($conn:expr, $kind:expr, $profile:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let profile = $profile;
        let now = $now;
    let profile_key = profile.profile_key.trim().to_string();
    if profile_key.is_empty()
        || profile_key.len() > 255
        || profile_key.chars().any(|ch| ch.is_control())
    {
        return Err(AppError::BadRequest(
            "authorization profile key is invalid".to_string(),
        ));
    }
    let existing_by_id_sql = format!(
        "{} WHERE id = {} AND application_id = {}",
        select_application_authorization_profile_sql(),
        ph(kind, 1),
        ph(kind, 2)
    );
    let existing_by_id = sql_query(existing_by_id_sql)
        .bind::<Text, _>(profile.id.clone())
        .bind::<Text, _>(profile.application_id.clone())
        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
        .optional()
        .map_err(AppError::from)?;
    let existing_by_key_sql = format!(
        "{} WHERE application_id = {} AND profile_key = {}",
        select_application_authorization_profile_sql(),
        ph(kind, 1),
        ph(kind, 2)
    );
    if let Some(existing_by_key) = sql_query(existing_by_key_sql)
        .bind::<Text, _>(profile.application_id.clone())
        .bind::<Text, _>(profile_key.clone())
        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
        .optional()
        .map_err(AppError::from)?
    {
        if existing_by_key.id != profile.id {
            return Err(AppError::BadRequest(
                "authorization profile key is already used by another connection".to_string(),
            ));
        }
    }

    if existing_by_id.is_some() {
        let sql = format!(
            "UPDATE application_authorization_profiles SET profile_key = {}, connection_kind = {}, connection_id = {}, source_mode = {}, remote_version = {}, remote_digest = {}, sync_status = {}, last_synced_at = {}, last_error = {}, updated_at = {} WHERE id = {} AND application_id = {}",
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
        sql_query(sql)
            .bind::<Text, _>(profile_key)
            .bind::<Text, _>(profile.connection_kind)
            .bind::<Nullable<Text>, _>(profile.connection_id)
            .bind::<Text, _>(profile.source_mode)
            .bind::<Nullable<Text>, _>(profile.remote_version)
            .bind::<Nullable<Text>, _>(profile.remote_digest)
            .bind::<Text, _>(profile.sync_status)
            .bind::<Nullable<BigInt>, _>(profile.last_synced_at)
            .bind::<Nullable<Text>, _>(profile.last_error)
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(profile.id.clone())
            .bind::<Text, _>(profile.application_id.clone())
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    } else {
        let sql = format!(
            "INSERT INTO application_authorization_profiles (id, application_id, profile_key, connection_kind, connection_id, source_mode, remote_version, remote_digest, sync_status, last_synced_at, last_error, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
            ph(kind, 13)
        );
        sql_query(sql)
            .bind::<Text, _>(profile.id.clone())
            .bind::<Text, _>(profile.application_id.clone())
            .bind::<Text, _>(profile_key)
            .bind::<Text, _>(profile.connection_kind)
            .bind::<Nullable<Text>, _>(profile.connection_id)
            .bind::<Text, _>(profile.source_mode)
            .bind::<Nullable<Text>, _>(profile.remote_version)
            .bind::<Nullable<Text>, _>(profile.remote_digest)
            .bind::<Text, _>(profile.sync_status)
            .bind::<Nullable<BigInt>, _>(profile.last_synced_at)
            .bind::<Nullable<Text>, _>(profile.last_error)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    let sql = format!(
        "{} WHERE id = {} AND application_id = {}",
        select_application_authorization_profile_sql(),
        ph(kind, 1),
        ph(kind, 2)
    );
    sql_query(sql)
        .bind::<Text, _>(profile.id)
        .bind::<Text, _>(profile.application_id)
        .get_result::<ApplicationAuthorizationProfileRecord>(conn)
        .map_err(AppError::from)
    }};
}

/// Makes the application-level authorization boundary explicit. Every
/// application has one physical `default` profile, including applications
/// that do not yet expose a client-bound protocol. Runtime adapters resolve
/// this row instead of falling back to a second application-wide role graph.
macro_rules! ensure_application_default_profile_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let application_id = $application_id;
        let existing_sql = format!(
            "{} WHERE application_id = {} AND profile_key = {}",
            select_application_authorization_profile_sql(),
            ph(kind, 1),
            ph(kind, 2)
        );
        if let Some(existing) = sql_query(existing_sql)
            .bind::<Text, _>(application_id.to_string())
            .bind::<Text, _>("default")
            .get_result::<ApplicationAuthorizationProfileRecord>(conn)
            .optional()
            .map_err(AppError::from)?
        {
            existing
        } else {
            write_application_profile_on_conn!(
                conn,
                kind,
                NewApplicationAuthorizationProfile {
                    id: format!("application-default-profile:{application_id}"),
                    application_id: application_id.to_string(),
                    profile_key: "default".to_string(),
                    connection_kind: "application".to_string(),
                    connection_id: None,
                    source_mode: crate::application_discovery_contract::SOURCE_MODE_MANUAL
                        .to_string(),
                    remote_version: None,
                    remote_digest: None,
                    sync_status: crate::application_discovery_contract::SYNC_STATUS_MANUAL
                        .to_string(),
                    last_synced_at: None,
                    last_error: None,
                },
                $now,
            )?
        }
    }};
}

macro_rules! ensure_application_client_binding_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $client_db_id:expr, $protocol:expr, $authorization_profile_id:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let application_id = $application_id;
        let client_db_id = $client_db_id;
        let protocol = $protocol;
        let authorization_profile_id = $authorization_profile_id;
        let now = $now;
    let application_count_sql = format!(
        "SELECT COUNT(*) AS count FROM applications WHERE id = {}",
        ph(kind, 1)
    );
    if sql_query(application_count_sql)
        .bind::<Text, _>(application_id.to_string())
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        == 0
    {
        return Err(AppError::NotFound);
    }
    let profile_count_sql = format!(
        "SELECT COUNT(*) AS count FROM application_authorization_profiles WHERE id = {} AND application_id = {}",
        ph(kind, 1),
        ph(kind, 2)
    );
    if sql_query(profile_count_sql)
        .bind::<Text, _>(authorization_profile_id.to_string())
        .bind::<Text, _>(application_id.to_string())
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        == 0
    {
        return Err(AppError::BadRequest(
            "authorization profile must belong to the application".to_string(),
        ));
    }
    let same_organization_sql = format!(
        "SELECT COUNT(*) AS count FROM applications INNER JOIN clients ON clients.id = {} WHERE applications.id = {} AND clients.organization_id = applications.organization_id",
        ph(kind, 1),
        ph(kind, 2)
    );
    if sql_query(same_organization_sql)
        .bind::<Text, _>(client_db_id.to_string())
        .bind::<Text, _>(application_id.to_string())
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
        "{} WHERE client_db_id = {}",
        select_application_client_binding_sql(),
        ph(kind, 1)
    );
    let existing_binding = sql_query(existing_binding_sql)
        .bind::<Text, _>(client_db_id.to_string())
        .get_result::<ApplicationClientBindingRecord>(conn)
        .optional()
        .map_err(AppError::from)?;
    if let Some(existing_binding) = existing_binding.as_ref()
        && existing_binding.application_id != *application_id
    {
        return Err(AppError::BadRequest(
            "OIDC client already belongs to another application".to_string(),
        ));
    }
    let auth_domain_id = format!("auth-domain:{application_id}");
    let auth_domain_count_sql = format!(
        "SELECT COUNT(*) AS count FROM application_auth_domains WHERE application_id = {}",
        ph(kind, 1)
    );
    if sql_query(auth_domain_count_sql)
        .bind::<Text, _>(application_id.to_string())
        .get_result::<CountRow>(conn)
        .map_err(AppError::from)?
        .count
        == 0
    {
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
            .bind::<Text, _>(auth_domain_id.clone())
            .bind::<Text, _>(application_id.to_string())
            .bind::<Text, _>("default")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    if existing_binding.is_some() {
        let update_binding_sql = format!(
            "UPDATE application_client_bindings SET protocol = {}, authorization_profile_id = {}, auth_domain_id = {}, is_active = {}, updated_at = {} WHERE application_id = {} AND client_db_id = {}",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6),
            ph(kind, 7)
        );
        sql_query(update_binding_sql)
            .bind::<Text, _>(protocol.to_string())
            .bind::<Text, _>(authorization_profile_id.to_string())
            .bind::<Text, _>(auth_domain_id)
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(application_id.to_string())
            .bind::<Text, _>(client_db_id.to_string())
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    } else {
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
            .bind::<Text, _>(application_id.to_string())
            .bind::<Text, _>(client_db_id.to_string())
            .bind::<Text, _>(protocol.to_string())
            .bind::<Text, _>(authorization_profile_id.to_string())
            .bind::<Text, _>(auth_domain_id)
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    Ok::<(), AppError>(())
    }};
}

macro_rules! delete_client_on_conn {
    ($conn:expr, $kind:expr, $id:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let id = $id;
    let client_sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
    let client = sql_query(client_sql)
        .bind::<Text, _>(id.to_string())
        .get_result::<ClientRecord>(conn)
        .optional()
        .map_err(AppError::from)?
        .ok_or(AppError::NotFound)?;
    for (table, column) in [
        ("authorization_codes", "client_id"),
        ("refresh_tokens", "client_id"),
        ("client_grants", "client_id"),
        ("device_authorizations", "client_id"),
        ("pushed_authorization_requests", "client_id"),
        ("oidc_login_grants", "client_id"),
        ("client_assertion_jtis", "client_id"),
    ] {
        let sql = format!(
            "DELETE FROM {table} WHERE {column} IN (SELECT client_id FROM clients WHERE id = {})",
            ph(kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>(id.to_string())
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    for table in ["client_registrations", "client_claim_mappers"] {
        let sql = format!(
            "DELETE FROM {table} WHERE client_db_id = {}",
            ph(kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>(id.to_string())
            .execute(&mut *conn)
            .map_err(AppError::from)?;
    }
    let binding_sql = format!(
        "DELETE FROM application_client_bindings WHERE client_db_id = {}",
        ph(kind, 1)
    );
    sql_query(binding_sql)
        .bind::<Text, _>(id.to_string())
        .execute(&mut *conn)
        .map_err(AppError::from)?;
    let sql = format!("DELETE FROM clients WHERE id = {}", ph(kind, 1));
    let affected = sql_query(sql)
        .bind::<Text, _>(id.to_string())
        .execute(&mut *conn)
        .map_err(AppError::from)?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(client)
    }};
}
