macro_rules! allocate_application_slug_on_conn {
    ($conn:expr, $kind:expr, $organization_id:expr, $client_id:expr $(,)?) => {{
        let base_slug = application_slug_base($client_id);
        let base_sql = format!(
            "SELECT COUNT(*) AS count FROM applications WHERE organization_id = {} AND slug = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        let base_taken = sql_query(base_sql)
            .bind::<Text, _>($organization_id)
            .bind::<Text, _>(&base_slug)
            .get_result::<CountRow>($conn)
            .map_err(AppError::from)?
            .count
            > 0;
        if !base_taken {
            base_slug
        } else {
            let candidate = application_slug_collision_candidate(&base_slug, $client_id);
            let candidate_sql = format!(
                "SELECT COUNT(*) AS count FROM applications WHERE organization_id = {} AND slug = {}",
                ph($kind, 1),
                ph($kind, 2)
            );
            let candidate_taken = sql_query(candidate_sql)
                .bind::<Text, _>($organization_id)
                .bind::<Text, _>(&candidate)
                .get_result::<CountRow>($conn)
                .map_err(AppError::from)?
                .count
                > 0;
            if !candidate_taken {
                candidate
            } else {
                // A digest collision is extraordinarily unlikely, but the
                // database unique key remains the final concurrency guard.
                let mut prefix = base_slug;
                prefix.truncate(31);
                format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
            }
        }
    }};
}

macro_rules! insert_application_on_conn {
    ($conn:expr, $kind:expr, $id:expr, $application:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let application = $application;
        let unique_identity_factors = util::to_json(&application.unique_identity_factors)?;
        let sql = format!(
            "INSERT INTO applications (id, organization_id, slug, name, description, access_mode, registration_mode, account_selection_mode, unique_identity_factors, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3),
            ph($kind, 4),
            ph($kind, 5),
            ph($kind, 6),
            ph($kind, 7),
            ph($kind, 8),
            ph($kind, 9),
            ph($kind, 10),
            ph($kind, 11),
            ph($kind, 12)
        );
        sql_query(sql)
            .bind::<Text, _>($id)
            .bind::<Text, _>(&application.organization_id)
            .bind::<Text, _>(&application.slug)
            .bind::<Text, _>(&application.name)
            .bind::<Nullable<Text>, _>(&application.description)
            .bind::<Text, _>(&application.access_mode)
            .bind::<Text, _>(&application.registration_mode)
            .bind::<Text, _>(&application.account_selection_mode)
            .bind::<Text, _>(unique_identity_factors)
            .bind::<Integer, _>(i32::from(application.is_active))
            .bind::<BigInt, _>($now)
            .bind::<BigInt, _>($now)
            .execute(conn)
            .map_err(AppError::from)?;
        let _ = ensure_application_default_profile_on_conn!(conn, $kind, $id, $now);
        let sql = format!("{} WHERE id = {}", select_application_sql(), ph($kind, 1));
        sql_query(sql)
            .bind::<Text, _>($id)
            .get_result::<ApplicationRecord>(conn)
            .map_err(AppError::from)
    }};
}

macro_rules! update_application_on_conn {
    ($conn:expr, $kind:expr, $id:expr, $application:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let application = $application;
        let unique_identity_factors = util::to_json(&application.unique_identity_factors)?;
        let sql = format!(
            "UPDATE applications SET organization_id = {}, slug = {}, name = {}, description = {}, access_mode = {}, registration_mode = {}, account_selection_mode = {}, unique_identity_factors = {}, is_active = {}, updated_at = {} WHERE id = {}",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3),
            ph($kind, 4),
            ph($kind, 5),
            ph($kind, 6),
            ph($kind, 7),
            ph($kind, 8),
            ph($kind, 9),
            ph($kind, 10),
            ph($kind, 11)
        );
        let affected = sql_query(sql)
            .bind::<Text, _>(&application.organization_id)
            .bind::<Text, _>(&application.slug)
            .bind::<Text, _>(&application.name)
            .bind::<Nullable<Text>, _>(&application.description)
            .bind::<Text, _>(&application.access_mode)
            .bind::<Text, _>(&application.registration_mode)
            .bind::<Text, _>(&application.account_selection_mode)
            .bind::<Text, _>(unique_identity_factors)
            .bind::<Integer, _>(i32::from(application.is_active))
            .bind::<BigInt, _>($now)
            .bind::<Text, _>($id)
            .execute(conn)
            .map_err(AppError::from)?;
        if affected == 0 {
            return Err(AppError::NotFound);
        }
        let sql = format!("{} WHERE id = {}", select_application_sql(), ph($kind, 1));
        sql_query(sql)
            .bind::<Text, _>($id)
            .get_result::<ApplicationRecord>(conn)
            .map_err(AppError::from)
    }};
}

macro_rules! upsert_application_module_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $module_key:expr, $config_json:expr, $is_enabled:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let application_id = $application_id;
        let module_key = $module_key;
        let config_json = $config_json;
        let is_enabled = $is_enabled;
        let lock_sql = format!(
            "UPDATE applications SET updated_at = updated_at WHERE id = {}",
            ph($kind, 1)
        );
        if sql_query(lock_sql)
            .bind::<Text, _>(application_id)
            .execute(conn)
            .map_err(AppError::from)?
            == 0
        {
            return Err(AppError::NotFound);
        }
        let exists_sql = format!(
            "SELECT COUNT(*) AS count FROM application_modules WHERE application_id = {} AND module_key = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        let exists = sql_query(exists_sql)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(module_key)
            .get_result::<CountRow>(conn)
            .map_err(AppError::from)?
            .count
            > 0;
        if exists {
            let update_sql = format!(
                "UPDATE application_modules SET config_json = {}, is_enabled = {}, updated_at = {} WHERE application_id = {} AND module_key = {}",
                ph($kind, 1),
                ph($kind, 2),
                ph($kind, 3),
                ph($kind, 4),
                ph($kind, 5)
            );
            sql_query(update_sql)
                .bind::<Text, _>(config_json)
                .bind::<Integer, _>(i32::from(is_enabled))
                .bind::<BigInt, _>($now)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(module_key)
                .execute(conn)
                .map_err(AppError::from)?;
        } else {
            let insert_sql = format!(
                "INSERT INTO application_modules (application_id, module_key, config_json, is_enabled, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                ph($kind, 1),
                ph($kind, 2),
                ph($kind, 3),
                ph($kind, 4),
                ph($kind, 5),
                ph($kind, 6)
            );
            sql_query(insert_sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(module_key)
                .bind::<Text, _>(config_json)
                .bind::<Integer, _>(i32::from(is_enabled))
                .bind::<BigInt, _>($now)
                .bind::<BigInt, _>($now)
                .execute(conn)
                .map_err(AppError::from)?;
        }
        let select_sql = format!(
            "{} WHERE application_id = {} AND module_key = {}",
            select_application_module_sql(),
            ph($kind, 1),
            ph($kind, 2)
        );
        sql_query(select_sql)
            .bind::<Text, _>(application_id)
            .bind::<Text, _>(module_key)
            .get_result::<ApplicationModuleRecord>(conn)
            .map_err(AppError::from)
    }};
}

macro_rules! insert_application_scim_token_on_conn {
    ($conn:expr, $kind:expr, $token:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let token = $token;
        let scopes = util::to_json(&token.scopes)?;
        let sql = format!(
            "INSERT INTO application_scim_tokens (id, application_id, token_prefix, token_hash, scopes, expires_at, revoked_at, last_used_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3),
            ph($kind, 4),
            ph($kind, 5),
            ph($kind, 6),
            ph($kind, 7),
            ph($kind, 8),
            ph($kind, 9)
        );
        sql_query(sql)
            .bind::<Text, _>(&token.id)
            .bind::<Text, _>(&token.application_id)
            .bind::<Text, _>(&token.token_prefix)
            .bind::<Text, _>(&token.token_hash)
            .bind::<Text, _>(scopes)
            .bind::<Nullable<BigInt>, _>(token.expires_at)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .bind::<BigInt, _>($now)
            .execute(conn)
            .map_err(AppError::from)?;
        let sql = format!(
            "{} WHERE id = {}",
            select_application_scim_token_sql(),
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>(&token.id)
            .get_result::<ApplicationScimTokenRecord>(conn)
            .map_err(AppError::from)
    }};
}

macro_rules! rotate_application_jwt_secret_on_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $client_id:expr, $secret_hash:expr, $grace_seconds:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let client_sql = format!(
            "{} WHERE application_id = {} AND client_id = {}",
            select_application_jwt_client_sql(),
            ph($kind, 1),
            ph($kind, 2)
        );
        let client = sql_query(client_sql)
            .bind::<Text, _>($application_id)
            .bind::<Text, _>($client_id)
            .get_result::<ApplicationJwtClientRecord>(conn)
            .optional()
            .map_err(AppError::from)?
            .ok_or(AppError::NotFound)?;
        if client.client_type != "confidential" || client.is_active != 1 {
            return Err(AppError::BadRequest(
                "JWT secrets require an active confidential client".to_string(),
            ));
        }
        let secret_hash = $secret_hash;
        if secret_hash.trim().is_empty() || secret_hash.len() > 512 {
            return Err(AppError::BadRequest(
                "application JWT secret hash is invalid".to_string(),
            ));
        }
        let expires_at = $now.saturating_add($grace_seconds.clamp(0, 86_400));
        let update_sql = format!(
            "UPDATE application_jwt_client_secrets SET expires_at = CASE WHEN expires_at IS NULL OR expires_at > {} THEN {} ELSE expires_at END WHERE jwt_client_id = {} AND revoked_at IS NULL",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3)
        );
        sql_query(update_sql)
            .bind::<BigInt, _>(expires_at)
            .bind::<BigInt, _>(expires_at)
            .bind::<Text, _>(&client.id)
            .execute(conn)
            .map_err(AppError::from)?;
        let secret_id = uuid::Uuid::new_v4().to_string();
        let insert_sql = format!(
            "INSERT INTO application_jwt_client_secrets (id, jwt_client_id, secret_hash, created_at, expires_at, revoked_at) VALUES ({}, {}, {}, {}, {}, {})",
            ph($kind, 1),
            ph($kind, 2),
            ph($kind, 3),
            ph($kind, 4),
            ph($kind, 5),
            ph($kind, 6)
        );
        sql_query(insert_sql)
            .bind::<Text, _>(&secret_id)
            .bind::<Text, _>(&client.id)
            .bind::<Text, _>(secret_hash)
            .bind::<BigInt, _>($now)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .bind::<Nullable<BigInt>, _>(None::<i64>)
            .execute(conn)
            .map_err(AppError::from)?;
        let select_sql = format!(
            "{} WHERE id = {}",
            select_application_jwt_secret_sql(),
            ph($kind, 1)
        );
        sql_query(select_sql)
            .bind::<Text, _>(secret_id)
            .get_result::<ApplicationJwtClientSecretRecord>(conn)
            .map_err(AppError::from)
    }};
}
