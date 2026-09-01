macro_rules! ensure_user_identity_available {
    ($conn:expr, $kind:expr, $candidate:expr, $message:expr) => {{
        let candidate = &$candidate;
        let count = sql_query(count_user_identity_conflicts_sql($kind))
            .bind::<Text, _>(&candidate.email)
            .bind::<Text, _>(&candidate.username)
            .bind::<Nullable<Text>, _>(candidate.exclude_user_id.clone())
            .bind::<Nullable<Text>, _>(candidate.exclude_user_id.clone())
            .get_result::<CountRow>($conn)
            .map_err(AppError::from)?
            .count;
        if count > 0 {
            Err(AppError::BadRequest($message.to_string()))
        } else {
            Ok(())
        }
    }};
}

macro_rules! ensure_first_user_registration_still_first {
    ($conn:expr, $expected_first_user:expr) => {{
        if $expected_first_user {
            let count = sql_query(count_all_users_sql())
                .get_result::<CountRow>($conn)
                .map_err(AppError::from)?
                .count;
            ensure_first_user_registration_state($expected_first_user, count)
        } else {
            Ok(())
        }
    }};
}

/// Application identity bindings are leases over a user's currently verified
/// contacts, not historical account attributes.  A contact change releases
/// only that contact's leases; deactivation releases them all.
macro_rules! clear_user_application_identity_bindings_for_conn {
    ($conn:expr, $kind:expr, $user_id:expr) => {{
        let sql = format!(
            "DELETE FROM application_identity_bindings WHERE user_id = {}",
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>($user_id)
            .execute($conn)
            .map(|_| ())
            .map_err(AppError::from)
    }};
}

macro_rules! clear_user_application_identity_factor_bindings_for_conn {
    ($conn:expr, $kind:expr, $user_id:expr, $factor_type:expr) => {{
        let sql = format!(
            "DELETE FROM application_identity_bindings WHERE user_id = {} AND factor_type = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        sql_query(sql)
            .bind::<Text, _>($user_id)
            .bind::<Text, _>($factor_type)
            .execute($conn)
            .map(|_| ())
            .map_err(AppError::from)
    }};
}

macro_rules! clear_application_identity_bindings_for_user_for_conn {
    ($conn:expr, $kind:expr, $application_id:expr, $user_id:expr) => {{
        let sql = format!(
            "DELETE FROM application_identity_bindings WHERE application_id = {} AND user_id = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        sql_query(sql)
            .bind::<Text, _>($application_id)
            .bind::<Text, _>($user_id)
            .execute($conn)
            .map(|_| ())
            .map_err(AppError::from)
    }};
}

macro_rules! latest_verification_code {
    ($conn:expr, $kind:expr, $claim:expr) => {{
        let claim = $claim;
        sql_query(crate::db::auth_challenges::select_latest_verification_code_sql($kind))
            .bind::<Text, _>(&claim.channel)
            .bind::<Text, _>(&claim.target)
            .bind::<Text, _>(&claim.purpose)
            .get_result::<VerificationCodeRecord>($conn)
            .optional()
            .map_err(AppError::from)?
    }};
}

macro_rules! increment_verification_attempts {
    ($conn:expr, $kind:expr, $id:expr) => {{
        sql_query(crate::db::auth_challenges::increment_verification_attempts_sql($kind))
            .bind::<Text, _>($id)
            .execute($conn)
            .map_err(AppError::from)?
    }};
}

macro_rules! mark_verification_code_consumed {
    ($conn:expr, $kind:expr, $now:expr, $id:expr) => {{
        sql_query(crate::db::auth_challenges::consume_verification_code_sql(
            $kind,
        ))
        .bind::<BigInt, _>($now)
        .bind::<Text, _>($id)
        .execute($conn)
        .map_err(AppError::from)?
    }};
}

macro_rules! clear_user_auth_state_for_conn {
    ($conn:expr, $kind:expr, $user_id:expr) => {{
        for table in ["session_credentials", "browser_context_accounts"] {
            let sql = format!(
                "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id = {})",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($user_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        for (table, column) in USER_AUTH_STATE_TABLES {
            let sql = format!("DELETE FROM {table} WHERE {column} = {}", ph($kind, 1));
            sql_query(sql)
                .bind::<Text, _>($user_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! revoke_trial_enrollment_auth_state_for_invitation {
    ($conn:expr, $kind:expr, $invitation_id:expr) => {{
        for table in ["session_credentials", "browser_context_accounts"] {
            let sql = format!(
                "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN (SELECT user_id FROM trial_enrollments WHERE invitation_id = {}))",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($invitation_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        for (table, column) in [
            ("authorization_codes", "user_id"),
            ("oidc_login_grants", "user_id"),
            ("refresh_tokens", "user_id"),
            ("device_authorizations", "authorized_user_id"),
        ] {
            let sql = format!(
                "DELETE FROM {table} WHERE {column} IN (SELECT user_id FROM trial_enrollments WHERE invitation_id = {})",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($invitation_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        let sql = format!(
            "DELETE FROM sessions WHERE user_id IN (SELECT user_id FROM trial_enrollments WHERE invitation_id = {})",
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>($invitation_id)
            .execute($conn)
            .map_err(AppError::from)?;
    }};
}

macro_rules! revoke_trial_enrollment_auth_state_for_organization {
    ($conn:expr, $kind:expr, $organization_id:expr) => {{
        for table in ["session_credentials", "browser_context_accounts"] {
            let sql = format!(
                "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN (SELECT user_id FROM trial_enrollments WHERE organization_id = {}))",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($organization_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        for (table, column) in [
            ("authorization_codes", "user_id"),
            ("oidc_login_grants", "user_id"),
            ("refresh_tokens", "user_id"),
            ("device_authorizations", "authorized_user_id"),
        ] {
            let sql = format!(
                "DELETE FROM {table} WHERE {column} IN (SELECT user_id FROM trial_enrollments WHERE organization_id = {})",
                ph($kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>($organization_id)
                .execute($conn)
                .map_err(AppError::from)?;
        }
        let sql = format!(
            "DELETE FROM sessions WHERE user_id IN (SELECT user_id FROM trial_enrollments WHERE organization_id = {})",
            ph($kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>($organization_id)
            .execute($conn)
            .map_err(AppError::from)?;
    }};
}
