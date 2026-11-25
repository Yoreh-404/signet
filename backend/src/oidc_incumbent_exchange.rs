pub(super) fn store_incumbent_authorization_code(
    conn: &mut BackendConn,
    input: IncumbentAuthorizationInput<'_>,
    #[cfg(test)] setup: &dyn Fn(&mut BackendConn) -> AppResult<()>,
    #[cfg(test)] before_commit: &dyn Fn(&mut BackendConn) -> AppResult<()>,
) -> AppResult<String> {
    use crate::application_discovery::incumbent_preflight::{self, RequestScope};

    let IncumbentAuthorizationInput {
        state, resolved, issuer, ip, credential, session_id, user, pin, approved, gate,
    } = input;
    ledger::registry_write_transaction(conn, |conn| {
        #[cfg(test)]
        setup(conn)?;
        let gate_snapshot = RestoreSnapshot::capture(gate).ok_or(AppError::Forbidden)?;
        let now = util::now_ts();
        let session = ledger::current_incumbent_browser_on_conn(
            conn, credential, session_id, &user.id, now,
        )?.ok_or(AppError::Forbidden)?;
        if !ledger::exact_active_policy(conn, gate, pin, approved)? {
            return Err(AppError::Forbidden);
        }
        let client = find_client_by_client_id_on_conn(conn, &resolved.client_id)?
            .filter(|client| client.id == pin.client_db_id)
            .ok_or(AppError::Forbidden)?;
        validate_authorize_request_for_client(&client, resolved)?;
        let scopes = normalize_and_validate_requested_scopes(
            &client, resolved.scope.as_deref(), &state.settings.oidc.supported_scopes,
        )?;
        let exact = RequestScope::from_resolved(issuer, resolved).ok_or(AppError::Forbidden)?;
        if !incumbent_preflight::matches_signed_request(pin, approved, &exact) {
            return Err(AppError::Forbidden);
        }
        let graph = load_policy_snapshot(conn, &client.id, &session.user_id)?;
        let application = graph.application.as_ref().ok_or(AppError::Forbidden)?;
        let binding = graph.binding.as_ref().ok_or(AppError::Forbidden)?;
        if !graph.is_authorizable || !graph.is_interactive_client_runtime_active()
            || !graph.has_client_application_boundary(&client.id)
            || !graph.has_profile_application_boundary()
            || application.id != pin.application_db_id
            || !matches!(
                mfa_decision(
                    conn, &client, &session, resolved, ip,
                )?,
                MfaDecision::Satisfied
            )
        {
            return Err(AppError::Forbidden);
        }
        let code = util::random_token(32);
        let requested = resolved.requested_assurance()?;
        let assurance = session.authentication_assurance();
        let acr = assurance::DefaultAssurancePolicy.select_acr(&assurance, &requested)?;
        assurance::DefaultAssurancePolicy.assert_amr(&assurance, &requested)?;
        let context_id = find_or_create_application_auth_context_on_conn(
            conn, &binding.auth_domain_id, &session.user_id, &acr,
            &assurance.amr, session.created_at, now,
        )?;
        let details = authorization_details::normalize_authorization_details_for_client(
            &client, resolved.authorization_details.as_deref(),
        )?;
        let PreparedAuthorizationCode { redirect_code, row } = build_authorization_code_material(
            resolved, &scopes, &session, &client, user, &application.id,
            &binding.authorization_profile_id, context_id, code, acr, assurance.amr,
            details, state.settings.oidc.authorization_code_ttl_seconds,
        );
        let inserted_at = util::now_ts();
        let amr = util::to_json(&row.amr)?;
        ledger::bind_code_provenance_on_conn(conn, &row, pin, approved, inserted_at)?;
        insert_authorization_code_on_conn(conn, row, amr, inserted_at)?;
        #[cfg(test)]
        before_commit(conn)?;
        if !gate_snapshot.unchanged() {
            return Err(AppError::Forbidden);
        }
        Ok(redirect_code)
    })
}
/// Complete the exact incumbent exchange using the normal access signer and
/// claim machinery. No route calls this and the token embeds no admin authority.
pub(super) fn exchange_incumbent_access_token<'a>(
    conn: &mut BackendConn,
    state: &AppState,
    effective_issuer: &str,
    gate: &crate::application_discovery::axon_v3_restore::RestoreInterlock,
    pin: &crate::application_discovery::incumbent_preflight::IncumbentPin<'_>,
    approved: &'a crate::application_discovery::axon_v3_acceptance::VerifiedPolicy,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
) -> AppResult<(ledger::CommittedIncumbentCode<'a>, String)> {

    if effective_issuer != approved.policy().issuer {
        return Err(AppError::Forbidden);
    }
    ledger::consume_incumbent_code(
        conn, gate, pin, approved, code, client_id, redirect_uri, verifier,
        |conn, evidence| {
            let user = find_user_by_id_on_conn(conn, evidence.user_id())?
                .ok_or(AppError::Forbidden)?;
            let signed = evidence.approved_policy().policy();
            let client = find_client_by_client_id_on_conn(conn, &signed.client_id)?
                .filter(|client| client.id == evidence.client_db_id())
                .ok_or(AppError::Forbidden)?;
            let graph = load_policy_snapshot(conn, &client.id, &user.id)?;
            if !graph.has_profile_application_boundary()
                || !graph.application.as_ref().is_some_and(|row| row.id == evidence.application_db_id())
                || !graph.profile.as_ref().is_some_and(|row| row.id == evidence.profile_id())
                || !graph.binding.as_ref().is_some_and(|row| row.authorization_profile_id == evidence.profile_id())
            {
                return Err(AppError::Forbidden);
            }
            let snapshot = AuthorizationSnapshot::from_current_policy(state, &client, &user, graph)?;
            let mut claims = snapshot.claims_for_user(
                &client, &user, evidence.scope(), crate::claim_mapper::ClaimOutputTarget::AccessToken,
            )?;
            claims.remove("axon_admin");
            claims.remove("axon_admin_authority_v3");
            claims.insert("application_id".into(), evidence.application_db_id().into());
            claims.insert("authorization_profile_id".into(), evidence.profile_id().into());
            oidc_token::insert_sid_claim(&mut claims, Some(evidence.public_sid()));

            let token = state.jwt.sign_access_token_with_issuer_and_claims(
                effective_issuer,
                crate::jwt::TokenSubject {
                    user: &user,
                    client_id: &signed.client_id,
                    audience: Some(&signed.audience),
                    scope: evidence.scope(),
                    nonce: None,
                    auth_time: Some(evidence.auth_time()),
                },
                state.settings.oidc.access_token_ttl_seconds,
                claims,
            )?;
            let claims = state.jwt.verify_access_token_for_introspection(&token, &[effective_issuer])?;
            ledger::bind_access_proof_on_conn(conn, evidence, &claims)?;
            Ok(token)
        },
    )
}

/// Internal verifier candidate. The authenticated caller identity and effective
/// issuer are supplied by the existing server auth/issuer path, not HTTP data.
pub(super) fn verify_incumbent_access_proof(
    conn: &mut BackendConn,
    state: &AppState,
    authenticated_verifier_db_id: &str,
    effective_issuer: &str,
    pin: &crate::application_discovery::incumbent_preflight::IncumbentPin<'_>,
    approved: &crate::application_discovery::axon_v3_acceptance::VerifiedPolicy,
    token: &str,
) -> AppResult<bool> {

    let Some(enrolled) = state.settings.discovery.axon_admin_v3.as_ref() else { return Ok(false); };
    let gate = crate::application_discovery::axon_v3_restore::RestoreInterlock::new(
        enrolled.restore_marker_path.clone(), enrolled.restore_marker_owner_uid,
    );
    let signed = approved.policy();
    if effective_issuer != signed.issuer || signed.issuer != enrolled.issuer
        || signed.organization_id != enrolled.organization_id || signed.enrollment_id != enrolled.enrollment_id
        || signed.application_id != enrolled.application_id || signed.client_id != enrolled.client_id
        || signed.audience != enrolled.audience || signed.origin != enrolled.origin
        || enrolled.introspection_client_id == enrolled.client_id
    {
        return Ok(false);
    }
    let Ok(claims) = state.jwt.verify_access_token_for_introspection(token, &[effective_issuer])
        else { return Ok(false); };

    ledger::registry_read_transaction(conn, |conn| {
        let Some(snapshot) = RestoreSnapshot::capture(&gate) else { return Ok(false); };
        let Some(verifier) = find_client_by_client_id_on_conn(conn, &enrolled.introspection_client_id)?
            else { return Ok(false); };
        if verifier.id != authenticated_verifier_db_id || verifier.is_active != 1
            || verifier.token_endpoint_auth_method == "none"
            || verifier.organization_id.as_deref() != Some(enrolled.organization_id.as_str())
            || verifier.audience != enrolled.audience
        {
            return Ok(false);
        }
        Ok(ledger::read_live_access_proof_on_conn(conn, &gate, pin, approved, &claims, util::now_ts())?
            && snapshot.unchanged())
    })
}
