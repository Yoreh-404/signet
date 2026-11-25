// Resolve the exact existing site registration on the caller's connection.
#[derive(diesel::QueryableByName)]
struct BindingRow {
    #[diesel(sql_type = Text)]
    application_db_id: String,
    #[diesel(sql_type = Text)]
    client_db_id: String,
    #[diesel(sql_type = Text)]
    enrolled_jwks: String,
    #[diesel(sql_type = Text)]
    redirect_uris: String,
    #[diesel(sql_type = Text)]
    scopes: String,
    #[diesel(sql_type = Text)]
    grant_types: String,
    #[diesel(sql_type = Text)]
    response_types: String,
}
fn exactly(raw: &str, expected: &str) -> bool {
    serde_json::from_str::<Vec<String>>(raw).is_ok_and(|v| v == [expected])
}
fn enrolled_registry_on_conn(
    conn: &mut BackendConn, approved: &VerifiedPolicy,
) -> QueryResult<Option<BindingRow>> {
    let p = approved.policy();
    let callback = format!("{}/admin/api/auth/signet/callback", p.origin);
    let rows: Vec<BindingRow> = sql_query(registry_select("SELECT a.id AS application_db_id,
        c.id AS client_db_id, d.signing_public_jwks AS enrolled_jwks,
        c.redirect_uris, c.scopes, c.grant_types, c.response_types
        FROM applications a
        JOIN organizations o ON o.id = a.organization_id AND o.is_active = 1
        JOIN application_discovery d ON d.application_id = a.id
        JOIN application_client_bindings b ON b.application_id = a.id
        JOIN clients c ON c.id = b.client_db_id AND c.organization_id = o.id
        WHERE o.id = $1 AND a.slug = $2 AND a.is_active = 1
        AND d.management_mode = 'website_managed' AND d.operator_disabled = 0 AND d.website_url = $3
        AND c.client_id = $4 AND c.audience = $5 AND c.is_active = 1
        AND b.is_active = 1 AND b.protocol IN ('oidc', 'oauth2_oidc')
        AND c.token_endpoint_auth_method = 'none'
        AND c.require_pkce = 1 AND c.require_s256_pkce = 1
        LIMIT 2"))
        .bind::<Text, _>(&p.organization_id).bind::<Text, _>(&p.application_id)
        .bind::<Text, _>(&p.origin).bind::<Text, _>(&p.client_id)
        .bind::<Text, _>(&p.audience).load(conn)?;
    let [row] = rows.as_slice() else { return Ok(None); };
    if !exactly(&row.redirect_uris, &callback) || !exactly(&row.scopes, "openid")
        || !exactly(&row.grant_types, "authorization_code") || !exactly(&row.response_types, "code")
    {
        return Ok(None);
    }
    Ok(rows.into_iter().next())
}


/// Read-side prerequisite only. The caller must also establish current
/// interactive browser eligibility with the same exact verified pin and
/// recheck the authorities atomically at code admission. This cannot
/// construct verified policy from unauthenticated ledger bytes.
pub(crate) fn exact_active_policy(
    conn: &mut BackendConn, gate: &RestoreInterlock, pin: &IncumbentPin<'_>,
    approved: &VerifiedPolicy,
) -> QueryResult<bool> {
    let Some(snapshot) = RestoreSnapshot::capture(gate) else { return Ok(false); };
    let p = approved.policy();
    let Some(registration) = enrolled_registry_on_conn(conn, approved)? else { return Ok(false); };
    if pin.withdrawn || pin.policy_sha256 != approved.sha256()
        || pin.revision != p.revision || pin.generation != p.generation
        || registration.application_db_id != pin.application_db_id
        || registration.client_db_id != pin.client_db_id
        || !approved_enrolled_signer(approved, pin.signer_pin, &registration.enrolled_jwks)
    {
        return Ok(false);
    }
    #[derive(diesel::QueryableByName)]
    struct Active {
        #[diesel(sql_type = Text)] policy_json: String,
    }
    let active = sql_query("SELECT policy_json FROM axon_v3_incumbent_activation
        WHERE singleton = 1 AND profile = 'incumbent_v1' AND withdrawn = 0
        AND application_db_id = $1 AND client_db_id = $2 AND organization_id = $3
        AND enrollment_id = $4 AND signer_pin = $5
        AND policy_sha256 = $6 AND revision = $7 AND generation = $8")
        .bind::<Text, _>(pin.application_db_id).bind::<Text, _>(pin.client_db_id)
        .bind::<Text, _>(&p.organization_id).bind::<Text, _>(&p.enrollment_id)
        .bind::<Text, _>(pin.signer_pin).bind::<Text, _>(approved.sha256())
        .bind::<BigInt, _>(p.revision).bind::<BigInt, _>(p.generation)
        .get_result::<Active>(conn).optional()?;
    Ok(active.is_some_and(|row| row.policy_json == approved.bytes()) && snapshot.unchanged())
}

/// Dormant restart reader. The trusted floor and enrollment must come from
/// protected caller state, not the database record being recovered.
/// This reconstructs policy material, not a user/session authorization.
pub(crate) fn restore_accepted_policy(
    conn: &mut BackendConn,
    gate: &RestoreInterlock,
    pin: &IncumbentPin<'_>,
    trusted: &crate::application_discovery::axon_v3_acceptance::TrustedRegistration<'_>,
    now: i64,
) -> QueryResult<Option<VerifiedPolicy>> {
    use crate::application_discovery::axon_v3_acceptance::verify_acceptance;
    #[derive(diesel::QueryableByName)]
    struct Receipt {
        #[diesel(sql_type = Text)] policy_json: String,
        #[diesel(sql_type = Text)] accepted_jws: String,
        #[diesel(sql_type = BigInt)] verified_at: i64,
    }
    registry_read_transaction(conn, |conn| {
        let Some(marker) = RestoreSnapshot::capture(gate) else { return Ok(None); };
        let receipt = sql_query("SELECT policy_json, accepted_jws, verified_at
            FROM axon_v3_incumbent_activation
            WHERE singleton=1 AND profile='incumbent_v1' AND withdrawn=0
            AND accepted_jws IS NOT NULL AND verified_at > 0 AND verified_at <= $1
            AND application_db_id=$2 AND client_db_id=$3 AND signer_pin=$4
            AND policy_sha256=$5 AND revision=$6 AND generation=$7")
            .bind::<BigInt, _>(now)
            .bind::<Text, _>(pin.application_db_id).bind::<Text, _>(pin.client_db_id)
            .bind::<Text, _>(pin.signer_pin).bind::<Text, _>(pin.policy_sha256)
            .bind::<BigInt, _>(pin.revision).bind::<BigInt, _>(pin.generation)
            .get_result::<Receipt>(conn).optional()?;
        let Some(receipt) = receipt else { return Ok(None); };
        let Ok(policy) = verify_acceptance(
            receipt.policy_json.as_bytes(), &receipt.accepted_jws, trusted, receipt.verified_at,
        ) else { return Ok(None); };
        #[derive(diesel::QueryableByName)]
        struct Site { #[diesel(sql_type = Text)] application_id: String }
        let fresh = sql_query("SELECT application_id FROM application_discovery
            WHERE application_id=$1 AND management_mode='website_managed'
            AND operator_disabled=0 AND last_verified_revision IS NOT NULL
            AND snapshot_json IS NOT NULL
            AND (last_verified_expires_at IS NULL OR last_verified_expires_at > $2)")
            .bind::<Text, _>(pin.application_db_id).bind::<BigInt, _>(now)
            .get_result::<Site>(conn).optional()?
            .is_some_and(|site| site.application_id == pin.application_db_id);
        Ok((fresh && exact_active_policy(conn, gate, pin, &policy)? && marker.unchanged())
            .then_some(policy))
    })
}

/// Dormant foreground writer. Both configured trust and the enrolled
/// registry must agree; no caller-supplied DB ID and no shared stage.
pub(crate) fn write_enrolled_incumbent(
    conn: &mut BackendConn, enrolled: &crate::config::AxonAdminV3Enrollment,
    trust: &crate::config::AxonAdminTrust, expected: Option<Version<'_>>, next: &VerifiedPolicy,
) -> QueryResult<()> {
    write_enrolled_incumbent_checked(conn, enrolled, trust, expected, next, || ())
}

#[cfg(test)]
pub(crate) fn write_enrolled_incumbent_with_test_hook(
    conn: &mut BackendConn, enrolled: &crate::config::AxonAdminV3Enrollment,
    trust: &crate::config::AxonAdminTrust, expected: Option<Version<'_>>, next: &VerifiedPolicy,
    after_registry_read: impl FnOnce(),
) -> QueryResult<()> {
    write_enrolled_incumbent_checked(conn, enrolled, trust, expected, next, after_registry_read)
}

fn write_enrolled_incumbent_checked(
    conn: &mut BackendConn, enrolled: &crate::config::AxonAdminV3Enrollment,
    trust: &crate::config::AxonAdminTrust, expected: Option<Version<'_>>, next: &VerifiedPolicy,
    after_registry_read: impl FnOnce(),
) -> QueryResult<()> {
    let p = next.policy();
    if p.organization_id != enrolled.organization_id || p.enrollment_id != enrolled.enrollment_id
        || p.application_id != enrolled.application_id || p.issuer != enrolled.issuer
        || p.client_id != enrolled.client_id || p.audience != enrolled.audience
        || p.origin != enrolled.origin || trust.organization_id != enrolled.organization_id
        || trust.application_id != enrolled.application_id || trust.client_id != enrolled.client_id
        || trust.audience != enrolled.audience || trust.origin != enrolled.origin
        || crate::dcr::is_website_client_id(&p.client_id)
    {
        return Err(Error::RollbackTransaction);
    }
    let signer = crate::application_discovery::axon_signer_pin(&trust.signing_public_jwks)
        .ok_or(Error::RollbackTransaction)?;
    let gate = RestoreInterlock::new(enrolled.restore_marker_path.clone(), enrolled.restore_marker_owner_uid);
    let initial = RestoreSnapshot::capture(&gate).ok_or(Error::RollbackTransaction)?;
    // Resolution and CAS share one writer lock; the inner CAS is a savepoint.
    registry_write_transaction(conn, |conn| {
        let row = enrolled_registry_on_conn(conn, next)?.ok_or(Error::RollbackTransaction)?;
        after_registry_read();
        compare_and_set(conn, &gate, &IncumbentPin {
            application_db_id: &row.application_db_id, client_db_id: &row.client_db_id,
            policy_sha256: next.sha256(), signer_pin: &signer, revision: p.revision,
            generation: p.generation, withdrawn: false,
        }, &row.enrolled_jwks, expected, next)?;
        if !initial.unchanged() {
            return Err(Error::RollbackTransaction);
        }
        Ok(())
    })
}

pub(crate) fn compare_and_set(
    conn: &mut BackendConn, gate: &RestoreInterlock, binding: &IncumbentPin<'_>,
    enrolled_jwks: &str, expected: Option<Version<'_>>, next: &VerifiedPolicy,
) -> QueryResult<()> {
    compare_and_set_checked(conn, gate, binding, enrolled_jwks, expected, next, || {})
}

#[cfg(test)]
pub(crate) fn compare_and_set_with_test_hook(
    conn: &mut BackendConn, gate: &RestoreInterlock,
    binding: &IncumbentPin<'_>, enrolled_jwks: &str,
    expected: Option<Version<'_>>, next: &VerifiedPolicy,
    before_final_check: impl FnOnce(),
) -> QueryResult<()> {
    compare_and_set_checked(conn, gate, binding, enrolled_jwks, expected, next, before_final_check)
}

fn compare_and_set_checked(
    conn: &mut BackendConn, gate: &RestoreInterlock,
    binding: &IncumbentPin<'_>, enrolled_jwks: &str,
    expected: Option<Version<'_>>, next: &VerifiedPolicy, before_final_check: impl FnOnce(),
) -> QueryResult<()> {
    let policy = next.policy();
    if binding.withdrawn || binding.policy_sha256 != next.sha256()
        || binding.revision != policy.revision || binding.generation != policy.generation
        || !approved_enrolled_signer(next, binding.signer_pin, enrolled_jwks)
    {
        return Err(Error::RollbackTransaction);
    }
    let snapshot = RestoreSnapshot::capture(gate).ok_or(Error::RollbackTransaction)?;
    conn.transaction(|conn| {
        let changed = match expected {
            None => sql_query("INSERT INTO axon_v3_incumbent_activation
                SELECT 1, 'incumbent_v1', $1, $2, $3, $4, $5, $6, $7, $8, $9, 0, $10, $11
                WHERE NOT EXISTS (SELECT 1 FROM axon_v3_incumbent_activation WHERE singleton = 1)")
                .bind::<Text, _>(binding.application_db_id).bind::<Text, _>(binding.client_db_id)
                .bind::<Text, _>(&policy.organization_id).bind::<Text, _>(&policy.enrollment_id)
                .bind::<Text, _>(binding.signer_pin)
                .bind::<Text, _>(next.sha256()).bind::<Text, _>(next.bytes())
                .bind::<BigInt, _>(policy.revision).bind::<BigInt, _>(policy.generation)
                .bind::<Text, _>(next.approval()).bind::<BigInt, _>(next.verified_at())
                .execute(conn)?,
            Some(expected) => sql_query("UPDATE axon_v3_incumbent_activation
                SET policy_sha256 = $1, policy_json = $2, revision = $3, generation = $4, withdrawn = 0,
                    accepted_jws = $5, verified_at = $6
                WHERE singleton = 1 AND profile = 'incumbent_v1'
                AND application_db_id = $7 AND client_db_id = $8 AND organization_id = $9
                AND enrollment_id = $10 AND signer_pin = $11
                AND policy_sha256 = $12 AND revision = $13 AND generation = $14
                AND revision < $15 AND generation < $16")
                .bind::<Text, _>(next.sha256()).bind::<Text, _>(next.bytes())
                .bind::<BigInt, _>(policy.revision).bind::<BigInt, _>(policy.generation)
                .bind::<Text, _>(next.approval()).bind::<BigInt, _>(next.verified_at())
                .bind::<Text, _>(binding.application_db_id).bind::<Text, _>(binding.client_db_id)
                .bind::<Text, _>(&policy.organization_id).bind::<Text, _>(&policy.enrollment_id)
                .bind::<Text, _>(binding.signer_pin)
                .bind::<Text, _>(expected.digest).bind::<BigInt, _>(expected.revision)
                .bind::<BigInt, _>(expected.generation)
                .bind::<BigInt, _>(policy.revision).bind::<BigInt, _>(policy.generation)
                .execute(conn)?,
        };
        before_final_check();
        if changed != 1 || !snapshot.unchanged() {
            return Err(Error::RollbackTransaction);
        }
        Ok(())
    })
}

/// Exact tombstone; intentionally does not require the restore gate to be open.
pub(crate) fn withdraw(conn: &mut BackendConn, binding: &IncumbentPin<'_>)
    -> QueryResult<usize> {
    sql_query("UPDATE axon_v3_incumbent_activation SET withdrawn = 1
        WHERE singleton = 1 AND profile = 'incumbent_v1' AND withdrawn = 0
        AND application_db_id = $1 AND client_db_id = $2 AND signer_pin = $3
        AND policy_sha256 = $4 AND revision = $5 AND generation = $6")
        .bind::<Text, _>(binding.application_db_id).bind::<Text, _>(binding.client_db_id)
        .bind::<Text, _>(binding.signer_pin)
        .bind::<Text, _>(binding.policy_sha256)
        .bind::<BigInt, _>(binding.revision).bind::<BigInt, _>(binding.generation)
        .execute(conn)
}
