//! Inactive incumbent ledger definition. Compiling this module does not
//! register a migration or provide an operator or authorization caller.
#![allow(dead_code)]

use crate::application_discovery::axon_v3_restore::{Reconciliation, RestoreInterlock};

pub(crate) const SCHEMA: &str = "CREATE TABLE axon_v3_incumbent_activation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile TEXT NOT NULL CHECK (profile = 'incumbent_v1'),
    application_db_id TEXT NOT NULL,
    client_db_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    signer_pin TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    withdrawn INTEGER NOT NULL CHECK (withdrawn IN (0, 1))
)";

/// Current row identity for future exact compare-and-set; this is not a grant.
#[derive(Clone, Copy)]
pub(crate) struct Version<'a> {
    pub(crate) digest: &'a str,
    pub(crate) revision: i64,
    pub(crate) generation: i64,
}

/// Keep the original operator gate alive across one prospective transaction.
/// This is not an approval to activate, or a standalone restore guarantee.
pub(crate) struct RestoreSnapshot<'a> {
    interlock: &'a RestoreInterlock,
    initial: Reconciliation,
}

impl<'a> RestoreSnapshot<'a> {
    pub(crate) fn capture(interlock: &'a RestoreInterlock) -> Option<Self> {
        Some(Self { interlock, initial: interlock.reconciled()? })
    }

    pub(crate) fn unchanged(&self) -> bool {
        self.interlock.reconciled().as_ref() == Some(&self.initial)
    }
}

// Private storage primitive: callers do not exist outside the fixture.
// Accepting a value here alone must never be treated as authorization.
#[cfg(all(feature = "sqlite", feature = "axon-incumbent-storage"))]
pub(crate) mod sqlite {
    use super::{RestoreInterlock, RestoreSnapshot, Version};
    use crate::application_discovery::{
        axon_v3_acceptance::VerifiedPolicy,
        incumbent_preflight::{IncumbentPin, approved_enrolled_signer},
    };
    use diesel::{Connection, QueryResult, RunQueryDsl, SqliteConnection, result::Error,
        sql_query, sql_types::{BigInt, Text}};

    /// Dormant foreground writer. Both configured trust and the enrolled
    /// registry must agree; no caller-supplied DB ID and no shared stage.
    pub(crate) fn write_enrolled_incumbent(
        conn: &mut SqliteConnection, enrolled: &crate::config::AxonAdminV3Enrollment,
        trust: &crate::config::AxonAdminTrust, expected: Option<Version<'_>>, next: &VerifiedPolicy,
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
        let callback = format!("{}/admin/api/auth/signet/callback", p.origin);
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
        conn.transaction(|conn| {
            let rows: Vec<BindingRow> = sql_query("SELECT a.id AS application_db_id,
                c.id AS client_db_id, d.signing_public_jwks AS enrolled_jwks,
                c.redirect_uris, c.scopes, c.grant_types, c.response_types
                FROM applications a
                JOIN organizations o ON o.id = a.organization_id AND o.is_active = 1
                JOIN application_discovery d ON d.application_id = a.id
                JOIN application_client_bindings b ON b.application_id = a.id
                JOIN clients c ON c.id = b.client_db_id AND c.organization_id = o.id
                WHERE o.id = ? AND a.slug = ? AND a.is_active = 1
                AND d.management_mode = 'website_managed' AND d.operator_disabled = 0 AND d.website_url = ?
                AND c.client_id = ? AND c.audience = ? AND c.is_active = 1
                AND b.is_active = 1 AND b.protocol IN ('oidc', 'oauth2_oidc')
                AND c.token_endpoint_auth_method = 'none'
                AND c.require_pkce = 1 AND c.require_s256_pkce = 1
                LIMIT 2")
                .bind::<Text, _>(&p.organization_id).bind::<Text, _>(&p.application_id)
                .bind::<Text, _>(&p.origin).bind::<Text, _>(&p.client_id)
                .bind::<Text, _>(&p.audience).load(conn)?;
            let [row] = rows.as_slice() else { return Err(Error::RollbackTransaction); };
            if !exactly(&row.redirect_uris, &callback) || !exactly(&row.scopes, "openid")
                || !exactly(&row.grant_types, "authorization_code") || !exactly(&row.response_types, "code")
            {
                return Err(Error::RollbackTransaction);
            }
            compare_and_set(conn, &gate, &IncumbentPin {
                application_db_id: &row.application_db_id, client_db_id: &row.client_db_id,
                policy_sha256: next.sha256(), signer_pin: &signer, revision: p.revision,
                generation: p.generation, withdrawn: false,
            }, &row.enrolled_jwks, expected, next)
        })
    }

    pub(crate) fn compare_and_set(
        conn: &mut SqliteConnection, gate: &RestoreInterlock, binding: &IncumbentPin<'_>,
        enrolled_jwks: &str, expected: Option<Version<'_>>, next: &VerifiedPolicy,
    ) -> QueryResult<()> {
        compare_and_set_checked(conn, gate, binding, enrolled_jwks, expected, next, || {})
    }

    #[cfg(test)]
    pub(crate) fn compare_and_set_with_test_hook(
        conn: &mut SqliteConnection, gate: &RestoreInterlock,
        binding: &IncumbentPin<'_>, enrolled_jwks: &str,
        expected: Option<Version<'_>>, next: &VerifiedPolicy,
        before_final_check: impl FnOnce(),
    ) -> QueryResult<()> {
        compare_and_set_checked(conn, gate, binding, enrolled_jwks, expected, next, before_final_check)
    }

    fn compare_and_set_checked(
        conn: &mut SqliteConnection, gate: &RestoreInterlock,
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
                    SELECT 1, 'incumbent_v1', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0
                    WHERE NOT EXISTS (SELECT 1 FROM axon_v3_incumbent_activation WHERE singleton = 1)")
                    .bind::<Text, _>(binding.application_db_id).bind::<Text, _>(binding.client_db_id)
                    .bind::<Text, _>(&policy.organization_id).bind::<Text, _>(&policy.enrollment_id)
                    .bind::<Text, _>(binding.signer_pin)
                    .bind::<Text, _>(next.sha256()).bind::<Text, _>(next.bytes())
                    .bind::<BigInt, _>(policy.revision).bind::<BigInt, _>(policy.generation)
                    .execute(conn)?,
                Some(expected) => sql_query("UPDATE axon_v3_incumbent_activation
                    SET policy_sha256 = ?, policy_json = ?, revision = ?, generation = ?, withdrawn = 0
                    WHERE singleton = 1 AND profile = 'incumbent_v1'
                    AND application_db_id = ? AND client_db_id = ? AND organization_id = ?
                    AND enrollment_id = ? AND signer_pin = ?
                    AND policy_sha256 = ? AND revision = ? AND generation = ?
                    AND revision < ? AND generation < ?")
                    .bind::<Text, _>(next.sha256()).bind::<Text, _>(next.bytes())
                    .bind::<BigInt, _>(policy.revision).bind::<BigInt, _>(policy.generation)
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
    pub(crate) fn withdraw(conn: &mut SqliteConnection, binding: &IncumbentPin<'_>)
        -> QueryResult<usize> {
        sql_query("UPDATE axon_v3_incumbent_activation SET withdrawn = 1
            WHERE singleton = 1 AND profile = 'incumbent_v1' AND withdrawn = 0
            AND application_db_id = ? AND client_db_id = ? AND signer_pin = ?
            AND policy_sha256 = ? AND revision = ? AND generation = ?")
            .bind::<Text, _>(binding.application_db_id).bind::<Text, _>(binding.client_db_id)
            .bind::<Text, _>(binding.signer_pin)
            .bind::<Text, _>(binding.policy_sha256)
            .bind::<BigInt, _>(binding.revision).bind::<BigInt, _>(binding.generation)
            .execute(conn)
    }
}
