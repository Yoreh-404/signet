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
    host_sha256 TEXT NOT NULL,
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
        axon_signer_pin,
        axon_v3_acceptance::{VerifiedPolicy, enrolled_signer_key_sha256},
        incumbent_preflight::IncumbentPin,
    };
    use diesel::{Connection, QueryResult, RunQueryDsl, SqliteConnection, result::Error,
        sql_query, sql_types::{BigInt, Text}};

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
            || axon_signer_pin(enrolled_jwks).as_deref() != Some(binding.signer_pin)
            || enrolled_signer_key_sha256(enrolled_jwks).as_deref() != Some(next.signer_key_sha256())
        {
            return Err(Error::RollbackTransaction);
        }
        let snapshot = RestoreSnapshot::capture(gate).ok_or(Error::RollbackTransaction)?;
        conn.transaction(|conn| {
            let changed = match expected {
                None => sql_query("INSERT INTO axon_v3_incumbent_activation
                    SELECT 1, 'incumbent_v1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0
                    WHERE NOT EXISTS (SELECT 1 FROM axon_v3_incumbent_activation WHERE singleton = 1)")
                    .bind::<Text, _>(binding.application_db_id).bind::<Text, _>(binding.client_db_id)
                    .bind::<Text, _>(&policy.organization_id).bind::<Text, _>(&policy.enrollment_id)
                    .bind::<Text, _>(binding.host_sha256).bind::<Text, _>(binding.signer_pin)
                    .bind::<Text, _>(next.sha256()).bind::<Text, _>(next.bytes())
                    .bind::<BigInt, _>(policy.revision).bind::<BigInt, _>(policy.generation)
                    .execute(conn)?,
                Some(expected) => sql_query("UPDATE axon_v3_incumbent_activation
                    SET policy_sha256 = ?, policy_json = ?, revision = ?, generation = ?, withdrawn = 0
                    WHERE singleton = 1 AND profile = 'incumbent_v1'
                    AND application_db_id = ? AND client_db_id = ? AND organization_id = ?
                    AND enrollment_id = ? AND host_sha256 = ? AND signer_pin = ?
                    AND policy_sha256 = ? AND revision = ? AND generation = ?
                    AND revision < ? AND generation < ?")
                    .bind::<Text, _>(next.sha256()).bind::<Text, _>(next.bytes())
                    .bind::<BigInt, _>(policy.revision).bind::<BigInt, _>(policy.generation)
                    .bind::<Text, _>(binding.application_db_id).bind::<Text, _>(binding.client_db_id)
                    .bind::<Text, _>(&policy.organization_id).bind::<Text, _>(&policy.enrollment_id)
                    .bind::<Text, _>(binding.host_sha256).bind::<Text, _>(binding.signer_pin)
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
            AND application_db_id = ? AND client_db_id = ? AND host_sha256 = ? AND signer_pin = ?
            AND policy_sha256 = ? AND revision = ? AND generation = ?")
            .bind::<Text, _>(binding.application_db_id).bind::<Text, _>(binding.client_db_id)
            .bind::<Text, _>(binding.host_sha256).bind::<Text, _>(binding.signer_pin)
            .bind::<Text, _>(binding.policy_sha256)
            .bind::<BigInt, _>(binding.revision).bind::<BigInt, _>(binding.generation)
            .execute(conn)
    }
}
