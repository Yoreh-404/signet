//! Inactive incumbent ledger definition. Compiling this module does not
//! register a migration or provide any DB, operator, or authorization caller.
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
