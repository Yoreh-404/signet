//! A Signet-wide operator restore gate for durable Axon administration only.
//! The deployment controller closes it before a controlled restore and only
//! reopens after reconciling the restored account, policy and revocation data.
#![allow(dead_code)]

use super::axon_v2_rollback::open_operator_anchor;
use serde::Deserialize;
use std::{io::Read, path::PathBuf};

#[derive(Clone)]
pub(crate) struct RestoreInterlock {
    path: PathBuf,
    owner_uid: u32,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum State { Held, Reconciled }

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reconciliation {
    format: String,
    state: State,
    operation_id: uuid::Uuid,
}

impl RestoreInterlock {
    pub(crate) fn new(path: PathBuf, owner_uid: u32) -> Self { Self { path, owner_uid } }

    /// Fail closed if no independent state exists. Check again before
    /// returning a privileged read so a concurrent restore hold wins.
    pub(crate) fn reconciled(&self) -> Option<Reconciliation> {
        const LIMIT: u64 = 1024;
        if !self.path.is_absolute() { return None; }
        let file = open_operator_anchor(&self.path, self.owner_uid, LIMIT)?;
        let mut bytes = Vec::new();
        file.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > LIMIT { return None; }
        let marker: Reconciliation = serde_json::from_slice(&bytes).ok()?;
        (marker.format == "signet-privileged-restore/v1" && marker.state == State::Reconciled
            && !marker.operation_id.is_nil()).then_some(marker)
    }
}
