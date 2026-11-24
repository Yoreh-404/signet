//! Private restart policy material. No command, listener or route calls it.
#![allow(dead_code)]

use super::{
    axon_signer_pin,
    axon_v2_rollback::open_operator_anchor,
    axon_v3_acceptance::{TrustedFloor, TrustedRegistration, VerifiedPolicy},
    axon_v3_restore::RestoreInterlock,
    incumbent_preflight::IncumbentPin,
};
use crate::{
    config::{AxonAdminTrust, AxonAdminV3Enrollment},
    db::axon_v3_incumbent_storage::sqlite,
};
use diesel::{QueryResult, SqliteConnection};
use serde::Deserialize;
use std::{io::Read, path::Path};

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FloorState {
    Active,
    Stopped,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RestartFloor {
    format: String,
    state: FloorState,
    organization_id: String,
    enrollment_id: String,
    application_db_id: String,
    client_db_id: String,
    policy_sha256: String,
    revision: i64,
    generation: i64,
    permissions: Vec<String>,
}

fn read_floor(path: &Path, owner: u32) -> Option<RestartFloor> {
    const LIMIT: u64 = 65_536;
    if !path.is_absolute() {
        return None;
    }
    let mut bytes = Vec::new();
    open_operator_anchor(path, owner, LIMIT)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > LIMIT {
        return None;
    }
    let floor: RestartFloor = serde_json::from_slice(&bytes).ok()?;
    (floor.format == "signet-incumbent-restart-floor/v1").then_some(floor)
}

/// The protected floor is separately provisioned, never synthesized from a
/// database row or the restore marker. Restoring it does not grant access.
pub(super) fn restore_from_operator_floor(
    conn: &mut SqliteConnection,
    floor_path: &Path,
    enrolled: &AxonAdminV3Enrollment,
    trust: &AxonAdminTrust,
    now: i64,
) -> QueryResult<Option<VerifiedPolicy>> {
    let owner = enrolled.restore_marker_owner_uid;
    let Some(floor) = read_floor(floor_path, owner) else { return Ok(None); };
    if floor.state != FloorState::Active
        || floor.organization_id != enrolled.organization_id
        || floor.enrollment_id != enrolled.enrollment_id
        || trust.organization_id != enrolled.organization_id
        || trust.application_id != enrolled.application_id
        || trust.client_id != enrolled.client_id
        || trust.audience != enrolled.audience
        || trust.origin != enrolled.origin
    {
        return Ok(None);
    }
    let Some(signer) = axon_signer_pin(&trust.signing_public_jwks) else { return Ok(None); };
    let gate = RestoreInterlock::new(enrolled.restore_marker_path.clone(), owner);
    let pin = IncumbentPin {
        application_db_id: &floor.application_db_id,
        client_db_id: &floor.client_db_id,
        policy_sha256: &floor.policy_sha256,
        signer_pin: &signer,
        revision: floor.revision,
        generation: floor.generation,
        withdrawn: false,
    };
    let verified = sqlite::restore_accepted_policy(conn, &gate, &pin, &TrustedRegistration {
        organization_id: &enrolled.organization_id,
        enrollment_id: &enrolled.enrollment_id,
        application_id: &enrolled.application_id,
        issuer: &enrolled.issuer,
        client_id: &enrolled.client_id,
        audience: &enrolled.audience,
        origin: &enrolled.origin,
        permissions: &floor.permissions,
        approval_audience: &enrolled.issuer,
        approval_jwks: &trust.signing_public_jwks,
        floor: &TrustedFloor {
            policy_sha256: &floor.policy_sha256,
            revision: floor.revision,
            generation: floor.generation,
            halted: floor.state == FloorState::Stopped,
        },
    }, now)?;
    Ok(verified.filter(|_| read_floor(floor_path, owner).as_ref() == Some(&floor)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::Connection;

    #[test]
    fn subprocess_restart() {
        let Ok(fixture) = std::env::var("SIGNET_TEST_RESTART_MATERIAL") else { return; };
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
        let enrolled = serde_json::from_value(document["enrollment"].clone()).unwrap();
        let trust = serde_json::from_value(document["trust"].clone()).unwrap();
        let mut conn = SqliteConnection::establish(document["database"].as_str().unwrap()).unwrap();
        let restored = restore_from_operator_floor(
            &mut conn, Path::new(document["floor"].as_str().unwrap()), &enrolled, &trust,
            document["now"].as_i64().unwrap(),
        ).unwrap().map(|value| value.sha256().to_owned());
        let expected = std::env::var("SIGNET_TEST_RESTART_EXPECTED").unwrap();
        assert_eq!(restored.as_deref().unwrap_or("denied"), expected);
    }
}
