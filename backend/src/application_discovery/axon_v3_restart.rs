//! Reconstruct the explicitly selected incumbent policy from signed storage
//! and independently protected operator state. Never trusts a restored DB alone.
#![allow(dead_code)]

use super::{
    axon_signer_pin,
    axon_v2_rollback::open_operator_anchor,
    axon_v3_acceptance::{TrustedFloor, TrustedRegistration, VerifiedPolicy},
    axon_v3_restore::RestoreInterlock,
    incumbent_preflight::IncumbentPin,
};
use crate::config::{AxonAdminTrust, AxonAdminV3Enrollment};
use diesel::QueryResult;
#[cfg(feature = "sqlite")]
use diesel::SqliteConnection;
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

pub(crate) struct RestoredIncumbent {
    floor: RestartFloor,
    signer: String,
    pub(crate) policy: VerifiedPolicy,
}

impl RestoredIncumbent {
    pub(crate) fn pin(&self) -> IncumbentPin<'_> {
        IncumbentPin {
            application_db_id: &self.floor.application_db_id,
            client_db_id: &self.floor.client_db_id,
            policy_sha256: &self.floor.policy_sha256,
            signer_pin: &self.signer,
            revision: self.floor.revision,
            generation: self.floor.generation,
            withdrawn: self.floor.state == FloorState::Stopped,
        }
    }

    pub(crate) fn still_current(&self, path: &Path, owner: u32) -> bool {
        read_floor(path, owner).as_ref() == Some(&self.floor)
    }
}

/// The protected floor is separately provisioned, never synthesized from a
/// database row or the restore marker. Restoring it does not grant access.
#[cfg(feature = "sqlite")]
pub(super) fn restore_from_operator_floor(
    conn: &mut SqliteConnection,
    floor_path: &Path,
    enrolled: &AxonAdminV3Enrollment,
    trust: &AxonAdminTrust,
    now: i64,
) -> QueryResult<Option<VerifiedPolicy>> {
    restore_sqlite_material(conn, floor_path, enrolled, trust, now)
        .map(|value| value.map(|material| material.policy))
}

#[cfg(feature = "sqlite")]
pub(crate) fn restore_sqlite_material(
    conn: &mut SqliteConnection, floor_path: &Path, enrolled: &AxonAdminV3Enrollment,
    trust: &AxonAdminTrust, now: i64,
) -> QueryResult<Option<RestoredIncumbent>> {
    restore_using_operator_floor(floor_path, enrolled, trust, now, |gate, pin, trusted, now| {
        crate::db::axon_v3_incumbent_storage::sqlite::restore_accepted_policy(
            conn, gate, pin, trusted, now)
    })
}

#[cfg(feature = "postgres")]
pub(crate) fn restore_postgres_material(
    conn: &mut diesel::PgConnection,
    floor_path: &Path,
    enrolled: &AxonAdminV3Enrollment,
    trust: &AxonAdminTrust,
    now: i64,
) -> QueryResult<Option<RestoredIncumbent>> {
    restore_using_operator_floor(floor_path, enrolled, trust, now, |gate, pin, trusted, now| {
        crate::db::axon_v3_incumbent_storage::postgres::restore_accepted_policy(
            conn, gate, pin, trusted, now)
    })
}

fn restore_using_operator_floor(
    floor_path: &Path,
    enrolled: &AxonAdminV3Enrollment,
    trust: &AxonAdminTrust,
    now: i64,
    read: impl FnOnce(&RestoreInterlock, &IncumbentPin<'_>, &TrustedRegistration<'_>, i64)
        -> QueryResult<Option<VerifiedPolicy>>,
) -> QueryResult<Option<RestoredIncumbent>> {
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
    let verified = read(&gate, &pin, &TrustedRegistration {
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
    Ok(verified.filter(|_| read_floor(floor_path, owner).as_ref() == Some(&floor))
        .map(|policy| RestoredIncumbent { floor, signer, policy }))
}

pub(super) fn apply_selected_operator_floor(settings: &crate::Settings, db: &crate::db::Db,
    expected: &str, approved: Option<&VerifiedPolicy>) -> crate::error::AppResult<()> {
    use crate::{db::{Db, axon_v3_incumbent_storage as ledger}, error::AppError};
    let config = &settings.discovery;
    let enrolled = config.axon_admin_v3.as_ref().ok_or(AppError::Forbidden)?;
    let trust = config.axon_admin_trust.as_ref().ok_or(AppError::Forbidden)?;
    let path = config.axon_admin_incumbent_floor.as_ref().ok_or(AppError::Forbidden)?;
    let owner = enrolled.restore_marker_owner_uid;
    let floor = read_floor(path, owner).ok_or(AppError::Forbidden)?;
    if floor.policy_sha256 != expected || floor.organization_id != enrolled.organization_id
        || floor.enrollment_id != enrolled.enrollment_id || trust.organization_id != enrolled.organization_id
        || trust.application_id != enrolled.application_id || trust.client_id != enrolled.client_id
        || trust.audience != enrolled.audience || trust.origin != enrolled.origin
        || floor.revision < 1 || floor.generation < 1
    { return Err(AppError::Forbidden); }
    if let Some(receipt) = approved {
        let p = receipt.policy();
        if floor.state != FloorState::Active || receipt.sha256() != expected
            || p.revision != floor.revision || p.generation != floor.generation
            || p.permissions != floor.permissions
        { return Err(AppError::Forbidden); }
    }
    let signer = axon_signer_pin(&trust.signing_public_jwks).ok_or(AppError::Forbidden)?;
    let gate = RestoreInterlock::new(enrolled.restore_marker_path.clone(), owner);
    let pin = IncumbentPin { application_db_id: &floor.application_db_id, client_db_id: &floor.client_db_id,
        policy_sha256: expected, signer_pin: &signer, revision: floor.revision,
        generation: floor.generation, withdrawn: floor.state == FloorState::Stopped };
    let current = || read_floor(path, owner).as_ref() == Some(&floor);
    #[allow(unreachable_patterns)]
    let changed = match db {
        #[cfg(feature = "sqlite")]
        Db::Sqlite(pool) => {
            let mut conn = pool.get()?;
            ledger::sqlite::apply_selected_floor(&mut conn, &gate, &pin, approved, current)
        }
        #[cfg(feature = "postgres")]
        Db::Postgres(pool) => {
            let mut conn = pool.get()?;
            ledger::postgres::apply_selected_floor(&mut conn, &gate, &pin, approved, current)
        }
        _ => return Err(AppError::Forbidden),
    };
    changed.map_err(|err| match err {
        diesel::result::Error::RollbackTransaction => AppError::Forbidden,
        other => AppError::from(other),
    })?;
    if approved.is_none() && floor.state != FloorState::Stopped {
        return Err(AppError::BadRequest("withdrawn in the database; the independent operator floor is still active and must be stopped for restore-resistant withdrawal".into()));
    }
    Ok(())
}

#[cfg(all(test, feature = "sqlite"))]
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
