//! Foreground deployment operator control. No HTTP route calls this entrypoint.
use super::axon_v3_acceptance::{TrustedFloor, TrustedRegistration, VerifiedPolicy, read_stored_policy, verify_acceptance};
use super::axon_v3_restore::RestoreInterlock;
use crate::config::{AxonAdminTrust, AxonAdminV3Enrollment};
use crate::{Settings, db::Db, error::{AppError, AppResult}};
use std::{fs::File, io::Read};

fn input(path: &str, limit: u64) -> AppResult<Vec<u8>> {
    let file = File::open(path).map_err(|_| AppError::Forbidden)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(|_| AppError::Forbidden)?;
    if bytes.is_empty() || bytes.len() as u64 > limit { return Err(AppError::Forbidden); }
    Ok(bytes)
}

fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|value|
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

fn verified_activation(
    enrolled: &AxonAdminV3Enrollment, trust: &AxonAdminTrust,
    policy: &str, approval: &str, expected: &str,
) -> AppResult<VerifiedPolicy> {
    if !valid_digest(expected)
        || trust.organization_id != enrolled.organization_id || trust.application_id != enrolled.application_id
        || trust.client_id != enrolled.client_id || trust.audience != enrolled.audience || trust.origin != enrolled.origin
    { return Err(AppError::Forbidden); }
    let bytes = input(policy, 65_536)?;
    let approval = input(approval, 8192)?;
    let approval = std::str::from_utf8(&approval).map_err(|_| AppError::Forbidden)?;
    let checked = read_stored_policy(&bytes, expected).ok_or(AppError::Forbidden)?;
    verify_acceptance(&bytes, approval, &TrustedRegistration {
        organization_id: &enrolled.organization_id, enrollment_id: &enrolled.enrollment_id,
        application_id: &enrolled.application_id, issuer: &enrolled.issuer,
        client_id: &enrolled.client_id, audience: &enrolled.audience, origin: &enrolled.origin,
        permissions: &checked.permissions, approval_audience: &enrolled.issuer,
        approval_jwks: &trust.signing_public_jwks, floor: &TrustedFloor {
            policy_sha256: expected, revision: checked.revision, generation: checked.generation, halted: false,
        },
    }, crate::util::now_ts())
}

#[allow(dead_code)]
pub(super) struct PreviousIncumbent<'a> {
    pub(super) digest: &'a str,
    pub(super) revision: i64,
    pub(super) generation: i64,
}

/// Unregistered foreground seam. A future caller must use only protected
/// deployment Settings and its actual configured Db. Never create a SQLite
/// fallback when the deployment uses a different DB.
#[allow(dead_code)]
pub(super) fn write_incumbent_from_foreground(
    settings: &Settings, db: &Db, policy: &str, approval: &str, expected: &str,
    previous: Option<PreviousIncumbent<'_>>,
) -> AppResult<()> {
    #[cfg(all(any(feature = "sqlite", feature = "postgres"), feature = "axon-incumbent-storage"))]
    {
        let enrolled = settings.discovery.axon_admin_v3.as_ref().ok_or(AppError::Forbidden)?;
        let trust = settings.discovery.axon_admin_trust.as_ref().ok_or(AppError::Forbidden)?;
        let gate = RestoreInterlock::new(enrolled.restore_marker_path.clone(), enrolled.restore_marker_owner_uid);
        if gate.reconciled().is_none() { return Err(AppError::Forbidden); }
        let verified = verified_activation(enrolled, trust, policy, approval, expected)?;
        let previous = previous.map(|p| crate::db::axon_v3_incumbent_storage::Version {
            digest: p.digest, revision: p.revision, generation: p.generation,
        });
        use crate::db::axon_v3_incumbent_storage as ledger;
        #[allow(unreachable_patterns)]
        let result = match db {
            #[cfg(feature = "sqlite")]
            Db::Sqlite(pool) => {
                let mut conn = pool.get()?;
                ledger::sqlite::write_enrolled_incumbent(&mut conn, enrolled, trust, previous, &verified)
            }
            #[cfg(feature = "postgres")]
            Db::Postgres(pool) => {
                let mut conn = pool.get()?;
                ledger::postgres::write_enrolled_incumbent(&mut conn, enrolled, trust, previous, &verified)
            }
            _ => return Err(AppError::Forbidden),
        };
        return result.map_err(|error| match error {
            diesel::result::Error::RollbackTransaction => AppError::Forbidden,
            other => AppError::from(other),
        });
    }
    #[cfg(not(all(any(feature = "sqlite", feature = "postgres"), feature = "axon-incumbent-storage")))]
    {
        let _ = (settings, db, policy, approval, expected, previous);
        Err(AppError::Forbidden)
    }
}

pub async fn run_axon_v3_operator_command(settings: &Settings, db: &Db, args: &[String]) -> AppResult<()> {
    let Some(enrolled) = settings.discovery.axon_admin_v3.as_ref() else { return Err(AppError::Forbidden); };
    match args {
        [command, expected] if command == "withdraw" && valid_digest(expected) => {
            #[cfg(all(target_os = "linux", feature = "axon-incumbent-storage", any(feature = "postgres", feature = "sqlite")))]
            if settings.discovery.axon_admin_incumbent_floor.is_some() {
                return super::axon_v3_restart::apply_selected_operator_floor(settings, db, expected, None);
            }
            db.withdraw_axon_v3_policy(enrolled.clone(), expected.clone()).await
        }
        [command, policy, approval, expected] if command == "activate" && valid_digest(expected) => {
            // The configured existing enrollment signer remains the only signer;
            // CLI users cannot supply a replacement key or a different scope.
            let Some(trust) = settings.discovery.axon_admin_trust.as_ref() else { return Err(AppError::Forbidden); };
            if trust.organization_id != enrolled.organization_id || trust.application_id != enrolled.application_id
                || trust.client_id != enrolled.client_id || trust.audience != enrolled.audience || trust.origin != enrolled.origin
            { return Err(AppError::Forbidden); }
            let gate = RestoreInterlock::new(enrolled.restore_marker_path.clone(), enrolled.restore_marker_owner_uid);
            if gate.reconciled().is_none() { return Err(AppError::Forbidden); }
            let verified = verified_activation(enrolled, trust, policy, approval, expected)?;
            #[cfg(all(target_os = "linux", feature = "axon-incumbent-storage", any(feature = "postgres", feature = "sqlite")))]
            if settings.discovery.axon_admin_incumbent_floor.is_some() {
                return super::axon_v3_restart::apply_selected_operator_floor(settings, db, expected, Some(&verified));
            }
            db.stage_axon_v3_policy(verified).await?;
            db.activate_axon_v3_policy(enrolled.clone(), expected.clone(), &gate).await
        }
        _ => Err(AppError::BadRequest(
            "usage: axon-v3 activate <policy-json> <acceptance-jws> <policy-sha256> | withdraw <policy-sha256>".into(),
        )),
    }
}
