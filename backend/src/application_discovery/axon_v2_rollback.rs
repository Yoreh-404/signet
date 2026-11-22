//! Trusted rollback floor for the opt-in Axon authority only.
//! The operator must retain this file independently of database/config backups,
//! protect it from service writers, and atomically replace it before revocation.
//! The service only reads it and never silently bootstraps or rewinds it.
use serde::Deserialize;
use std::{fs::File, io::Read, path::Path};

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AxonRollbackFloor {
    pub organization_id: String,
    pub application_id: String,
    pub enrollment_id: String,
    pub minimum_generation: i64,
    pub revision: i64,
    pub digest: String,
    pub halted: bool,
}

pub(crate) fn read_axon_rollback_floor(
    policy: &crate::config::AxonAdminV2Policy,
    trust: &crate::config::AxonAdminTrust,
) -> Option<AxonRollbackFloor> {
    let path = Path::new(policy.rollback_marker_path.as_deref()?);
    if !path.is_absolute() {
        return None;
    }
    let info = path.symlink_metadata().ok()?;
    if !info.is_file() || info.len() > 4096 {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o222 != 0 {
            return None;
        }
    }
    let mut bytes = Vec::new();
    File::open(path).ok()?.take(4097).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    let floor = serde_json::from_slice::<AxonRollbackFloor>(&bytes).ok()?;
    if floor.organization_id != trust.organization_id
        || floor.application_id != trust.application_id
        || floor.enrollment_id.is_empty() || floor.enrollment_id != policy.enrollment_id
        || floor.minimum_generation <= 0 || floor.revision <= 0
        || floor.digest.len() != 43
        || !floor.digest.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return None;
    }
    Some(floor)
}
