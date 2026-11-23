//! Trusted rollback floor for the opt-in Axon authority only.
//! The operator must retain this file independently of database/config backups,
//! protect it from service writers, and atomically replace it before revocation.
//! The service only reads it and never silently bootstraps or rewinds it.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
    let file = open_operator_anchor(path, policy.rollback_marker_owner_uid?, 4096)?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes).ok()?;
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

const ACCOUNT_FORMAT: &str = "signet-axon-account-revocations/v1";
const MAX_ACCOUNT_EVIDENCE: u64 = 65_536;
const MAX_ACCOUNTS: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAccountEvidence {
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountEvidence {
    format: String,
    organization_id: String,
    application_id: String,
    enrollment_id: String,
    minimum_generation: i64,
    revision: i64,
    digest: String,
    revoked_account_ids: Vec<String>,
}

fn read_account_evidence(
    config: &crate::config::AxonAccountRevocations,
    floor: &AxonRollbackFloor,
    owner: u32,
) -> Option<AccountEvidence> {
    let path = Path::new(&config.marker_path);
    if !path.is_absolute() { return None; }
    let file = open_operator_anchor(path, owner, MAX_ACCOUNT_EVIDENCE)?;
    let mut bytes = Vec::new();
    file.take(MAX_ACCOUNT_EVIDENCE + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_ACCOUNT_EVIDENCE { return None; }
    let envelope: SignedAccountEvidence = serde_json::from_slice(&bytes).ok()?;
    let payload = URL_SAFE_NO_PAD.decode(envelope.payload).ok()?;
    if URL_SAFE_NO_PAD.encode(Sha256::digest(&payload)) != config.payload_digest { return None; }
    let key: [u8; 32] = URL_SAFE_NO_PAD.decode(&config.signing_public_key).ok()?.try_into().ok()?;
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(envelope.signature).ok()?).ok()?;
    VerifyingKey::from_bytes(&key).ok()?.verify_strict(&payload, &signature).ok()?;
    let evidence: AccountEvidence = serde_json::from_slice(&payload).ok()?;
    let ids = &evidence.revoked_account_ids;
    if evidence.format != ACCOUNT_FORMAT
        || evidence.organization_id != floor.organization_id
        || evidence.application_id != floor.application_id
        || evidence.enrollment_id != floor.enrollment_id
        || evidence.minimum_generation != floor.minimum_generation
        || evidence.revision != floor.revision
        || evidence.digest != floor.digest
        || ids.len() > MAX_ACCOUNTS
        || !ids.windows(2).all(|pair| pair[0] < pair[1])
        || !ids.iter().all(|id| uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == *id))
    { return None; }
    Some(evidence)
}

/// Only denies this exact v2 authority. A valid signed empty list differs
/// from missing evidence. The independently retained reviewed digest binds
/// the exact list, even if an older signature has the same floor generation.
pub(crate) fn axon_account_may_project(
    policy: &crate::config::AxonAdminV2Policy,
    floor: &AxonRollbackFloor,
    account_id: &str,
) -> bool {
    policy.account_revocations.as_ref().is_none_or(|config| {
        policy.revision == floor.revision && policy.digest == floor.digest
            && policy.rollback_marker_owner_uid
                .and_then(|owner| read_account_evidence(config, floor, owner)).is_some_and(|evidence| {
                evidence.revoked_account_ids.binary_search_by(|id| id.as_str().cmp(account_id)).is_err()
            })
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exact_account_evidence_rejects_same_generation_replay_and_other_scope() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("current.json");
        let next = dir.join("next.json");
        let owner = rustix::process::geteuid().as_raw();
        let floor = AxonRollbackFloor {
            organization_id: "tenant".into(), application_id: "axon".into(), enrollment_id: "enrollment".into(),
            minimum_generation: 4, revision: 5, digest: "a".repeat(43), halted: false,
        };
        let user = "10000000-0000-4000-8000-000000000001";
        let other = "10000000-0000-4000-8000-000000000002";
        let key = SigningKey::from_bytes(&[7;32]);
        let sign = |tenant: &str, ids: &[&str], signer: &SigningKey| {
            let payload = serde_json::to_vec(&json!({
                "format":ACCOUNT_FORMAT,"organization_id":tenant,"application_id":floor.application_id,
                "enrollment_id":floor.enrollment_id,"minimum_generation":floor.minimum_generation,
                "revision":floor.revision,"digest":floor.digest,"revoked_account_ids":ids,
            })).unwrap();
            let signature = signer.sign(&payload);
            (URL_SAFE_NO_PAD.encode(Sha256::digest(&payload)), json!({
                "payload":URL_SAFE_NO_PAD.encode(payload),"signature":URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            }))
        };
        let write = |envelope: &serde_json::Value| {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(&next, envelope.to_string()).unwrap();
            let mut permissions = std::fs::metadata(&next).unwrap().permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(&next, permissions).unwrap();
            std::fs::rename(&next, &path).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        };
        let mut config = crate::config::AxonAccountRevocations {
            marker_path:path.to_string_lossy().into_owned(),
            signing_public_key:URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            payload_digest:String::new(),
        };
        let (old_pin, old) = sign("tenant", &[], &key);
        let read = |config: &crate::config::AxonAccountRevocations, floor: &AxonRollbackFloor| {
            read_account_evidence(config, floor, owner)
        };
        config.payload_digest = old_pin;
        assert!(read(&config, &floor).is_none(), "missing is not a valid empty list");
        write(&old);
        assert!(read(&config, &floor).unwrap().revoked_account_ids.is_empty());
        let (pin, current) = sign("tenant", &[user], &key);
        config.payload_digest = pin.clone();
        assert!(read(&config, &floor).is_none(), "same-generation older valid proof");
        write(&current);
        assert_eq!(read(&config, &floor).unwrap().revoked_account_ids, [user]);
        assert!(!read(&config, &floor).unwrap().revoked_account_ids.contains(&other.into()));
        assert!(read_account_evidence(&config, &floor, owner.wrapping_add(1)).is_none());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read(&config, &floor).is_none(), "valid evidence on a writable parent is untrusted");
        let (_, wrong_key) = sign("tenant", &[user], &SigningKey::from_bytes(&[8;32]));
        write(&wrong_key);
        assert!(read(&config, &floor).is_none());
        let (wrong_scope_pin, wrong_scope) = sign("different-tenant", &[user], &key);
        config.payload_digest = wrong_scope_pin;
        write(&wrong_scope);
        assert!(read(&config, &floor).is_none());
        let (bad_pin, bad) = sign("tenant", &[other,user], &key);
        config.payload_digest = bad_pin;
        write(&bad);
        assert!(read(&config, &floor).is_none());
        config.payload_digest = pin;
        write(&old);
        assert!(read(&config, &floor).is_none(), "old file atomically restored");
        write(&current);
        let advanced_floor = AxonRollbackFloor { minimum_generation: 5, ..floor };
        assert!(read(&config, &advanced_floor).is_none());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(target_os = "linux")]
pub(super) fn open_operator_anchor(path: &Path, owner: u32, limit: u64) -> Option<File> {
    use rustix::fs::{self, FileType, Mode, OFlags};
    let parent = fs::open(
        path.parent()?, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ).ok()?;
    let trusted = fs::fstat(&parent).ok()?;
    if trusted.st_uid != owner || trusted.st_mode & 0o222 != 0 {
        return None;
    }
    let fd = fs::openat(
        &parent, path.file_name()?, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ).ok()?;
    let opened = fs::fstat(&fd).ok()?;
    if opened.st_uid != owner || opened.st_mode & 0o222 != 0
        || opened.st_size <= 0 || opened.st_size as u64 > limit
        || FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || opened.st_dev != trusted.st_dev
    {
        return None;
    }
    // Test-only temp fixtures cannot mount a filesystem. Production requires
    // both descriptors on an authenticated operator's read-only mount.
    #[cfg(not(test))]
    {
        use rustix::fs::StatVfsMountFlags;
        if owner == rustix::process::geteuid().as_raw()
            || !fs::fstatvfs(&parent).ok()?.f_flag.contains(StatVfsMountFlags::RDONLY)
            || !fs::fstatvfs(&fd).ok()?.f_flag.contains(StatVfsMountFlags::RDONLY)
        {
            return None;
        }
    }
    Some(File::from(fd))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open_operator_anchor(_: &Path, _: u32, _: u64) -> Option<File> {
    None
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn atomic_anchor_open_rejects_writable_parent_and_symlink() {
    use std::{fs, os::unix::fs::{PermissionsExt, symlink}};
    let dir = std::env::temp_dir().join(format!("signet-anchor-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let real = dir.join("real");
    let link = dir.join("link");
    fs::write(&real, b"synthetic anchor contents").unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o400)).unwrap();
    symlink(&real, &link).unwrap();
    let owner = rustix::process::geteuid().as_raw();
    assert!(open_operator_anchor(&real, owner, 4096).is_none());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(open_operator_anchor(&link, owner, 4096).is_none());
    assert!(open_operator_anchor(&real, owner.wrapping_add(1), 4096).is_none());
    assert!(open_operator_anchor(&real, owner, 1).is_none());
    assert!(open_operator_anchor(&real, owner, 4096).is_some());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(dir).unwrap();
}
