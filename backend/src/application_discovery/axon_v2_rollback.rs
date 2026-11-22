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
    let file = open_operator_anchor(path, policy.rollback_marker_owner_uid?)?;
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

#[cfg(target_os = "linux")]
fn open_operator_anchor(path: &Path, owner: u32) -> Option<File> {
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
        || opened.st_size <= 0 || opened.st_size > 4096
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
fn open_operator_anchor(_: &Path, _: u32) -> Option<File> {
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
    assert!(open_operator_anchor(&real, owner).is_none());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(open_operator_anchor(&link, owner).is_none());
    assert!(open_operator_anchor(&real, owner.wrapping_add(1)).is_none());
    assert!(open_operator_anchor(&real, owner).is_some());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(dir).unwrap();
}
