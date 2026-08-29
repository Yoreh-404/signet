pub const MANAGEMENT_MODE_SIGNET: &str = "signet_managed";
pub const MANAGEMENT_MODE_WEBSITE: &str = "website_managed";
pub const SOURCE_WEBSITE: &str = "website_manifest";
pub const SOURCE_MANUAL: &str = "manual";
pub const SOURCE_MODE_MANUAL: &str = "manual";
pub const SOURCE_MODE_DISCOVERY: &str = "application_discovery";
pub const SYNC_STATUS_MANUAL: &str = "manual";
pub const SYNC_STATUS_SYNCED: &str = "accepted";
pub const SYNC_STATUS_NO_PROFILE: &str = "no_profile";
pub const SYNC_STATUS_ERROR: &str = "unknown";
pub const SYNC_UNCONFIGURED: &str = "unconfigured";
pub const SYNC_PENDING: &str = "pending";
pub const SYNC_ACCEPTED: &str = "accepted";
pub const SYNC_REJECTED: &str = "rejected";
pub const SYNC_UNKNOWN: &str = "unknown";
pub const SYNC_SYNCED: &str = SYNC_ACCEPTED;
pub const SYNC_ERROR: &str = SYNC_UNKNOWN;
pub const SYNC_DISABLED: &str = "disabled";

pub fn website_discovery_runtime_active(
    management_mode: &str,
    operator_disabled: bool,
    last_verified_revision: Option<i64>,
    last_verified_expires_at: Option<i64>,
    snapshot_available: bool,
    now: i64,
) -> bool {
    management_mode != MANAGEMENT_MODE_WEBSITE
        || (!operator_disabled
            && last_verified_revision.is_some()
            && snapshot_available
            && last_verified_expires_at.is_none_or(|expires_at| expires_at > now))
}
