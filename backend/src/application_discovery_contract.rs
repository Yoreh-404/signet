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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscoveryRuntimeState {
    NotWebsiteManaged,
    Current,
    OperatorDisabled,
    MissingVerifiedMetadata,
    Expired,
}

pub(crate) fn discovery_runtime_state(
    management_mode: &str,
    operator_disabled: bool,
    last_verified_revision: Option<i64>,
    last_verified_expires_at: Option<i64>,
    snapshot_available: bool,
    now: i64,
) -> DiscoveryRuntimeState {
    use DiscoveryRuntimeState::*;
    if management_mode != MANAGEMENT_MODE_WEBSITE {
        NotWebsiteManaged
    } else if operator_disabled {
        OperatorDisabled
    } else if last_verified_revision.is_none() || !snapshot_available {
        MissingVerifiedMetadata
    } else if last_verified_expires_at.is_some_and(|expires_at| expires_at <= now) {
        Expired
    } else {
        Current
    }
}

pub fn website_discovery_runtime_active(
    management_mode: &str,
    operator_disabled: bool,
    last_verified_revision: Option<i64>,
    last_verified_expires_at: Option<i64>,
    snapshot_available: bool,
    now: i64,
) -> bool {
    discovery_runtime_state(management_mode, operator_disabled, last_verified_revision,
        last_verified_expires_at, snapshot_available, now).runtime_active()
}

impl DiscoveryRuntimeState {
    pub(crate) fn runtime_active(self) -> bool {
        matches!(self, Self::NotWebsiteManaged | Self::Current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_diagnosis_preserves_ordinary_eligibility() {
        let now = 10;
        for mode in [MANAGEMENT_MODE_SIGNET, MANAGEMENT_MODE_WEBSITE] {
            for disabled in [false, true] {
                for revision in [None, Some(1)] {
                    for snapshot in [false, true] {
                        for expiry in [None, Some(9), Some(10), Some(11)] {
                            let expected = mode != MANAGEMENT_MODE_WEBSITE
                                || (!disabled && revision.is_some() && snapshot
                                    && expiry.is_none_or(|expiry| expiry > now));
                            assert_eq!(website_discovery_runtime_active(
                                mode, disabled, revision, expiry, snapshot, now
                            ), expected);
                        }
                    }
                }
            }
        }
        let state = |disabled, revision| discovery_runtime_state(
            MANAGEMENT_MODE_WEBSITE, disabled, revision, Some(now), true, now,
        );
        assert_eq!(state(false, Some(1)), DiscoveryRuntimeState::Expired);
        assert_eq!(state(true, Some(1)), DiscoveryRuntimeState::OperatorDisabled);
        assert_eq!(state(false, None), DiscoveryRuntimeState::MissingVerifiedMetadata);
    }
}
