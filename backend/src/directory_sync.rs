//! Application-scoped LDAP/AD directory synchronization.
//!
//! Authentication and synchronization intentionally use different traits. A
//! login only proves one password at one point in time; a synchronization run
//! reconciles a complete directory snapshot with one website's enterprise
//! boundary. Keeping the connector separate from reconciliation makes the
//! state machine testable without a live LDAP server and prevents provider
//! protocol details from leaking into the database layer.

use crate::{
    AppState, applications,
    db::{ApplicationRecord, DirectorySyncRunRecord, LdapProviderRecord},
    error::{AppError, AppResult},
    organizations::OrganizationEmailPolicy,
    util,
};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, adapters::PagedResults};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::time::Duration;

const PAGE_SIZE: i32 = 500;
const MAX_RETRIES: usize = 3;
const DEFAULT_MAX_ENTRIES: usize = 100_000;
const DIRECTORY_SYNC_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct DirectorySyncConfig {
    pub user_filter: String,
    pub group_base_dn: Option<String>,
    pub group_filter: String,
    pub group_id_attribute: String,
    pub group_name_attribute: String,
    pub group_member_attribute: String,
    pub sync_groups: bool,
    pub reactivate_users: bool,
    pub max_entries: usize,
    pub deprovision_action: String,
}

impl DirectorySyncConfig {
    pub fn from_module_config(
        provider: &LdapProviderRecord,
        config: &Map<String, Value>,
    ) -> AppResult<Self> {
        let user_filter = config
            .get("user_sync_filter")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| provider.user_filter.replace("{login}", "*"));
        if user_filter.is_empty() || !user_filter.contains('(') {
            return Err(AppError::BadRequest(
                "LDAP directory sync user_filter is invalid".to_string(),
            ));
        }

        let group_base_dn = config
            .get("group_base_dn")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let max_entries = config
            .get("max_entries")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_MAX_ENTRIES as u64)
            .clamp(1, DEFAULT_MAX_ENTRIES as u64) as usize;
        let deprovision_action = config
            .get("deprovision_action")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("remove_membership")
            .to_string();
        if deprovision_action != "remove_membership" {
            return Err(AppError::BadRequest(
                "directory sync currently supports only remove_membership deprovisioning"
                    .to_string(),
            ));
        }

        Ok(Self {
            user_filter,
            group_base_dn,
            group_filter: config
                .get("group_filter")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("(objectClass=group)")
                .to_string(),
            group_id_attribute: config
                .get("group_id_attribute")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("dn")
                .to_string(),
            group_name_attribute: config
                .get("group_name_attribute")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("cn")
                .to_string(),
            group_member_attribute: config
                .get("group_member_attribute")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("member")
                .to_string(),
            sync_groups: config
                .get("sync_groups")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            reactivate_users: config
                .get("reactivate_users")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            max_entries,
            deprovision_action,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DirectorySyncUser {
    pub subject: String,
    pub dn: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DirectorySyncGroup {
    pub external_id: String,
    pub display_name: String,
    pub member_subjects: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DirectorySnapshot {
    pub users: Vec<DirectorySyncUser>,
    pub groups: Vec<DirectorySyncGroup>,
}

/// Provider adapter used by the reconciliation state machine. Tests and
/// future providers can implement this trait without opening a network
/// connection or changing reconciliation semantics.
#[allow(async_fn_in_trait)]
pub trait DirectorySyncProvider {
    async fn snapshot(
        &self,
        provider: &LdapProviderRecord,
        config: &DirectorySyncConfig,
    ) -> AppResult<DirectorySnapshot>;
}

#[derive(Debug, Clone, Copy)]
pub struct LdapDirectorySyncProvider;

impl DirectorySyncProvider for LdapDirectorySyncProvider {
    async fn snapshot(
        &self,
        provider: &LdapProviderRecord,
        config: &DirectorySyncConfig,
    ) -> AppResult<DirectorySnapshot> {
        let mut settings = LdapConnSettings::new();
        if provider.starttls == 1 {
            settings = settings.set_starttls(true);
        }
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &provider.url)
            .await
            .map_err(ldap_error)?;
        ldap3::drive!(conn);
        if !provider.bind_dn.trim().is_empty() {
            ldap.simple_bind(&provider.bind_dn, &provider.bind_password)
                .await
                .map_err(ldap_error)?
                .success()
                .map_err(ldap_error)?;
        }

        let mut user_attrs = provider_attrs(provider);
        for value in ["dn"] {
            if !user_attrs
                .iter()
                .any(|item| item.eq_ignore_ascii_case(value))
            {
                user_attrs.push(value.to_string());
            }
        }
        let user_entries = search_entries(
            &mut ldap,
            &provider.base_dn,
            &config.user_filter,
            user_attrs,
            config.max_entries,
        )
        .await?;
        let mut users = Vec::with_capacity(user_entries.len());
        let mut subjects = BTreeSet::new();
        for entry in user_entries {
            let user = user_from_entry(provider, entry)?;
            if !subjects.insert(user.subject.clone()) {
                return Err(AppError::BadRequest(
                    "LDAP directory sync returned duplicate user subjects".to_string(),
                ));
            }
            users.push(user);
        }

        let groups = if config.sync_groups {
            if let Some(group_base_dn) = config.group_base_dn.as_deref() {
                let attrs = vec![
                    config.group_id_attribute.clone(),
                    config.group_name_attribute.clone(),
                    config.group_member_attribute.clone(),
                ];
                let entries = search_entries(
                    &mut ldap,
                    group_base_dn,
                    &config.group_filter,
                    attrs,
                    config.max_entries,
                )
                .await?;
                let mut groups = Vec::with_capacity(entries.len());
                let mut group_ids = BTreeSet::new();
                for entry in entries {
                    let external_id =
                        attr_or_dn(&entry, &config.group_id_attribute).ok_or_else(|| {
                            AppError::BadRequest("LDAP group id is missing".to_string())
                        })?;
                    let display_name = attr(&entry, &config.group_name_attribute)
                        .unwrap_or_else(|| external_id.clone());
                    if !group_ids.insert(external_id.clone()) {
                        return Err(AppError::BadRequest(
                            "LDAP directory sync returned duplicate group subjects".to_string(),
                        ));
                    }
                    groups.push(DirectorySyncGroup {
                        external_id,
                        display_name,
                        member_subjects: attr_values(&entry, &config.group_member_attribute),
                    });
                }
                groups
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let _ = ldap.unbind().await;
        Ok(DirectorySnapshot { users, groups })
    }
}

pub async fn run_application_ldap_sync(
    state: &AppState,
    application_id: &str,
    provider_id: &str,
) -> AppResult<DirectorySyncRunRecord> {
    run_application_ldap_sync_with_provider(
        state,
        application_id,
        provider_id,
        &LdapDirectorySyncProvider,
    )
    .await
}

pub async fn run_application_ldap_sync_with_provider<P: DirectorySyncProvider>(
    state: &AppState,
    application_id: &str,
    provider_id: &str,
    connector: &P,
) -> AppResult<DirectorySyncRunRecord> {
    let application = state
        .db
        .find_application_by_id(application_id)
        .await?
        .ok_or(AppError::NotFound)?;
    applications::ensure_application_runtime_active(state, &application).await?;
    let module = applications::enabled_module_config(state, application_id, "directory_sync")
        .await?
        .ok_or_else(|| AppError::BadRequest("enable directory sync first".to_string()))?;
    if module.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Err(AppError::BadRequest(
            "enable directory sync first".to_string(),
        ));
    }
    if !module_provider_ids(&module)
        .iter()
        .any(|id| id == provider_id)
    {
        return Err(AppError::Forbidden);
    }
    let provider = find_provider_by_id(state, provider_id).await?;
    if provider
        .organization_id
        .as_deref()
        .is_some_and(|organization_id| organization_id != application.organization_id)
    {
        return Err(AppError::Forbidden);
    }
    if provider.is_active != 1 {
        return Err(AppError::BadRequest(
            "LDAP provider is disabled".to_string(),
        ));
    }
    let config = DirectorySyncConfig::from_module_config(&provider, &module)?;
    let run = state
        .db
        .start_directory_sync_run(application_id, provider_id)
        .await?;

    let snapshot = match snapshot_with_lease_heartbeat(
        state,
        application_id,
        provider_id,
        &run.id,
        connector,
        &provider,
        &config,
        DIRECTORY_SYNC_HEARTBEAT_INTERVAL,
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let detail = sync_error_detail(&error);
            let _ = finalize_failed_run(state, application_id, provider_id, &run, detail).await;
            return Err(error);
        }
    };

    // The connector may spend a long time paging a large directory.  Renew
    // only after the immutable snapshot is complete; if another worker
    // reclaimed an expired lease while this worker was talking to LDAP, fail
    // closed before publishing any local state.
    if let Err(error) = state
        .db
        .renew_directory_sync_lease(application_id, provider_id, &run.id)
        .await
    {
        let detail = sync_error_detail(&error);
        let _ = finalize_failed_run(state, application_id, provider_id, &run, detail).await;
        return Err(error);
    }

    let result = reconcile_snapshot(state, &application, &provider, &config, &run, snapshot).await;
    match result {
        Ok(stats) => {
            let cursor = Some(util::now_ts().to_string());
            let finalized = state
                .db
                .finalize_directory_sync_run(
                    application_id,
                    provider_id,
                    &run.id,
                    "succeeded",
                    stats.total_seen,
                    stats.created_count,
                    stats.updated_count,
                    stats.disabled_count,
                    None,
                    cursor,
                )
                .await;
            match finalized {
                Ok(run) => Ok(run),
                Err(error) => {
                    let detail = sync_error_detail(&error);
                    let _ =
                        finalize_failed_run(state, application_id, provider_id, &run, detail).await;
                    Err(error)
                }
            }
        }
        Err(error) => {
            let detail = sync_error_detail(&error);
            let _ = finalize_failed_run(state, application_id, provider_id, &run, detail).await;
            Err(error)
        }
    }
}

pub async fn list_application_ldap_sync_runs(
    state: &AppState,
    application_id: &str,
) -> AppResult<Vec<DirectorySyncRunRecord>> {
    state.db.list_directory_sync_runs(application_id, 20).await
}

fn module_provider_ids(config: &Map<String, Value>) -> Vec<String> {
    config
        .get("ldap_provider_ids")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

async fn find_provider_by_id(state: &AppState, provider_id: &str) -> AppResult<LdapProviderRecord> {
    state
        .db
        .find_ldap_provider_by_id(provider_id)
        .await?
        .ok_or(AppError::NotFound)
}

async fn snapshot_with_retries<P: DirectorySyncProvider>(
    connector: &P,
    provider: &LdapProviderRecord,
    config: &DirectorySyncConfig,
) -> AppResult<DirectorySnapshot> {
    let mut attempt = 0;
    loop {
        match connector.snapshot(provider, config).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => {
                attempt += 1;
                if attempt >= MAX_RETRIES {
                    return Err(error);
                }
                tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
            }
        }
    }
}

/// Runs the provider snapshot while the current run's lease is renewed.
///
/// The heartbeat is deliberately kept as a future in this task instead of a
/// detached spawned task.  `tokio::select!` drops the heartbeat immediately
/// when the snapshot finishes or fails, so there is no task to leak when a
/// request is cancelled.  If a renewal fails, the provider future is dropped
/// and no snapshot can reach reconciliation.
async fn snapshot_with_lease_heartbeat<P: DirectorySyncProvider>(
    state: &AppState,
    application_id: &str,
    provider_id: &str,
    run_id: &str,
    connector: &P,
    provider: &LdapProviderRecord,
    config: &DirectorySyncConfig,
    heartbeat_interval: Duration,
) -> AppResult<DirectorySnapshot> {
    let snapshot = snapshot_with_retries(connector, provider, config);
    let heartbeat = renew_lease_until_failure(
        state.db.clone(),
        application_id.to_string(),
        provider_id.to_string(),
        run_id.to_string(),
        heartbeat_interval,
    );
    tokio::pin!(snapshot);
    tokio::pin!(heartbeat);

    tokio::select! {
        biased;
        heartbeat = &mut heartbeat => match heartbeat {
            Ok(()) => Err(AppError::Internal(
                "directory synchronization lease heartbeat stopped unexpectedly".to_string(),
            )),
            Err(error) => Err(error),
        },
        snapshot = &mut snapshot => snapshot,
    }
}

async fn renew_lease_until_failure(
    db: crate::db::Db,
    application_id: String,
    provider_id: String,
    run_id: String,
    heartbeat_interval: Duration,
) -> AppResult<()> {
    loop {
        tokio::time::sleep(heartbeat_interval).await;
        db.renew_directory_sync_lease(&application_id, &provider_id, &run_id)
            .await?;
    }
}

#[derive(Debug, Default)]
struct SyncStats {
    total_seen: i64,
    created_count: i64,
    updated_count: i64,
    disabled_count: i64,
}

async fn reconcile_snapshot(
    state: &AppState,
    application: &ApplicationRecord,
    provider: &LdapProviderRecord,
    config: &DirectorySyncConfig,
    run: &DirectorySyncRunRecord,
    snapshot: DirectorySnapshot,
) -> AppResult<SyncStats> {
    let organization = state
        .db
        .find_organization_by_id(&application.organization_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let DirectorySnapshot { users, groups } = snapshot;

    // Validate the complete provider snapshot before mutating any account or
    // group.  A connector normally performs these checks too, but keeping the
    // invariant at the reconciliation boundary prevents a custom connector,
    // a future provider, or a partially malformed response from producing a
    // half-applied sync run.
    let mut snapshot_subjects = BTreeSet::new();
    for directory_user in &users {
        let email = crate::security_policy::normalize_login_subject(&directory_user.email);
        if directory_user.subject.trim().is_empty() || directory_user.dn.trim().is_empty() {
            return Err(AppError::BadRequest(
                "directory sync user subject and dn are required".to_string(),
            ));
        }
        if !organization.allows_email(&email)? {
            return Err(AppError::Forbidden);
        }
        if !snapshot_subjects.insert(directory_user.subject.clone()) {
            return Err(AppError::BadRequest(
                "directory sync contains duplicate user subjects".to_string(),
            ));
        }
    }
    let mut snapshot_group_ids = BTreeSet::new();
    for directory_group in &groups {
        if directory_group.external_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "directory sync group external id is required".to_string(),
            ));
        }
        if !snapshot_group_ids.insert(directory_group.external_id.clone()) {
            return Err(AppError::BadRequest(
                "directory sync contains duplicate group subjects".to_string(),
            ));
        }
    }

    let plan = crate::db::DirectorySyncSnapshotPlan {
        users: users
            .iter()
            .map(|directory_user| {
                Ok(crate::db::DirectorySyncUserPlan {
                    subject: directory_user.subject.clone(),
                    dn: directory_user.dn.clone(),
                    email: crate::security_policy::normalize_login_subject(&directory_user.email),
                    username: directory_username(&directory_user.username, &directory_user.subject),
                    display_name: directory_user.display_name.clone(),
                    phone: directory_user.phone.clone(),
                    password_hash: None,
                })
            })
            .collect::<AppResult<Vec<_>>>()?,
        groups: config
            .sync_groups
            .then(|| {
                groups
                    .iter()
                    .map(|directory_group| crate::db::DirectorySyncGroupPlan {
                        external_id: directory_group.external_id.clone(),
                        display_name: directory_group.display_name.clone(),
                        member_subjects: directory_group.member_subjects.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    let applied = state
        .db
        .apply_directory_sync_snapshot(
            crate::db::DirectorySyncApplyContext {
                application_id: application.id.clone(),
                provider_id: provider.id.clone(),
                run_id: run.id.clone(),
                provider_key: provider.provider_key(),
                organization_id: application.organization_id.clone(),
                provider_display_name: provider.display_name.clone(),
                reactivate_users: config.reactivate_users,
                expected_application_updated_at: Some(application.updated_at),
                expected_provider_updated_at: Some(provider.updated_at),
                expected_organization_updated_at: Some(organization.updated_at),
            },
            plan,
        )
        .await?;
    Ok(SyncStats {
        total_seen: applied.total_seen,
        created_count: applied.created_count,
        updated_count: applied.updated_count,
        disabled_count: applied.disabled_count,
    })
}

async fn finalize_failed_run(
    state: &AppState,
    application_id: &str,
    provider_id: &str,
    run: &DirectorySyncRunRecord,
    detail: String,
) -> AppResult<DirectorySyncRunRecord> {
    state
        .db
        .finalize_directory_sync_run(
            application_id,
            provider_id,
            &run.id,
            "failed",
            0,
            0,
            0,
            0,
            Some(detail),
            None,
        )
        .await
}

fn sync_error_detail(error: &AppError) -> String {
    match error {
        AppError::Database(_) | AppError::Internal(_) => {
            "directory provider operation failed".to_string()
        }
        other => other.to_string(),
    }
}

async fn search_entries(
    ldap: &mut ldap3::Ldap,
    base: &str,
    filter: &str,
    attrs: Vec<String>,
    max_entries: usize,
) -> AppResult<Vec<SearchEntry>> {
    let mut stream = ldap
        .streaming_search_with(
            PagedResults::new(PAGE_SIZE),
            base,
            Scope::Subtree,
            filter,
            attrs,
        )
        .await
        .map_err(ldap_error)?;
    let mut entries = Vec::new();
    while let Some(entry) = stream.next().await.map_err(ldap_error)? {
        entries.push(SearchEntry::construct(entry));
        if entries.len() > max_entries {
            return Err(AppError::BadRequest(
                "LDAP directory sync result exceeds max_entries".to_string(),
            ));
        }
    }
    stream.finish().await.success().map_err(ldap_error)?;
    Ok(entries)
}

fn user_from_entry(
    provider: &LdapProviderRecord,
    entry: SearchEntry,
) -> AppResult<DirectorySyncUser> {
    let dn = entry.dn.clone();
    let subject = attr_or_dn(&entry, &provider.user_id_attribute).ok_or(AppError::Unauthorized)?;
    let email = attr(&entry, &provider.email_attribute).ok_or(AppError::Unauthorized)?;
    let username = attr(&entry, &provider.username_attribute)
        .or_else(|| email.split('@').next().map(ToOwned::to_owned))
        .unwrap_or_else(|| "directory-user".to_string());
    Ok(DirectorySyncUser {
        subject,
        dn,
        email,
        username,
        display_name: attr(&entry, &provider.display_name_attribute),
        phone: attr(&entry, &provider.phone_attribute),
    })
}

fn provider_attrs(provider: &LdapProviderRecord) -> Vec<String> {
    let mut attrs = BTreeSet::new();
    for attr in [
        provider.user_id_attribute.as_str(),
        provider.email_attribute.as_str(),
        provider.username_attribute.as_str(),
        provider.display_name_attribute.as_str(),
        provider.phone_attribute.as_str(),
    ] {
        let attr = attr.trim();
        if !attr.is_empty() && !attr.eq_ignore_ascii_case("dn") {
            attrs.insert(attr.to_string());
        }
    }
    attrs.into_iter().collect()
}

fn attr_or_dn(entry: &SearchEntry, name: &str) -> Option<String> {
    if name.trim().eq_ignore_ascii_case("dn") {
        Some(entry.dn.clone())
    } else {
        attr(entry, name)
    }
}

fn attr(entry: &SearchEntry, name: &str) -> Option<String> {
    attr_values(entry, name).into_iter().next()
}

fn attr_values(entry: &SearchEntry, name: &str) -> Vec<String> {
    let name = name.trim();
    if name.is_empty() {
        return Vec::new();
    }
    entry
        .attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, values)| {
            values
                .iter()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn directory_username(username: &str, subject: &str) -> String {
    let base = username
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect::<String>();
    let base = if base.is_empty() {
        "directory-user".to_string()
    } else {
        base
    };
    format!(
        "{}-{}",
        base,
        util::sha256_base64url(subject)
            .chars()
            .take(8)
            .collect::<String>()
    )
}

fn ldap_error(error: ldap3::LdapError) -> AppError {
    AppError::Internal(format!("LDAP operation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "sqlite")]
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    #[cfg(feature = "sqlite")]
    use tokio::sync::Notify;

    #[test]
    fn directory_usernames_are_stable_and_safe() {
        assert_eq!(
            directory_username("Alice Smith", "uid=alice,dc=example"),
            directory_username("Alice Smith", "uid=alice,dc=example")
        );
        assert!(!directory_username("Alice Smith", "uid=alice,dc=example").contains(' '));
    }

    #[test]
    fn sync_config_uses_provider_login_filter_as_safe_default() {
        let provider = LdapProviderRecord {
            id: "id".to_string(),
            slug: "corp".to_string(),
            display_name: "Corp".to_string(),
            organization_id: None,
            url: "ldap://ldap.example".to_string(),
            starttls: 0,
            bind_dn: String::new(),
            bind_password: String::new(),
            base_dn: "dc=example".to_string(),
            user_filter: "(&(objectClass=person)(uid={login}))".to_string(),
            user_id_attribute: "dn".to_string(),
            email_attribute: "mail".to_string(),
            username_attribute: "uid".to_string(),
            display_name_attribute: "cn".to_string(),
            phone_attribute: String::new(),
            is_active: 1,
            allow_login: 1,
            allow_registration: 1,
            created_at: 0,
            updated_at: 0,
        };
        let config = DirectorySyncConfig::from_module_config(&provider, &Map::new()).unwrap();
        assert_eq!(config.user_filter, "(&(objectClass=person)(uid=*))");
        assert!(config.sync_groups);
    }

    #[cfg(feature = "sqlite")]
    #[derive(Clone)]
    struct FakeDirectorySyncProvider {
        failures_before_success: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
        snapshot: DirectorySnapshot,
    }

    #[cfg(feature = "sqlite")]
    impl DirectorySyncProvider for FakeDirectorySyncProvider {
        async fn snapshot(
            &self,
            _provider: &LdapProviderRecord,
            _config: &DirectorySyncConfig,
        ) -> AppResult<DirectorySnapshot> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let failures = self.failures_before_success.load(Ordering::SeqCst);
            if failures > 0 {
                self.failures_before_success.fetch_sub(1, Ordering::SeqCst);
                return Err(AppError::Internal("temporary directory outage".to_string()));
            }
            Ok(self.snapshot.clone())
        }
    }

    #[cfg(feature = "sqlite")]
    #[derive(Clone)]
    struct BlockingDirectorySyncProvider {
        started: Arc<Notify>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    #[cfg(feature = "sqlite")]
    struct SnapshotDropMarker(Arc<std::sync::atomic::AtomicBool>);

    #[cfg(feature = "sqlite")]
    impl Drop for SnapshotDropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[cfg(feature = "sqlite")]
    impl DirectorySyncProvider for BlockingDirectorySyncProvider {
        async fn snapshot(
            &self,
            _provider: &LdapProviderRecord,
            _config: &DirectorySyncConfig,
        ) -> AppResult<DirectorySnapshot> {
            let _marker = SnapshotDropMarker(self.dropped.clone());
            self.started.notify_one();
            std::future::pending::<AppResult<DirectorySnapshot>>().await
        }
    }

    #[cfg(feature = "sqlite")]
    async fn directory_sync_test_state() -> (AppState, std::path::PathBuf) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-directory-sync-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.pool_size = 2;
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        (AppState { settings, db, jwt }, path)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn snapshot_heartbeat_fails_closed_and_cancels_provider() {
        let (state, path) = directory_sync_test_state().await;
        let run = state
            .db
            .start_directory_sync_run("heartbeat-app", "heartbeat-provider")
            .await
            .unwrap();
        let provider = LdapProviderRecord {
            id: "heartbeat-provider".to_string(),
            slug: "heartbeat-provider".to_string(),
            display_name: "Heartbeat Provider".to_string(),
            organization_id: Some("heartbeat-org".to_string()),
            url: "ldap://directory.example.test".to_string(),
            starttls: 0,
            bind_dn: String::new(),
            bind_password: String::new(),
            base_dn: "dc=example,dc=test".to_string(),
            user_filter: "(objectClass=person)".to_string(),
            user_id_attribute: "uid".to_string(),
            email_attribute: "mail".to_string(),
            username_attribute: "uid".to_string(),
            display_name_attribute: "cn".to_string(),
            phone_attribute: String::new(),
            is_active: 1,
            allow_login: 1,
            allow_registration: 1,
            created_at: 0,
            updated_at: 0,
        };
        let config = DirectorySyncConfig {
            user_filter: "(objectClass=person)".to_string(),
            group_base_dn: None,
            group_filter: "(objectClass=group)".to_string(),
            group_id_attribute: "dn".to_string(),
            group_name_attribute: "cn".to_string(),
            group_member_attribute: "member".to_string(),
            sync_groups: false,
            reactivate_users: true,
            max_entries: 10,
            deprovision_action: "remove_membership".to_string(),
        };
        let fake = BlockingDirectorySyncProvider {
            started: Arc::new(Notify::new()),
            dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let started = fake.started.clone();
        let dropped = fake.dropped.clone();
        let result = {
            let snapshot = snapshot_with_lease_heartbeat(
                &state,
                "heartbeat-app",
                "heartbeat-provider",
                &run.id,
                &fake,
                &provider,
                &config,
                Duration::from_millis(5),
            );
            tokio::pin!(snapshot);
            let started_wait = started.notified();
            tokio::pin!(started_wait);
            tokio::select! {
                _ = &mut started_wait => {}
                result = &mut snapshot => panic!("snapshot completed before the lease was revoked: {result:?}"),
            }
            state
                .db
                .finish_directory_sync_run(&run.id, "failed", 0, 0, 0, 0, None, None)
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), &mut snapshot)
                .await
                .expect("lease heartbeat should fail promptly")
                .unwrap_err()
        };
        assert!(matches!(result, AppError::BadRequest(message) if message.contains("lease")));
        assert!(dropped.load(Ordering::SeqCst));

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    fn sync_application(organization_id: &str, slug: &str) -> crate::db::NewApplication {
        crate::db::NewApplication {
            organization_id: organization_id.to_string(),
            slug: slug.to_string(),
            name: format!("{slug} website"),
            description: None,
            access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn sync_provider(organization_id: &str) -> crate::db::NewLdapProvider {
        crate::db::NewLdapProvider {
            slug: "integration-directory".to_string(),
            display_name: "Integration Directory".to_string(),
            organization_id: Some(organization_id.to_string()),
            url: "ldaps://directory.example.test".to_string(),
            starttls: false,
            bind_dn: "cn=reader,dc=example,dc=test".to_string(),
            bind_password: Some("secret".to_string()),
            base_dn: "dc=example,dc=test".to_string(),
            user_filter: "(&(objectClass=person)(uid={login}))".to_string(),
            user_id_attribute: "uid".to_string(),
            email_attribute: "mail".to_string(),
            username_attribute: "uid".to_string(),
            display_name_attribute: "cn".to_string(),
            phone_attribute: "telephoneNumber".to_string(),
            is_active: true,
            allow_login: true,
            allow_registration: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn application_update(
        application: &ApplicationRecord,
        is_active: bool,
    ) -> crate::db::NewApplication {
        crate::db::NewApplication {
            organization_id: application.organization_id.clone(),
            slug: application.slug.clone(),
            name: application.name.clone(),
            description: application.description.clone(),
            access_mode: application.access_mode.clone(),
            registration_mode: application.registration_mode.clone(),
            account_selection_mode: application.account_selection_mode.clone(),
            unique_identity_factors: application.unique_identity_factors().unwrap(),
            is_active,
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn directory_sync_retries_reconciles_idempotently_and_respects_boundaries() {
        let (state, path) = directory_sync_test_state().await;
        let organization = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "sync-integration".to_string(),
                name: "Sync Integration".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.test".to_string()],
                is_active: true,
            })
            .await
            .unwrap();
        let application = state
            .db
            .insert_application(sync_application(&organization.id, "sync-primary"))
            .await
            .unwrap();
        let no_groups_application = state
            .db
            .insert_application(sync_application(&organization.id, "sync-no-groups"))
            .await
            .unwrap();
        let foreign_organization = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "sync-foreign".to_string(),
                name: "Sync Foreign".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let foreign_application = state
            .db
            .insert_application(sync_application(
                &foreign_organization.id,
                "sync-foreign-website",
            ))
            .await
            .unwrap();
        let provider = state
            .db
            .insert_ldap_provider(sync_provider(&organization.id))
            .await
            .unwrap();

        let primary_config = serde_json::json!({
            "enabled": true,
            "ldap_provider_ids": [provider.id],
            "sync_groups": true,
            "reactivate_users": true,
            "group_base_dn": "ou=groups,dc=example,dc=test",
            "group_filter": "",
            "group_id_attribute": "dn",
            "group_name_attribute": "cn",
            "group_member_attribute": "member"
        });
        state
            .db
            .upsert_application_module(
                &application.id,
                "directory_sync",
                &primary_config.to_string(),
                true,
            )
            .await
            .unwrap();
        let no_groups_config = serde_json::json!({
            "enabled": true,
            "ldap_provider_ids": [provider.id],
            "sync_groups": false,
            "reactivate_users": true,
            "group_base_dn": "ou=groups,dc=example,dc=test",
            "group_filter": "",
            "group_id_attribute": "dn",
            "group_name_attribute": "cn",
            "group_member_attribute": "member"
        });
        state
            .db
            .upsert_application_module(
                &no_groups_application.id,
                "directory_sync",
                &no_groups_config.to_string(),
                true,
            )
            .await
            .unwrap();
        let foreign_config = serde_json::json!({
            "enabled": true,
            "ldap_provider_ids": [provider.id]
        });
        state
            .db
            .upsert_application_module(
                &foreign_application.id,
                "directory_sync",
                &foreign_config.to_string(),
                true,
            )
            .await
            .unwrap();

        let subject = "uid=alice,dc=example,dc=test".to_string();
        let fake = FakeDirectorySyncProvider {
            failures_before_success: Arc::new(AtomicUsize::new(2)),
            calls: Arc::new(AtomicUsize::new(0)),
            snapshot: DirectorySnapshot {
                users: vec![DirectorySyncUser {
                    subject: subject.clone(),
                    dn: subject.clone(),
                    email: "alice@example.test".to_string(),
                    username: "alice".to_string(),
                    display_name: Some("Alice".to_string()),
                    phone: None,
                }],
                groups: vec![DirectorySyncGroup {
                    external_id: "group-operators".to_string(),
                    display_name: "Operators".to_string(),
                    member_subjects: vec![subject.clone()],
                }],
            },
        };

        let first_run =
            run_application_ldap_sync_with_provider(&state, &application.id, &provider.id, &fake)
                .await
                .unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
        assert_eq!(first_run.status, "succeeded");
        assert_eq!(first_run.total_seen, 1);
        assert_eq!(first_run.created_count, 1);
        assert_eq!(first_run.updated_count, 0);
        let checkpoint = state
            .db
            .find_directory_sync_checkpoint(&application.id, &provider.id)
            .await
            .unwrap()
            .unwrap();
        assert!(checkpoint.cursor.is_some());
        assert_eq!(checkpoint.consecutive_failures, 0);

        let user = state
            .db
            .find_user_by_email("alice@example.test")
            .await
            .unwrap()
            .unwrap();
        assert!(
            state
                .db
                .user_belongs_to_organization(&organization.id, &user.id)
                .await
                .unwrap()
        );
        assert_eq!(
            state
                .db
                .list_directory_sync_memberships(&application.id, &provider.id)
                .await
                .unwrap()
                .len(),
            1
        );
        let groups = state
            .db
            .list_application_scim_groups(&application.id)
            .await
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            state
                .db
                .list_application_scim_group_members(&application.id, &groups[0].id)
                .await
                .unwrap()
                .len(),
            1
        );

        // A hand-managed enterprise role is never downgraded by a later
        // directory snapshot, and the same snapshot is idempotent.
        state
            .db
            .upsert_organization_member(
                &organization.id,
                &user.id,
                crate::organizations::ROLE_ADMIN,
            )
            .await
            .unwrap();
        let second_run =
            run_application_ldap_sync_with_provider(&state, &application.id, &provider.id, &fake)
                .await
                .unwrap();
        assert_eq!(second_run.created_count, 0);
        assert_eq!(second_run.updated_count, 1);
        assert_eq!(
            state
                .db
                .list_organization_members(&organization.id)
                .await
                .unwrap()
                .into_iter()
                .find(|member| member.user_id == user.id)
                .unwrap()
                .role,
            crate::organizations::ROLE_ADMIN
        );
        assert_eq!(
            state
                .db
                .list_application_scim_groups(&application.id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            state
                .db
                .list_directory_sync_runs(&application.id, 20)
                .await
                .unwrap()
                .len(),
            2
        );

        let no_groups_run = run_application_ldap_sync_with_provider(
            &state,
            &no_groups_application.id,
            &provider.id,
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(no_groups_run.status, "succeeded");
        assert!(
            state
                .db
                .list_application_scim_groups(&no_groups_application.id)
                .await
                .unwrap()
                .is_empty()
        );

        // A directly persisted stale module cannot bypass the runtime
        // organization check; the connector must not even be called.
        let calls_before_foreign = fake.calls.load(Ordering::SeqCst);
        assert!(matches!(
            run_application_ldap_sync_with_provider(
                &state,
                &foreign_application.id,
                &provider.id,
                &fake,
            )
            .await,
            Err(AppError::Forbidden)
        ));
        assert_eq!(fake.calls.load(Ordering::SeqCst), calls_before_foreign);
        assert!(
            state
                .db
                .list_directory_sync_runs(&foreign_application.id, 20)
                .await
                .unwrap()
                .is_empty()
        );

        // A failed provider run keeps the last successful cursor and records
        // the failure.  A later successful run clears the failure counter and
        // advances the checkpoint instead of starting from an unknown state.
        let successful_cursor = state
            .db
            .find_directory_sync_checkpoint(&application.id, &provider.id)
            .await
            .unwrap()
            .unwrap()
            .cursor;
        fake.failures_before_success.store(3, Ordering::SeqCst);
        assert!(matches!(
            run_application_ldap_sync_with_provider(&state, &application.id, &provider.id, &fake,)
                .await,
            Err(AppError::Internal(_))
        ));
        let failed_checkpoint = state
            .db
            .find_directory_sync_checkpoint(&application.id, &provider.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed_checkpoint.cursor, successful_cursor);
        assert_eq!(failed_checkpoint.consecutive_failures, 1);
        assert_eq!(
            state
                .db
                .list_directory_sync_runs(&application.id, 20)
                .await
                .unwrap()
                .first()
                .unwrap()
                .status,
            "failed"
        );

        fake.failures_before_success.store(0, Ordering::SeqCst);
        let recovered =
            run_application_ldap_sync_with_provider(&state, &application.id, &provider.id, &fake)
                .await
                .unwrap();
        assert_eq!(recovered.status, "succeeded");
        assert_eq!(
            state
                .db
                .find_directory_sync_checkpoint(&application.id, &provider.id)
                .await
                .unwrap()
                .unwrap()
                .consecutive_failures,
            0
        );

        // Inactive application, enterprise, and provider boundaries reject a
        // sync before opening the connector and therefore cannot create a
        // misleading successful run.
        let calls_before_inactive_app = fake.calls.load(Ordering::SeqCst);
        state
            .db
            .update_application(
                &no_groups_application.id,
                application_update(&no_groups_application, false),
            )
            .await
            .unwrap();
        assert!(matches!(
            run_application_ldap_sync_with_provider(
                &state,
                &no_groups_application.id,
                &provider.id,
                &fake,
            )
            .await,
            Err(AppError::Forbidden)
        ));
        assert_eq!(fake.calls.load(Ordering::SeqCst), calls_before_inactive_app);
        state
            .db
            .update_application(
                &no_groups_application.id,
                application_update(&no_groups_application, true),
            )
            .await
            .unwrap();

        let calls_before_inactive_org = fake.calls.load(Ordering::SeqCst);
        state
            .db
            .update_organization(
                &organization.id,
                crate::db::NewOrganization {
                    slug: "sync-integration".to_string(),
                    name: "Sync Integration".to_string(),
                    kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                    description: None,
                    allowed_email_domains: vec!["example.test".to_string()],
                    is_active: false,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            run_application_ldap_sync_with_provider(&state, &application.id, &provider.id, &fake,)
                .await,
            Err(AppError::Forbidden)
        ));
        assert_eq!(fake.calls.load(Ordering::SeqCst), calls_before_inactive_org);
        state
            .db
            .update_organization(
                &organization.id,
                crate::db::NewOrganization {
                    slug: "sync-integration".to_string(),
                    name: "Sync Integration".to_string(),
                    kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                    description: None,
                    allowed_email_domains: vec!["example.test".to_string()],
                    is_active: true,
                },
            )
            .await
            .unwrap();

        let calls_before_inactive_provider = fake.calls.load(Ordering::SeqCst);
        let mut inactive_provider = sync_provider(&organization.id);
        inactive_provider.is_active = false;
        state
            .db
            .update_ldap_provider(&provider.id, inactive_provider)
            .await
            .unwrap();
        assert!(matches!(
            run_application_ldap_sync_with_provider(&state, &application.id, &provider.id, &fake,)
                .await,
            Err(AppError::BadRequest(_))
        ));
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            calls_before_inactive_provider
        );

        // Duplicate subjects are rejected during the preflight phase, before
        // the first duplicate row can create an account or membership.
        let duplicate_subject = "uid=duplicate,dc=example,dc=test".to_string();
        let duplicate_fake = FakeDirectorySyncProvider {
            failures_before_success: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(AtomicUsize::new(0)),
            snapshot: DirectorySnapshot {
                users: vec![
                    DirectorySyncUser {
                        subject: duplicate_subject.clone(),
                        dn: duplicate_subject.clone(),
                        email: "duplicate-one@example.test".to_string(),
                        username: "duplicate-one".to_string(),
                        display_name: None,
                        phone: None,
                    },
                    DirectorySyncUser {
                        subject: duplicate_subject,
                        dn: "uid=duplicate-second,dc=example,dc=test".to_string(),
                        email: "duplicate-two@example.test".to_string(),
                        username: "duplicate-two".to_string(),
                        display_name: None,
                        phone: None,
                    },
                ],
                groups: Vec::new(),
            },
        };
        // Restore the provider so this assertion reaches reconciliation.
        let mut active_provider = sync_provider(&organization.id);
        active_provider.is_active = true;
        state
            .db
            .update_ldap_provider(&provider.id, active_provider)
            .await
            .unwrap();
        assert!(matches!(
            run_application_ldap_sync_with_provider(
                &state,
                &application.id,
                &provider.id,
                &duplicate_fake,
            )
            .await,
            Err(AppError::BadRequest(_))
        ));
        assert_eq!(duplicate_fake.calls.load(Ordering::SeqCst), 1);
        assert!(
            state
                .db
                .find_user_by_email("duplicate-one@example.test")
                .await
                .unwrap()
                .is_none()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
