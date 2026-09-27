use crate::{
    Settings,
    db::{Db, RuntimeSettingsRecord},
    error::{AppError, AppResult},
    iap::{IapCachedAuthorization, IapRoutingIndex},
    jwt::{JwtManager, TokenClaims},
    util,
};
use axum::http::HeaderMap;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
struct TimedValue<T> {
    value: T,
    loaded_at: Instant,
}

impl<T> TimedValue<T> {
    fn is_fresh(&self, ttl: Duration) -> bool {
        ttl > Duration::ZERO && self.loaded_at.elapsed() < ttl
    }
}

pub(crate) type IapRoutingSnapshot = (Arc<IapRoutingIndex>, u64);

struct SequencedTimedValue<T> {
    value: T,
    loaded_at: Instant,
    generation: u64,
}

/// Bounded cache with amortized O(1) insertion and eviction.
///
/// Each store appends a generation-tagged key to `order`. Updating an existing
/// key therefore leaves an old queue item behind, but eviction simply skips
/// queue items whose generation is no longer current. The stale queue is
/// compacted only after it grows well beyond the live cache size. This keeps
/// the common high-churn ForwardAuth path O(1) without adding a dependency or
/// turning cache reads into LRU writes.
struct BoundedTimedCache<T> {
    entries: HashMap<String, SequencedTimedValue<T>>,
    order: VecDeque<(String, u64)>,
    next_generation: u64,
}

impl<T> Default for BoundedTimedCache<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            next_generation: 0,
        }
    }
}

impl<T: Clone> BoundedTimedCache<T> {
    fn fresh(&self, key: &str, ttl: Duration) -> Option<T> {
        self.entries
            .get(key)
            .filter(|entry| ttl > Duration::ZERO && entry.loaded_at.elapsed() < ttl)
            .map(|entry| entry.value.clone())
    }

    fn value(&self, key: &str) -> Option<T> {
        self.entries.get(key).map(|entry| entry.value.clone())
    }

    fn younger_than(&self, key: &str, max_age: Duration) -> Option<T> {
        self.entries
            .get(key)
            .filter(|entry| entry.loaded_at.elapsed() < max_age)
            .map(|entry| entry.value.clone())
    }

    fn store(&mut self, key: String, value: T, max_entries: usize) {
        self.next_generation = self.next_generation.wrapping_add(1);
        if self.next_generation == 0 {
            self.next_generation = 1;
        }
        let generation = self.next_generation;
        self.entries.insert(
            key.clone(),
            SequencedTimedValue {
                value,
                loaded_at: Instant::now(),
                generation,
            },
        );
        self.order.push_back((key, generation));

        while self.entries.len() > max_entries {
            let Some((candidate, queued_generation)) = self.order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&candidate)
                .is_some_and(|entry| entry.generation == queued_generation)
            {
                self.entries.remove(&candidate);
            }
        }

        let compact_threshold = max_entries.saturating_mul(4).max(64);
        if self.order.len() > compact_threshold {
            let mut live = self
                .entries
                .iter()
                .map(|(key, entry)| (entry.loaded_at, key.clone(), entry.generation))
                .collect::<Vec<_>>();
            live.sort_unstable_by_key(|(loaded_at, _, _)| *loaded_at);
            self.order = live
                .into_iter()
                .map(|(_, key, generation)| (key, generation))
                .collect();
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CachedHttpDocument {
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub fresh_until: Instant,
    pub stale_until: Instant,
    pub cacheable: bool,
    pub(crate) stored_at: Instant,
}

#[derive(Default)]
struct RuntimeCaches {
    runtime_settings: RwLock<Option<TimedValue<RuntimeSettingsRecord>>>,
    runtime_settings_refresh: Mutex<()>,
    iap_generation: AtomicU64,
    iap_routing: RwLock<Option<TimedValue<IapRoutingSnapshot>>>,
    iap_applications_refresh: Mutex<()>,
    iap_bearer_claims: RwLock<BoundedTimedCache<TokenClaims>>,
    iap_bearer_claims_refresh: RwLock<HashMap<String, Weak<Mutex<()>>>>,
    iap_authorizations: RwLock<BoundedTimedCache<IapCachedAuthorization>>,
    iap_authorization_refresh: RwLock<HashMap<String, Weak<Mutex<()>>>>,
    oidc_authorization_details_types: RwLock<Option<TimedValue<Vec<String>>>>,
    oidc_metadata_refresh: Mutex<()>,
    client_jwks: RwLock<HashMap<String, CachedHttpDocument>>,
    client_jwks_refresh: RwLock<HashMap<String, Weak<Mutex<()>>>>,
}

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
    pub db: Db,
    pub jwt: JwtManager,
    caches: Arc<RuntimeCaches>,
}

impl AppState {
    pub fn new(settings: Settings, db: Db, jwt: JwtManager) -> Self {
        Self {
            settings,
            db,
            jwt,
            caches: Arc::new(RuntimeCaches::default()),
        }
    }

    pub async fn runtime_settings(&self) -> AppResult<RuntimeSettingsRecord> {
        let ttl = Duration::from_millis(self.settings.performance.runtime_settings_cache_millis);
        if let Some(value) = self.cached_runtime_settings(ttl)? {
            return Ok(value);
        }
        if ttl == Duration::ZERO {
            return self.db.runtime_settings().await;
        }
        let _refresh = self.caches.runtime_settings_refresh.lock().await;
        if let Some(value) = self.cached_runtime_settings(ttl)? {
            return Ok(value);
        }
        let value = self.db.runtime_settings().await?;
        *self.caches.runtime_settings.write().map_err(|_| {
            AppError::Internal("runtime settings cache lock poisoned".to_string())
        })? = Some(TimedValue {
            value: value.clone(),
            loaded_at: Instant::now(),
        });
        Ok(value)
    }

    fn cached_runtime_settings(&self, ttl: Duration) -> AppResult<Option<RuntimeSettingsRecord>> {
        let guard =
            self.caches.runtime_settings.read().map_err(|_| {
                AppError::Internal("runtime settings cache lock poisoned".to_string())
            })?;
        Ok(guard
            .as_ref()
            .filter(|entry| entry.is_fresh(ttl))
            .map(|entry| entry.value.clone()))
    }

    pub fn invalidate_runtime_settings_cache(&self) {
        if let Ok(mut guard) = self.caches.runtime_settings.write() {
            *guard = None;
        }
        self.invalidate_iap_authorization_cache();
    }

    pub(crate) async fn iap_routing_snapshot(&self) -> AppResult<IapRoutingSnapshot> {
        let ttl = Duration::from_millis(self.settings.performance.iap_routing_cache_millis);
        if let Some(value) = self.cached_iap_routing_snapshot(ttl)? {
            return Ok(value);
        }
        if ttl == Duration::ZERO {
            let generation = self.caches.iap_generation.load(Ordering::Acquire);
            let rules = self.db.list_active_iap_applications().await?;
            return Ok((Arc::new(IapRoutingIndex::new(rules)), generation));
        }
        let _refresh = match self.caches.iap_applications_refresh.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                if let Some(value) = self.cached_iap_routing_snapshot_stale_while_refresh(ttl)? {
                    return Ok(value);
                }
                self.caches.iap_applications_refresh.lock().await
            }
        };
        if let Some(value) = self.cached_iap_routing_snapshot(ttl)? {
            return Ok(value);
        }
        let generation = self.caches.iap_generation.load(Ordering::Acquire);
        let value = Arc::new(IapRoutingIndex::new(
            self.db.list_active_iap_applications().await?,
        ));
        let snapshot = (value, generation);
        *self
            .caches
            .iap_routing
            .write()
            .map_err(|_| AppError::Internal("IAP routing cache lock poisoned".to_string()))? =
            Some(TimedValue {
                value: snapshot.clone(),
                loaded_at: Instant::now(),
            });
        Ok(snapshot)
    }

    pub(crate) async fn iap_routing_index(&self) -> AppResult<Arc<IapRoutingIndex>> {
        self.iap_routing_snapshot()
            .await
            .map(|(routing, _)| routing)
    }

    fn cached_iap_routing_snapshot(&self, ttl: Duration) -> AppResult<Option<IapRoutingSnapshot>> {
        let generation = self.caches.iap_generation.load(Ordering::Acquire);
        let guard = self
            .caches
            .iap_routing
            .read()
            .map_err(|_| AppError::Internal("IAP routing cache lock poisoned".to_string()))?;
        Ok(guard
            .as_ref()
            .filter(|entry| entry.value.1 == generation && entry.is_fresh(ttl))
            .map(|entry| entry.value.clone()))
    }

    fn cached_iap_routing_snapshot_stale_while_refresh(
        &self,
        ttl: Duration,
    ) -> AppResult<Option<IapRoutingSnapshot>> {
        let grace = Duration::from_millis(
            self.settings
                .performance
                .iap_routing_stale_while_refresh_millis,
        );
        if ttl == Duration::ZERO || grace == Duration::ZERO {
            return Ok(None);
        }
        let max_age = ttl.saturating_add(grace);
        let generation = self.caches.iap_generation.load(Ordering::Acquire);
        let guard = self
            .caches
            .iap_routing
            .read()
            .map_err(|_| AppError::Internal("IAP routing cache lock poisoned".to_string()))?;
        Ok(guard
            .as_ref()
            .filter(|entry| entry.value.1 == generation && entry.loaded_at.elapsed() < max_age)
            .map(|entry| entry.value.clone()))
    }

    pub fn invalidate_iap_applications_cache(&self) {
        self.caches.iap_generation.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut guard) = self.caches.iap_routing.write() {
            *guard = None;
        }
        self.invalidate_iap_authorization_cache();
    }

    pub async fn oidc_authorization_details_types(&self) -> AppResult<Vec<String>> {
        let ttl = Duration::from_millis(self.settings.performance.oidc_metadata_cache_millis);
        if let Some(value) = self.cached_oidc_authorization_details_types(ttl)? {
            return Ok(value);
        }
        if ttl == Duration::ZERO {
            return crate::authorization_details::supported_types_from_clients(
                &self.db.list_clients().await?,
            );
        }
        let _refresh = self.caches.oidc_metadata_refresh.lock().await;
        if let Some(value) = self.cached_oidc_authorization_details_types(ttl)? {
            return Ok(value);
        }
        let value = crate::authorization_details::supported_types_from_clients(
            &self.db.list_clients().await?,
        )?;
        *self
            .caches
            .oidc_authorization_details_types
            .write()
            .map_err(|_| AppError::Internal("OIDC metadata cache lock poisoned".to_string()))? =
            Some(TimedValue {
                value: value.clone(),
                loaded_at: Instant::now(),
            });
        Ok(value)
    }

    fn cached_oidc_authorization_details_types(
        &self,
        ttl: Duration,
    ) -> AppResult<Option<Vec<String>>> {
        let cache = self
            .caches
            .oidc_authorization_details_types
            .read()
            .map_err(|_| AppError::Internal("OIDC metadata cache lock poisoned".to_string()))?;
        Ok(cache
            .as_ref()
            .filter(|entry| entry.is_fresh(ttl))
            .map(|entry| entry.value.clone()))
    }

    /// Returns claims for the exact bearer token bytes only after they have
    /// already passed cryptographic verification and the IAP-specific token
    /// class checks. The cache deliberately shares the tiny IAP authorization
    /// TTL so key/issuer changes remain tightly bounded while page-load asset
    /// bursts do not repeat the same RSA verification thousands of times.
    pub(crate) fn iap_bearer_claims_cache_entry(
        &self,
        key: &str,
    ) -> AppResult<Option<TokenClaims>> {
        let ttl = Duration::from_millis(self.settings.performance.iap_authorization_cache_millis);
        if ttl == Duration::ZERO {
            return Ok(None);
        }
        let cache =
            self.caches.iap_bearer_claims.read().map_err(|_| {
                AppError::Internal("IAP bearer claims cache lock poisoned".to_string())
            })?;
        Ok(cache
            .fresh(key, ttl)
            .filter(|claims| claims.exp > util::now_ts()))
    }

    pub(crate) fn store_iap_bearer_claims_cache_entry(
        &self,
        key: String,
        claims: TokenClaims,
    ) -> AppResult<()> {
        if self.settings.performance.iap_authorization_cache_millis == 0
            || claims.exp <= util::now_ts()
        {
            return Ok(());
        }
        let mut cache =
            self.caches.iap_bearer_claims.write().map_err(|_| {
                AppError::Internal("IAP bearer claims cache lock poisoned".to_string())
            })?;
        cache.store(
            key,
            claims,
            self.settings
                .performance
                .iap_authorization_cache_max_entries,
        );
        Ok(())
    }

    pub(crate) fn iap_bearer_claims_refresh_lock(&self, key: &str) -> AppResult<Arc<Mutex<()>>> {
        if let Some(lock) = self
            .caches
            .iap_bearer_claims_refresh
            .read()
            .map_err(|_| AppError::Internal("IAP bearer refresh lock poisoned".to_string()))?
            .get(key)
            .and_then(Weak::upgrade)
        {
            return Ok(lock);
        }
        let mut locks = self
            .caches
            .iap_bearer_claims_refresh
            .write()
            .map_err(|_| AppError::Internal("IAP bearer refresh lock poisoned".to_string()))?;
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key.to_string(), Arc::downgrade(&lock));
        Ok(lock)
    }

    pub(crate) fn iap_authorization_cache_entry(
        &self,
        key: &str,
    ) -> AppResult<Option<IapCachedAuthorization>> {
        let ttl = Duration::from_millis(self.settings.performance.iap_authorization_cache_millis);
        if ttl == Duration::ZERO {
            return Ok(None);
        }
        let cache =
            self.caches.iap_authorizations.read().map_err(|_| {
                AppError::Internal("IAP authorization cache lock poisoned".to_string())
            })?;
        Ok(cache.fresh(key, ttl))
    }

    /// Returns the last authorization snapshot even after the short decision
    /// TTL has elapsed. Callers must re-run authorization before using it for
    /// access control; the stale value exists only so an unchanged signed IAP
    /// assertion can be reused until its own, longer expiration window.
    pub(crate) fn iap_authorization_cache_entry_stale(
        &self,
        key: &str,
    ) -> AppResult<Option<IapCachedAuthorization>> {
        if self.settings.performance.iap_authorization_cache_millis == 0 {
            return Ok(None);
        }
        self.caches
            .iap_authorizations
            .read()
            .map_err(|_| AppError::Internal("IAP authorization cache lock poisoned".to_string()))
            .map(|cache| cache.value(key))
    }

    /// Returns an expired decision only inside the tightly bounded
    /// stale-while-refresh window. Callers must additionally prove that a
    /// refresh for this exact session+rule key is already in progress before
    /// using the result for access control.
    pub(crate) fn iap_authorization_stale_while_refresh_entry(
        &self,
        key: &str,
    ) -> AppResult<Option<IapCachedAuthorization>> {
        let ttl = Duration::from_millis(self.settings.performance.iap_authorization_cache_millis);
        let grace = Duration::from_millis(
            self.settings
                .performance
                .iap_authorization_stale_while_refresh_millis,
        );
        if ttl == Duration::ZERO || grace == Duration::ZERO {
            return Ok(None);
        }
        let max_age = ttl.saturating_add(grace);
        let cache =
            self.caches.iap_authorizations.read().map_err(|_| {
                AppError::Internal("IAP authorization cache lock poisoned".to_string())
            })?;
        Ok(cache.younger_than(key, max_age))
    }

    pub(crate) fn store_iap_authorization_cache_entry(
        &self,
        key: String,
        value: IapCachedAuthorization,
    ) -> AppResult<()> {
        if self.settings.performance.iap_authorization_cache_millis == 0 {
            return Ok(());
        }
        let mut cache =
            self.caches.iap_authorizations.write().map_err(|_| {
                AppError::Internal("IAP authorization cache lock poisoned".to_string())
            })?;
        let max_entries = self
            .settings
            .performance
            .iap_authorization_cache_max_entries;
        cache.store(key, value, max_entries);
        Ok(())
    }

    pub(crate) fn iap_authorization_refresh_lock(&self, key: &str) -> AppResult<Arc<Mutex<()>>> {
        if let Some(lock) = self
            .caches
            .iap_authorization_refresh
            .read()
            .map_err(|_| AppError::Internal("IAP authorization refresh lock poisoned".to_string()))?
            .get(key)
            .and_then(Weak::upgrade)
        {
            return Ok(lock);
        }
        let mut locks = self.caches.iap_authorization_refresh.write().map_err(|_| {
            AppError::Internal("IAP authorization refresh lock poisoned".to_string())
        })?;
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key.to_string(), Arc::downgrade(&lock));
        Ok(lock)
    }

    fn invalidate_iap_authorization_cache(&self) {
        if let Ok(mut cache) = self.caches.iap_bearer_claims.write() {
            cache.clear();
        }
        if let Ok(mut cache) = self.caches.iap_authorizations.write() {
            cache.clear();
        }
    }

    pub(crate) fn client_jwks_cache_entry(
        &self,
        key: &str,
    ) -> AppResult<Option<CachedHttpDocument>> {
        self.caches
            .client_jwks
            .read()
            .map_err(|_| AppError::Internal("client JWKS cache lock poisoned".to_string()))
            .map(|cache| cache.get(key).cloned())
    }

    pub(crate) fn store_client_jwks_cache_entry(
        &self,
        key: String,
        mut value: CachedHttpDocument,
    ) -> AppResult<()> {
        let mut cache = self
            .caches
            .client_jwks
            .write()
            .map_err(|_| AppError::Internal("client JWKS cache lock poisoned".to_string()))?;
        if !value.cacheable {
            cache.remove(&key);
            return Ok(());
        }
        value.stored_at = Instant::now();
        let max_entries = self.settings.performance.client_jwks_max_entries;
        if !cache.contains_key(&key)
            && cache.len() >= max_entries
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.stored_at)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(key, value);
        Ok(())
    }

    pub(crate) fn client_jwks_refresh_lock(&self, key: &str) -> AppResult<Arc<Mutex<()>>> {
        if let Some(lock) = self
            .caches
            .client_jwks_refresh
            .read()
            .map_err(|_| AppError::Internal("client JWKS refresh lock poisoned".to_string()))?
            .get(key)
            .and_then(Weak::upgrade)
        {
            return Ok(lock);
        }
        let mut locks = self
            .caches
            .client_jwks_refresh
            .write()
            .map_err(|_| AppError::Internal("client JWKS refresh lock poisoned".to_string()))?;
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key.to_string(), Arc::downgrade(&lock));
        Ok(lock)
    }

    pub async fn effective_public_base_url(&self, headers: &HeaderMap) -> AppResult<String> {
        let runtime = self.runtime_settings().await?;
        Ok(util::external_base_url_for(
            runtime.trust_proxy_headers == 1,
            headers,
            &runtime.public_base_url,
        ))
    }

    pub async fn effective_issuer(&self, headers: &HeaderMap) -> AppResult<String> {
        let runtime = self.runtime_settings().await?;
        Ok(util::external_base_url_for(
            runtime.trust_proxy_headers == 1,
            headers,
            &runtime.issuer,
        ))
    }

    pub async fn accepted_issuers(&self, headers: &HeaderMap) -> AppResult<Vec<String>> {
        let runtime = self.runtime_settings().await?;
        let effective =
            util::external_base_url_for(runtime.trust_proxy_headers == 1, headers, &runtime.issuer);
        let mut issuers = vec![effective, runtime.issuer, self.settings.oidc.issuer.clone()];
        issuers.iter_mut().for_each(|value| {
            *value = value.trim_end_matches('/').to_string();
        });
        issuers.sort();
        issuers.dedup();
        Ok(issuers)
    }

    pub async fn request_ip(
        &self,
        headers: &HeaderMap,
        remote_addr: Option<SocketAddr>,
    ) -> AppResult<Option<String>> {
        let runtime = self.runtime_settings().await?;
        Ok(util::request_ip_for(
            runtime.trust_proxy_headers == 1,
            headers,
            remote_addr,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedTimedCache;

    #[test]
    fn bounded_timed_cache_evicts_oldest_live_generation_without_linear_scan() {
        let mut cache = BoundedTimedCache::default();
        cache.store("a".to_string(), 1_u64, 2);
        cache.store("b".to_string(), 2_u64, 2);

        // Refreshing a leaves the old queue generation behind. Adding c must
        // skip that stale queue item and evict b, which is now the oldest
        // live generation.
        cache.store("a".to_string(), 3_u64, 2);
        cache.store("c".to_string(), 4_u64, 2);

        assert_eq!(cache.value("a"), Some(3));
        assert_eq!(cache.value("b"), None);
        assert_eq!(cache.value("c"), Some(4));
        assert_eq!(cache.entries.len(), 2);
    }

    #[test]
    fn bounded_timed_cache_compacts_stale_generation_queue() {
        let mut cache = BoundedTimedCache::default();
        for value in 0_u64..512 {
            cache.store("hot".to_string(), value, 2);
        }

        assert_eq!(cache.value("hot"), Some(511));
        assert_eq!(cache.entries.len(), 1);
        assert!(cache.order.len() <= 64);

        cache.clear();
        assert!(cache.entries.is_empty());
        assert!(cache.order.is_empty());
    }
}
