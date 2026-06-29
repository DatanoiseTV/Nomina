//! Shared application state, used by both the DNS handler and the web API.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::config::Config;
use crate::db::Db;
use crate::dns::cache::DnsCache;
use crate::dns::conditional::ConditionalSet;
use crate::dns::mdns::MdnsRegistry;
use crate::dns::upstream::Upstream;
use crate::filter::FilterSet;
use crate::geo::GeoDb;
use crate::models::{BlockMode, ResolutionMode, Settings};
use crate::stats::Stats;
use crate::store::ZoneStore;

/// Tracks failed login attempts to throttle brute-force attempts.
#[derive(Default)]
struct LoginThrottle {
    failures: HashMap<String, (u32, Instant)>,
}

const LOCKOUT_THRESHOLD: u32 = 8;
const LOCKOUT_WINDOW: Duration = Duration::from_secs(300);

pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
    pub stats: Arc<Stats>,
    store: RwLock<Arc<ZoneStore>>,
    upstream: RwLock<Option<Arc<Upstream>>>,
    conditional: RwLock<Arc<ConditionalSet>>,
    filter: RwLock<Arc<FilterSet>>,
    cache: RwLock<Arc<DnsCache>>,
    settings: RwLock<Settings>,
    geo: Arc<GeoDb>,
    mdns: Arc<MdnsRegistry>,
    /// Monotonic counter driving round-robin answer rotation.
    rr_counter: AtomicU64,
    throttle: Mutex<LoginThrottle>,
    qlog_tx: tokio::sync::mpsc::Sender<crate::stats::RecentQuery>,
    /// Blocked domains queued for background resolution (map's blocked-dest layer).
    blocked_tx: tokio::sync::mpsc::Sender<String>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        config: Arc<Config>,
        store: ZoneStore,
        upstream: Option<Upstream>,
        conditional: ConditionalSet,
        filter: FilterSet,
        settings: Settings,
        qlog_tx: tokio::sync::mpsc::Sender<crate::stats::RecentQuery>,
        blocked_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Self {
        let geo = Arc::new(GeoDb::load(
            config.geo.geoip_db.as_deref(),
            config.geo.asn_db.as_deref(),
        ));
        Self {
            db,
            config,
            stats: Arc::new(Stats::new()),
            store: RwLock::new(Arc::new(store)),
            upstream: RwLock::new(upstream.map(Arc::new)),
            conditional: RwLock::new(Arc::new(conditional)),
            filter: RwLock::new(Arc::new(filter)),
            cache: RwLock::new(Arc::new(DnsCache::new(
                settings.cache_size as usize,
                settings.cache_min_ttl,
                settings.cache_max_ttl,
            ))),
            geo,
            mdns: Arc::new(MdnsRegistry::default()),
            settings: RwLock::new(settings),
            rr_counter: AtomicU64::new(0),
            throttle: Mutex::new(LoginThrottle::default()),
            qlog_tx,
            blocked_tx,
        }
    }

    /// Queue a blocked domain for background resolution (for the map's
    /// blocked-destination layer). Dropped silently if the worker is backed up.
    pub fn note_blocked_domain(&self, domain: String) {
        let _ = self.blocked_tx.try_send(domain);
    }

    /// Queue a query-log entry for async persistence. Drops the entry (rather
    /// than blocking the resolver) if the writer is backed up.
    pub fn log_query(&self, entry: crate::stats::RecentQuery) {
        let _ = self.qlog_tx.try_send(entry);
    }

    /// Snapshot the current authoritative store (cheap Arc clone).
    pub fn store(&self) -> Arc<ZoneStore> {
        self.store.read().clone()
    }

    /// Snapshot the current upstream resolver, if resolution is enabled.
    pub fn upstream(&self) -> Option<Arc<Upstream>> {
        self.upstream.read().clone()
    }

    /// Snapshot the current conditional-forwarding set.
    pub fn conditional(&self) -> Arc<ConditionalSet> {
        self.conditional.read().clone()
    }

    /// Rebuild conditional forwarders from the database.
    pub fn reload_conditional(&self) -> anyhow::Result<()> {
        let settings = self.settings.read().clone();
        let set = ConditionalSet::load(&self.db, &settings)?;
        *self.conditional.write() = Arc::new(set);
        Ok(())
    }

    /// Snapshot the current filter set.
    pub fn filter(&self) -> Arc<FilterSet> {
        self.filter.read().clone()
    }

    /// Snapshot the current upstream answer cache.
    pub fn cache(&self) -> Arc<DnsCache> {
        self.cache.read().clone()
    }

    pub fn block_mode(&self) -> BlockMode {
        self.settings.read().block_mode
    }

    pub fn resolution_mode(&self) -> ResolutionMode {
        self.settings.read().resolution_mode
    }

    pub fn query_log(&self) -> crate::models::QueryLog {
        self.settings.read().query_log
    }

    pub fn dnssec_validate_upstream(&self) -> bool {
        self.settings.read().dnssec_validate_upstream
    }

    /// The GeoIP/ASN databases (may be empty if none configured).
    pub fn geo(&self) -> Arc<GeoDb> {
        self.geo.clone()
    }

    /// The mDNS discovery registry.
    pub fn mdns(&self) -> Arc<MdnsRegistry> {
        self.mdns.clone()
    }

    pub fn load_balance(&self) -> crate::models::LoadBalance {
        self.settings.read().load_balance
    }

    pub fn blocked_asns(&self) -> Vec<u32> {
        self.settings.read().blocked_asns.clone()
    }

    pub fn mdns_enabled(&self) -> bool {
        self.settings.read().mdns_enabled
    }

    /// Configured mDNS publish zone, normalized (trimmed, lowercased). `None`
    /// when unset, so publishing is effectively off.
    pub fn mdns_zone(&self) -> Option<String> {
        let z = self
            .settings
            .read()
            .mdns_zone
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if z.is_empty() { None } else { Some(z) }
    }

    pub fn mdns_ttl(&self) -> u32 {
        self.settings.read().mdns_ttl.max(1)
    }

    pub fn mdns_publish_public(&self) -> bool {
        self.settings.read().mdns_publish_public
    }

    pub fn blocklist_refresh_hours(&self) -> u32 {
        self.settings.read().blocklist_refresh_hours
    }

    /// Next round-robin rotation offset.
    pub fn next_rotation(&self) -> u64 {
        self.rr_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn homograph_mode(&self) -> crate::models::HomographMode {
        self.settings.read().homograph_protection
    }

    pub fn axfr_require_tsig(&self) -> bool {
        self.settings.read().axfr_require_tsig
    }

    pub fn tsig_keys(&self) -> Vec<crate::models::TsigKey> {
        self.settings.read().tsig_keys.clone()
    }

    /// Build a TSIG signer for a configured key name, if present and valid.
    pub fn tsig_signer(&self, key_name: &str) -> Option<hickory_proto::rr::TSigner> {
        let settings = self.settings.read();
        settings
            .tsig_keys
            .iter()
            .find(|k| k.name == key_name)
            .and_then(|k| crate::dns::tsig::build_signer(k).ok())
    }

    /// Is `ip` allowed to request an AXFR zone transfer?
    pub fn axfr_allowed(&self, ip: std::net::IpAddr) -> bool {
        self.settings
            .read()
            .allow_axfr_from
            .iter()
            .filter_map(|s| s.parse::<ipnet::IpNet>().ok())
            .any(|n| n.contains(&ip))
    }

    /// Rebuild the in-memory authoritative store from the database.
    pub fn reload_store(&self) -> anyhow::Result<()> {
        let store = ZoneStore::load(&self.db)?;
        *self.store.write() = Arc::new(store);
        Ok(())
    }

    /// Rebuild the in-memory filter (blocklists/rules/rewrites) from the database.
    pub fn reload_filter(&self) -> anyhow::Result<()> {
        let blocking = self.settings.read().blocking_enabled;
        let filter = FilterSet::load(&self.db, blocking)?;
        *self.filter.write() = Arc::new(filter);
        Ok(())
    }

    /// Apply a new settings snapshot: store it, rebuild the upstream, and reload
    /// the filter (blocking toggle lives in settings).
    pub fn apply_settings(&self, settings: Settings) {
        *self.settings.write() = settings.clone();
        match Upstream::build(&settings) {
            Ok(up) => *self.upstream.write() = up.map(Arc::new),
            Err(e) => {
                tracing::error!("failed to build upstream: {e}");
                *self.upstream.write() = None;
            }
        }
        if let Err(e) = self.reload_filter() {
            tracing::error!("failed to reload filter: {e}");
        }
        if let Err(e) = self.reload_conditional() {
            tracing::error!("failed to reload conditional forwarders: {e}");
        }
        // Rebuild the edge cache so changed size/TTL bounds take effect.
        *self.cache.write() = Arc::new(DnsCache::new(
            settings.cache_size as usize,
            settings.cache_min_ttl,
            settings.cache_max_ttl,
        ));
    }

    // ----- login throttling -----------------------------------------------

    pub fn is_locked_out(&self, key: &str) -> bool {
        let mut t = self.throttle.lock();
        if let Some((count, when)) = t.failures.get(key).copied() {
            if when.elapsed() > LOCKOUT_WINDOW {
                t.failures.remove(key);
                return false;
            }
            return count >= LOCKOUT_THRESHOLD;
        }
        false
    }

    pub fn record_login_failure(&self, key: &str) {
        let mut t = self.throttle.lock();
        let entry = t
            .failures
            .entry(key.to_string())
            .or_insert((0, Instant::now()));
        if entry.1.elapsed() > LOCKOUT_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn clear_login_failures(&self, key: &str) {
        self.throttle.lock().failures.remove(key);
    }
}

pub type SharedState = Arc<AppState>;
