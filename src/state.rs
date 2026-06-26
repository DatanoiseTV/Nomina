//! Shared application state, used by both the DNS handler and the web API.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::config::Config;
use crate::db::Db;
use crate::dns::upstream::Upstream;
use crate::filter::FilterSet;
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
    filter: RwLock<Arc<FilterSet>>,
    settings: RwLock<Settings>,
    throttle: Mutex<LoginThrottle>,
}

impl AppState {
    pub fn new(
        db: Db,
        config: Arc<Config>,
        store: ZoneStore,
        upstream: Option<Upstream>,
        filter: FilterSet,
        settings: Settings,
    ) -> Self {
        Self {
            db,
            config,
            stats: Arc::new(Stats::new()),
            store: RwLock::new(Arc::new(store)),
            upstream: RwLock::new(upstream.map(Arc::new)),
            filter: RwLock::new(Arc::new(filter)),
            settings: RwLock::new(settings),
            throttle: Mutex::new(LoginThrottle::default()),
        }
    }

    /// Snapshot the current authoritative store (cheap Arc clone).
    pub fn store(&self) -> Arc<ZoneStore> {
        self.store.read().clone()
    }

    /// Snapshot the current upstream resolver, if resolution is enabled.
    pub fn upstream(&self) -> Option<Arc<Upstream>> {
        self.upstream.read().clone()
    }

    /// Snapshot the current filter set.
    pub fn filter(&self) -> Arc<FilterSet> {
        self.filter.read().clone()
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
        let entry = t.failures.entry(key.to_string()).or_insert((0, Instant::now()));
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
