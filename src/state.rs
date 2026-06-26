//! Shared application state, used by both the DNS handler and the web API.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::config::Config;
use crate::db::Db;
use crate::dns::forwarder::Forwarder;
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
    forwarder: RwLock<Option<Arc<Forwarder>>>,
    throttle: Mutex<LoginThrottle>,
}

impl AppState {
    pub fn new(
        db: Db,
        config: Arc<Config>,
        store: ZoneStore,
        forwarder: Option<Forwarder>,
    ) -> Self {
        Self {
            db,
            config,
            stats: Arc::new(Stats::new()),
            store: RwLock::new(Arc::new(store)),
            forwarder: RwLock::new(forwarder.map(Arc::new)),
            throttle: Mutex::new(LoginThrottle::default()),
        }
    }

    /// Snapshot the current authoritative store (cheap Arc clone).
    pub fn store(&self) -> Arc<ZoneStore> {
        self.store.read().clone()
    }

    /// Snapshot the current forwarder, if forwarding is configured/enabled.
    pub fn forwarder(&self) -> Option<Arc<Forwarder>> {
        self.forwarder.read().clone()
    }

    /// Rebuild the in-memory authoritative store from the database and swap it
    /// in atomically. Called after any zone/record/view change.
    pub fn reload_store(&self) -> anyhow::Result<()> {
        let store = ZoneStore::load(&self.db)?;
        *self.store.write() = Arc::new(store);
        Ok(())
    }

    /// Rebuild the forwarder from the given settings and swap it in.
    pub fn rebuild_forwarder(&self, settings: &crate::models::Settings) {
        if !settings.forward_enabled {
            *self.forwarder.write() = None;
            return;
        }
        match Forwarder::build(settings) {
            Ok(f) => *self.forwarder.write() = Some(Arc::new(f)),
            Err(e) => {
                tracing::error!("failed to rebuild forwarder: {e}");
                *self.forwarder.write() = None;
            }
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
