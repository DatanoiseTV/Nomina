//! Lightweight in-memory query statistics. Lock-free counters plus a small
//! bounded ring of recent queries for the dashboard.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const RECENT_CAPACITY: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryOutcome {
    Authoritative,
    Forwarded,
    NxDomain,
    Refused,
    ServFail,
}

impl QueryOutcome {
    fn as_str(self) -> &'static str {
        match self {
            QueryOutcome::Authoritative => "authoritative",
            QueryOutcome::Forwarded => "forwarded",
            QueryOutcome::NxDomain => "nxdomain",
            QueryOutcome::Refused => "refused",
            QueryOutcome::ServFail => "servfail",
        }
    }
}

#[derive(Clone, Serialize)]
pub struct RecentQuery {
    pub at: String,
    pub client: String,
    pub view: Option<String>,
    pub name: String,
    pub qtype: String,
    pub outcome: String,
    pub rcode: String,
}

#[derive(Default)]
struct Counters {
    total: AtomicU64,
    authoritative: AtomicU64,
    forwarded: AtomicU64,
    nxdomain: AtomicU64,
    refused: AtomicU64,
    servfail: AtomicU64,
}

pub struct Stats {
    counters: Counters,
    by_qtype: Mutex<BTreeMap<String, u64>>,
    recent: Mutex<VecDeque<RecentQuery>>,
    started: Instant,
    started_at: String,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            counters: Counters::default(),
            by_qtype: Mutex::new(BTreeMap::new()),
            recent: Mutex::new(VecDeque::with_capacity(RECENT_CAPACITY)),
            started: Instant::now(),
            started_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
        }
    }
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        client: String,
        view: Option<String>,
        name: String,
        qtype: String,
        outcome: QueryOutcome,
        rcode: String,
    ) {
        self.counters.total.fetch_add(1, Ordering::Relaxed);
        match outcome {
            QueryOutcome::Authoritative => {
                self.counters.authoritative.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::Forwarded => {
                self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::NxDomain => {
                self.counters.nxdomain.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::Refused => {
                self.counters.refused.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::ServFail => {
                self.counters.servfail.fetch_add(1, Ordering::Relaxed);
            }
        }

        {
            let mut m = self.by_qtype.lock();
            *m.entry(qtype.clone()).or_insert(0) += 1;
        }

        let entry = RecentQuery {
            at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            client,
            view,
            name,
            qtype,
            outcome: outcome.as_str().to_string(),
            rcode,
        };
        let mut r = self.recent.lock();
        if r.len() == RECENT_CAPACITY {
            r.pop_front();
        }
        r.push_back(entry);
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let by_qtype = self.by_qtype.lock().clone();
        let recent: Vec<RecentQuery> = self.recent.lock().iter().rev().cloned().collect();
        serde_json::json!({
            "total": self.counters.total.load(Ordering::Relaxed),
            "authoritative": self.counters.authoritative.load(Ordering::Relaxed),
            "forwarded": self.counters.forwarded.load(Ordering::Relaxed),
            "cached": 0,
            "nxdomain": self.counters.nxdomain.load(Ordering::Relaxed),
            "refused": self.counters.refused.load(Ordering::Relaxed),
            "servfail": self.counters.servfail.load(Ordering::Relaxed),
            "by_qtype": by_qtype,
            "recent": recent,
        })
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn started_at(&self) -> &str {
        &self.started_at
    }
}
