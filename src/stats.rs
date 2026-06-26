//! In-memory query statistics for the dashboard.
//!
//! Aggregate counters and a per-second time series are always collected — these
//! carry no identifying information. Per-query detail (recent queries, top
//! domains) and client IPs are gated by the [`QueryLog`] setting, which defaults
//! to `Off` for privacy. `Anonymized` masks client IPs (IPv4 → /24, IPv6 → /48).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::models::QueryLog;

const RECENT_CAPACITY: usize = 200;
const SERIES_WINDOW: usize = 300; // seconds retained
const SERIES_OUTPUT: usize = 60; // seconds returned to the dashboard
const TOP_TRACK_CAP: usize = 5000; // distinct domains tracked
const TOP_RETURN: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryOutcome {
    Authoritative,
    Forwarded,
    NxDomain,
    Refused,
    ServFail,
    Blocked,
    Rewritten,
}

impl QueryOutcome {
    fn as_str(self) -> &'static str {
        match self {
            QueryOutcome::Authoritative => "authoritative",
            QueryOutcome::Forwarded => "forwarded",
            QueryOutcome::NxDomain => "nxdomain",
            QueryOutcome::Refused => "refused",
            QueryOutcome::ServFail => "servfail",
            QueryOutcome::Blocked => "blocked",
            QueryOutcome::Rewritten => "rewritten",
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
    blocked: AtomicU64,
}

/// Per-second ring of query counts for the rate chart.
struct Series {
    buckets: Vec<u64>,
    last_sec: u64,
}

impl Series {
    fn new() -> Self {
        Self {
            buckets: vec![0; SERIES_WINDOW],
            last_sec: 0,
        }
    }

    fn bump(&mut self, sec: u64) {
        if sec != self.last_sec {
            // Zero buckets for the elapsed (skipped) seconds.
            let gap = (sec - self.last_sec).min(SERIES_WINDOW as u64);
            for i in 1..=gap {
                let idx = ((self.last_sec + i) as usize) % SERIES_WINDOW;
                self.buckets[idx] = 0;
            }
            self.last_sec = sec;
        }
        self.buckets[(sec as usize) % SERIES_WINDOW] += 1;
    }

    /// Counts for the last `SERIES_OUTPUT` seconds, oldest first.
    fn recent(&self, now_sec: u64) -> Vec<u64> {
        let mut out = Vec::with_capacity(SERIES_OUTPUT);
        let start = now_sec.saturating_sub(SERIES_OUTPUT as u64 - 1);
        for s in start..=now_sec {
            // Buckets older than the window have already been cleared, but guard
            // against reading a stale value for a second that hasn't ticked.
            let v = if s > self.last_sec {
                0
            } else {
                self.buckets[(s as usize) % SERIES_WINDOW]
            };
            out.push(v);
        }
        out
    }

    fn qps(&self, now_sec: u64, window: u64) -> f64 {
        let start = now_sec.saturating_sub(window - 1);
        let mut sum = 0u64;
        for s in start..=now_sec {
            if s <= self.last_sec {
                sum += self.buckets[(s as usize) % SERIES_WINDOW];
            }
        }
        sum as f64 / window as f64
    }
}

pub struct Stats {
    counters: Counters,
    by_qtype: Mutex<BTreeMap<String, u64>>,
    recent: Mutex<VecDeque<RecentQuery>>,
    top_domains: Mutex<HashMap<String, u64>>,
    top_blocked: Mutex<HashMap<String, u64>>,
    series: Mutex<Series>,
    started: Instant,
    started_at: String,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            counters: Counters::default(),
            by_qtype: Mutex::new(BTreeMap::new()),
            recent: Mutex::new(VecDeque::with_capacity(RECENT_CAPACITY)),
            top_domains: Mutex::new(HashMap::new()),
            top_blocked: Mutex::new(HashMap::new()),
            series: Mutex::new(Series::new()),
            started: Instant::now(),
            started_at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default(),
        }
    }
}

/// Mask a client IP for anonymized logging.
fn anonymize(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }

    fn now_sec(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn record(
        &self,
        mode: QueryLog,
        client: IpAddr,
        view: Option<String>,
        name: String,
        qtype: String,
        outcome: QueryOutcome,
        rcode: String,
    ) {
        // Aggregate, non-identifying counters — always collected.
        self.counters.total.fetch_add(1, Ordering::Relaxed);
        match outcome {
            QueryOutcome::Authoritative | QueryOutcome::Rewritten => {
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
            QueryOutcome::Blocked => {
                self.counters.blocked.fetch_add(1, Ordering::Relaxed);
            }
        }
        {
            let mut q = self.by_qtype.lock();
            *q.entry(qtype.clone()).or_insert(0) += 1;
        }
        self.series.lock().bump(self.now_sec());

        // Per-query detail is gated by the privacy setting.
        if mode == QueryLog::Off {
            return;
        }

        if outcome == QueryOutcome::Blocked {
            let mut tb = self.top_blocked.lock();
            if tb.len() < TOP_TRACK_CAP || tb.contains_key(&name) {
                *tb.entry(name.clone()).or_insert(0) += 1;
            }
        }
        {
            let mut td = self.top_domains.lock();
            if td.len() < TOP_TRACK_CAP || td.contains_key(&name) {
                *td.entry(name.clone()).or_insert(0) += 1;
            }
        }

        let client = match mode {
            QueryLog::Full => client.to_string(),
            _ => anonymize(client),
        };
        let entry = RecentQuery {
            at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default(),
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

    /// Clear retained per-query detail (recent queries + top domains).
    pub fn clear_log(&self) {
        self.recent.lock().clear();
        self.top_domains.lock().clear();
        self.top_blocked.lock().clear();
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let now_sec = self.now_sec();
        let by_qtype = self.by_qtype.lock().clone();
        let recent: Vec<RecentQuery> = self.recent.lock().iter().rev().cloned().collect();
        let (series, qps_1m, qps_10s) = {
            let s = self.series.lock();
            (s.recent(now_sec), s.qps(now_sec, 60), s.qps(now_sec, 10))
        };
        let total = self.counters.total.load(Ordering::Relaxed);
        let uptime = self.started.elapsed().as_secs().max(1);

        json!({
            "total": total,
            "authoritative": self.counters.authoritative.load(Ordering::Relaxed),
            "forwarded": self.counters.forwarded.load(Ordering::Relaxed),
            "cached": 0,
            "nxdomain": self.counters.nxdomain.load(Ordering::Relaxed),
            "refused": self.counters.refused.load(Ordering::Relaxed),
            "servfail": self.counters.servfail.load(Ordering::Relaxed),
            "blocked": self.counters.blocked.load(Ordering::Relaxed),
            "by_qtype": by_qtype,
            "qps_10s": (qps_10s * 100.0).round() / 100.0,
            "qps_1m": (qps_1m * 100.0).round() / 100.0,
            "qps_avg": (total as f64 / uptime as f64 * 100.0).round() / 100.0,
            "series_per_sec": series,
            "recent": recent,
            "top_domains": top_n(&self.top_domains.lock()),
            "top_blocked": top_n(&self.top_blocked.lock()),
        })
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn started_at(&self) -> &str {
        &self.started_at
    }
}

fn top_n(map: &HashMap<String, u64>) -> Vec<serde_json::Value> {
    let mut v: Vec<(&String, &u64)> = map.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    v.into_iter()
        .take(TOP_RETURN)
        .map(|(name, count)| json!({ "name": name, "count": count }))
        .collect()
}
