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
const LATENCY_CAPACITY: usize = 4000;
const SERIES_WINDOW: usize = 300; // seconds retained
const SERIES_OUTPUT: usize = 60; // seconds returned to the dashboard
const TOP_TRACK_CAP: usize = 5000; // distinct domains tracked
const RESOLVED_CAP: usize = 5000; // distinct resolved IPs tracked for the map
const TOP_RETURN: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryOutcome {
    Authoritative,
    Forwarded,
    Cached,
    NxDomain,
    Refused,
    ServFail,
    Blocked,
    Rewritten,
    /// Blocked as a dangerous lookalike / homograph (phishing protection).
    Dangerous,
}

impl QueryOutcome {
    fn as_str(self) -> &'static str {
        match self {
            QueryOutcome::Authoritative => "authoritative",
            QueryOutcome::Forwarded => "forwarded",
            QueryOutcome::Cached => "cached",
            QueryOutcome::NxDomain => "nxdomain",
            QueryOutcome::Refused => "refused",
            QueryOutcome::ServFail => "servfail",
            QueryOutcome::Blocked => "blocked",
            QueryOutcome::Rewritten => "rewritten",
            QueryOutcome::Dangerous => "dangerous",
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
    cached: AtomicU64,
    nxdomain: AtomicU64,
    refused: AtomicU64,
    servfail: AtomicU64,
    blocked: AtomicU64,
    dangerous: AtomicU64,
    dnssec_failures: AtomicU64,
    ipv4: AtomicU64,
    ipv6: AtomicU64,
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
    /// Recent per-query latencies in microseconds (bounded ring).
    latencies: Mutex<VecDeque<u64>>,
    /// Public resolved (answer) IPs -> count, for the geo map (bounded).
    resolved: Mutex<HashMap<IpAddr, u64>>,
    /// Public IPs that blocked domains resolve to (background-resolved) -> count.
    blocked_dest: Mutex<HashMap<IpAddr, u64>>,
    /// Public client IPs that issued blocked requests -> count.
    blocked_client: Mutex<HashMap<IpAddr, u64>>,
    /// Blocklist id -> number of blocks attributed to it.
    blocklist_hits: Mutex<HashMap<i64, u64>>,
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
            latencies: Mutex::new(VecDeque::with_capacity(LATENCY_CAPACITY)),
            resolved: Mutex::new(HashMap::new()),
            blocked_dest: Mutex::new(HashMap::new()),
            blocked_client: Mutex::new(HashMap::new()),
            blocklist_hits: Mutex::new(HashMap::new()),
            started: Instant::now(),
            started_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
        }
    }
}

/// Whether an address is a globally-routable public IP (worth geolocating).
/// Excludes private, loopback, link-local, unique-local, multicast, CGNAT, and
/// documentation ranges.
fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.is_multicast()
                || a.octets()[0] == 0
                || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64)) // 100.64/10 CGNAT
        }
        IpAddr::V6(a) => {
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (a.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (a.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || a.segments()[0] == 0x2001 && a.segments()[1] == 0x0db8) // 2001:db8::/32 doc
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

    /// Record a query. Returns the logged [`RecentQuery`] when per-query logging
    /// is enabled (so the caller can persist it), or `None` when logging is off.
    pub fn record(
        &self,
        mode: QueryLog,
        client: IpAddr,
        view: Option<String>,
        name: String,
        qtype: String,
        outcome: QueryOutcome,
        rcode: String,
    ) -> Option<RecentQuery> {
        // Aggregate, non-identifying counters — always collected.
        self.counters.total.fetch_add(1, Ordering::Relaxed);
        if client.is_ipv4() {
            self.counters.ipv4.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.ipv6.fetch_add(1, Ordering::Relaxed);
        }
        match outcome {
            QueryOutcome::Authoritative | QueryOutcome::Rewritten => {
                self.counters.authoritative.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::Forwarded => {
                self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::Cached => {
                self.counters.cached.fetch_add(1, Ordering::Relaxed);
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
            QueryOutcome::Dangerous => {
                self.counters.dangerous.fetch_add(1, Ordering::Relaxed);
            }
        }
        {
            let mut q = self.by_qtype.lock();
            *q.entry(qtype.clone()).or_insert(0) += 1;
        }
        self.series.lock().bump(self.now_sec());

        // Per-query detail is gated by the privacy setting.
        if mode == QueryLog::Off {
            return None;
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
        r.push_back(entry.clone());
        Some(entry)
    }

    /// Record an upstream answer rejected by DNSSEC validation (counted while
    /// `dnssec_validate_upstream` is enabled).
    pub fn record_dnssec_failure(&self) {
        self.counters
            .dnssec_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record public resolved (answer) IP addresses for the geo map. Private,
    /// loopback, and otherwise non-global addresses are ignored.
    pub fn record_resolved<I: IntoIterator<Item = IpAddr>>(&self, ips: I) {
        let mut m = self.resolved.lock();
        for ip in ips {
            if !is_global(ip) {
                continue;
            }
            if m.len() < RESOLVED_CAP || m.contains_key(&ip) {
                *m.entry(ip).or_insert(0) += 1;
            }
        }
    }

    /// Snapshot of resolved IPs and their counts (for `/api/map`).
    pub fn resolved_ips(&self) -> Vec<(IpAddr, u64)> {
        self.resolved.lock().iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Record a public IP that a blocked domain resolved to (background-resolved
    /// for the map's blocked-destination layer). Non-global addresses ignored.
    pub fn record_blocked_dest(&self, ip: IpAddr) {
        if !is_global(ip) {
            return;
        }
        let mut m = self.blocked_dest.lock();
        if m.len() < RESOLVED_CAP || m.contains_key(&ip) {
            *m.entry(ip).or_insert(0) += 1;
        }
    }

    /// Snapshot of blocked-destination IPs and counts (for `/api/map`).
    pub fn blocked_dest_ips(&self) -> Vec<(IpAddr, u64)> {
        self.blocked_dest.lock().iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Record the public client IP of a blocked request (map's blocked-client
    /// layer). Private/LAN clients are ignored — they don't geolocate.
    pub fn record_blocked_client(&self, ip: IpAddr) {
        if !is_global(ip) {
            return;
        }
        let mut m = self.blocked_client.lock();
        if m.len() < RESOLVED_CAP || m.contains_key(&ip) {
            *m.entry(ip).or_insert(0) += 1;
        }
    }

    /// Snapshot of blocked-client IPs and counts (for `/api/map`).
    pub fn blocked_client_ips(&self) -> Vec<(IpAddr, u64)> {
        self.blocked_client.lock().iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Attribute a block to the blocklist that supplied the domain.
    pub fn record_blocklist_hit(&self, id: i64) {
        *self.blocklist_hits.lock().entry(id).or_insert(0) += 1;
    }

    /// Per-blocklist hit counts (blocklist id -> hits).
    pub fn blocklist_hits(&self) -> HashMap<i64, u64> {
        self.blocklist_hits.lock().clone()
    }

    /// Record a query's end-to-end resolution latency.
    pub fn record_latency(&self, d: std::time::Duration) {
        let us = d.as_micros().min(u64::MAX as u128) as u64;
        let mut l = self.latencies.lock();
        if l.len() == LATENCY_CAPACITY {
            l.pop_front();
        }
        l.push_back(us);
    }

    /// min/avg/median/max latency in milliseconds over the recent window.
    fn latency_stats(&self) -> serde_json::Value {
        let mut v: Vec<u64> = self.latencies.lock().iter().copied().collect();
        if v.is_empty() {
            return json!({ "count": 0, "min_ms": 0.0, "avg_ms": 0.0, "median_ms": 0.0, "max_ms": 0.0 });
        }
        v.sort_unstable();
        let n = v.len();
        let to_ms = |us: u64| (us as f64 / 1000.0 * 100.0).round() / 100.0;
        let sum: u128 = v.iter().map(|&x| x as u128).sum();
        let avg_us = (sum / n as u128) as u64;
        let median_us = if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2
        };
        json!({
            "count": n,
            "min_ms": to_ms(v[0]),
            "avg_ms": to_ms(avg_us),
            "median_ms": to_ms(median_us),
            "max_ms": to_ms(v[n - 1]),
        })
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
            "cached": self.counters.cached.load(Ordering::Relaxed),
            "nxdomain": self.counters.nxdomain.load(Ordering::Relaxed),
            "refused": self.counters.refused.load(Ordering::Relaxed),
            "servfail": self.counters.servfail.load(Ordering::Relaxed),
            "blocked": self.counters.blocked.load(Ordering::Relaxed),
            "dangerous": self.counters.dangerous.load(Ordering::Relaxed),
            "dnssec_failures": self.counters.dnssec_failures.load(Ordering::Relaxed),
            "ipv4": self.counters.ipv4.load(Ordering::Relaxed),
            "ipv6": self.counters.ipv6.load(Ordering::Relaxed),
            "by_qtype": by_qtype,
            "qps_10s": (qps_10s * 100.0).round() / 100.0,
            "qps_1m": (qps_1m * 100.0).round() / 100.0,
            "qps_avg": (total as f64 / uptime as f64 * 100.0).round() / 100.0,
            "latency": self.latency_stats(),
            "series_per_sec": series,
            "recent": recent,
            "top_domains": top_n(&self.top_domains.lock()),
            "top_blocked": top_n(&self.top_blocked.lock()),
        })
    }

    /// Render aggregate metrics in Prometheus text exposition format. Only
    /// non-identifying aggregates are exposed (no client IPs or query names).
    pub fn prometheus(&self) -> String {
        let c = &self.counters;
        let now_sec = self.now_sec();
        let (qps_1m, qps_10s) = {
            let s = self.series.lock();
            (s.qps(now_sec, 60), s.qps(now_sec, 10))
        };
        let mut out = String::new();
        let counter = |out: &mut String, name: &str, help: &str, val: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {val}\n"
            ));
        };
        let gauge = |out: &mut String, name: &str, help: &str, val: f64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {val}\n"
            ));
        };

        counter(
            &mut out,
            "nomina_queries_total",
            "Total DNS queries handled.",
            c.total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "nomina_dnssec_validation_failures_total",
            "Upstream answers rejected by DNSSEC validation.",
            c.dnssec_failures.load(Ordering::Relaxed),
        );

        out.push_str("# HELP nomina_queries_by_family Queries by client IP family.\n# TYPE nomina_queries_by_family counter\n");
        out.push_str(&format!(
            "nomina_queries_by_family{{family=\"ipv4\"}} {}\n",
            c.ipv4.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "nomina_queries_by_family{{family=\"ipv6\"}} {}\n",
            c.ipv6.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP nomina_queries_by_outcome Queries by outcome.\n# TYPE nomina_queries_by_outcome counter\n");
        for (label, val) in [
            ("authoritative", c.authoritative.load(Ordering::Relaxed)),
            ("forwarded", c.forwarded.load(Ordering::Relaxed)),
            ("cached", c.cached.load(Ordering::Relaxed)),
            ("nxdomain", c.nxdomain.load(Ordering::Relaxed)),
            ("refused", c.refused.load(Ordering::Relaxed)),
            ("servfail", c.servfail.load(Ordering::Relaxed)),
            ("blocked", c.blocked.load(Ordering::Relaxed)),
        ] {
            out.push_str(&format!(
                "nomina_queries_by_outcome{{outcome=\"{label}\"}} {val}\n"
            ));
        }

        out.push_str("# HELP nomina_queries_by_qtype Queries by record type.\n# TYPE nomina_queries_by_qtype counter\n");
        for (qtype, val) in self.by_qtype.lock().iter() {
            out.push_str(&format!(
                "nomina_queries_by_qtype{{qtype=\"{qtype}\"}} {val}\n"
            ));
        }

        gauge(
            &mut out,
            "nomina_uptime_seconds",
            "Process uptime in seconds.",
            self.uptime_seconds() as f64,
        );
        gauge(
            &mut out,
            "nomina_qps_10s",
            "Queries per second over the last 10s.",
            (qps_10s * 100.0).round() / 100.0,
        );
        gauge(
            &mut out,
            "nomina_qps_1m",
            "Queries per second over the last 60s.",
            (qps_1m * 100.0).round() / 100.0,
        );
        out
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
