//! A small TTL answer-cache that sits in front of the upstream resolver.
//!
//! hickory's resolver/recursor cache internally, but expose no hit/miss/size
//! metrics. This edge cache is the source of the dashboard's cache statistics
//! and also short-circuits repeat upstream round-trips for hot names. It is keyed
//! by (lowercased name, record type) and is view-independent: it only ever holds
//! non-authoritative answers, which are identical across split-horizon views.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, Record, RecordType};
use parking_lot::Mutex;

/// A cached upstream answer, returned to the resolver on a hit.
#[derive(Clone)]
pub struct CachedAnswer {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub rcode: ResponseCode,
}

struct Entry {
    answers: Vec<Record>,
    authority: Vec<Record>,
    rcode: ResponseCode,
    expires: Instant,
}

pub struct DnsCache {
    map: Mutex<HashMap<(String, RecordType), Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    cap: usize,
    min_ttl: u32,
    max_ttl: u32,
}

/// Negative (NXDOMAIN / NODATA) answers are cached for a short fixed period when
/// the upstream supplies no SOA to derive a TTL from.
const NEGATIVE_TTL: u32 = 30;

impl DnsCache {
    pub fn new(cap: usize, min_ttl: u32, max_ttl: u32) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            cap: cap.max(1),
            min_ttl,
            max_ttl: max_ttl.max(1),
        }
    }

    fn key(name: &Name, rtype: RecordType) -> (String, RecordType) {
        (
            name.to_string().trim_end_matches('.').to_ascii_lowercase(),
            rtype,
        )
    }

    /// Look up a fresh cached answer, recording a hit or miss.
    pub fn get(&self, name: &Name, rtype: RecordType, now: Instant) -> Option<CachedAnswer> {
        let k = Self::key(name, rtype);
        let mut m = self.map.lock();
        if let Some(e) = m.get(&k) {
            if e.expires > now {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(CachedAnswer {
                    answers: e.answers.clone(),
                    authority: e.authority.clone(),
                    rcode: e.rcode,
                });
            }
            m.remove(&k);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Cache an upstream answer. ServFail is never cached (transient); other
    /// rcodes use the smallest record TTL clamped to the configured bounds, or a
    /// short negative TTL when there are no records to derive one from.
    pub fn put(
        &self,
        name: &Name,
        rtype: RecordType,
        answers: &[Record],
        authority: &[Record],
        rcode: ResponseCode,
        now: Instant,
    ) {
        if rcode == ResponseCode::ServFail {
            return;
        }
        let raw_ttl = answers
            .iter()
            .chain(authority.iter())
            .map(|r| r.ttl)
            .min()
            .unwrap_or(NEGATIVE_TTL);
        let ttl = raw_ttl.clamp(self.min_ttl.max(1), self.max_ttl);

        let mut m = self.map.lock();
        if m.len() >= self.cap {
            m.retain(|_, e| e.expires > now);
            if m.len() >= self.cap {
                // Still full of live entries: skip caching rather than evict
                // arbitrarily. The cap is a soft ceiling on memory.
                return;
            }
        }
        m.insert(
            Self::key(name, rtype),
            Entry {
                answers: answers.to_vec(),
                authority: authority.to_vec(),
                rcode,
                expires: now + Duration::from_secs(ttl as u64),
            },
        );
    }

    /// (hits, misses, live-entry count) for the dashboard.
    pub fn stats(&self, now: Instant) -> (u64, u64, usize) {
        let size = self.map.lock().values().filter(|e| e.expires > now).count();
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            size,
        )
    }

    pub fn clear(&self) {
        self.map.lock().clear();
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }
}
