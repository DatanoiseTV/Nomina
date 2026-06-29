//! A small TTL answer-cache that sits in front of the upstream resolver.
//!
//! hickory's resolver/recursor cache internally, but expose no hit/miss/size
//! metrics. This edge cache is the source of the dashboard's cache statistics
//! and also short-circuits repeat upstream round-trips for hot names. It is keyed
//! by (lowercased name, record type) and is view-independent: it only ever holds
//! non-authoritative answers, which are identical across split-horizon views.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, Record, RecordType};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

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

    /// Persist the live (non-expired) entries to `path` as JSON, storing each
    /// entry's *remaining* TTL (since `Instant` has no portable meaning). Returns
    /// the number of entries written.
    pub fn save(&self, path: &Path) -> std::io::Result<usize> {
        let now = Instant::now();
        let entries: Vec<Persisted> = self
            .map
            .lock()
            .iter()
            .filter_map(|((name, rtype), e)| {
                let remaining = e.expires.checked_duration_since(now)?.as_secs();
                if remaining == 0 {
                    return None;
                }
                Some(Persisted {
                    name: name.clone(),
                    rtype: *rtype,
                    rcode: e.rcode,
                    ttl: remaining as u32,
                    answers: e.answers.clone(),
                    authority: e.authority.clone(),
                })
            })
            .collect();
        let json = serde_json::to_vec(&entries).map_err(std::io::Error::other)?;
        std::fs::write(path, json)?;
        Ok(entries.len())
    }

    /// Load previously-persisted entries from `path`, re-deriving expiry from the
    /// stored remaining TTL. Missing/corrupt files are ignored (returns 0).
    pub fn load(&self, path: &Path) -> usize {
        let Ok(bytes) = std::fs::read(path) else {
            return 0;
        };
        let Ok(entries) = serde_json::from_slice::<Vec<Persisted>>(&bytes) else {
            return 0;
        };
        let now = Instant::now();
        let mut m = self.map.lock();
        let mut n = 0;
        for p in entries {
            if p.ttl == 0 || m.len() >= self.cap {
                continue;
            }
            m.insert(
                (p.name, p.rtype),
                Entry {
                    answers: p.answers,
                    authority: p.authority,
                    rcode: p.rcode,
                    expires: now + Duration::from_secs(p.ttl as u64),
                },
            );
            n += 1;
        }
        n
    }
}

/// On-disk representation of a cached answer (remaining TTL in seconds).
#[derive(Serialize, Deserialize)]
struct Persisted {
    name: String,
    rtype: RecordType,
    rcode: ResponseCode,
    ttl: u32,
    answers: Vec<Record>,
    authority: Vec<Record>,
}
