//! Conditional forwarding: queries under a configured domain (and its
//! subdomains) go to a dedicated set of upstreams instead of the global
//! resolver. Built from the database and hot-swapped like the other in-memory
//! structures.

use std::sync::Arc;

use crate::db::Db;
use crate::dns::upstream::{Upstream, build_forward_resolver};
use crate::models::{Settings, domain_covers};

struct Rule {
    domain: String,
    label_count: usize,
    upstream: Arc<Upstream>,
}

#[derive(Default)]
pub struct ConditionalSet {
    rules: Vec<Rule>,
}

impl ConditionalSet {
    /// Build from the database. Per-rule resolvers reuse the global cache
    /// settings. Invalid rules are logged and skipped.
    pub fn load(db: &Db, settings: &Settings) -> anyhow::Result<Self> {
        db.with(|conn| Ok(Self::build_from(conn, settings)))
            .map_err(Into::into)
    }

    fn build_from(conn: &mut diesel::sqlite::SqliteConnection, settings: &Settings) -> Self {
        let mut rules = Vec::new();
        for cf in Db::list_conditional_forwards(conn).unwrap_or_default() {
            if !cf.enabled || cf.forwarders.is_empty() {
                continue;
            }
            let domain = cf.domain.trim_end_matches('.').to_ascii_lowercase();
            match build_forward_resolver(&cf.forwarders, settings) {
                Ok(resolver) => rules.push(Rule {
                    label_count: domain.split('.').count(),
                    domain,
                    upstream: Arc::new(Upstream::Forward(Box::new(resolver))),
                }),
                Err(e) => {
                    tracing::warn!(domain = %cf.domain, "skipping conditional forward: {e}");
                }
            }
        }
        // Most-specific (longest) domain wins.
        rules.sort_by_key(|r| std::cmp::Reverse(r.label_count));
        Self { rules }
    }

    /// The dedicated upstream for `name` (lowercase, no trailing dot), if any rule
    /// covers it.
    pub fn match_for(&self, name: &str) -> Option<Arc<Upstream>> {
        self.rules
            .iter()
            .find(|r| domain_covers(&r.domain, name))
            .map(|r| r.upstream.clone())
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}
