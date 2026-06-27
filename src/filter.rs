//! In-memory filtering layer: blocklists, manual allow/deny rules, and DNS
//! rewrites. Built from the database and hot-swapped on change, like the zone
//! store. The query path consults it via [`FilterSet::decide`].

use std::collections::HashSet;
use std::net::IpAddr;

use hickory_proto::rr::Name;
use tracing::warn;

use crate::db::Db;
use crate::models::domain_covers;

/// A rewrite destination.
#[derive(Clone)]
pub enum RewriteTarget {
    Ip(IpAddr),
    Name(Name),
}

/// The decision for a single name.
#[derive(Clone)]
pub enum Decision {
    /// No filter applies; resolve normally.
    Pass,
    /// Explicitly allow-listed; resolve normally and never block.
    Allow,
    /// Sinkhole this name.
    Block,
    /// Answer with a fixed target.
    Rewrite(RewriteTarget),
}

#[derive(Default)]
pub struct FilterSet {
    blocking_enabled: bool,
    /// Exact domains from downloaded blocklists.
    blocked: HashSet<String>,
    /// Manual deny patterns (match domain + subdomains).
    deny_rules: Vec<String>,
    /// Manual allow patterns.
    allow_rules: Vec<String>,
    /// (pattern, target) rewrites.
    rewrites: Vec<(String, RewriteTarget)>,
}

impl FilterSet {
    pub fn load(db: &Db, blocking_enabled: bool) -> anyhow::Result<Self> {
        db.with(|conn| Ok(Self::build_from(conn, blocking_enabled)))
            .map_err(Into::into)
    }

    fn build_from(conn: &rusqlite::Connection, blocking_enabled: bool) -> Self {
        let mut set = FilterSet {
            blocking_enabled,
            ..Default::default()
        };

        for d in Db::enabled_block_domains(conn).unwrap_or_default() {
            set.blocked.insert(d.to_ascii_lowercase());
        }

        for rule in Db::list_block_rules(conn).unwrap_or_default() {
            let d = rule.domain.trim_end_matches('.').to_ascii_lowercase();
            match rule.action {
                crate::models::RuleAction::Deny => set.deny_rules.push(d),
                crate::models::RuleAction::Allow => set.allow_rules.push(d),
            }
        }

        for rw in Db::list_rewrites(conn).unwrap_or_default() {
            if !rw.enabled {
                continue;
            }
            let pattern = rw.domain.trim_end_matches('.').to_ascii_lowercase();
            let target = match rw.target.trim().parse::<IpAddr>() {
                Ok(ip) => RewriteTarget::Ip(ip),
                Err(_) => {
                    let fqdn = if rw.target.ends_with('.') {
                        rw.target.clone()
                    } else {
                        format!("{}.", rw.target.trim())
                    };
                    match Name::from_utf8(&fqdn) {
                        Ok(mut n) => {
                            n.set_fqdn(true);
                            RewriteTarget::Name(n)
                        }
                        Err(e) => {
                            warn!(rewrite = rw.id, "skipping invalid rewrite target: {e}");
                            continue;
                        }
                    }
                }
            };
            set.rewrites.push((pattern, target));
        }

        set
    }

    /// Decide what to do with a name (lowercase, no trailing dot).
    /// Precedence: rewrite > allow > block.
    pub fn decide(&self, name: &str) -> Decision {
        for (pattern, target) in &self.rewrites {
            if domain_covers(pattern, name) {
                return Decision::Rewrite(target.clone());
            }
        }
        if self.allow_rules.iter().any(|p| domain_covers(p, name)) {
            return Decision::Allow;
        }
        if self.blocking_enabled
            && (self.blocked.contains(name) || self.deny_rules.iter().any(|p| domain_covers(p, name)))
            {
                return Decision::Block;
            }
        Decision::Pass
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    pub fn rewrite_count(&self) -> usize {
        self.rewrites.len()
    }
}
