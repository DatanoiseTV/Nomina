//! Upstream resolution for non-authoritative names. Either forwards to the
//! configured resolvers (with caching) or resolves recursively from the root
//! servers, depending on [`ResolutionMode`].

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions};

use crate::models::{ForwardProtocol, Forwarder, ResolutionMode, Settings, ROOT_SERVERS};

/// The result of resolving a query upstream.
pub struct UpstreamResult {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub rcode: ResponseCode,
}

/// An upstream resolver: either a forwarding stub resolver or a recursive
/// resolver rooted at the DNS root servers.
pub enum Upstream {
    Forward(Box<TokioResolver>),
    Recurse(Box<Recursor<TokioRuntimeProvider>>),
}

impl Upstream {
    /// Build the upstream from settings. Returns `None` for authoritative-only
    /// mode (`ResolutionMode::Off`).
    #[allow(clippy::field_reassign_with_default)] // RecursorOptions is non-exhaustive
    pub fn build(settings: &Settings) -> anyhow::Result<Option<Self>> {
        match settings.resolution_mode {
            ResolutionMode::Off => Ok(None),
            ResolutionMode::Forward => Ok(Some(Upstream::Forward(Box::new(
                build_forward_resolver(&settings.forwarders, settings)?,
            )))),
            ResolutionMode::Recursive => {
                let roots: Vec<IpAddr> = ROOT_SERVERS
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                let mut opts = RecursorOptions::default();
                opts.response_cache_size = settings.cache_size;
                // Validate from the built-in IANA root trust anchor when enabled;
                // otherwise stay security-unaware (the default).
                let policy = if settings.dnssec_validate_upstream {
                    DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default())
                } else {
                    DnssecPolicy::SecurityUnaware
                };
                let recursor = Recursor::new(
                    &roots,
                    policy,
                    None,
                    opts,
                    TokioRuntimeProvider::default(),
                )
                .map_err(|e| anyhow::anyhow!("building recursor: {e}"))?;
                Ok(Some(Upstream::Recurse(Box::new(recursor))))
            }
        }
    }

    pub async fn resolve(&self, name: &Name, rtype: RecordType) -> UpstreamResult {
        match self {
            Upstream::Forward(resolver) => Self::resolve_forward(resolver, name, rtype).await,
            Upstream::Recurse(recursor) => Self::resolve_recurse(recursor, name, rtype).await,
        }
    }

    async fn resolve_forward(
        resolver: &TokioResolver,
        name: &Name,
        rtype: RecordType,
    ) -> UpstreamResult {
        match resolver.lookup(name.clone(), rtype).await {
            Ok(lookup) => UpstreamResult {
                answers: lookup.answers().to_vec(),
                authority: lookup.authorities().to_vec(),
                rcode: ResponseCode::NoError,
            },
            Err(NetError::Dns(DnsError::NoRecordsFound(nr))) => {
                let authority = nr
                    .soa
                    .as_ref()
                    .map(|soa| vec![soa.as_ref().clone().into_record_of_rdata()])
                    .unwrap_or_default();
                UpstreamResult {
                    answers: vec![],
                    authority,
                    rcode: nr.response_code,
                }
            }
            Err(e) => {
                tracing::debug!(%name, ?rtype, "upstream forward failed: {e}");
                UpstreamResult {
                    answers: vec![],
                    authority: vec![],
                    rcode: ResponseCode::ServFail,
                }
            }
        }
    }

    async fn resolve_recurse(
        recursor: &Recursor<TokioRuntimeProvider>,
        name: &Name,
        rtype: RecordType,
    ) -> UpstreamResult {
        let mut q = name.clone();
        q.set_fqdn(true);
        let query = Query::query(q, rtype);
        match recursor.resolve(query, Instant::now(), false).await {
            Ok(msg) => UpstreamResult {
                answers: msg.answers.clone(),
                authority: msg.authorities.clone(),
                rcode: msg.response_code,
            },
            Err(e) => {
                tracing::debug!(%name, ?rtype, "recursive resolution failed: {e}");
                UpstreamResult {
                    answers: vec![],
                    authority: vec![],
                    rcode: ResponseCode::ServFail,
                }
            }
        }
    }
}

/// Build a forwarding stub resolver from an explicit set of upstreams (used by
/// both the global forwarder and per-domain conditional forwarders).
pub fn build_forward_resolver(
    forwarders: &[Forwarder],
    settings: &Settings,
) -> anyhow::Result<TokioResolver> {
    let mut name_servers = Vec::new();
    for f in forwarders {
        let ip: IpAddr = match f.addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                tracing::warn!(addr = %f.addr, "skipping invalid forwarder address: {e}");
                continue;
            }
        };
        let mut connections = Vec::new();
        match f.protocol {
            ForwardProtocol::Udp => {
                let mut udp = ConnectionConfig::udp();
                udp.port = f.port;
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = f.port;
                connections.push(udp);
                connections.push(tcp);
            }
            ForwardProtocol::Tcp => {
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = f.port;
                connections.push(tcp);
            }
            ForwardProtocol::Tls => {
                let name = f.tls_name.clone().unwrap_or_else(|| f.addr.clone());
                let mut c = ConnectionConfig::tls(Arc::from(name.as_str()));
                c.port = f.port;
                connections.push(c);
            }
            ForwardProtocol::Https => {
                let name = f.tls_name.clone().unwrap_or_else(|| f.addr.clone());
                let mut c = ConnectionConfig::https(Arc::from(name.as_str()), None);
                c.port = f.port;
                connections.push(c);
            }
        }
        name_servers.push(NameServerConfig::new(ip, true, connections));
    }

    if name_servers.is_empty() {
        anyhow::bail!("no valid forwarders configured");
    }

    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    let opts: &mut ResolverOpts = builder.options_mut();
    opts.cache_size = settings.cache_size;
    if settings.cache_min_ttl > 0 {
        opts.positive_min_ttl = Some(Duration::from_secs(settings.cache_min_ttl as u64));
    }
    opts.positive_max_ttl = Some(Duration::from_secs(settings.cache_max_ttl as u64));
    opts.negative_max_ttl = Some(Duration::from_secs(settings.cache_max_ttl as u64));
    opts.ndots = 0;
    // DNSSEC validation against the built-in IANA root trust anchor. When on,
    // bogus answers are rejected and surface to the client as SERVFAIL.
    opts.validate = settings.dnssec_validate_upstream;
    Ok(builder.build()?)
}
