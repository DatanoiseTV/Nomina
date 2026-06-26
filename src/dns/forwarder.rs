//! Upstream forwarding + caching for non-authoritative queries.
//!
//! Wraps a hickory [`TokioResolver`] (which provides the cache). It is built
//! from [`Settings`] and can be rebuilt live when settings change.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};

use crate::models::{ForwardProtocol, Settings};

/// The outcome of forwarding one query upstream.
pub struct ForwardResult {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub rcode: ResponseCode,
}

pub struct Forwarder {
    resolver: TokioResolver,
    pub enabled: bool,
}

impl Forwarder {
    /// Build a resolver from the current settings.
    pub fn build(settings: &Settings) -> anyhow::Result<Self> {
        let mut name_servers = Vec::new();
        for f in &settings.forwarders {
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
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());

        let opts: &mut ResolverOpts = builder.options_mut();
        opts.cache_size = settings.cache_size;
        if settings.cache_min_ttl > 0 {
            opts.positive_min_ttl = Some(Duration::from_secs(settings.cache_min_ttl as u64));
        }
        opts.positive_max_ttl = Some(Duration::from_secs(settings.cache_max_ttl as u64));
        opts.negative_max_ttl = Some(Duration::from_secs(settings.cache_max_ttl as u64));
        // Don't append search domains to forwarded queries.
        opts.ndots = 0;

        let resolver = builder.build()?;

        Ok(Self {
            resolver,
            enabled: settings.forward_enabled,
        })
    }

    /// Forward a query upstream. Cache hits are served transparently by the
    /// resolver.
    pub async fn resolve(&self, name: &Name, rtype: RecordType) -> ForwardResult {
        match self.resolver.lookup(name.clone(), rtype).await {
            Ok(lookup) => ForwardResult {
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
                ForwardResult {
                    answers: vec![],
                    authority,
                    rcode: nr.response_code,
                }
            }
            Err(e) => {
                tracing::debug!(%name, ?rtype, "upstream lookup failed: {e}");
                ForwardResult {
                    answers: vec![],
                    authority: vec![],
                    rcode: ResponseCode::ServFail,
                }
            }
        }
    }
}
