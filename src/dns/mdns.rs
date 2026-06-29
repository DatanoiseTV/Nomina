//! mDNS (multicast DNS) discovery.
//!
//! Passively learns `*.local` hostnames announced on the LAN (and nudges the
//! network with a periodic service-enumeration query), then makes them
//! resolvable as low-TTL records under a configured zone — e.g. `macbook.local`
//! becomes `macbook.<zone>`. The resolver consults [`MdnsRegistry`] for names
//! under that zone before falling through to the authoritative store.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::warn;

const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// Discovered `*.local` hosts (single-label name, lowercase) -> addresses + expiry.
#[derive(Default)]
pub struct MdnsRegistry {
    hosts: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

impl MdnsRegistry {
    pub fn insert(&self, host: &str, ip: IpAddr, ttl: Duration) {
        let mut m = self.hosts.lock();
        let entry = m
            .entry(host.to_ascii_lowercase())
            .or_insert_with(|| (Vec::new(), Instant::now() + ttl));
        entry.1 = Instant::now() + ttl;
        if !entry.0.contains(&ip) {
            entry.0.push(ip);
        }
    }

    /// Fresh addresses of `host` matching the query type (A→v4, AAAA→v6, else all).
    pub fn lookup(&self, host: &str, rtype: RecordType) -> Vec<IpAddr> {
        let m = self.hosts.lock();
        match m.get(&host.to_ascii_lowercase()) {
            Some((ips, exp)) if *exp > Instant::now() => ips
                .iter()
                .copied()
                .filter(|ip| match rtype {
                    RecordType::A => ip.is_ipv4(),
                    RecordType::AAAA => ip.is_ipv6(),
                    _ => true,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Number of currently-fresh hosts.
    pub fn count(&self) -> usize {
        let now = Instant::now();
        self.hosts.lock().values().filter(|(_, e)| *e > now).count()
    }
}

/// Extract (single-label host, address) pairs from the `*.local` A/AAAA records
/// in an mDNS message (answers + additionals).
fn hosts_from_message(msg: &Message) -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    for r in msg.answers.iter().chain(msg.additionals.iter()) {
        let name = r.name.to_string();
        let lower = name.trim_end_matches('.').to_ascii_lowercase();
        let Some(label) = lower.strip_suffix(".local") else {
            continue;
        };
        let label = label.trim_end_matches('.');
        if label.is_empty() || label.contains('.') {
            continue; // only flat hostnames, e.g. "macbook.local"
        }
        let ip = match &r.data {
            RData::A(a) => IpAddr::V4(a.0),
            RData::AAAA(a) => IpAddr::V6(a.0),
            _ => continue,
        };
        out.push((label.to_string(), ip));
    }
    out
}

/// A multicast-DNS service-enumeration query, to prompt responses on the LAN.
fn enumeration_query() -> Vec<u8> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    if let Ok(name) = Name::from_ascii("_services._dns-sd._udp.local.") {
        let mut q = Query::query(name, RecordType::PTR);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
    }
    msg.to_vec().unwrap_or_default()
}

fn bind_socket() -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?; // coexist with a system mDNS responder
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())?;
    sock.join_multicast_v4(&MDNS_V4, &Ipv4Addr::UNSPECIFIED)?;
    UdpSocket::from_std(sock.into())
}

/// Run the mDNS listener: learn hosts from multicast traffic and refresh with a
/// periodic enumeration query. Returns (logs and stops) if the socket can't bind.
pub async fn run(registry: Arc<MdnsRegistry>, ttl: Duration) {
    let sock = match bind_socket() {
        Ok(s) => s,
        Err(e) => {
            warn!("mDNS discovery disabled (cannot bind :5353): {e}");
            return;
        }
    };
    tracing::info!("mDNS discovery listening on 224.0.0.251:5353");
    let dest = SocketAddr::from((MDNS_V4, MDNS_PORT));
    let _ = sock.send_to(&enumeration_query(), dest).await;

    let mut buf = vec![0u8; 4096];
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => match res {
                Ok((n, _src)) => {
                    if let Ok(msg) = Message::from_vec(&buf[..n]) {
                        for (host, ip) in hosts_from_message(&msg) {
                            registry.insert(&host, ip, ttl);
                        }
                    }
                }
                Err(e) => warn!("mDNS recv error: {e}"),
            },
            _ = tick.tick() => {
                let _ = sock.send_to(&enumeration_query(), dest).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::Record;

    #[test]
    fn registry_insert_lookup_and_family() {
        let r = MdnsRegistry::default();
        r.insert("macbook", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), Duration::from_secs(60));
        assert_eq!(r.lookup("MacBook", RecordType::A).len(), 1);
        assert!(r.lookup("macbook", RecordType::AAAA).is_empty());
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn registry_expires() {
        let r = MdnsRegistry::default();
        r.insert("nas", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), Duration::from_millis(0));
        std::thread::sleep(Duration::from_millis(5));
        assert!(r.lookup("nas", RecordType::A).is_empty());
    }

    #[test]
    fn parses_local_a_records() {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("macbook.local.").unwrap(),
            120,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 7))),
        ));
        // A service instance (multi-label under .local) must be ignored.
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("printer._http._tcp.local.").unwrap(),
            120,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 8))),
        ));
        let hosts = hosts_from_message(&msg);
        assert_eq!(hosts, vec![("macbook".to_string(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)))]);
    }
}
