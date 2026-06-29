//! mDNS (multicast DNS) discovery.
//!
//! Passively learns `*.local` hostnames announced on the LAN (and nudges the
//! network with a periodic service-enumeration query), then makes them
//! resolvable as low-TTL records under a configured zone — e.g. `macbook.local`
//! becomes `macbook.<zone>`. The resolver consults [`MdnsRegistry`] for names
//! under that zone before falling through to the authoritative store.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::warn;

const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
/// DNS-SD meta-query: "what service types exist on this link?"
const SERVICES_META: &str = "_services._dns-sd._udp.local.";
/// Cap on the dedup set of already-queried names, to bound memory.
const QUERIED_CAP: usize = 4096;

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

    /// Reverse lookup: the host label that currently owns `ip`, if any (fresh).
    pub fn reverse(&self, ip: &IpAddr) -> Option<String> {
        let now = Instant::now();
        self.hosts
            .lock()
            .iter()
            .find(|(_, (ips, exp))| *exp > now && ips.contains(ip))
            .map(|(host, _)| host.clone())
    }

    /// Forget all discovered hosts (used when mDNS is disabled at runtime).
    pub fn clear(&self) {
        self.hosts.lock().clear();
    }

    /// Number of currently-fresh hosts.
    pub fn count(&self) -> usize {
        let now = Instant::now();
        self.hosts.lock().values().filter(|(_, e)| *e > now).count()
    }

    /// Snapshot of currently-fresh hosts: (host label, addresses, seconds left).
    /// Sorted by host name for stable display.
    pub fn snapshot(&self) -> Vec<(String, Vec<IpAddr>, u64)> {
        let now = Instant::now();
        let mut out: Vec<(String, Vec<IpAddr>, u64)> = self
            .hosts
            .lock()
            .iter()
            .filter(|(_, (_, exp))| *exp > now)
            .map(|(host, (ips, exp))| {
                (host.clone(), ips.clone(), exp.saturating_duration_since(now).as_secs())
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
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

/// Is `ip` usable on the local network (private/ULA/link-local/loopback) rather
/// than a globally-routable public address?
pub fn is_lan_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            let o = v6.octets();
            let ula = (o[0] & 0xfe) == 0xfc; // fc00::/7 (unique local)
            let link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80; // fe80::/10
            ula || link_local
        }
    }
}

/// Build a multicast-DNS query carrying one or more questions. Class is left as
/// plain `IN` (QM, the top "unicast-response" bit clear) so responders answer on
/// multicast — where this passive listener can snoop the addresses.
fn query_for(questions: &[(Name, RecordType)]) -> Vec<u8> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    for (name, rtype) in questions {
        let mut q = Query::query(name.clone(), *rtype);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
    }
    msg.to_vec().unwrap_or_default()
}

/// The single-question service-enumeration query that kicks off discovery.
fn enumeration_query() -> Vec<u8> {
    match Name::from_ascii(SERVICES_META) {
        Ok(name) => query_for(&[(name, RecordType::PTR)]),
        Err(_) => Vec::new(),
    }
}

/// Walk a received message and decide which follow-up questions to ask so more
/// hosts get pulled onto multicast where we can snoop their addresses:
///   `_services._dns-sd._udp.local` PTR -> service type
///   `<service-type>.local`         PTR -> service instance
///   `<service-instance>`           SRV -> target hostname (then A/AAAA)
/// Plus: any `<host>.local` address question another client asks (service-less
/// hosts like a Raspberry Pi never appear in the DNS-SD graph, but they do
/// answer a direct query — so re-issuing it as a multicast query surfaces them).
/// `queried` dedups so we don't re-ask the same (name,type) within a cycle.
fn follow_up_questions(msg: &Message, queried: &mut HashSet<String>) -> Vec<(Name, RecordType)> {
    let mut out = Vec::new();
    let mut want = |name: Name, rtype: RecordType, out: &mut Vec<(Name, RecordType)>| {
        let key = format!("{}|{rtype}", name.to_string().to_ascii_lowercase());
        if queried.len() < QUERIED_CAP && queried.insert(key) {
            out.push((name, rtype));
        }
    };
    for r in msg.answers.iter().chain(msg.additionals.iter()) {
        match &r.data {
            RData::PTR(ptr) => {
                let target = (**ptr).clone();
                let owner = r.name.to_string().trim_end_matches('.').to_ascii_lowercase();
                if owner == SERVICES_META.trim_end_matches('.') {
                    // Enumerated a service *type*: browse it for instances.
                    want(target, RecordType::PTR, &mut out);
                } else {
                    // A service *instance*: resolve it to a host via SRV.
                    want(target, RecordType::SRV, &mut out);
                }
            }
            RData::SRV(srv) => {
                // Got the target hostname: ask for its addresses directly.
                let host = srv.target.clone();
                want(host.clone(), RecordType::A, &mut out);
                want(host, RecordType::AAAA, &mut out);
            }
            _ => {}
        }
    }
    // Re-issue address questions other clients ask for flat `*.local` hosts.
    for q in msg.queries.iter() {
        if !matches!(q.query_type(), RecordType::A | RecordType::AAAA | RecordType::ANY) {
            continue;
        }
        if is_flat_local(q.name()) {
            want(q.name().clone(), RecordType::A, &mut out);
            want(q.name().clone(), RecordType::AAAA, &mut out);
        }
    }
    out
}

/// True for a single-label `*.local` name (e.g. `rpi5.local`), the shape of a
/// plain mDNS hostname (as opposed to a service instance or type).
fn is_flat_local(name: &Name) -> bool {
    let s = name.to_string();
    let s = s.trim_end_matches('.').to_ascii_lowercase();
    match s.strip_suffix(".local") {
        Some(label) => !label.is_empty() && !label.contains('.'),
        None => false,
    }
}

fn bind_socket() -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?; // coexist with a system mDNS responder
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())?;

    // Join the group on every multicast-capable IPv4 interface, not just the
    // default. On a multi-homed host (VPNs, bridges, virtual NICs), an
    // INADDR_ANY join can land on the wrong interface and miss the real LAN —
    // so explicitly join each one. The INADDR_ANY join is the baseline.
    let _ = sock.join_multicast_v4(&MDNS_V4, &Ipv4Addr::UNSPECIFIED);
    let mut joined = 0u32;
    for ifaddr in lan_interface_addrs() {
        if sock.join_multicast_v4(&MDNS_V4, &ifaddr).is_ok() {
            joined += 1;
        }
    }
    tracing::debug!("mDNS joined group on {joined} interface(s)");
    UdpSocket::from_std(sock.into())
}

/// IPv4 addresses of every up, multicast-capable, non-loopback interface — used
/// as the local-interface selector for IGMP joins.
fn lan_interface_addrs() -> Vec<Ipv4Addr> {
    use nix::ifaddrs::getifaddrs;
    use nix::net::if_::InterfaceFlags;
    let mut out = Vec::new();
    let Ok(iter) = getifaddrs() else { return out };
    for ifa in iter {
        if !ifa.flags.contains(InterfaceFlags::IFF_UP)
            || !ifa.flags.contains(InterfaceFlags::IFF_MULTICAST)
            || ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK)
        {
            continue;
        }
        if let Some(sin) = ifa.address.and_then(|a| a.as_sockaddr_in().copied()) {
            let ip = sin.ip();
            if !ip.is_unspecified() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Supervise the mDNS listener against the runtime setting: start it when mDNS
/// is enabled, stop it (and forget discovered hosts) when disabled. Polls the
/// setting so toggling it in the UI takes effect within a couple of seconds with
/// no restart. Spawned once at startup regardless of the initial setting.
pub async fn supervise(state: crate::state::SharedState) {
    let mut handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut last_public = state.mdns_publish_public();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let enabled = state.mdns_enabled();
        let running = handle.as_ref().is_some_and(|h| !h.is_finished());
        match (running, enabled) {
            (false, true) => {
                handle = Some(tokio::spawn(run(state.clone())));
            }
            (true, false) => {
                if let Some(h) = handle.take() {
                    h.abort();
                }
                state.mdns().clear();
            }
            _ => {}
        }
        // If the LAN-only/public policy changed, drop the registry so it
        // re-learns under the new rule (instead of lingering until TTL expiry).
        let pub_now = state.mdns_publish_public();
        if pub_now != last_public {
            last_public = pub_now;
            state.mdns().clear();
        }
    }
}

/// Run the mDNS listener: learn hosts from multicast traffic and actively walk
/// the DNS-SD chain to pull addresses onto the wire. Returns (logs and stops) if
/// the socket can't bind. Records are inserted with the live configured TTL.
pub async fn run(state: crate::state::SharedState) {
    let registry = state.mdns();
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

    // Names we have already asked about this cycle; cleared on each tick so the
    // chain is re-walked periodically (and freed hosts get re-confirmed).
    let mut queried: HashSet<String> = HashSet::new();
    let mut buf = vec![0u8; 9000];
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => match res {
                Ok((n, src)) => {
                    let Ok(msg) = Message::from_vec(&buf[..n]) else { continue };
                    // Passive harvest: learn any *.local host addresses present.
                    // By default only LAN-scoped addresses are republished; the
                    // operator can opt in to public addresses too.
                    let ttl = Duration::from_secs(state.mdns_ttl() as u64);
                    let publish_public = state.mdns_publish_public();
                    for (host, ip) in hosts_from_message(&msg) {
                        if publish_public || is_lan_addr(&ip) {
                            registry.insert(&host, ip, ttl);
                        }
                    }
                    // Active chase: advance the DNS-SD chain toward addresses.
                    let follow = follow_up_questions(&msg, &mut queried);
                    if !follow.is_empty() {
                        // Chunk to keep individual query packets small.
                        for batch in follow.chunks(16) {
                            let _ = sock.send_to(&query_for(batch), dest).await;
                        }
                        tracing::debug!("mDNS rx {n}B from {src}: asked {} follow-up(s)", follow.len());
                    }
                }
                Err(e) => warn!("mDNS recv error: {e}"),
            },
            _ = tick.tick() => {
                queried.clear();
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

    #[test]
    fn lan_filter_drops_public_addrs() {
        use std::net::Ipv6Addr;
        // Private/ULA/link-local/loopback are LAN-scoped.
        assert!(is_lan_addr(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));
        assert!(is_lan_addr(&IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
        assert!(is_lan_addr(&"fd24:b546::1".parse::<Ipv6Addr>().unwrap().into()));
        assert!(is_lan_addr(&"fe80::1".parse::<Ipv6Addr>().unwrap().into()));
        // Public addresses are not.
        assert!(!is_lan_addr(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_lan_addr(&"2a02:8109::1".parse::<Ipv6Addr>().unwrap().into()));
    }

    #[test]
    fn extraction_is_policy_agnostic() {
        // hosts_from_message extracts every *.local single-label A/AAAA; the
        // LAN-only-vs-public decision is applied by the caller via is_lan_addr.
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        let public: std::net::Ipv6Addr = "2a02:8109::5".parse().unwrap();
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("macbook.local.").unwrap(),
            120,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(public)),
        ));
        let hosts = hosts_from_message(&msg);
        assert_eq!(hosts, vec![("macbook".to_string(), IpAddr::V6(public))]);
        assert!(!is_lan_addr(&hosts[0].1)); // ...but the caller would skip it
    }

    #[test]
    fn reverse_lookup() {
        let r = MdnsRegistry::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        r.insert("macbook", ip, Duration::from_secs(60));
        assert_eq!(r.reverse(&ip).as_deref(), Some("macbook"));
        assert!(r.reverse(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
    }
}
