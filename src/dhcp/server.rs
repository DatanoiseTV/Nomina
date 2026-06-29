//! DHCP serving layer: binds the v4/v6 sockets, answers clients, persists
//! leases, registers DNS, and replies on the wire.
//!
//! Binding happens while still privileged (ports 67/547 are privileged); the
//! serving loops run after privilege drop, mirroring [`crate::dns::server`].
//!
//! The reply *construction* is split into pure functions ([`build_v4_reply`],
//! [`build_v6_reply`], [`select_v4_scope`], [`subnet_mask_v4`],
//! [`merge_options`]) so the wire format and policy are unit-testable without a
//! socket. The async loops are thin glue over those plus the lease engine.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::db::Db;
use crate::dhcp::lease;
use crate::dhcp::options::encode_option;
use crate::dhcp::v4::{Dhcp4Message, Dhcp4MessageType};
use crate::dhcp::v6::{Dhcp6Message, Dhcp6MessageType, IaAddress, IaNa, duid_ll, encode_ia_na};
use crate::models::{DhcpOption, DhcpScope, IpFamily, LeaseState};
use crate::state::SharedState;

/// How long a DHCPOFFER / ADVERTISE reservation is held before the client must
/// confirm with a REQUEST. Capped to the scope lease time for tiny leases.
const OFFER_HOLD_SECS: u32 = 120;

/// DHCPv4 client port (replies for un-relayed clients go here).
const V4_CLIENT_PORT: u16 = 68;
/// DHCPv4 relay/server port (replies via a relay go here).
const V4_RELAY_PORT: u16 = 67;
/// DHCPv6 client port (replies go to the source IP on this port).
const V6_CLIENT_PORT: u16 = 546;

/// Pre-bound DHCP sockets. Binding happens while privileged; the serving loops
/// run after privilege drop.
pub struct DhcpSockets {
    v4: Vec<(SocketAddr, Option<RecvIface>, UdpSocket)>,
    v6: Vec<(SocketAddr, UdpSocket)>,
}

impl DhcpSockets {
    /// Whether any listener is configured (the server is otherwise a no-op).
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Bind all configured DHCPv4/DHCPv6 sockets. Call before dropping privileges.
/// Returns empty socket sets (a no-op server) when nothing is configured.
///
/// `scope_interfaces` are the distinct interface names that enabled DHCPv4 scopes
/// are pinned to (from the DB). On Linux each gets its own SO_BINDTODEVICE socket
/// so directly-connected (non-relayed) VLAN clients select the right scope; the
/// global `config.dhcp.v4_listen` sockets remain for relayed/untagged traffic.
pub fn bind(config: &Config, scope_interfaces: &[String]) -> anyhow::Result<DhcpSockets> {
    let mut v4 = Vec::new();
    for addr in &config.dhcp.v4_listen {
        let sock = bind_v4(*addr).with_context(|| format!("binding DHCPv4 {addr}"))?;
        v4.push((*addr, None, sock));
    }
    let bind_all = SocketAddr::from((Ipv4Addr::UNSPECIFIED, V4_RELAY_PORT));
    for name in scope_interfaces {
        match bind_v4_device(name) {
            Ok((sock, addr)) => {
                tracing::info!("DHCPv4 bound to interface {name}");
                v4.push((bind_all, Some(RecvIface { name: name.clone(), addr }), sock));
            }
            Err(e) => tracing::warn!("DHCPv4: cannot bind to interface {name}: {e}"),
        }
    }
    let mut v6 = Vec::new();
    for addr in &config.dhcp.v6_listen {
        let sock = bind_v6(*addr).with_context(|| format!("binding DHCPv6 {addr}"))?;
        v6.push((*addr, sock));
    }
    Ok(DhcpSockets { v4, v6 })
}

/// Bind a broadcast-capable DHCPv4 socket pinned to a network interface (Linux
/// SO_BINDTODEVICE). `target` is either an interface name (`eth0.20`) or an IPv4
/// address on that interface (`192.168.20.1`) — an IP is resolved to its owning
/// interface so binding stays broadcast-correct (a socket bound to a plain
/// unicast IP would not receive broadcast DISCOVERs). Returns the socket and the
/// interface's IPv4 address (for subnet-based scope selection).
///
/// Interface binding is Linux-only; elsewhere this returns an error and the
/// scope falls back to relay / first-scope selection on the global listener.
fn bind_v4_device(target: &str) -> anyhow::Result<(UdpSocket, Option<Ipv4Addr>)> {
    #[cfg(target_os = "linux")]
    {
        let (ifname, addr) = resolve_bind_target(target)
            .ok_or_else(|| anyhow::anyhow!("no interface matches '{target}'"))?;
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.set_broadcast(true)?;
        sock.set_nonblocking(true)?;
        sock.bind_device(Some(ifname.as_bytes()))?;
        sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, V4_RELAY_PORT)).into())?;
        let udp = UdpSocket::from_std(sock.into())?;
        Ok((udp, addr))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
        anyhow::bail!("per-interface DHCP binding requires Linux (SO_BINDTODEVICE)")
    }
}

/// Resolve a bind target (interface name or IPv4 address) to (interface name,
/// interface address). An IP is matched to the interface that owns it.
#[cfg(target_os = "linux")]
fn resolve_bind_target(target: &str) -> Option<(String, Option<Ipv4Addr>)> {
    use nix::ifaddrs::getifaddrs;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        let iter = getifaddrs().ok()?;
        for ifa in iter {
            if let Some(sin) = ifa.address.and_then(|a| a.as_sockaddr_in().copied()) {
                if sin.ip() == ip {
                    return Some((ifa.interface_name, Some(ip)));
                }
            }
        }
        None
    } else {
        Some((target.to_string(), interface_ipv4(target)))
    }
}

/// The first IPv4 address assigned to interface `name`, if any.
#[cfg(target_os = "linux")]
fn interface_ipv4(name: &str) -> Option<Ipv4Addr> {
    use nix::ifaddrs::getifaddrs;
    let iter = getifaddrs().ok()?;
    for ifa in iter {
        if ifa.interface_name != name {
            continue;
        }
        if let Some(sin) = ifa.address.and_then(|a| a.as_sockaddr_in().copied()) {
            return Some(sin.ip());
        }
    }
    None
}

/// Bind a broadcast-capable IPv4 UDP socket (SO_REUSEADDR + SO_BROADCAST). The
/// broadcast option is required because un-relayed replies go to
/// 255.255.255.255 rather than using raw-socket unicast-with-manual-ARP.
fn bind_v4(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Bind an IPv6-only UDP socket for the DHCPv6 server port.
fn bind_v6(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(true)?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Spawn the per-socket serving loops. Returns immediately; the loops run as
/// detached tasks for the life of the process. A no-op when nothing is bound.
pub async fn run(state: SharedState, sockets: DhcpSockets) {
    for (addr, iface, sock) in sockets.v4 {
        match &iface {
            Some(ic) => tracing::info!("DHCPv4 listening on {addr} (interface {})", ic.name),
            None => tracing::info!("DHCPv4 listening on {addr}"),
        }
        let st = state.clone();
        tokio::spawn(async move { v4_loop(st, addr, iface, sock).await });
    }
    for (addr, sock) in sockets.v6 {
        tracing::info!("DHCPv6 listening on {addr}");
        let st = state.clone();
        tokio::spawn(async move { v6_loop(st, addr, sock).await });
    }
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// DHCPv4 serving loop
// ---------------------------------------------------------------------------

async fn v4_loop(state: SharedState, addr: SocketAddr, iface: Option<RecvIface>, sock: UdpSocket) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 1500];
    loop {
        let n = match sock.recv_from(&mut buf).await {
            Ok((n, _src)) => n,
            Err(e) => {
                tracing::warn!("DHCPv4 recv on {addr}: {e}");
                continue;
            }
        };
        let msg = match Dhcp4Message::parse(&buf[..n]) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("DHCPv4 parse error: {e}");
                continue;
            }
        };
        if let Err(e) = handle_v4(&state, &sock, iface.as_ref(), &msg).await {
            tracing::warn!("DHCPv4 handling error: {e}");
        }
    }
}

/// The DHCPv4 client identifier: option 61 (Client Identifier) as hex when
/// present, otherwise the hardware address. Reservations are keyed by the same
/// value, so an admin keying a reservation by MAC matches clients that omit
/// option 61 (the common case).
fn v4_client_id(msg: &Dhcp4Message) -> String {
    match msg.client_id() {
        Some(id) if !id.is_empty() => id.iter().map(|b| format!("{b:02x}")).collect(),
        _ => msg.client_mac(),
    }
}

async fn handle_v4(
    state: &SharedState,
    sock: &UdpSocket,
    iface: Option<&RecvIface>,
    msg: &Dhcp4Message,
) -> anyhow::Result<()> {
    let Some(mtype) = msg.message_type() else {
        tracing::debug!("DHCPv4: no message type (option 53); ignoring");
        return Ok(());
    };

    let scopes = state.db.run(Db::list_dhcp_scopes).await?;
    let Some(scope) = select_v4_scope(&scopes, msg.giaddr, iface).cloned() else {
        tracing::debug!(
            "DHCPv4 {mtype:?}: no matching scope for giaddr {}",
            msg.giaddr
        );
        return Ok(());
    };
    let sid = scope.id;
    let reservations = state
        .db
        .run(move |c| Db::list_dhcp_reservations(c, sid))
        .await?;
    let leases = state
        .db
        .run(move |c| Db::list_dhcp_leases(c, Some(sid)))
        .await?;

    let cid = v4_client_id(msg);
    let now = now_unix();

    match mtype {
        Dhcp4MessageType::Discover => {
            let req_ip = msg.requested_ip().map(IpAddr::V4);
            let Some(IpAddr::V4(yiaddr)) =
                lease::allocate(&scope, &reservations, &leases, &cid, req_ip, now)
            else {
                tracing::info!("DHCPv4 DISCOVER from {cid}: pool exhausted, no offer");
                return Ok(());
            };
            let merged = merged_for_client(&scope, &reservations, &cid);
            let reply = build_v4_reply(msg, &scope, &merged, yiaddr, Dhcp4MessageType::Offer);
            // Hold the offer briefly so a slow client can still REQUEST it.
            let hold = scope.lease_secs.min(OFFER_HOLD_SECS) as i64;
            persist_v4_lease(
                state,
                &scope,
                yiaddr,
                &cid,
                msg.hostname(),
                now,
                now + hold,
                LeaseState::Offered,
            )
            .await?;
            send_v4(sock, &reply, v4_reply_dest(msg, false)).await?;
        }
        Dhcp4MessageType::Request => {
            let req_ip = msg.requested_ip().map(IpAddr::V4);
            let alloc = lease::allocate(&scope, &reservations, &leases, &cid, req_ip, now);
            // The address the client wants: explicit option 50, else (on renew)
            // its current address in ciaddr.
            let desired = msg
                .requested_ip()
                .or_else(|| (msg.ciaddr != Ipv4Addr::UNSPECIFIED).then_some(msg.ciaddr));
            match alloc {
                Some(IpAddr::V4(yiaddr)) if desired.is_none_or(|d| d == yiaddr) => {
                    let merged = merged_for_client(&scope, &reservations, &cid);
                    let reply = build_v4_reply(msg, &scope, &merged, yiaddr, Dhcp4MessageType::Ack);
                    let exp = now + scope.lease_secs as i64;
                    persist_v4_lease(
                        state,
                        &scope,
                        yiaddr,
                        &cid,
                        msg.hostname(),
                        now,
                        exp,
                        LeaseState::Active,
                    )
                    .await?;
                    send_v4(sock, &reply, v4_reply_dest(msg, false)).await?;
                    register_dns(state, &scope, IpAddr::V4(yiaddr), msg.hostname()).await;
                }
                _ => {
                    let reply = build_v4_reply(
                        msg,
                        &scope,
                        &[],
                        Ipv4Addr::UNSPECIFIED,
                        Dhcp4MessageType::Nak,
                    );
                    send_v4(sock, &reply, v4_reply_dest(msg, true)).await?;
                }
            }
        }
        Dhcp4MessageType::Release => {
            release_v4_lease(state, &leases, &cid, LeaseState::Released).await?;
        }
        Dhcp4MessageType::Decline => {
            release_v4_lease(state, &leases, &cid, LeaseState::Declined).await?;
        }
        Dhcp4MessageType::Inform => {
            // Configuration only: no address allocation, no lease, no yiaddr.
            let merged = merged_for_client(&scope, &reservations, &cid);
            let reply = build_v4_reply(
                msg,
                &scope,
                &merged,
                Ipv4Addr::UNSPECIFIED,
                Dhcp4MessageType::Ack,
            );
            send_v4(sock, &reply, v4_reply_dest(msg, false)).await?;
        }
        // OFFER/ACK/NAK are server→client; we never receive them.
        other => tracing::debug!("DHCPv4: ignoring {other:?}"),
    }
    Ok(())
}

/// Persist a v4 lease for `(scope, ip)`.
#[allow(clippy::too_many_arguments)]
async fn persist_v4_lease(
    state: &SharedState,
    scope: &DhcpScope,
    ip: Ipv4Addr,
    cid: &str,
    hostname: Option<String>,
    starts: i64,
    expires: i64,
    st: LeaseState,
) -> anyhow::Result<()> {
    let sid = scope.id;
    let ip = ip.to_string();
    let cid = cid.to_string();
    let starts = rfc3339(starts);
    let expires = rfc3339(expires);
    state
        .db
        .run(move |c| {
            Db::upsert_dhcp_lease(
                c,
                sid,
                IpFamily::V4,
                &ip,
                &cid,
                hostname.as_deref(),
                &starts,
                &expires,
                st,
            )
            .map(|_| ())
        })
        .await?;
    Ok(())
}

/// Mark this client's lease(s) for RELEASE or DECLINE. RELEASE frees the address
/// (delete the row); DECLINE keeps the lease marked `declined` so an admin can
/// see the address conflict the client reported.
async fn release_v4_lease(
    state: &SharedState,
    leases: &[crate::models::DhcpLease],
    cid: &str,
    st: LeaseState,
) -> anyhow::Result<()> {
    let mine: Vec<crate::models::DhcpLease> = leases
        .iter()
        .filter(|l| l.identifier.eq_ignore_ascii_case(cid))
        .cloned()
        .collect();
    if mine.is_empty() {
        return Ok(());
    }
    state
        .db
        .run(move |c| {
            for l in &mine {
                if st == LeaseState::Released {
                    Db::delete_dhcp_lease(c, l.id)?;
                } else {
                    Db::upsert_dhcp_lease(
                        c,
                        l.scope_id,
                        l.family,
                        &l.ip,
                        &l.identifier,
                        l.hostname.as_deref(),
                        &l.starts_at,
                        &l.expires_at,
                        LeaseState::Declined,
                    )?;
                }
            }
            Ok(())
        })
        .await?;
    Ok(())
}

/// Send a v4 reply, logging (not propagating) a transient socket error.
async fn send_v4(sock: &UdpSocket, bytes: &[u8], dest: SocketAddr) -> anyhow::Result<()> {
    sock.send_to(bytes, dest)
        .await
        .with_context(|| format!("sending DHCPv4 reply to {dest}"))?;
    Ok(())
}

/// Where a DHCPv4 reply is addressed (RFC 2131 §4.1, simplified for a
/// single-segment server — we never do raw-socket unicast-with-manual-ARP):
/// - via a relay (giaddr set) → the relay on port 67;
/// - a renewing client (ciaddr set) → that unicast address on port 68;
/// - otherwise broadcast to 255.255.255.255:68 (needs SO_BROADCAST).
///
/// NAK has no usable client address, so it always broadcasts unless relayed.
fn v4_reply_dest(req: &Dhcp4Message, is_nak: bool) -> SocketAddr {
    let broadcast = SocketAddr::from(([255, 255, 255, 255], V4_CLIENT_PORT));
    if req.giaddr != Ipv4Addr::UNSPECIFIED {
        return SocketAddr::new(IpAddr::V4(req.giaddr), V4_RELAY_PORT);
    }
    if is_nak {
        return broadcast;
    }
    if req.ciaddr != Ipv4Addr::UNSPECIFIED {
        return SocketAddr::new(IpAddr::V4(req.ciaddr), V4_CLIENT_PORT);
    }
    broadcast
}

// ---------------------------------------------------------------------------
// DHCPv6 serving loop
// ---------------------------------------------------------------------------

async fn v6_loop(state: SharedState, addr: SocketAddr, sock: UdpSocket) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("DHCPv6 recv on {addr}: {e}");
                continue;
            }
        };
        let msg = match Dhcp6Message::parse(&buf[..n]) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("DHCPv6 parse error: {e}");
                continue;
            }
        };
        if let Err(e) = handle_v6(&state, &sock, &msg, src).await {
            tracing::warn!("DHCPv6 handling error: {e}");
        }
    }
}

async fn handle_v6(
    state: &SharedState,
    sock: &UdpSocket,
    msg: &Dhcp6Message,
    src: SocketAddr,
) -> anyhow::Result<()> {
    // Relay-forwarded messages (RELAY-FORW) are out of scope; we serve clients
    // on the same link only. Pick the first enabled IPv6 scope (giaddr has no
    // v6 equivalent here).
    let scopes = state.db.run(Db::list_dhcp_scopes).await?;
    let Some(scope) = scopes
        .iter()
        .find(|s| s.enabled && s.family == IpFamily::V6)
        .cloned()
    else {
        tracing::debug!("DHCPv6 {:?}: no enabled v6 scope", msg.msg_type);
        return Ok(());
    };
    let Some(duid) = msg.client_duid() else {
        tracing::debug!("DHCPv6 {:?}: no client DUID; ignoring", msg.msg_type);
        return Ok(());
    };

    let sid = scope.id;
    let reservations = state
        .db
        .run(move |c| Db::list_dhcp_reservations(c, sid))
        .await?;
    let leases = state
        .db
        .run(move |c| Db::list_dhcp_leases(c, Some(sid)))
        .await?;
    let now = now_unix();
    let server_duid = server_duid();

    let dest = SocketAddr::new(src.ip(), V6_CLIENT_PORT);

    match msg.msg_type {
        Dhcp6MessageType::Solicit
        | Dhcp6MessageType::Request
        | Dhcp6MessageType::Renew
        | Dhcp6MessageType::Rebind => {
            let Some(IpAddr::V6(assigned)) =
                lease::allocate(&scope, &reservations, &leases, &duid, None, now)
            else {
                tracing::info!("DHCPv6 {:?} from {duid}: pool exhausted", msg.msg_type);
                return Ok(());
            };
            let (reply_type, state_kind, hold) = if msg.msg_type == Dhcp6MessageType::Solicit {
                (
                    Dhcp6MessageType::Advertise,
                    LeaseState::Offered,
                    scope.lease_secs.min(OFFER_HOLD_SECS) as i64,
                )
            } else {
                (
                    Dhcp6MessageType::Reply,
                    LeaseState::Active,
                    scope.lease_secs as i64,
                )
            };
            let reply = build_v6_reply(msg, &scope, assigned, reply_type, &server_duid);
            persist_v6_lease(state, &scope, assigned, &duid, now, now + hold, state_kind).await?;
            sock.send_to(&reply, dest)
                .await
                .with_context(|| format!("sending DHCPv6 reply to {dest}"))?;
            if state_kind == LeaseState::Active {
                register_dns(state, &scope, IpAddr::V6(assigned), v6_fqdn(msg)).await;
            }
        }
        Dhcp6MessageType::Release | Dhcp6MessageType::Decline => {
            let ids: Vec<i64> = leases
                .iter()
                .filter(|l| l.identifier.eq_ignore_ascii_case(&duid))
                .map(|l| l.id)
                .collect();
            if !ids.is_empty() {
                state
                    .db
                    .run(move |c| {
                        for id in ids {
                            Db::delete_dhcp_lease(c, id)?;
                        }
                        Ok(())
                    })
                    .await?;
            }
        }
        other => tracing::debug!("DHCPv6: ignoring {other:?}"),
    }
    Ok(())
}

async fn persist_v6_lease(
    state: &SharedState,
    scope: &DhcpScope,
    ip: Ipv6Addr,
    duid: &str,
    starts: i64,
    expires: i64,
    st: LeaseState,
) -> anyhow::Result<()> {
    let sid = scope.id;
    let ip = ip.to_string();
    let duid = duid.to_string();
    let starts = rfc3339(starts);
    let expires = rfc3339(expires);
    state
        .db
        .run(move |c| {
            Db::upsert_dhcp_lease(
                c,
                sid,
                IpFamily::V6,
                &ip,
                &duid,
                None,
                &starts,
                &expires,
                st,
            )
            .map(|_| ())
        })
        .await?;
    Ok(())
}

/// A stable server DUID-LL (RFC 8415 §11.2) derived from the host name. Stable
/// across restarts on the same host so clients' Server-ID checks keep matching.
fn server_duid() -> Vec<u8> {
    duid_ll(1, &host_seed())
}

/// Six bytes derived from a stable host identifier, formatted as a
/// locally-administered unicast MAC for use in the DUID-LL.
fn host_seed() -> [u8; 6] {
    let name = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "nomina".to_string());
    let mut h = DefaultHasher::new();
    name.hash(&mut h);
    let v = h.finish().to_be_bytes();
    let mut mac = [v[0], v[1], v[2], v[3], v[4], v[5]];
    // Locally-administered (bit 1 set), unicast (bit 0 clear).
    mac[0] = (mac[0] & 0xfe) | 0x02;
    mac
}

/// Best-effort hostname from a DHCPv6 Client FQDN option (option 39): one flags
/// byte then a DNS-wire-encoded domain name. Returns the first label.
fn v6_fqdn(msg: &Dhcp6Message) -> Option<String> {
    let raw = msg.option(39)?;
    if raw.len() < 2 {
        return None;
    }
    // Skip the flags byte; read the first DNS label.
    let labels = &raw[1..];
    let len = *labels.first()? as usize;
    if len == 0 || 1 + len > labels.len() {
        return None;
    }
    std::str::from_utf8(&labels[1..1 + len])
        .ok()
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// DNS registration (shared by v4 ACK and v6 REPLY that grant an address)
// ---------------------------------------------------------------------------

/// Register the granted address in DNS: a forward A/AAAA in the scope's zone,
/// plus a PTR if a covering reverse zone already exists. No-op unless the scope
/// opted in, has a zone, and the client supplied a hostname.
async fn register_dns(
    state: &SharedState,
    scope: &DhcpScope,
    ip: IpAddr,
    hostname: Option<String>,
) {
    if !scope.dns_register {
        return;
    }
    let Some(zone) = scope.dns_zone.clone() else {
        return;
    };
    let Some(host) = hostname.and_then(|h| sanitize_label(&h)) else {
        return;
    };
    let ttl = scope.lease_secs.max(60);
    let fqdn = format!("{host}.{zone}");

    // Forward record.
    let fqdn_fwd = fqdn.clone();
    let res = state
        .db
        .run_mut(move |c| Db::dyndns_set_address(c, &fqdn_fwd, ip, None, ttl))
        .await;
    match res {
        Ok(_) => {
            if let Err(e) = state.reload_store() {
                tracing::warn!("DHCP DNS register: store reload failed: {e}");
            }
        }
        Err(e) => {
            tracing::warn!("DHCP DNS register for {fqdn}: {e}");
            return;
        }
    }

    // PTR, only if a covering reverse zone already exists.
    let Some(rev) = reverse_name(ip) else {
        return;
    };
    let target = format!("{fqdn}.");
    let _ = state
        .db
        .run_mut(move |c| {
            let zones = Db::list_zones(c)?;
            // Longest-suffix match of the reverse name against a reverse zone.
            let mut best: Option<(i64, String)> = None;
            for z in &zones {
                let zn = z.name.trim_end_matches('.').to_ascii_lowercase();
                if !(zn.ends_with(".in-addr.arpa")
                    || zn.ends_with(".ip6.arpa")
                    || zn == "in-addr.arpa"
                    || zn == "ip6.arpa")
                {
                    continue;
                }
                if (rev == zn || rev.ends_with(&format!(".{zn}")))
                    && best.as_ref().is_none_or(|(_, n)| zn.len() > n.len())
                {
                    best = Some((z.id, zn));
                }
            }
            let Some((zone_id, zone_name)) = best else {
                return Ok(());
            };
            let rel = if rev == zone_name {
                "@".to_string()
            } else {
                rev[..rev.len() - zone_name.len() - 1].to_string()
            };
            Db::create_record(c, zone_id, None, &rel, "PTR", Some(ttl), &target).map(|_| ())
        })
        .await
        .map_err(|e| tracing::warn!("DHCP PTR register: {e}"));
}

/// Reduce a client-supplied hostname to a single safe DNS label (lowercase,
/// alphanumeric + hyphen, max 63 chars). Returns `None` if nothing usable
/// remains.
fn sanitize_label(raw: &str) -> Option<String> {
    let first = raw.split('.').next().unwrap_or(raw);
    let cleaned: String = first
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(63)
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// The reverse-DNS owner name for an address (`d.c.b.a.in-addr.arpa` for v4,
/// the nibble form under `ip6.arpa` for v6).
fn reverse_name(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            Some(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(a) => {
            let mut s = String::with_capacity(72);
            for byte in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            s.push_str("ip6.arpa");
            Some(s)
        }
    }
}

// ---------------------------------------------------------------------------
// Pure reply builders & policy (unit-tested)
// ---------------------------------------------------------------------------

/// The interface a directly-connected DHCPv4 request arrived on, when the
/// listening socket is bound to a specific device (Linux SO_BINDTODEVICE). Lets
/// non-relayed VLAN clients (giaddr == 0) select the right scope.
#[derive(Clone, Debug, Default)]
pub struct RecvIface {
    pub name: String,
    pub addr: Option<Ipv4Addr>,
}

/// Select the DHCPv4 scope for a request, in priority order:
///   1. relayed (`giaddr` set) → the enabled v4 scope whose subnet contains it;
///   2. arrived on a bound interface → the scope pinned to that interface, else
///      the scope whose subnet contains the interface's own address;
///   3. fallback → the first enabled v4 scope.
pub fn select_v4_scope<'a>(
    scopes: &'a [DhcpScope],
    giaddr: Ipv4Addr,
    iface: Option<&RecvIface>,
) -> Option<&'a DhcpScope> {
    let enabled_v4 = |s: &&DhcpScope| s.enabled && s.family == IpFamily::V4;

    if giaddr != Ipv4Addr::UNSPECIFIED {
        if let Some(s) = scopes.iter().filter(enabled_v4).find(|s| {
            s.subnet
                .parse::<ipnet::Ipv4Net>()
                .map(|net| net.contains(&giaddr))
                .unwrap_or(false)
        }) {
            return Some(s);
        }
    }

    if let Some(ic) = iface {
        // Scope explicitly pinned to this interface wins.
        if let Some(s) = scopes
            .iter()
            .filter(enabled_v4)
            .find(|s| s.interface.as_deref() == Some(ic.name.as_str()))
        {
            return Some(s);
        }
        // Otherwise the scope whose subnet contains the interface's own address.
        if let Some(addr) = ic.addr {
            if let Some(s) = scopes.iter().filter(enabled_v4).find(|s| {
                s.subnet
                    .parse::<ipnet::Ipv4Net>()
                    .map(|net| net.contains(&addr))
                    .unwrap_or(false)
            }) {
                return Some(s);
            }
        }
    }

    scopes.iter().find(enabled_v4)
}

/// The IPv4 subnet mask implied by a CIDR subnet string (e.g. `192.168.1.0/24`
/// → `255.255.255.0`). `None` if the string is not parseable as an IPv4 CIDR.
pub fn subnet_mask_v4(subnet: &str) -> Option<Ipv4Addr> {
    subnet.parse::<ipnet::Ipv4Net>().ok().map(|n| n.netmask())
}

/// Merge a scope's options with a matching reservation's options: reservation
/// options override the scope's by code; the rest are unioned.
pub fn merge_options(
    scope_opts: &[DhcpOption],
    reservation_opts: &[DhcpOption],
) -> Vec<DhcpOption> {
    let mut out: Vec<DhcpOption> = scope_opts.to_vec();
    for ro in reservation_opts {
        if let Some(slot) = out.iter_mut().find(|o| o.code == ro.code) {
            *slot = ro.clone();
        } else {
            out.push(ro.clone());
        }
    }
    out
}

/// Compute the merged option set for a specific client (scope options overridden
/// by the matching reservation's options, if any).
fn merged_for_client(
    scope: &DhcpScope,
    reservations: &[crate::models::DhcpReservation],
    cid: &str,
) -> Vec<DhcpOption> {
    match reservations
        .iter()
        .find(|r| r.identifier.eq_ignore_ascii_case(cid))
    {
        Some(r) => merge_options(&scope.options, &r.options),
        None => scope.options.clone(),
    }
}

/// Build a DHCPv4 OFFER/ACK/NAK reply on the wire.
///
/// Sets `op = BOOTREPLY`, echoes xid/flags/chaddr/giaddr/ciaddr/htype/hlen from
/// the request, sets `yiaddr` and `siaddr = server_id`, then the options:
/// 53 (message type), 54 (server identifier), 51 (lease time, when an address is
/// granted), 1 (subnet mask), then every option in `merged_opts` (already
/// scope-overridden-by-reservation) via [`encode_option`], then END.
///
/// A NAK carries only 53 (=NAK) and 54, with no yiaddr or other options.
pub fn build_v4_reply(
    req: &Dhcp4Message,
    scope: &DhcpScope,
    merged_opts: &[DhcpOption],
    yiaddr: Ipv4Addr,
    msg_type: Dhcp4MessageType,
) -> Vec<u8> {
    let server_id = scope
        .server_id
        .as_deref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    let mut reply = Dhcp4Message {
        op: 2, // BOOTREPLY
        htype: req.htype,
        hlen: req.hlen,
        hops: 0,
        xid: req.xid,
        secs: 0,
        flags: req.flags,
        ciaddr: req.ciaddr,
        yiaddr,
        siaddr: server_id,
        giaddr: req.giaddr,
        chaddr: req.chaddr,
        sname: [0u8; 64],
        file: [0u8; 128],
        options: Vec::new(),
    };

    reply.set_message_type(msg_type);
    reply.set_option(54, server_id.octets().to_vec());

    if msg_type == Dhcp4MessageType::Nak {
        // NAK: yiaddr must be zero and no further options.
        reply.yiaddr = Ipv4Addr::UNSPECIFIED;
        return reply.build();
    }

    // Lease time only when an address is actually granted (not for INFORM).
    if yiaddr != Ipv4Addr::UNSPECIFIED {
        reply.set_option(51, scope.lease_secs.to_be_bytes().to_vec());
    }
    if let Some(mask) = subnet_mask_v4(&scope.subnet) {
        reply.set_option(1, mask.octets().to_vec());
    }
    for opt in merged_opts {
        // Subnet mask, message type, server id, and lease time are emitted
        // above; skip any duplicates the admin added to the option set.
        if matches!(opt.code, 1 | 51 | 53 | 54) || opt.code > 255 {
            continue;
        }
        match encode_option(opt) {
            Ok(bytes) => reply.set_option(opt.code as u8, bytes),
            Err(e) => tracing::debug!("DHCPv4 option {} skipped: {e}", opt.code),
        }
    }

    // PXE / BOOTP bridging: many network-boot clients read the legacy BOOTP
    // header fields (`file` = bootfile, `siaddr` = next-server) rather than the
    // equivalent DHCP options. Mirror option 67 into `file`, and option 66 into
    // `siaddr` when it is given as a literal IPv4 address.
    if msg_type != Dhcp4MessageType::Nak {
        for opt in merged_opts {
            match opt.code {
                67 => {
                    let bytes = opt.value.as_bytes();
                    let n = bytes.len().min(reply.file.len());
                    reply.file[..n].copy_from_slice(&bytes[..n]);
                }
                66 => {
                    if let Ok(ip) = opt.value.trim().parse::<Ipv4Addr>() {
                        reply.siaddr = ip;
                    }
                }
                _ => {}
            }
        }
    }

    reply.build()
}

/// Build a DHCPv6 ADVERTISE/REPLY on the wire: echoes the Client ID, includes
/// the Server ID, an IA_NA carrying the assigned address with lifetimes
/// (T1 = lease/2, T2 = lease*0.8, preferred = valid = lease), and the scope's
/// DNS server (option 23) / domain search (option 24) options.
pub fn build_v6_reply(
    req: &Dhcp6Message,
    scope: &DhcpScope,
    assigned: Ipv6Addr,
    msg_type: Dhcp6MessageType,
    server_duid: &[u8],
) -> Vec<u8> {
    let mut reply = Dhcp6Message::new(msg_type, req.transaction_id);

    // Echo the client's DUID (option 1).
    if let Some(cid) = req.option(1) {
        reply.set_option(1, cid.to_vec());
    }
    // Our server DUID (option 2).
    reply.set_option(2, server_duid.to_vec());

    let lease = scope.lease_secs;
    let iaid = req.ia_na().map(|ia| ia.iaid).unwrap_or(1);
    let ia = IaNa {
        iaid,
        t1: lease / 2,
        t2: (lease / 5) * 4,
        addresses: vec![IaAddress {
            addr: assigned,
            preferred: lease,
            valid: lease,
        }],
    };
    reply.set_option(3, encode_ia_na(&ia));

    // DNS servers (23) and domain search (24) from the scope's options.
    for opt in &scope.options {
        if matches!(opt.code, 23 | 24) {
            match encode_option(opt) {
                Ok(bytes) => reply.set_option(opt.code, bytes),
                Err(e) => tracing::debug!("DHCPv6 option {} skipped: {e}", opt.code),
            }
        }
    }
    reply.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DhcpOptionKind;

    fn scope_v4(subnet: &str, server_id: Option<&str>) -> DhcpScope {
        DhcpScope {
            id: 1,
            name: "lan".into(),
            enabled: true,
            family: IpFamily::V4,
            subnet: subnet.into(),
            range_start: "192.168.1.100".into(),
            range_end: "192.168.1.200".into(),
            lease_secs: 3600,
            dns_register: false,
            dns_zone: None,
            server_id: server_id.map(String::from),
            interface: None,
            options: vec![],
            created_at: "1970-01-01T00:00:00Z".into(),
        }
    }

    fn opt(code: u16, value: &str, kind: DhcpOptionKind) -> DhcpOption {
        DhcpOption {
            code,
            name: None,
            value: value.into(),
            kind,
        }
    }

    fn discover() -> Dhcp4Message {
        let mut m = Dhcp4Message {
            op: 1,
            htype: 1,
            hlen: 6,
            xid: 0xdead_beef,
            flags: 0x8000,
            chaddr: {
                let mut c = [0u8; 16];
                c[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);
                c
            },
            ..Default::default()
        };
        m.set_message_type(Dhcp4MessageType::Discover);
        m
    }

    #[test]
    fn builds_offer_with_all_fields() {
        let s = scope_v4("192.168.1.0/24", Some("192.168.1.1"));
        let merged = vec![opt(3, "192.168.1.1", DhcpOptionKind::IpList)];
        let yi = Ipv4Addr::new(192, 168, 1, 150);
        let bytes = build_v4_reply(&discover(), &s, &merged, yi, Dhcp4MessageType::Offer);

        let p = Dhcp4Message::parse(&bytes).unwrap();
        assert_eq!(p.op, 2);
        assert_eq!(p.xid, 0xdead_beef);
        assert_eq!(p.yiaddr, yi);
        assert_eq!(p.message_type(), Some(Dhcp4MessageType::Offer));
        assert_eq!(p.server_id(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(p.siaddr, Ipv4Addr::new(192, 168, 1, 1));
        // Lease time (51) == scope lease.
        assert_eq!(p.option(51), Some(3600u32.to_be_bytes().as_slice()));
        // Subnet mask (1) for /24.
        assert_eq!(p.option(1), Some([255, 255, 255, 0].as_slice()));
        // Router (3) from the merged option set.
        assert_eq!(p.option(3), Some([192, 168, 1, 1].as_slice()));
        // chaddr echoed.
        assert_eq!(&p.chaddr[..6], &[0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn pxe_options_bridge_to_bootp_fields() {
        let s = scope_v4("192.168.1.0/24", Some("192.168.1.1"));
        let merged = vec![
            opt(66, "192.168.1.2", DhcpOptionKind::Text), // next-server (literal IP)
            opt(67, "pxelinux.0", DhcpOptionKind::Text),  // bootfile
            opt(60, "PXEClient", DhcpOptionKind::Text),
        ];
        let yi = Ipv4Addr::new(192, 168, 1, 150);
        let bytes = build_v4_reply(&discover(), &s, &merged, yi, Dhcp4MessageType::Ack);
        let p = Dhcp4Message::parse(&bytes).unwrap();
        // Option 67 mirrored into the BOOTP `file` field for PXE clients.
        assert!(p.file.starts_with(b"pxelinux.0"));
        // Option 66 (literal IP) mirrored into `siaddr` (next-server).
        assert_eq!(p.siaddr, Ipv4Addr::new(192, 168, 1, 2));
        // The options themselves are still present.
        assert_eq!(p.option(67), Some(b"pxelinux.0".as_slice()));
        assert_eq!(p.option(60), Some(b"PXEClient".as_slice()));
    }

    #[test]
    fn ack_carries_lease_and_mask_for_slash25() {
        let s = scope_v4("192.168.1.128/25", Some("192.168.1.129"));
        let mut req = discover();
        req.set_message_type(Dhcp4MessageType::Request);
        let yi = Ipv4Addr::new(192, 168, 1, 150);
        let bytes = build_v4_reply(&req, &s, &[], yi, Dhcp4MessageType::Ack);
        let p = Dhcp4Message::parse(&bytes).unwrap();
        assert_eq!(p.message_type(), Some(Dhcp4MessageType::Ack));
        assert_eq!(p.yiaddr, yi);
        assert_eq!(p.option(1), Some([255, 255, 255, 128].as_slice()));
        assert_eq!(p.server_id(), Some(Ipv4Addr::new(192, 168, 1, 129)));
    }

    #[test]
    fn nak_has_no_yiaddr_or_extra_options() {
        let s = scope_v4("192.168.1.0/24", Some("192.168.1.1"));
        let bytes = build_v4_reply(
            &discover(),
            &s,
            &[opt(3, "192.168.1.1", DhcpOptionKind::IpList)],
            Ipv4Addr::new(192, 168, 1, 150),
            Dhcp4MessageType::Nak,
        );
        let p = Dhcp4Message::parse(&bytes).unwrap();
        assert_eq!(p.message_type(), Some(Dhcp4MessageType::Nak));
        assert_eq!(p.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(p.server_id(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        // No lease, mask, or router option in a NAK.
        assert_eq!(p.option(51), None);
        assert_eq!(p.option(1), None);
        assert_eq!(p.option(3), None);
    }

    #[test]
    fn subnet_mask_derivation() {
        assert_eq!(
            subnet_mask_v4("192.168.1.0/24"),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(
            subnet_mask_v4("192.168.1.0/25"),
            Some(Ipv4Addr::new(255, 255, 255, 128))
        );
        assert_eq!(
            subnet_mask_v4("10.0.0.0/30"),
            Some(Ipv4Addr::new(255, 255, 255, 252))
        );
        assert_eq!(subnet_mask_v4("0.0.0.0/0"), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(subnet_mask_v4("not-a-subnet"), None);
    }

    #[test]
    fn scope_selection_by_giaddr_then_first_enabled() {
        let mut a = scope_v4("10.0.0.0/24", Some("10.0.0.1"));
        a.id = 1;
        a.name = "a".into();
        let mut b = scope_v4("192.168.5.0/24", Some("192.168.5.1"));
        b.id = 2;
        b.name = "b".into();
        let scopes = vec![a, b];

        // A relayed request from 192.168.5.x picks scope b by subnet.
        let sel = select_v4_scope(&scopes, Ipv4Addr::new(192, 168, 5, 9), None).unwrap();
        assert_eq!(sel.id, 2);
        // No giaddr → first enabled scope (a).
        let sel0 = select_v4_scope(&scopes, Ipv4Addr::UNSPECIFIED, None).unwrap();
        assert_eq!(sel0.id, 1);
        // A giaddr matching no scope subnet → first enabled scope (a).
        let sel_nomatch = select_v4_scope(&scopes, Ipv4Addr::new(172, 16, 0, 1), None).unwrap();
        assert_eq!(sel_nomatch.id, 1);

        // A disabled first scope is skipped.
        let mut scopes2 = scopes.clone();
        scopes2[0].enabled = false;
        let sel2 = select_v4_scope(&scopes2, Ipv4Addr::UNSPECIFIED, None).unwrap();
        assert_eq!(sel2.id, 2);
    }

    #[test]
    fn select_v4_scope_by_interface() {
        // Two directly-connected VLAN scopes, no relay (giaddr == 0).
        let mut a = scope_v4("192.168.10.0/24", Some("192.168.10.1"));
        a.id = 1;
        a.name = "vlan10".into();
        a.interface = Some("eth0.10".into());
        let mut b = scope_v4("192.168.20.0/24", Some("192.168.20.1"));
        b.id = 2;
        b.name = "vlan20".into();
        b.interface = Some("eth0.20".into());
        let scopes = vec![a, b];

        // Request arriving on eth0.20 selects the scope pinned to it.
        let ic = RecvIface { name: "eth0.20".into(), addr: None };
        let sel = select_v4_scope(&scopes, Ipv4Addr::UNSPECIFIED, Some(&ic)).unwrap();
        assert_eq!(sel.id, 2);

        // An interface with no explicit pin falls back to subnet-by-address.
        let scopes2: Vec<_> = scopes.iter().cloned().map(|mut s| { s.interface = None; s }).collect();
        let ic2 = RecvIface { name: "br0".into(), addr: Some(Ipv4Addr::new(192, 168, 10, 1)) };
        let sel2 = select_v4_scope(&scopes2, Ipv4Addr::UNSPECIFIED, Some(&ic2)).unwrap();
        assert_eq!(sel2.id, 1);

        // Relay still wins over interface.
        let ic3 = RecvIface { name: "eth0.10".into(), addr: None };
        let sel3 = select_v4_scope(&scopes, Ipv4Addr::new(192, 168, 20, 1), Some(&ic3)).unwrap();
        assert_eq!(sel3.id, 2);
    }

    #[test]
    fn reservation_options_override_scope_options() {
        let scope_opts = vec![
            opt(6, "8.8.8.8", DhcpOptionKind::IpList),
            opt(15, "lan", DhcpOptionKind::Text),
        ];
        let res_opts = vec![
            opt(6, "1.1.1.1", DhcpOptionKind::IpList), // overrides scope's DNS
            opt(3, "10.0.0.1", DhcpOptionKind::IpList), // new (router)
        ];
        let merged = merge_options(&scope_opts, &res_opts);
        // DNS overridden.
        let dns = merged.iter().find(|o| o.code == 6).unwrap();
        assert_eq!(dns.value, "1.1.1.1");
        // Domain name preserved.
        assert!(merged.iter().any(|o| o.code == 15 && o.value == "lan"));
        // Router added.
        assert!(merged.iter().any(|o| o.code == 3 && o.value == "10.0.0.1"));
        assert_eq!(merged.len(), 3);
    }

    fn scope_v6() -> DhcpScope {
        DhcpScope {
            id: 9,
            name: "v6".into(),
            enabled: true,
            family: IpFamily::V6,
            subnet: "2001:db8::/64".into(),
            range_start: "2001:db8::10".into(),
            range_end: "2001:db8::1f".into(),
            lease_secs: 3600,
            dns_register: false,
            dns_zone: None,
            server_id: None,
            interface: None,
            options: vec![opt(23, "2001:db8::53", DhcpOptionKind::IpList)],
            created_at: "1970-01-01T00:00:00Z".into(),
        }
    }

    fn solicit() -> Dhcp6Message {
        let mut m = Dhcp6Message::new(Dhcp6MessageType::Solicit, [0x11, 0x22, 0x33]);
        m.set_option(1, duid_ll(1, &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]));
        m.set_option(
            3,
            encode_ia_na(&IaNa {
                iaid: 0x42,
                t1: 0,
                t2: 0,
                addresses: vec![],
            }),
        );
        m
    }

    #[test]
    fn v6_advertise_contains_ia_na_and_server_id() {
        let s = scope_v6();
        let assigned: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let sduid = duid_ll(1, &[1, 2, 3, 4, 5, 6]);
        let bytes = build_v6_reply(
            &solicit(),
            &s,
            assigned,
            Dhcp6MessageType::Advertise,
            &sduid,
        );

        let p = Dhcp6Message::parse(&bytes).unwrap();
        assert_eq!(p.msg_type, Dhcp6MessageType::Advertise);
        assert_eq!(p.transaction_id, [0x11, 0x22, 0x33]);
        // Client DUID echoed.
        assert_eq!(p.client_duid().as_deref(), Some("00030001deadbeef0001"));
        // Server DUID present.
        assert_eq!(p.server_duid().as_deref(), Some("00030001010203040506"));
        // IA_NA with the assigned address, preserved IAID, and lifetimes.
        let ia = p.ia_na().unwrap();
        assert_eq!(ia.iaid, 0x42);
        assert_eq!(ia.t1, 1800);
        assert_eq!(ia.t2, 2880);
        assert_eq!(ia.addresses.len(), 1);
        assert_eq!(ia.addresses[0].addr, assigned);
        assert_eq!(ia.addresses[0].valid, 3600);
        // DNS server option (23) carried from the scope.
        assert!(p.option(23).is_some());
    }

    #[test]
    fn v6_reply_round_trips() {
        let s = scope_v6();
        let assigned: Ipv6Addr = "2001:db8::1f".parse().unwrap();
        let sduid = duid_ll(1, &[9, 9, 9, 9, 9, 9]);
        // A REQUEST → REPLY.
        let mut req = solicit();
        req.msg_type = Dhcp6MessageType::Request;
        let bytes = build_v6_reply(&req, &s, assigned, Dhcp6MessageType::Reply, &sduid);
        let p = Dhcp6Message::parse(&bytes).unwrap();
        assert_eq!(p.msg_type, Dhcp6MessageType::Reply);
        assert_eq!(p.ia_na().unwrap().addresses[0].addr, assigned);
        assert_eq!(p.server_duid().as_deref(), Some("00030001090909090909"));
    }

    #[test]
    fn reverse_name_v4_and_v6() {
        assert_eq!(
            reverse_name(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))),
            Some("50.1.168.192.in-addr.arpa".to_string())
        );
        let r = reverse_name("2001:db8::1".parse().unwrap()).unwrap();
        assert!(r.ends_with("ip6.arpa"));
        assert!(r.starts_with("1.0.0.0"));
    }

    #[test]
    fn sanitize_label_strips_unsafe_chars() {
        assert_eq!(sanitize_label("Laptop").as_deref(), Some("laptop"));
        assert_eq!(sanitize_label("my pc!.local").as_deref(), Some("mypc"));
        assert_eq!(sanitize_label("-weird-").as_deref(), Some("weird"));
        assert_eq!(sanitize_label("..."), None);
        assert_eq!(sanitize_label(""), None);
    }
}
