//! Socket binding helpers with explicit IPv6 handling.
//!
//! IPv6 listeners are bound `IPV6_V6ONLY`, so an `[::]` listener accepts only
//! IPv6 and a separate `0.0.0.0` listener handles IPv4. This is predictable
//! across platforms (Linux defaults to dual-stack `[::]`, the BSDs/macOS to
//! v6-only) and lets a config list both wildcard addresses without the second
//! bind failing with "address already in use".

use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

fn configure(addr: SocketAddr, ty: Type, proto: Protocol) -> std::io::Result<Socket> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, ty, Some(proto))?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock)
}

/// Bind a TCP listener, IPv6-only for IPv6 addresses.
pub fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let sock = configure(addr, Type::STREAM, Protocol::TCP)?;
    sock.listen(1024)?;
    TcpListener::from_std(sock.into())
}

/// Bind a UDP socket, IPv6-only for IPv6 addresses.
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = configure(addr, Type::DGRAM, Protocol::UDP)?;
    UdpSocket::from_std(sock.into())
}
