//! Pure DHCP lease allocation logic.
//!
//! These functions operate purely on data — scope, reservations, and current
//! leases — and decide which address to hand a client. No sockets, no clock
//! reads (the caller passes `now_unix`), no I/O. This makes the allocation
//! policy fully deterministic and unit-testable.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::models::{DhcpLease, DhcpReservation, DhcpScope, IpFamily, LeaseState};

/// Upper bound on how many candidate addresses an IPv6 pool scan will probe
/// before giving up. A v6 range can span an astronomically large space; we never
/// walk more than this many addresses looking for a free one. v4 pools are small
/// enough to scan fully.
pub const MAX_V6_SCAN: u128 = 65_536;

/// Decide which address to allocate to `client_id` from `scope`.
///
/// Policy, in order:
/// 1. A reservation matching `client_id` always wins (even outside the pool).
/// 2. Reuse this client's existing, non-expired lease if it sits in the pool.
/// 3. Honor `requested_ip` if it's in the pool and free.
/// 4. Otherwise the lowest free address in `[range_start, range_end]`.
///
/// Returns `None` on pool exhaustion or if the scope's range is unparseable /
/// mismatched with its family.
pub fn allocate(
    scope: &DhcpScope,
    reservations: &[DhcpReservation],
    leases: &[DhcpLease],
    client_id: &str,
    requested_ip: Option<IpAddr>,
    now_unix: i64,
) -> Option<IpAddr> {
    let family = scope.family;

    // 1. Reservation for this client wins outright.
    for r in reservations {
        if r.identifier.eq_ignore_ascii_case(client_id) {
            if let Ok(ip) = r.ip.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Parse and validate the pool bounds.
    let start = scope.range_start.parse::<IpAddr>().ok()?;
    let end = scope.range_end.parse::<IpAddr>().ok()?;
    if !family_matches(start, family) || !family_matches(end, family) {
        return None;
    }
    let start_n = ip_to_u128(start);
    let end_n = ip_to_u128(end);
    if start_n > end_n {
        return None;
    }

    // Addresses that are off-limits: every reservation IP, plus every active or
    // offered, non-expired lease that belongs to a *different* client.
    let mut used: HashSet<u128> = HashSet::new();
    for r in reservations {
        if let Ok(ip) = r.ip.parse::<IpAddr>() {
            if family_matches(ip, family) {
                used.insert(ip_to_u128(ip));
            }
        }
    }
    for l in leases {
        if is_holding(l, now_unix) && !l.identifier.eq_ignore_ascii_case(client_id) {
            if let Ok(ip) = l.ip.parse::<IpAddr>() {
                if family_matches(ip, family) {
                    used.insert(ip_to_u128(ip));
                }
            }
        }
    }

    // 2. Reuse this client's own current lease if it's still in the pool.
    for l in leases {
        if l.identifier.eq_ignore_ascii_case(client_id) && is_holding(l, now_unix) {
            if let Ok(ip) = l.ip.parse::<IpAddr>() {
                let n = ip_to_u128(ip);
                if n >= start_n && n <= end_n && !used.contains(&n) {
                    return Some(ip);
                }
            }
        }
    }

    // 3. Honor the client's requested IP if it's in the pool and free.
    if let Some(req) = requested_ip {
        if family_matches(req, family) {
            let n = ip_to_u128(req);
            if n >= start_n && n <= end_n && !used.contains(&n) {
                return Some(req);
            }
        }
    }

    // 4. Lowest free address in the pool.
    let max_scan = match family {
        IpFamily::V4 => u128::MAX, // v4 ranges are small enough to walk fully
        IpFamily::V6 => MAX_V6_SCAN,
    };
    let mut n = start_n;
    let mut probed: u128 = 0;
    loop {
        if !used.contains(&n) {
            return Some(u128_to_ip(n, family));
        }
        if n == end_n {
            break;
        }
        n += 1;
        probed += 1;
        if probed >= max_scan {
            break;
        }
    }
    None
}

/// Whether a lease currently holds its address (offered/active and not expired).
fn is_holding(l: &DhcpLease, now_unix: i64) -> bool {
    matches!(l.state, LeaseState::Active | LeaseState::Offered) && !lease_expired(l, now_unix)
}

/// Whether a lease has passed its expiry. An unparseable timestamp is treated as
/// expired (fail open so the address can be reclaimed).
fn lease_expired(l: &DhcpLease, now_unix: i64) -> bool {
    match OffsetDateTime::parse(&l.expires_at, &Rfc3339) {
        Ok(t) => t.unix_timestamp() <= now_unix,
        Err(_) => true,
    }
}

fn family_matches(ip: IpAddr, family: IpFamily) -> bool {
    matches!(
        (ip, family),
        (IpAddr::V4(_), IpFamily::V4) | (IpAddr::V6(_), IpFamily::V6)
    )
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u32::from(a) as u128,
        IpAddr::V6(a) => u128::from(a),
    }
}

fn u128_to_ip(v: u128, family: IpFamily) -> IpAddr {
    match family {
        IpFamily::V4 => IpAddr::V4(Ipv4Addr::from(v as u32)),
        IpFamily::V6 => IpAddr::V6(Ipv6Addr::from(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc3339(unix: i64) -> String {
        OffsetDateTime::from_unix_timestamp(unix)
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    }

    fn scope_v4(start: &str, end: &str) -> DhcpScope {
        DhcpScope {
            id: 1,
            name: "test".into(),
            enabled: true,
            family: IpFamily::V4,
            subnet: "192.168.1.0/29".into(),
            range_start: start.into(),
            range_end: end.into(),
            lease_secs: 3600,
            dns_register: false,
            dns_zone: None,
            options: vec![],
            created_at: rfc3339(0),
        }
    }

    fn lease(scope_id: i64, ip: &str, id: &str, state: LeaseState, exp: i64) -> DhcpLease {
        DhcpLease {
            id: 0,
            scope_id,
            family: IpFamily::V4,
            ip: ip.into(),
            identifier: id.into(),
            hostname: None,
            starts_at: rfc3339(0),
            expires_at: rfc3339(exp),
            state,
            created_at: rfc3339(0),
        }
    }

    fn reservation(scope_id: i64, id: &str, ip: &str) -> DhcpReservation {
        DhcpReservation {
            id: 0,
            scope_id,
            identifier: id.into(),
            ip: ip.into(),
            hostname: None,
            options: vec![],
            created_at: rfc3339(0),
        }
    }

    #[test]
    fn allocates_lowest_from_empty_pool() {
        // /29 usable host range 192.168.1.1 .. .6
        let s = scope_v4("192.168.1.1", "192.168.1.6");
        let ip = allocate(&s, &[], &[], "aa:bb:cc:dd:ee:01", None, 1000);
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn reservation_takes_precedence() {
        let s = scope_v4("192.168.1.1", "192.168.1.6");
        let res = vec![reservation(1, "aa:bb:cc:dd:ee:01", "192.168.1.5")];
        let ip = allocate(&s, &res, &[], "AA:BB:CC:DD:EE:01", None, 1000);
        // Case-insensitive identifier match, returns the reserved address.
        assert_eq!(ip, Some("192.168.1.5".parse().unwrap()));
    }

    #[test]
    fn reserved_address_excluded_from_others() {
        let s = scope_v4("192.168.1.1", "192.168.1.6");
        let res = vec![reservation(1, "aa:bb:cc:dd:ee:01", "192.168.1.1")];
        // A different client must skip the reserved .1 and get .2.
        let ip = allocate(&s, &res, &[], "ff:ff:ff:ff:ff:ff", None, 1000);
        assert_eq!(ip, Some("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn same_client_reuses_existing_lease() {
        let s = scope_v4("192.168.1.1", "192.168.1.6");
        let leases = vec![lease(
            1,
            "192.168.1.4",
            "aa:bb:cc:dd:ee:01",
            LeaseState::Active,
            5000,
        )];
        let ip = allocate(&s, &[], &leases, "aa:bb:cc:dd:ee:01", None, 1000);
        assert_eq!(ip, Some("192.168.1.4".parse().unwrap()));
    }

    #[test]
    fn honors_requested_ip_when_free() {
        let s = scope_v4("192.168.1.1", "192.168.1.6");
        let req = Some("192.168.1.3".parse().unwrap());
        let ip = allocate(&s, &[], &[], "aa:bb:cc:dd:ee:02", req, 1000);
        assert_eq!(ip, Some("192.168.1.3".parse().unwrap()));
    }

    #[test]
    fn ignores_requested_ip_when_taken_or_out_of_range() {
        let s = scope_v4("192.168.1.1", "192.168.1.6");
        let leases = vec![lease(1, "192.168.1.3", "other", LeaseState::Active, 5000)];
        // Requested .3 is taken → falls back to lowest free (.1).
        let req = Some("192.168.1.3".parse().unwrap());
        assert_eq!(
            allocate(&s, &[], &leases, "me", req, 1000),
            Some("192.168.1.1".parse().unwrap())
        );
        // Requested out of range → ignored, lowest free returned.
        let req2 = Some("10.0.0.1".parse().unwrap());
        assert_eq!(
            allocate(&s, &[], &[], "me", req2, 1000),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        let s = scope_v4("192.168.1.1", "192.168.1.2");
        let leases = vec![
            lease(1, "192.168.1.1", "a", LeaseState::Active, 5000),
            lease(1, "192.168.1.2", "b", LeaseState::Active, 5000),
        ];
        assert_eq!(allocate(&s, &[], &leases, "c", None, 1000), None);
    }

    #[test]
    fn expired_lease_is_reclaimable() {
        let s = scope_v4("192.168.1.1", "192.168.1.1");
        // Single-address pool held by another client, but the lease expired at
        // t=500 and now is t=1000 → reclaimable.
        let leases = vec![lease(1, "192.168.1.1", "old", LeaseState::Active, 500)];
        assert_eq!(
            allocate(&s, &[], &leases, "new", None, 1000),
            Some("192.168.1.1".parse().unwrap())
        );
        // Declined leases also free the address for others (not active/offered).
        let declined = vec![lease(1, "192.168.1.1", "old", LeaseState::Declined, 5000)];
        assert_eq!(
            allocate(&s, &[], &declined, "new", None, 1000),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn v6_allocation_and_reuse() {
        let s = DhcpScope {
            id: 2,
            name: "v6".into(),
            enabled: true,
            family: IpFamily::V6,
            subnet: "2001:db8::/64".into(),
            range_start: "2001:db8::10".into(),
            range_end: "2001:db8::1f".into(),
            lease_secs: 3600,
            dns_register: false,
            dns_zone: None,
            options: vec![],
            created_at: rfc3339(0),
        };
        // Empty pool → lowest.
        assert_eq!(
            allocate(&s, &[], &[], "00:03:00:01:aa", None, 1000),
            Some("2001:db8::10".parse().unwrap())
        );
        // First address taken by another → next free.
        let leases = vec![DhcpLease {
            id: 0,
            scope_id: 2,
            family: IpFamily::V6,
            ip: "2001:db8::10".into(),
            identifier: "other".into(),
            hostname: None,
            starts_at: rfc3339(0),
            expires_at: rfc3339(5000),
            state: LeaseState::Active,
            created_at: rfc3339(0),
        }];
        assert_eq!(
            allocate(&s, &[], &leases, "me", None, 1000),
            Some("2001:db8::11".parse().unwrap())
        );
    }

    #[test]
    fn mismatched_family_range_returns_none() {
        // A v4-family scope whose range is accidentally v6 yields no address.
        let mut s = scope_v4("2001:db8::1", "2001:db8::6");
        s.family = IpFamily::V4;
        assert_eq!(allocate(&s, &[], &[], "me", None, 1000), None);
    }
}
