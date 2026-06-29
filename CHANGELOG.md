# Changelog

All notable changes to Nomina are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Map view** — plots the geolocated public IPs Nomina has resolved on an
  interactive world map (vendored Leaflet + OpenStreetMap tiles; no API key).
  Backed by `/api/map` and the GeoIP City database. DB-IP's free, account-less
  `lite` databases work as well as MaxMind GeoLite2.

### Fixed
- Light theme: form fields (e.g. the search box) no longer render with a dark
  background — inputs are styled uniformly and `color-scheme` is set per theme.
- Embedded web assets are served `Cache-Control: no-cache`, so a rebuilt UI is
  picked up without a manual hard refresh.

## [0.2.0] - 2026-06-28

### Added
- **DHCP server (IPv4 + IPv6)** — scopes with address pools, static reservations
  (MAC/DUID), and the full option set plus arbitrary user-defined options
  (typed: ip/ip-list/u8/u16/u32/bool/text/hex). Leases persist with an expiry
  sweeper; on grant, leases can auto-register A/AAAA (and PTR) in DNS. DHCPv4
  DISCOVER/REQUEST/RELEASE/DECLINE/INFORM and DHCPv6 SOLICIT/REQUEST/RENEW are
  served on UDP 67/547 (off unless `[dhcp]` is configured). Managed from a web UI
  (scopes, reservations, live leases, option editor) and `/api/dhcp/*`.
  **PXE / network boot**: catalog includes the boot options (43/60/66/67/93/94/
  97/150/209/210/211) and options 67/66 are mirrored into the BOOTP `file` /
  `siaddr` fields so PXE/iPXE clients boot. A `scripts/dhcp_probe.py` helper and
  `docs/dhcp-testing.md` cover local testing.
- **GeoDNS, load balancing & ASN filtering** — views can now match clients by
  country/continent/ASN (geo-targeted answers) using optional MaxMind GeoLite2
  databases (`[geo]` config); `load_balance` (round-robin/random) spreads
  multi-address answers; and `blocked_asns` rejects traffic by autonomous system.
  Round-robin and geo-view matching are covered by tests.
- **IPv6** — robust dual-stack binding (IPv6 listeners are bound v6-only, so
  listing both `0.0.0.0` and `[::]` works on every platform), per-family query
  counters (IPv4 vs IPv6) on the dashboard and in `/api/stats` + Prometheus, and
  IPv6 CIDRs everywhere views/allow-lists accept networks.

### Changed
- New neutral **zinc + indigo** UI theme (replacing the blue scheme) that reads
  cleanly in light and dark, with a persisted light/dark toggle in the top bar.
- The DHCP option editor is now **name-driven** — pick a named option and get a
  type-aware value field with a format hint, instead of raw code/kind/value rows
  ("Custom" still exposes any code).

## [0.1.0] - 2026-06-27

Initial public release. A single self-contained binary.

### Highlights
- **Upstream DNSSEC validation** — the `dnssec_validate_upstream` setting is now
  wired to the resolver (forward and recursive modes) using the built-in IANA
  root trust anchor; bogus answers are rejected (SERVFAIL). The dashboard shows a
  DNSSEC-failures counter when validation is enabled, exposed in `/api/stats`
  (`dnssec_failures`, `dnssec_validate`) and as a Prometheus counter.
- **Full record-type support** — expanded from 9 to 20 record types: added ANAME,
  CERT, CSYNC, HINFO, HTTPS, NAPTR, OPENPGPKEY, SMIMEA, SSHFP, SVCB, and TLSA.
  The record editor now renders **structured per-type fields** (MX preference,
  SRV weight/port, CAA flags/tag, TLSA/SMIMEA usage/selector/matching, SVCB/HTTPS
  priority/target/params, etc.) and assembles them into the wire format. Each
  type is covered by a parser round-trip test.
- **Request log page** — a paginated, filterable (search/outcome/type), sortable
  view of the persistent query log at `#/queries`, with **per-row quick actions**:
  block a domain (deny rule), allow it (allow rule), or open a prefilled rewrite.
  The same actions appear on the dashboard's recent-queries table, and the
  dashboard top-domains/top-blocked/recent cards gained "Show all" links into it.
- **DynDNS** — DynDNS2-compatible `GET /nic/update` endpoint (also `/v3/update`)
  for routers and dynamic-IP clients (ddclient, FRITZ!Box, UniFi, OpenWrt,
  No-IP). Updates are authenticated by dedicated scoped tokens (HTTP Basic auth,
  argon2-hashed secrets) that may only repoint the hostnames assigned to them.
  Upserts A/AAAA records in the matching local zone and bumps the zone serial so
  secondaries/AXFR/DNSSEC follow. Exempt from the management allow-list since
  clients live on dynamic remote IPs. Token management in the web UI and API
  (`/api/dyndns/tokens`).
- **Edge answer cache** in front of the upstream resolver, with hit/miss/size and
  hit-rate surfaced on the dashboard and in `/api/stats` (`cache` object). New
  `cached` query outcome.
- **Query-latency stats** (min/avg/median/max, milliseconds) on the dashboard and
  in `/api/stats` (`latency` object).
- **Dangerous-request counter** (homograph/lookalike blocks) in `/api/stats`.

### DNS
- Authoritative serving for A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, CAA.
- Split-horizon via CIDR-defined named views; per-record view overrides with an
  all-views fallback. Longest-suffix zone matching, CNAME chasing within a zone,
  wildcard records, and correct NXDOMAIN vs NODATA semantics.
- Resolution modes for non-authoritative names: **forward** (selectable
  upstreams over UDP/TCP/DoT/DoH, with caching), **recursive** (from the root
  servers), or **off** (authoritative-only / universal nameserver).
- Conditional forwarding: per-domain dedicated upstreams, matched before the
  global resolver and effective even in authoritative-only mode.
- BIND zone-file import and export.
- Filtering: Pi-hole-style blocklists from remote sources (hosts / domain
  formats), cached locally in SQLite; manual allow/deny rules; AdGuard-style
  rewrites (domain + subdomains to an IP or CNAME, effective even in
  authoritative-only mode). Block modes: NXDOMAIN / 0.0.0.0 / REFUSED.
- Transports: plain UDP/TCP (53), DNS-over-TLS (853), a self-contained
  DNS-over-HTTPS endpoint supporting both GET and POST (RFC 8484),
  DNS-over-QUIC (RFC 9250), and DNS-over-HTTP/3.
- Zone transfers: AXFR serving to IP-allow-listed secondaries (RFC 5936),
  view-aware; IXFR requests answered with a full transfer (RFC 1995 fallback);
  also acts as a secondary, replicating a zone from a primary with SOA-driven
  refresh. Optional TSIG (RFC 8945) authentication of transfers (hmac-sha1/256/
  512): secondaries sign their requests, and AXFR serving can require a valid
  TSIG.
- Opt-in per-zone DNSSEC online signing (ECDSA P-256): RRSIG over positive
  answers, DNSKEY at the apex, authenticated denials via minimally-covering NSEC
  (RFC 4470) or NSEC3 (RFC 5155/9276), and DS/DNSKEY export for the parent.
- Prometheus `/metrics` endpoint (aggregate, non-identifying).
- A curated catalog of well-known blocklists for one-click subscription.

### Management
- Embedded single-page web UI (no external assets) and a JSON API documented in
  `docs/api-contract.md`.
- Argon2 password hashing, server-side sessions (hashed at rest), strict
  same-site cookies, CSRF protection, and login throttling.
- Live reconfiguration of zones, records, views, forwarders, resolution mode,
  blocklists, rules, rewrites, and conditional forwarders without a restart.
- Privacy-aware query logging (off / anonymized / full, default off) and a
  dashboard with req/s rate, a time-series sparkline, top domains, and
  per-outcome counters.

### Security & operations
- Selectable bind addresses for DNS and the management interface; optional CIDR
  allow-list for the management server.
- Privilege dropping: bind privileged sockets as root, then drop to an
  unprivileged user/group.
- One ring-backed rustls crypto provider shared across the web UI, DoT, DoH, and
  encrypted upstreams. Built with unwinding panics so a malformed packet cannot
  abort the process.

[0.2.0]: https://github.com/DatanoiseTV/Nomina/releases/tag/v0.2.0
[0.1.0]: https://github.com/DatanoiseTV/Nomina/releases/tag/v0.1.0
