# Changelog

All notable changes to Nomina are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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

## [0.1.0] - 2026-06-26

Initial release. A single self-contained binary.

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

[0.1.0]: https://github.com/DatanoiseTV/Nomina/releases/tag/v0.1.0
