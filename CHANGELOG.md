# Changelog

All notable changes to PicoNS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

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
- Transports: plain UDP/TCP (53), DNS-over-TLS (853), and a self-contained
  DNS-over-HTTPS endpoint supporting both GET and POST (RFC 8484).
- AXFR zone-transfer serving to IP-allow-listed secondaries (RFC 5936),
  view-aware; disabled by default.

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

[0.1.0]: https://github.com/DatanoiseTV/PicoNS/releases/tag/v0.1.0
