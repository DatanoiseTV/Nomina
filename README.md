# Nomina

A secure, split-horizon DNS server for homelabs, hobbyists, and small networks —
in a single self-contained binary. It is authoritative for your own zones, can
forward or recurse for everything else, filters ads/trackers like Pi-hole, and
ships with a web UI and JSON API.

## Highlights

- **Split-horizon** — define named **views** by client CIDR (e.g. `internal`
  vs `external`) and serve different records to each. `nas.home.lan` can answer
  `10.0.0.5` inside and `203.0.113.5` outside.
- **Authoritative + resolver** — serve your zones authoritatively and either
  **forward** to upstreams (1.1.1.1, 9.9.9.9, or DoT/DoH resolvers), **recurse**
  from the root servers, or run **authoritative-only** for an isolated network.
- **Conditional forwarding** — send specific domains to dedicated upstreams
  (`corp.internal → 10.0.0.1`, `consul → 127.0.0.1:8600`), even with the global
  resolver off.
- **Filtering (Pi-hole style)** — subscribe to remote blocklists (hosts/domain
  lists, cached locally), add manual allow/deny rules, and sinkhole with
  NXDOMAIN, `0.0.0.0`, or REFUSED.
- **Rewrites (AdGuard style)** — point a domain and its subdomains at a fixed IP
  or CNAME (`ads.foobar.com → 1.2.3.4`), even with forwarding disabled.
- **DynDNS** — let routers and dynamic-IP clients update A/AAAA records over HTTP
  via a DynDNS2-compatible `/nic/update` endpoint (ddclient, FRITZ!Box, UniFi,
  OpenWrt, No-IP). Per-client tokens are scoped to specific hostnames.
- **Modern transports** — plain UDP/TCP, DNS-over-TLS, DNS-over-HTTPS
  (RFC 8484, GET **and** POST), DNS-over-QUIC (RFC 9250), and DNS-over-HTTP/3.
- **DNSSEC** — opt-in per-zone online signing (ECDSA P-256) with signed negative
  answers (**NSEC or NSEC3**); exports DS/DNSKEY for the parent.
- **Zone transfers, secondaries & import** — serve AXFR (and IXFR) to
  IP-allow-listed secondaries, act as a **secondary** (replicate a zone from a
  primary with SOA-driven refresh), optional **TSIG** authentication, and
  import/export BIND zone files.
- **Metrics** — Prometheus `/metrics` endpoint.
- **Privacy-first stats** — query logging is **off by default** (aggregate
  counters only); opt into anonymized (masked IPs) or full logging. The
  dashboard shows req/s, a rate sparkline, top domains, blocked/dangerous
  counts, query-latency (min/avg/median/max), and cache hit-rate.
- **Secure by default** — argon2 logins, server-side sessions, CSRF protection,
  login throttling, strict security headers, a strict CSP, selectable bind
  addresses, an optional management allow-list, and privilege dropping.
- **Single binary** — SQLite is bundled and the web UI is embedded. No runtime
  dependencies, no external services.

20 record types are supported, with structured per-type fields in the editor:
`A`, `AAAA`, `ANAME`, `CAA`, `CERT`, `CNAME`, `CSYNC`, `HINFO`, `HTTPS`, `MX`,
`NAPTR`, `NS`, `OPENPGPKEY`, `PTR`, `SMIMEA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`,
`TXT` (plus `SOA`, managed via zone settings).

## Quick start

```sh
cargo build --release
# Serve DNS on :53 and the UI on http://127.0.0.1:8053 (no root needed on
# non-privileged ports; for :53 run as root or grant CAP_NET_BIND_SERVICE).
./target/release/nomina --dns-listen 127.0.0.1:5353 --web-listen 127.0.0.1:8053
```

Open the web UI, create the admin account on first run, then add a zone, records,
and views. Point a client at the server and test:

```sh
dig @127.0.0.1 -p 5353 nas.home.lan A
```

### Configuration

Everything operational is managed at runtime via the UI/API and stored in the
database. Listen sockets, TLS, bind addresses, and privilege settings come from a
TOML file — see [`nomina.example.toml`](nomina.example.toml):

```sh
./nomina --config nomina.toml
```

Key CLI flags (override the config): `--dns-listen` (repeatable), `--dot-listen`,
`--doh-listen`, `--web-listen`, `--web-tls`, `--hostname`, `--data-dir`, `--log`.

### Running on privileged ports with privilege dropping

```toml
# nomina.toml
[dns]
listen = ["0.0.0.0:53"]
dot_listen = ["0.0.0.0:853"]
doh_listen = ["0.0.0.0:443"]

[web]
listen = "192.168.1.2:8053"   # LAN only, not public
tls = true

[privileges]
user = "nomina"               # bind as root, then drop
group = "nomina"
```

Start as root; Nomina binds the privileged sockets and drops to `nomina`. Ensure
`data_dir` is writable by that user.

## Architecture

- The DNS hot path reads an **in-memory store** (zones/records/views pre-parsed)
  and a **filter set** (blocklists/rules/rewrites); both are rebuilt from SQLite
  and atomically swapped on any change — queries never block on the database.
- All transports (UDP/TCP/DoT/DoH) funnel through one resolution core:
  **local zones → rewrite → allow → block → upstream (forward/recurse) → REFUSED**.
- TLS uses a single ring-backed rustls provider shared by the web UI, DoT, DoH,
  and encrypted upstreams. The release build keeps unwinding panics so a
  malformed packet can never abort the process.

The management API contract is the source of truth at
[`docs/api-contract.md`](docs/api-contract.md).

## Security notes

- Serve the web UI over HTTPS (`web.tls = true`) or behind a trusted reverse
  proxy; bind it to a private address and/or set `web.allow_networks`.
- A self-signed certificate is generated under `data_dir` if none is configured;
  provide your own for production.
- DoH on the management port shares the management allow-list — use a dedicated
  `doh_listen` for public DoH.

## Status & roadmap

v0.1.0 is feature-complete for homelab use and verified end-to-end. Possible
future work (contributions/feedback welcome):

- GeoDNS / geo-aware answers and load balancing (round-robin, weighted).
- ASN-based filtering and blocking (MaxMind GeoLite2).
- Native packages (deb/rpm) and a container image.

## License

MIT OR Apache-2.0.
