# PicoNS

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
- **Modern transports** — plain UDP/TCP, DNS-over-TLS, and DNS-over-HTTPS
  (RFC 8484, GET **and** POST).
- **Zone transfers & import** — serve AXFR to IP-allow-listed secondaries;
  import/export BIND zone files.
- **Privacy-first stats** — query logging is **off by default** (aggregate
  counters only); opt into anonymized (masked IPs) or full logging. The
  dashboard shows req/s, a rate sparkline, top domains, and blocked counts.
- **Secure by default** — argon2 logins, server-side sessions, CSRF protection,
  login throttling, strict security headers, a strict CSP, selectable bind
  addresses, an optional management allow-list, and privilege dropping.
- **Single binary** — SQLite is bundled and the web UI is embedded. No runtime
  dependencies, no external services.

Common record types are supported: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`,
`SOA`, `SRV`, `PTR`, `CAA`.

## Quick start

```sh
cargo build --release
# Serve DNS on :53 and the UI on http://127.0.0.1:8053 (no root needed on
# non-privileged ports; for :53 run as root or grant CAP_NET_BIND_SERVICE).
./target/release/picons --dns-listen 127.0.0.1:5353 --web-listen 127.0.0.1:8053
```

Open the web UI, create the admin account on first run, then add a zone, records,
and views. Point a client at the server and test:

```sh
dig @127.0.0.1 -p 5353 nas.home.lan A
```

### Configuration

Everything operational is managed at runtime via the UI/API and stored in the
database. Listen sockets, TLS, bind addresses, and privilege settings come from a
TOML file — see [`picons.example.toml`](picons.example.toml):

```sh
./picons --config picons.toml
```

Key CLI flags (override the config): `--dns-listen` (repeatable), `--dot-listen`,
`--doh-listen`, `--web-listen`, `--web-tls`, `--hostname`, `--data-dir`, `--log`.

### Running on privileged ports with privilege dropping

```toml
# picons.toml
[dns]
listen = ["0.0.0.0:53"]
dot_listen = ["0.0.0.0:853"]
doh_listen = ["0.0.0.0:443"]

[web]
listen = "192.168.1.2:8053"   # LAN only, not public
tls = true

[privileges]
user = "picons"               # bind as root, then drop
group = "picons"
```

Start as root; PicoNS binds the privileged sockets and drops to `picons`. Ensure
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

v0.1.0 is feature-complete for homelab use and verified end-to-end. Not yet
implemented (contributions/feedback welcome):

- Secondary/slave mode (pulling zones via AXFR/IXFR with SOA-driven refresh).
- DNSSEC signing of authoritative zones.
- DNS-over-QUIC and Prometheus metrics.

## License

MIT OR Apache-2.0.
