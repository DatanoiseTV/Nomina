# Nomina

A secure, split-horizon DNS server for homelabs, hobbyists, and small networks —
in a **single self-contained binary**. Nomina is authoritative for your own
zones, can forward or recurse for everything else, filters ads and trackers like
Pi-hole, speaks the modern encrypted transports, and ships with a web UI and a
JSON API. Written in Rust.

```sh
cargo build --release
./target/release/nomina --dns-listen 0.0.0.0:53 --web-listen 127.0.0.1:8053
```

## Why Nomina

Most DNS tools pick a side. Authoritative servers (BIND, Knot, NSD, PowerDNS,
CoreDNS) serve your zones but don't block ads or ship a friendly UI. Filtering
resolvers (Pi-hole, AdGuard Home, Blocky) block ads but aren't authoritative —
no real zones, no DNSSEC signing, no zone transfers. Nomina does **both**, adds
**split-horizon views** as a first-class concept, speaks **DoT/DoH/DoQ/DoH3**,
and is **one static binary** with the database and web UI embedded.

## Highlights

- **Split-horizon** — define named **views** by client CIDR (e.g. `internal`
  vs `external`) and serve different records to each. `nas.home.lan` can answer
  `10.0.0.5` inside and `203.0.113.5` outside.
- **Authoritative + resolver** — serve your zones authoritatively and either
  **forward** to upstreams (1.1.1.1, 9.9.9.9, or DoT/DoH resolvers), **recurse**
  from the root servers, or run **authoritative-only** for an isolated network.
- **20 record types** with structured per-type fields in the editor: `A`, `AAAA`,
  `ANAME`, `CAA`, `CERT`, `CNAME`, `CSYNC`, `HINFO`, `HTTPS`, `MX`, `NAPTR`,
  `NS`, `OPENPGPKEY`, `PTR`, `SMIMEA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TXT`
  (plus `SOA`, managed via zone settings).
- **Filtering (Pi-hole style)** — subscribe to ~20 well-known blocklists from a
  built-in catalog (Hagezi, OISD, StevenBlack, 1Hosts, URLhaus, Phishing Army,
  and more) or add your own; manual allow/deny rules; AdGuard-style rewrites.
  Block with NXDOMAIN, `0.0.0.0`, or REFUSED.
- **Phishing protection** — block IDN homograph / lookalike domains (e.g.
  Cyrillic "аpple.com") before they resolve.
- **DynDNS** — let routers and dynamic-IP clients update A/AAAA records over HTTP
  via a DynDNS2-compatible `/nic/update` endpoint (ddclient, FRITZ!Box, UniFi,
  OpenWrt, No-IP). Per-client tokens are scoped to specific hostnames.
- **DNSSEC** — opt-in per-zone online **signing** (ECDSA P-256) with signed
  negative answers (NSEC or NSEC3) and DS/DNSKEY export, plus optional **upstream
  validation** against the IANA root trust anchor.
- **Modern transports** — plain UDP/TCP, DNS-over-TLS, DNS-over-HTTPS (RFC 8484,
  GET and POST), DNS-over-QUIC (RFC 9250), and DNS-over-HTTP/3.
- **Zone transfers, secondaries & import** — serve AXFR/IXFR to IP-allow-listed
  secondaries, act as a **secondary** (SOA-driven refresh from a primary),
  optional **TSIG** authentication, and import/export BIND zone files.
- **Conditional forwarding** — send specific domains to dedicated upstreams,
  even with the global resolver off.
- **Observability** — a dashboard with req/s and a sparkline, top domains,
  per-outcome counters, blocked/dangerous counts, query latency
  (min/avg/median/max), cache hit-rate, DNSSEC-failure counts, a paginated and
  filterable **request log** with one-click block/allow/rewrite actions, and a
  Prometheus `/metrics` endpoint.
- **Privacy-first** — query logging is **off by default** (aggregate counters
  only); opt into anonymized (masked IPs) or full logging.
- **Secure by default** — argon2 logins, server-side sessions (hashed at rest),
  CSRF protection, login throttling, strict security headers and CSP, selectable
  bind addresses, an optional management allow-list, and privilege dropping.
- **Single binary** — SQLite is bundled and the web UI is embedded; schema
  changes are applied automatically via versioned migrations. No runtime
  dependencies, no external services.

## How it compares

This is a fair, conservative snapshot — check each project's current docs, as
features change. Nomina's distinguishing trait is the **combination**:
authoritative + filtering + split-horizon + encrypted transports in one Rust
binary. **[Technitium DNS](https://technitium.com/dns/) is the closest single-app
comparison** and is broader and more mature (it also does DHCP); Nomina's edge is
being a single self-contained Rust binary with split-horizon views as a core
concept and privacy-first logging.

| Capability | Nomina | Pi-hole | AdGuard Home | Technitium | BIND 9 | CoreDNS |
|---|---|---|---|---|---|---|
| Authoritative zones (full record types) | ✅ | partial¹ | partial¹ | ✅ | ✅ | ✅ |
| Split-horizon views | ✅ | ❌ | partial² | ✅ | ✅ | plugin |
| Recursive resolver | ✅ | via Unbound | ❌ | ✅ | ✅ | ❌ |
| Forwarding | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ad/tracker filtering | ✅ | ✅ | ✅ | ✅ | RPZ | plugin |
| DNSSEC validation | ✅ | via Unbound | ✅ | ✅ | ✅ | ❌ |
| DNSSEC signing (authoritative) | ✅ | ❌ | ❌ | ✅ | ✅ | plugin |
| DoT/DoH/DoQ **server** | ✅ | ❌³ | ✅ | ✅ | DoT/DoH⁴ | DoT/DoH |
| AXFR / secondary | ✅ | ❌ | ❌ | ✅ | ✅ | plugin |
| DynDNS-style HTTP update | ✅ | ❌ | ❌ | partial⁵ | RFC 2136⁵ | ❌ |
| Built-in web UI | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Single self-contained binary | ✅ | ❌ | ✅ | ❌⁶ | ❌ | ✅ |
| DHCP server | ❌ | ✅ | ✅ | ✅ | ❌⁷ | ❌ |
| Language | Rust | C/PHP | Go | C#/.NET | C | Go |

¹ Pi-hole and AdGuard Home support local DNS records / rewrites, not full
authoritative zones with arbitrary record types, DNSSEC signing, or AXFR.
² AdGuard Home has client-specific rules, not CIDR-view-based zones.
³ Pi-hole needs a separate proxy (e.g. cloudflared) for encrypted DNS.
⁴ BIND added DoT/DoH in 9.18+.
⁵ Technitium supports dynamic updates via its API; BIND uses RFC 2136 dynamic
update, not the HTTP DynDNS2 protocol routers speak. Nomina implements the
DynDNS2 `/nic/update` endpoint directly.
⁶ Technitium runs on .NET (self-contained builds exist but bundle the runtime).
⁷ DHCP is provided by separate ISC software, not BIND itself.

**What Nomina does not (yet) do:** no DHCP server, no GeoDNS/geo-aware answers
(on the roadmap), and it's young — it doesn't have the maturity, scale hardening,
or community of BIND/Technitium. For a pure recursive resolver, Unbound is
lighter; for a pure authoritative server at scale, Knot/NSD are battle-tested.

## Quick start

```sh
cargo build --release
# Serve DNS on a non-privileged port and the UI locally (no root needed):
./target/release/nomina --dns-listen 127.0.0.1:5353 --web-listen 127.0.0.1:8053
```

Open `http://127.0.0.1:8053`, create the admin account on first run, then add a
zone, records, and views. Test it:

```sh
dig @127.0.0.1 -p 5353 nas.home.lan A
```

### Configuration

Everything operational is managed at runtime via the UI/API and stored in the
database (SQLite, with automatic migrations). Listen sockets, TLS, bind
addresses, and privilege settings come from a TOML file — see
[`nomina.example.toml`](nomina.example.toml):

```sh
./nomina --config nomina.toml
```

Key CLI flags (override the config): `--dns-listen` (repeatable), `--dot-listen`,
`--doh-listen`, `--doq-listen`, `--doh3-listen`, `--web-listen`, `--web-tls`,
`--hostname`, `--data-dir`, `--log`.

### Privileged ports with privilege dropping

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

Start as root; Nomina binds the privileged sockets, then drops to `nomina`.
Ensure `data_dir` is writable by that user.

### Running as a service (systemd)

```ini
# /etc/systemd/system/nomina.service
[Unit]
Description=Nomina DNS server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/nomina --config /etc/nomina/nomina.toml --data-dir /var/lib/nomina
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
DynamicUser=yes
StateDirectory=nomina

[Install]
WantedBy=multi-user.target
```

## Architecture

- The DNS hot path reads an **in-memory store** (zones/records/views pre-parsed)
  and a **filter set** (blocklists/rules/rewrites); both are rebuilt from SQLite
  and atomically swapped on any change — queries never block on the database.
- All transports funnel through one resolution core:
  **local zones → rewrite → allow → block → conditional forward → upstream
  (forward/recurse) → REFUSED**.
- A small edge cache sits in front of the upstream resolver.
- Persistence is Diesel + SQLite (bundled) with versioned migrations applied on
  startup. TLS uses a single ring-backed rustls provider shared by the web UI,
  DoT, DoH, DoQ, and encrypted upstreams. The release build keeps unwinding
  panics so a malformed packet can never abort the process.

The management API contract is the source of truth at
[`docs/api-contract.md`](docs/api-contract.md).

## Security notes

- Serve the web UI over HTTPS (`web.tls = true`) or behind a trusted reverse
  proxy; bind it to a private address and/or set `web.allow_networks`.
- A self-signed certificate is generated under `data_dir` if none is configured;
  provide your own for production.
- DoH on the management port shares the management allow-list — use a dedicated
  `doh_listen` for public DoH.
- The DynDNS `/nic/update` endpoint is intentionally exempt from the management
  allow-list (clients have dynamic IPs); its per-token HTTP Basic credential is
  the security boundary.

## Roadmap

- GeoDNS / geo-aware answers and load balancing (round-robin, weighted).
- ASN-based filtering and blocking (MaxMind GeoLite2).
- Native packages (deb/rpm) and a container image.

## Contributing

Issues and pull requests are welcome. Please run `cargo fmt`, `cargo clippy`,
and `cargo test` before submitting. The JSON API is contract-first — update
`docs/api-contract.md` alongside any API change.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
