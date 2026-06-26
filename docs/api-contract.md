# PicoNS API Contract (v1)

Authoritative definition of the PicoNS management API. Backend and web UI both
build against this file. No endpoint, type, or error shape may be added in code
without updating this document first.

- Base path: `/api`
- Encoding: JSON (`Content-Type: application/json`) for all request/response
  bodies unless noted.
- All timestamps are RFC 3339 strings in UTC (e.g. `2026-06-26T10:00:00Z`).
- IDs are 64-bit integers serialized as JSON numbers.

## Authentication & CSRF

PicoNS uses **server-side sessions** with two cookies:

| Cookie            | HttpOnly | SameSite | Secure\* | Purpose                              |
|-------------------|----------|----------|----------|--------------------------------------|
| `picons_session`  | yes      | Strict   | yes      | Opaque session id (server lookup).   |
| `picons_csrf`     | no       | Strict   | yes      | Double-submit CSRF token (JS reads). |

\* `Secure` is set only when the management server is served over HTTPS.

- On successful login both cookies are set. The session id is stored server-side
  (only a hash is persisted); the CSRF token is random per session.
- **Every mutating request** (`POST`, `PUT`, `PATCH`, `DELETE`) must send the
  CSRF token in the `X-CSRF-Token` header. The server rejects the request with
  `403 csrf_failed` if the header is absent or does not match the `picons_csrf`
  cookie. `GET`/`HEAD` never require it.
- Unauthenticated access to any `/api/*` endpoint except `POST /api/auth/login`
  and `GET /api/health` returns `401 unauthorized`.

### Error shape

All non-2xx responses use:

```json
{ "error": { "code": "snake_case_code", "message": "Human readable detail" } }
```

Common codes: `unauthorized` (401), `csrf_failed` (403), `forbidden` (403),
`not_found` (404), `validation` (422), `conflict` (409), `internal` (500).
Validation errors may include `"fields": { "field_name": "reason" }`.

## Endpoints

### Health & status

#### `GET /api/health`
Unauthenticated liveness probe. → `200 { "status": "ok", "version": "0.1.0" }`

#### `GET /api/status`
→ `200`
```json
{
  "version": "0.1.0",
  "uptime_seconds": 12345,
  "started_at": "2026-06-26T08:00:00Z",
  "listeners": [
    { "kind": "udp",  "addr": "0.0.0.0:53",  "enabled": true },
    { "kind": "tcp",  "addr": "0.0.0.0:53",  "enabled": true },
    { "kind": "dot",  "addr": "0.0.0.0:853", "enabled": true },
    { "kind": "doh",  "addr": "0.0.0.0:443", "enabled": false }
  ],
  "zone_count": 3,
  "record_count": 42,
  "view_count": 2
}
```

#### `GET /api/stats`
Rolling query statistics since start.
→ `200`
```json
{
  "total": 10456,
  "authoritative": 8210,
  "forwarded": 1980,
  "cached": 0,
  "nxdomain": 210,
  "refused": 12,
  "servfail": 4,
  "blocked": 540,
  "by_qtype": { "A": 6000, "AAAA": 3000, "PTR": 400 },
  "qps_10s": 4.2,
  "qps_1m": 3.8,
  "qps_avg": 2.1,
  "series_per_sec": [0,1,3,2,5, "...60 values, oldest first"],
  "query_log": "off",
  "recent": [ /* RecentQuery, empty unless query_log != off */ ],
  "top_domains": [ { "name": "nas.home.lan", "count": 1200 } ],
  "top_blocked": [ { "name": "ads.example.com", "count": 300 } ]
}
```
`outcome` ∈ `authoritative | forwarded | cached | nxdomain | refused | servfail |
blocked | rewritten`. Aggregate counters, `qps_*`, and `series_per_sec` are always
present (non-identifying). `recent`, `top_domains`, and `top_blocked` are only
populated when `query_log` is `anonymized` or `full`.

**Privacy:** the `query_log` setting controls per-query retention and defaults to
`off` (no client IPs/names retained). `anonymized` masks client IPs (IPv4 → /24,
IPv6 → /48); `full` retains real IPs. `RecentQuery.client` reflects the mode.

#### `POST /api/stats/clear`
Clears retained per-query detail (recent queries + top domains). Aggregate
counters are kept. → `204`.

### Auth

#### `POST /api/auth/login`
Body: `{ "username": "admin", "password": "..." }`
→ `200 { "user": User }` and sets cookies. Invalid → `401 unauthorized`.
Rate-limited; after repeated failures → `429 too_many_requests`.

#### `POST /api/auth/logout`
Invalidates the session. → `204`.

#### `GET /api/auth/me`
→ `200 { "user": User }` or `401`.

#### `POST /api/auth/change-password`
Body: `{ "current_password": "...", "new_password": "..." }`
→ `204`. Wrong current → `403 forbidden`. Weak new (<12 chars) → `422 validation`.

`User` = `{ "id": 1, "username": "admin", "must_change_password": false, "created_at": "..." }`

### Views (split-horizon)

A **view** is a named set of client source CIDRs. The first view (by `priority`,
ascending) whose CIDR list contains the client IP wins. Exactly one view is the
default (matches everything not matched earlier); it cannot be deleted.

`View`:
```json
{ "id": 1, "name": "internal", "networks": ["10.0.0.0/8", "192.168.0.0/16"],
  "priority": 10, "is_default": false, "created_at": "..." }
```

- `GET /api/views` → `200 { "views": [View, ...] }`
- `POST /api/views` body `{ "name", "networks": [cidr], "priority": int }` → `201 { "view": View }`
- `PUT /api/views/:id` body same fields (partial allowed) → `200 { "view": View }`
- `DELETE /api/views/:id` → `204`. Deleting the default → `409 conflict`.

Validation: `name` matches `^[a-zA-Z0-9_-]{1,40}$`, unique. Each network is a
valid IPv4/IPv6 CIDR. `409 conflict` on duplicate name.

### Zones

`Zone`:
```json
{ "id": 1, "name": "home.lan", "enabled": true,
  "soa": { "primary_ns": "ns1.home.lan.", "admin_email": "admin.home.lan.",
           "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 60 },
  "default_ttl": 300, "record_count": 12, "created_at": "...", "updated_at": "..." }
```

- `GET /api/zones` → `200 { "zones": [Zone, ...] }`
- `POST /api/zones` body `{ "name", "default_ttl"?, "soa"? }` → `201 { "zone": Zone }`.
  A default SOA and an `NS` record are auto-generated if omitted.
- `GET /api/zones/:id` → `200 { "zone": Zone, "records": [Record, ...] }`
- `PUT /api/zones/:id` body partial → `200 { "zone": Zone }`
- `DELETE /api/zones/:id` → `204` (cascades to records).
- `GET /api/zones/:id/export` → `200 text/plain` RFC 1035 zone file (best effort).

Validation: `name` is a valid DNS name, unique, no trailing dot stored.

### Records

A `Record` belongs to a zone and optionally to a single view. `view_id: null`
means the record applies to **all** views (the fallback). A view-specific record
overrides the all-views record for the same `(name, type)` when the client is in
that view.

`Record`:
```json
{ "id": 5, "zone_id": 1, "view_id": 2, "name": "nas", "fqdn": "nas.home.lan",
  "type": "A", "ttl": 300, "data": "10.0.0.5", "enabled": true,
  "created_at": "...", "updated_at": "..." }
```

- `name`: label(s) relative to the zone. `"@"` means the zone apex. Stored
  without the zone suffix. `fqdn` is derived (read-only).
- `type`: one of the supported record types below.
- `data`: type-specific string form (see table). The server validates and
  normalizes it.
- `ttl`: optional; falls back to the zone `default_ttl` when null.

Endpoints:
- `GET /api/zones/:id/records` → `200 { "records": [Record, ...] }`
- `POST /api/zones/:id/records` body `{ "name","type","data","ttl"?,"view_id"? }` → `201 { "record": Record }`
- `PUT /api/records/:id` body partial → `200 { "record": Record }`
- `DELETE /api/records/:id` → `204`

#### Supported record types & `data` format

| Type    | `data` format / example                                              |
|---------|---------------------------------------------------------------------|
| `A`     | IPv4: `10.0.0.5`                                                     |
| `AAAA`  | IPv6: `fd00::5`                                                      |
| `CNAME` | target name: `host.home.lan.`                                        |
| `MX`    | `<pref> <exchange>`: `10 mail.home.lan.`                             |
| `TXT`   | free text (quotes optional): `v=spf1 -all`                          |
| `NS`    | nameserver name: `ns1.home.lan.`                                     |
| `SOA`   | managed via zone `soa`; not created as a normal record              |
| `SRV`   | `<prio> <weight> <port> <target>`: `0 5 5060 sip.home.lan.`         |
| `PTR`   | target name: `nas.home.lan.` (name is the reversed-IP label)        |
| `CAA`   | `<flags> <tag> <value>`: `0 issue "letsencrypt.org"`                |

Validation errors return `422 validation` with per-field detail.

### Settings

`Settings`:
```json
{
  "forwarders": [
    { "addr": "1.1.1.1", "protocol": "udp", "port": 53, "tls_name": null }
  ],
  "resolution_mode": "forward",
  "block_mode": "nxdomain",
  "blocking_enabled": true,
  "query_log": "off",
  "allow_axfr_from": [],
  "cache_size": 1024,
  "cache_min_ttl": 0,
  "cache_max_ttl": 86400,
  "dnssec_validate_upstream": false
}
```
- `protocol` ∈ `udp | tcp | tls | https`. `tls`/`https` require `tls_name`.
- `resolution_mode` ∈ `forward` (use the `forwarders`) | `recursive` (resolve from
  the root servers; no upstream needed) | `off` (authoritative-only: REFUSE names
  outside local zones — for a universal/internal-only nameserver).
- `block_mode` ∈ `nxdomain | zero_ip | refused` — how blocked names are answered.
- `blocking_enabled` toggles blocklist filtering (manual rules/rewrites still apply).
- `query_log` ∈ `off | anonymized | full` — privacy-aware per-query logging (default
  `off`). See `GET /api/stats`.
- `allow_axfr_from` — CIDRs permitted to request AXFR zone transfers (empty = off).
- `GET /api/settings` → `200 { "settings": Settings }`
- `PUT /api/settings` body partial → `200 { "settings": Settings }`. Changes rebuild
  the resolver and reload the filter live (no restart).

### Filtering: blocklists, rules, rewrites

`Blocklist`:
```json
{ "id": 1, "name": "StevenBlack", "url": "https://.../hosts", "format": "hosts",
  "enabled": true, "entry_count": 120000, "last_updated": "...", "last_error": null,
  "created_at": "..." }
```
`format` ∈ `hosts | domains`. Downloaded domains are cached locally (SQLite) so they
survive restarts and aren't re-fetched on boot.

- `GET /api/blocklists` → `200 { "blocklists": [Blocklist] }`
- `POST /api/blocklists` body `{ "name","url","format"?,"refresh_now"? }` → `201 { "blocklist": Blocklist }`
- `PUT /api/blocklists/:id` body `{ "name"?, "enabled"? }` → `200 { "blocklist": Blocklist }`
- `DELETE /api/blocklists/:id` → `204`
- `POST /api/blocklists/:id/refresh` → `200 { "blocklist": Blocklist }` (re-fetch one)
- `POST /api/blocklists/refresh_all` → `200 { "blocklists": [Blocklist] }`

`BlockRule` (manual allow/deny; matches the domain and its subdomains):
```json
{ "id": 1, "domain": "ads.example.com", "action": "deny", "comment": null, "created_at": "..." }
```
`action` ∈ `deny | allow` (allow exempts a name from blocklists).
- `GET /api/rules` → `200 { "rules": [BlockRule] }`
- `POST /api/rules` body `{ "domain","action","comment"? }` → `201 { "rule": BlockRule }`
- `DELETE /api/rules/:id` → `204`

`Rewrite` (answer a fixed IP or CNAME for a domain + subdomains; applies even in
authoritative-only mode):
```json
{ "id": 1, "domain": "ads.foobar.com", "target": "1.2.3.4", "enabled": true,
  "comment": null, "created_at": "..." }
```
`target` is an IPv4/IPv6 address (→ A/AAAA) or a hostname (→ CNAME).
- `GET /api/rewrites` → `200 { "rewrites": [Rewrite] }`
- `POST /api/rewrites` body `{ "domain","target","comment"? }` → `201 { "rewrite": Rewrite }`
- `PUT /api/rewrites/:id` body `{ "domain"?,"target"?,"enabled"? }` → `200 { "rewrite": Rewrite }`
- `DELETE /api/rewrites/:id` → `204`

`ConditionalForward` (per-domain upstreams; queries under `domain` + subdomains go
to dedicated forwarders, taking precedence over the global resolver and working
even in authoritative-only mode):
```json
{ "id": 1, "domain": "corp.internal",
  "forwarders": [ { "addr": "10.0.0.1", "protocol": "udp", "port": 53, "tls_name": null } ],
  "enabled": true, "created_at": "..." }
```
- `GET /api/conditional-forwards` → `200 { "conditional_forwards": [ConditionalForward] }`
- `POST /api/conditional-forwards` body `{ "domain","forwarders":[Forwarder] }` → `201 { "conditional_forward": ... }`
- `PUT /api/conditional-forwards/:id` body `{ "forwarders"?, "enabled"? }` → `200 { "conditional_forward": ... }`
- `DELETE /api/conditional-forwards/:id` → `204`

Precedence on a query: **local authoritative zones → rewrite → allow rule → block
(blocklist/deny rule) → conditional forward → global upstream (forward/recursive)
→ REFUSED (off mode)**.

`GET /api/status` additionally returns `conditional_forward_count`.

### Zone import

`POST /api/zones/:id/import` body `{ "zonefile": "<BIND master file text>", "replace"?: bool }`
→ `200 { "imported": N, "skipped": M }`. Parses a BIND-style zone file (with
`$ORIGIN`/`$TTL`), adds supported records to the all-views set, and skips SOA and
unsupported types. `replace: true` clears the zone's existing records first.
Pairs with `GET /api/zones/:id/export`.

`GET /api/status` additionally returns: `resolution_mode`, `blocked_domains`
(count), `rewrite_count`, `active_zone_count`.

`GET /api/stats` additionally returns a `blocked` counter; `outcome` values now
include `blocked` and `rewritten`.

### DoH endpoint (not part of `/api`)

`GET|POST /dns-query` implements RFC 8484 (DoH). Served on the management port
(when HTTPS) and on any configured DoH listeners. GET uses `?dns=<base64url>`;
POST uses an `application/dns-message` body. The TLS peer IP is used for
split-horizon view selection.

Listen addresses and TLS certificate paths are **startup config** (file/CLI/env),
not editable via the API, because changing a listen socket needs a restart.

## Conventions for the web UI

- The UI is a static bundle embedded in the binary, served from `/` (SPA: unknown
  non-`/api` paths return `index.html`).
- The UI reads the `picons_csrf` cookie and sends `X-CSRF-Token` on mutations.
- On `401` the UI redirects to the login screen.
- First run: if no admin user exists, `GET /api/auth/me` returns
  `409 { "error": { "code": "setup_required" } }` and the UI shows a one-time
  "create admin account" screen that calls `POST /api/auth/login` semantics via
  `POST /api/setup` `{ "username", "password" }` (only available until the first
  user is created; afterwards → `409 conflict`).
