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
  "cached": 1500,
  "nxdomain": 210,
  "refused": 12,
  "servfail": 4,
  "by_qtype": { "A": 6000, "AAAA": 3000, "PTR": 400 },
  "recent": [
    { "at": "2026-06-26T10:00:01Z", "client": "192.168.1.50", "view": "internal",
      "name": "nas.home.lan", "qtype": "A", "outcome": "authoritative", "rcode": "NOERROR" }
  ]
}
```
`outcome` ∈ `authoritative | forwarded | cached | nxdomain | refused | servfail`.

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
  "forward_enabled": true,
  "cache_size": 1024,
  "cache_min_ttl": 0,
  "cache_max_ttl": 86400,
  "dnssec_validate_upstream": false
}
```
- `protocol` ∈ `udp | tcp | tls | https`. `tls`/`https` require `tls_name`.
- `GET /api/settings` → `200 { "settings": Settings }`
- `PUT /api/settings` body partial → `200 { "settings": Settings }`. Applying
  forwarder/cache changes rebuilds the resolver live (no restart).

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
