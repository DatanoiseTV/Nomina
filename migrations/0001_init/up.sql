-- Initial schema for Nomina. Mirrors the original rusqlite schema with the
-- previously-incremental ALTER columns folded into the CREATE TABLE statements.

CREATE TABLE users (
    id                   INTEGER PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE,
    password_hash        TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL
);

CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

CREATE TABLE views (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    networks     TEXT NOT NULL,
    priority     INTEGER NOT NULL DEFAULT 100,
    is_default   INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE TABLE zones (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    enabled      INTEGER NOT NULL DEFAULT 1,
    soa          TEXT NOT NULL,
    default_ttl  INTEGER NOT NULL DEFAULT 300,
    serial       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE records (
    id          INTEGER PRIMARY KEY,
    zone_id     INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    view_id     INTEGER REFERENCES views(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    rtype       TEXT NOT NULL,
    ttl         INTEGER,
    data        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX idx_records_zone ON records(zone_id);

CREATE TABLE settings (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    json  TEXT NOT NULL
);

CREATE TABLE blocklists (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    url          TEXT NOT NULL UNIQUE,
    format       TEXT NOT NULL DEFAULT 'hosts',
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_updated TEXT,
    last_error   TEXT,
    created_at   TEXT NOT NULL
);

-- Local cache of downloaded blocklist domains so we don't re-fetch on restart.
CREATE TABLE blocklist_entries (
    blocklist_id INTEGER NOT NULL REFERENCES blocklists(id) ON DELETE CASCADE,
    domain       TEXT NOT NULL
);
CREATE INDEX idx_ble_list ON blocklist_entries(blocklist_id);

CREATE TABLE block_rules (
    id         INTEGER PRIMARY KEY,
    domain     TEXT NOT NULL,
    action     TEXT NOT NULL,
    comment    TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE rewrites (
    id         INTEGER PRIMARY KEY,
    domain     TEXT NOT NULL,
    target     TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    comment    TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE conditional_forwards (
    id         INTEGER PRIMARY KEY,
    domain     TEXT NOT NULL UNIQUE,
    forwarders TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

-- Persistent query log (written only when query logging is enabled).
CREATE TABLE query_log (
    id      INTEGER PRIMARY KEY,
    at      TEXT NOT NULL,
    client  TEXT NOT NULL,
    view    TEXT,
    name    TEXT NOT NULL,
    qtype   TEXT NOT NULL,
    outcome TEXT NOT NULL,
    rcode   TEXT NOT NULL
);
CREATE INDEX idx_qlog_id ON query_log(id);
CREATE INDEX idx_qlog_name ON query_log(name);
CREATE INDEX idx_qlog_outcome ON query_log(outcome);

-- Per-zone DNSSEC signing key (base64 PKCS#8 DER). Presence = signed zone.
CREATE TABLE dnssec_keys (
    zone_id    INTEGER PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    algorithm  INTEGER NOT NULL,
    secret     TEXT NOT NULL,
    nsec3      INTEGER NOT NULL DEFAULT 0,
    salt       TEXT,
    iterations INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

-- A zone that is a secondary (replicated from a primary via AXFR).
CREATE TABLE secondary_zones (
    zone_id      INTEGER PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    primary_addr TEXT NOT NULL,
    refresh_secs INTEGER NOT NULL DEFAULT 3600,
    last_check   TEXT,
    last_error   TEXT,
    tsig_key     TEXT,
    created_at   TEXT NOT NULL
);

-- DynDNS update credentials. Each token authenticates a DynDNS2 client and is
-- scoped to an explicit list of hostnames it may repoint (defence in depth: a
-- leaked token cannot touch records outside its scope).
CREATE TABLE dyndns_tokens (
    id             INTEGER PRIMARY KEY,
    label          TEXT NOT NULL,
    username       TEXT NOT NULL UNIQUE,
    secret_hash    TEXT NOT NULL,
    hostnames      TEXT NOT NULL,
    view_id        INTEGER REFERENCES views(id) ON DELETE SET NULL,
    ttl            INTEGER NOT NULL DEFAULT 60,
    enabled        INTEGER NOT NULL DEFAULT 1,
    last_update_at TEXT,
    last_ip        TEXT,
    created_at     TEXT NOT NULL
);
