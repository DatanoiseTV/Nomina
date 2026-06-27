-- DHCP server foundation: scopes, reservations, and dynamic leases.
-- Options for scopes/reservations are stored as a JSON array in a TEXT column,
-- mirroring the `views.networks` convention. Integer columns use INTEGER
-- (mapped to i64 in Rust); booleans are stored as 0/1 integers.

CREATE TABLE dhcp_scopes (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    enabled      INTEGER NOT NULL DEFAULT 1,
    family       TEXT NOT NULL,
    subnet       TEXT NOT NULL,
    range_start  TEXT NOT NULL,
    range_end    TEXT NOT NULL,
    lease_secs   INTEGER NOT NULL,
    dns_register INTEGER NOT NULL DEFAULT 0,
    dns_zone     TEXT,
    options      TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL
);

CREATE TABLE dhcp_reservations (
    id          INTEGER PRIMARY KEY,
    scope_id    INTEGER NOT NULL REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
    identifier  TEXT NOT NULL,
    ip          TEXT NOT NULL,
    hostname    TEXT,
    options     TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL
);

CREATE TABLE dhcp_leases (
    id          INTEGER PRIMARY KEY,
    scope_id    INTEGER NOT NULL REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
    family      TEXT NOT NULL,
    ip          TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    hostname    TEXT,
    starts_at   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    state       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (scope_id, ip)
);

CREATE INDEX idx_dhcp_reservations_scope ON dhcp_reservations(scope_id);
CREATE INDEX idx_dhcp_leases_scope ON dhcp_leases(scope_id);
CREATE INDEX idx_dhcp_leases_identifier ON dhcp_leases(identifier);
