//! Diesel table definitions, hand-written to match `migrations/0001_init`.
//!
//! Integer columns are declared `BigInt` (i64) to line up with the `i64` ids
//! used throughout `models`; widths narrower than i64 (e.g. a record TTL) are
//! cast in `db.rs` when mapping to the domain types. Boolean-valued columns are
//! stored as SQLite integers but declared `Bool` so the query builder reads and
//! writes them as `bool`.

diesel::table! {
    users (id) {
        id -> BigInt,
        username -> Text,
        password_hash -> Text,
        must_change_password -> Bool,
        created_at -> Text,
    }
}

diesel::table! {
    sessions (id) {
        id -> Text,
        user_id -> BigInt,
        csrf_token -> Text,
        created_at -> Text,
        expires_at -> Text,
    }
}

diesel::table! {
    views (id) {
        id -> BigInt,
        name -> Text,
        networks -> Text,
        priority -> BigInt,
        is_default -> Bool,
        created_at -> Text,
        countries -> Text,
        continents -> Text,
        asns -> Text,
    }
}

diesel::table! {
    zones (id) {
        id -> BigInt,
        name -> Text,
        enabled -> Bool,
        soa -> Text,
        default_ttl -> BigInt,
        serial -> BigInt,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    records (id) {
        id -> BigInt,
        zone_id -> BigInt,
        view_id -> Nullable<BigInt>,
        name -> Text,
        rtype -> Text,
        ttl -> Nullable<BigInt>,
        data -> Text,
        enabled -> Bool,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    settings (id) {
        id -> BigInt,
        json -> Text,
    }
}

diesel::table! {
    blocklists (id) {
        id -> BigInt,
        name -> Text,
        url -> Text,
        format -> Text,
        enabled -> Bool,
        last_updated -> Nullable<Text>,
        last_error -> Nullable<Text>,
        created_at -> Text,
    }
}

diesel::table! {
    blocklist_entries (blocklist_id, domain) {
        blocklist_id -> BigInt,
        domain -> Text,
    }
}

diesel::table! {
    block_rules (id) {
        id -> BigInt,
        domain -> Text,
        action -> Text,
        comment -> Nullable<Text>,
        created_at -> Text,
    }
}

diesel::table! {
    rewrites (id) {
        id -> BigInt,
        domain -> Text,
        target -> Text,
        enabled -> Bool,
        comment -> Nullable<Text>,
        created_at -> Text,
    }
}

diesel::table! {
    conditional_forwards (id) {
        id -> BigInt,
        domain -> Text,
        forwarders -> Text,
        enabled -> Bool,
        created_at -> Text,
    }
}

diesel::table! {
    query_log (id) {
        id -> BigInt,
        at -> Text,
        client -> Text,
        view -> Nullable<Text>,
        name -> Text,
        qtype -> Text,
        outcome -> Text,
        rcode -> Text,
    }
}

diesel::table! {
    dnssec_keys (zone_id) {
        zone_id -> BigInt,
        algorithm -> BigInt,
        secret -> Text,
        nsec3 -> Bool,
        salt -> Nullable<Text>,
        iterations -> BigInt,
        created_at -> Text,
    }
}

diesel::table! {
    secondary_zones (zone_id) {
        zone_id -> BigInt,
        primary_addr -> Text,
        refresh_secs -> BigInt,
        last_check -> Nullable<Text>,
        last_error -> Nullable<Text>,
        tsig_key -> Nullable<Text>,
        created_at -> Text,
    }
}

diesel::table! {
    dhcp_scopes (id) {
        id -> BigInt,
        name -> Text,
        enabled -> Bool,
        family -> Text,
        subnet -> Text,
        range_start -> Text,
        range_end -> Text,
        lease_secs -> BigInt,
        dns_register -> Bool,
        dns_zone -> Nullable<Text>,
        options -> Text,
        created_at -> Text,
    }
}

diesel::table! {
    dhcp_reservations (id) {
        id -> BigInt,
        scope_id -> BigInt,
        identifier -> Text,
        ip -> Text,
        hostname -> Nullable<Text>,
        options -> Text,
        created_at -> Text,
    }
}

diesel::table! {
    dhcp_leases (id) {
        id -> BigInt,
        scope_id -> BigInt,
        family -> Text,
        ip -> Text,
        identifier -> Text,
        hostname -> Nullable<Text>,
        starts_at -> Text,
        expires_at -> Text,
        state -> Text,
        created_at -> Text,
    }
}

diesel::table! {
    dyndns_tokens (id) {
        id -> BigInt,
        label -> Text,
        username -> Text,
        secret_hash -> Text,
        hostnames -> Text,
        view_id -> Nullable<BigInt>,
        ttl -> BigInt,
        enabled -> Bool,
        last_update_at -> Nullable<Text>,
        last_ip -> Nullable<Text>,
        created_at -> Text,
    }
}
