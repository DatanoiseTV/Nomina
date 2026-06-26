//! SQLite persistence layer.
//!
//! The DNS hot path never touches this — it reads the in-memory [`crate::store`].
//! The database is the source of truth, mutated by the admin API and reloaded
//! into the store after each change. A single connection is guarded by a mutex
//! and all access is dispatched onto the blocking thread pool via [`Db::run`].

use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::AppError;
use crate::models::*;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE,
    password_hash        TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS views (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    networks     TEXT NOT NULL,
    priority     INTEGER NOT NULL DEFAULT 100,
    is_default   INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zones (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    enabled      INTEGER NOT NULL DEFAULT 1,
    soa          TEXT NOT NULL,
    default_ttl  INTEGER NOT NULL DEFAULT 300,
    serial       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
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
CREATE INDEX IF NOT EXISTS idx_records_zone ON records(zone_id);

CREATE TABLE IF NOT EXISTS settings (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    json  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocklists (
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
CREATE TABLE IF NOT EXISTS blocklist_entries (
    blocklist_id INTEGER NOT NULL REFERENCES blocklists(id) ON DELETE CASCADE,
    domain       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ble_list ON blocklist_entries(blocklist_id);

CREATE TABLE IF NOT EXISTS block_rules (
    id         INTEGER PRIMARY KEY,
    domain     TEXT NOT NULL,
    action     TEXT NOT NULL,
    comment    TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rewrites (
    id         INTEGER PRIMARY KEY,
    domain     TEXT NOT NULL,
    target     TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    comment    TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS conditional_forwards (
    id         INTEGER PRIMARY KEY,
    domain     TEXT NOT NULL UNIQUE,
    forwarders TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

-- Per-zone DNSSEC signing key (base64 PKCS#8 DER). Presence = signed zone.
CREATE TABLE IF NOT EXISTS dnssec_keys (
    zone_id    INTEGER PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    algorithm  INTEGER NOT NULL,
    secret     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- A zone that is a secondary (replicated from a primary via AXFR).
CREATE TABLE IF NOT EXISTS secondary_zones (
    zone_id      INTEGER PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    primary_addr TEXT NOT NULL,
    refresh_secs INTEGER NOT NULL DEFAULT 3600,
    last_check   TEXT,
    last_error   TEXT,
    created_at   TEXT NOT NULL
);
"#;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

/// A stored session row (server-side).
pub struct SessionRow {
    pub user_id: i64,
    pub csrf_token: String,
    pub expires_at: OffsetDateTime,
}

/// A user row including the password hash (never serialized to the API).
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub must_change_password: bool,
    pub created_at: String,
}

impl UserRow {
    pub fn public(&self) -> User {
        User {
            id: self.id,
            username: self.username.clone(),
            must_change_password: self.must_change_password,
            created_at: self.created_at.clone(),
        }
    }
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Map a serde error encountered while (de)serializing a JSON column.
fn json_err(e: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
}

impl Db {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run a synchronous database closure on the blocking pool.
    pub async fn run<T, F>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            f(&guard)
        })
        .await?
        .map_err(Into::into)
    }

    /// Like [`Db::run`] but provides a mutable connection (for transactions).
    pub async fn run_mut<T, F>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock();
            f(&mut guard)
        })
        .await?
        .map_err(Into::into)
    }

    /// Synchronous access for startup paths (store load, bootstrap).
    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        let guard = self.conn.lock();
        f(&guard)
    }

    // ----- users -----------------------------------------------------------

    pub fn user_count(conn: &Connection) -> rusqlite::Result<i64> {
        conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
    }

    pub fn create_user(
        conn: &Connection,
        username: &str,
        password_hash: &str,
        must_change: bool,
    ) -> rusqlite::Result<i64> {
        conn.execute(
            "INSERT INTO users (username, password_hash, must_change_password, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, must_change as i64, now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn user_by_username(conn: &Connection, username: &str) -> rusqlite::Result<Option<UserRow>> {
        conn.query_row(
            "SELECT id, username, password_hash, must_change_password, created_at
             FROM users WHERE username = ?1",
            params![username],
            Self::map_user,
        )
        .optional()
    }

    pub fn user_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<UserRow>> {
        conn.query_row(
            "SELECT id, username, password_hash, must_change_password, created_at
             FROM users WHERE id = ?1",
            params![id],
            Self::map_user,
        )
        .optional()
    }

    pub fn set_password(conn: &Connection, id: i64, hash: &str) -> rusqlite::Result<()> {
        conn.execute(
            "UPDATE users SET password_hash = ?1, must_change_password = 0 WHERE id = ?2",
            params![hash, id],
        )?;
        Ok(())
    }

    fn map_user(r: &rusqlite::Row) -> rusqlite::Result<UserRow> {
        Ok(UserRow {
            id: r.get(0)?,
            username: r.get(1)?,
            password_hash: r.get(2)?,
            must_change_password: r.get::<_, i64>(3)? != 0,
            created_at: r.get(4)?,
        })
    }

    // ----- sessions --------------------------------------------------------

    pub fn create_session(
        conn: &Connection,
        id: &str,
        user_id: i64,
        csrf: &str,
        expires_at: OffsetDateTime,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO sessions (id, user_id, csrf_token, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                user_id,
                csrf,
                now(),
                expires_at.format(&Rfc3339).unwrap_or_default()
            ],
        )?;
        Ok(())
    }

    pub fn session(conn: &Connection, id: &str) -> rusqlite::Result<Option<SessionRow>> {
        conn.query_row(
            "SELECT user_id, csrf_token, expires_at FROM sessions WHERE id = ?1",
            params![id],
            |r| {
                let exp: String = r.get(2)?;
                let expires_at = OffsetDateTime::parse(&exp, &Rfc3339)
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH);
                Ok(SessionRow {
                    user_id: r.get(0)?,
                    csrf_token: r.get(1)?,
                    expires_at,
                })
            },
        )
        .optional()
    }

    pub fn delete_session(conn: &Connection, id: &str) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn prune_sessions(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            params![now()],
        )?;
        Ok(())
    }

    // ----- views -----------------------------------------------------------

    pub fn list_views(conn: &Connection) -> rusqlite::Result<Vec<View>> {
        let mut stmt = conn.prepare(
            "SELECT id, name, networks, priority, is_default, created_at
             FROM views ORDER BY priority ASC, id ASC",
        )?;
        let rows = stmt
            .query_map([], Self::map_view)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn view(conn: &Connection, id: i64) -> rusqlite::Result<Option<View>> {
        conn.query_row(
            "SELECT id, name, networks, priority, is_default, created_at FROM views WHERE id = ?1",
            params![id],
            Self::map_view,
        )
        .optional()
    }

    pub fn create_view(
        conn: &Connection,
        name: &str,
        networks: &[String],
        priority: i64,
    ) -> rusqlite::Result<i64> {
        let json = serde_json::to_string(networks).map_err(json_err)?;
        conn.execute(
            "INSERT INTO views (name, networks, priority, is_default, created_at)
             VALUES (?1, ?2, ?3, 0, ?4)",
            params![name, json, priority, now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_view(
        conn: &Connection,
        id: i64,
        name: Option<&str>,
        networks: Option<&[String]>,
        priority: Option<i64>,
    ) -> rusqlite::Result<()> {
        if let Some(name) = name {
            conn.execute("UPDATE views SET name = ?1 WHERE id = ?2", params![name, id])?;
        }
        if let Some(nets) = networks {
            let json = serde_json::to_string(nets).map_err(json_err)?;
            conn.execute("UPDATE views SET networks = ?1 WHERE id = ?2", params![json, id])?;
        }
        if let Some(p) = priority {
            conn.execute("UPDATE views SET priority = ?1 WHERE id = ?2", params![p, id])?;
        }
        Ok(())
    }

    pub fn delete_view(conn: &Connection, id: i64) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM views WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Ensure a default view exists (matches everything; lowest precedence).
    pub fn ensure_default_view(conn: &Connection) -> rusqlite::Result<()> {
        let exists: i64 =
            conn.query_row("SELECT COUNT(*) FROM views WHERE is_default = 1", [], |r| r.get(0))?;
        if exists == 0 {
            let json = serde_json::to_string(&["0.0.0.0/0", "::/0"]).map_err(json_err)?;
            conn.execute(
                "INSERT INTO views (name, networks, priority, is_default, created_at)
                 VALUES ('default', ?1, 1000, 1, ?2)",
                params![json, now()],
            )?;
        }
        Ok(())
    }

    fn map_view(r: &rusqlite::Row) -> rusqlite::Result<View> {
        let nets: String = r.get(2)?;
        let networks: Vec<String> = serde_json::from_str(&nets).map_err(json_err)?;
        Ok(View {
            id: r.get(0)?,
            name: r.get(1)?,
            networks,
            priority: r.get(3)?,
            is_default: r.get::<_, i64>(4)? != 0,
            created_at: r.get(5)?,
        })
    }

    // ----- zones -----------------------------------------------------------

    pub fn list_zones(conn: &Connection) -> rusqlite::Result<Vec<Zone>> {
        let mut stmt = conn.prepare(
            "SELECT z.id, z.name, z.enabled, z.soa, z.default_ttl, z.serial,
                    z.created_at, z.updated_at,
                    (SELECT COUNT(*) FROM records r WHERE r.zone_id = z.id) AS rc,
                    s.primary_addr, s.last_check, s.last_error,
                    (SELECT EXISTS(SELECT 1 FROM dnssec_keys d WHERE d.zone_id = z.id)) AS dnssec
             FROM zones z LEFT JOIN secondary_zones s ON s.zone_id = z.id
             ORDER BY z.name ASC",
        )?;
        let rows = stmt
            .query_map([], Self::map_zone)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn zone(conn: &Connection, id: i64) -> rusqlite::Result<Option<Zone>> {
        conn.query_row(
            "SELECT z.id, z.name, z.enabled, z.soa, z.default_ttl, z.serial,
                    z.created_at, z.updated_at,
                    (SELECT COUNT(*) FROM records r WHERE r.zone_id = z.id) AS rc,
                    s.primary_addr, s.last_check, s.last_error,
                    (SELECT EXISTS(SELECT 1 FROM dnssec_keys d WHERE d.zone_id = z.id)) AS dnssec
             FROM zones z LEFT JOIN secondary_zones s ON s.zone_id = z.id
             WHERE z.id = ?1",
            params![id],
            Self::map_zone,
        )
        .optional()
    }

    pub fn create_zone(
        conn: &Connection,
        name: &str,
        soa: &Soa,
        default_ttl: u32,
    ) -> rusqlite::Result<i64> {
        let soa_json = serde_json::to_string(soa).map_err(json_err)?;
        let ts = now();
        conn.execute(
            "INSERT INTO zones (name, enabled, soa, default_ttl, serial, created_at, updated_at)
             VALUES (?1, 1, ?2, ?3, 1, ?4, ?4)",
            params![name, soa_json, default_ttl, ts],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_zone(
        conn: &Connection,
        id: i64,
        enabled: Option<bool>,
        soa: Option<&Soa>,
        default_ttl: Option<u32>,
    ) -> rusqlite::Result<()> {
        if let Some(e) = enabled {
            conn.execute("UPDATE zones SET enabled = ?1 WHERE id = ?2", params![e as i64, id])?;
        }
        if let Some(soa) = soa {
            let soa_json = serde_json::to_string(soa).map_err(json_err)?;
            conn.execute("UPDATE zones SET soa = ?1 WHERE id = ?2", params![soa_json, id])?;
        }
        if let Some(ttl) = default_ttl {
            conn.execute("UPDATE zones SET default_ttl = ?1 WHERE id = ?2", params![ttl, id])?;
        }
        Self::bump_serial(conn, id)?;
        Ok(())
    }

    pub fn delete_zone(conn: &Connection, id: i64) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM zones WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Increment the zone serial and update the timestamp. Called on any change
    /// to the zone or its records.
    pub fn bump_serial(conn: &Connection, id: i64) -> rusqlite::Result<()> {
        conn.execute(
            "UPDATE zones SET serial = serial + 1, updated_at = ?1 WHERE id = ?2",
            params![now(), id],
        )?;
        Ok(())
    }

    fn map_zone(r: &rusqlite::Row) -> rusqlite::Result<Zone> {
        let soa_json: String = r.get(3)?;
        let soa: Soa = serde_json::from_str(&soa_json).map_err(json_err)?;
        let primary_addr: Option<String> = r.get(9)?;
        Ok(Zone {
            id: r.get(0)?,
            name: r.get(1)?,
            enabled: r.get::<_, i64>(2)? != 0,
            soa,
            default_ttl: r.get(4)?,
            serial: r.get(5)?,
            created_at: r.get(6)?,
            updated_at: r.get(7)?,
            record_count: r.get(8)?,
            is_secondary: primary_addr.is_some(),
            primary_addr,
            last_check: r.get(10)?,
            last_error: r.get(11)?,
            dnssec: r.get::<_, i64>(12)? != 0,
        })
    }

    // ----- records ---------------------------------------------------------

    pub fn list_records(conn: &Connection, zone_id: i64) -> rusqlite::Result<Vec<DnsRecord>> {
        let zone_name: String =
            conn.query_row("SELECT name FROM zones WHERE id = ?1", params![zone_id], |r| r.get(0))?;
        let mut stmt = conn.prepare(
            "SELECT id, zone_id, view_id, name, rtype, ttl, data, enabled, created_at, updated_at
             FROM records WHERE zone_id = ?1 ORDER BY name ASC, rtype ASC",
        )?;
        let rows = stmt
            .query_map(params![zone_id], |r| Self::map_record(r, &zone_name))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn record(conn: &Connection, id: i64) -> rusqlite::Result<Option<DnsRecord>> {
        let row: Option<(i64,)> = conn
            .query_row("SELECT zone_id FROM records WHERE id = ?1", params![id], |r| {
                Ok((r.get(0)?,))
            })
            .optional()?;
        let Some((zone_id,)) = row else { return Ok(None) };
        let zone_name: String =
            conn.query_row("SELECT name FROM zones WHERE id = ?1", params![zone_id], |r| r.get(0))?;
        conn.query_row(
            "SELECT id, zone_id, view_id, name, rtype, ttl, data, enabled, created_at, updated_at
             FROM records WHERE id = ?1",
            params![id],
            |r| Self::map_record(r, &zone_name),
        )
        .optional()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_record(
        conn: &Connection,
        zone_id: i64,
        view_id: Option<i64>,
        name: &str,
        rtype: &str,
        ttl: Option<u32>,
        data: &str,
    ) -> rusqlite::Result<i64> {
        let ts = now();
        conn.execute(
            "INSERT INTO records (zone_id, view_id, name, rtype, ttl, data, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)",
            params![zone_id, view_id, name, rtype, ttl, data, ts],
        )?;
        Self::bump_serial(conn, zone_id)?;
        Ok(conn.last_insert_rowid())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_record(
        conn: &Connection,
        id: i64,
        view_id: Option<Option<i64>>,
        name: Option<&str>,
        ttl: Option<Option<u32>>,
        data: Option<&str>,
        enabled: Option<bool>,
    ) -> rusqlite::Result<()> {
        if let Some(v) = view_id {
            conn.execute("UPDATE records SET view_id = ?1 WHERE id = ?2", params![v, id])?;
        }
        if let Some(n) = name {
            conn.execute("UPDATE records SET name = ?1 WHERE id = ?2", params![n, id])?;
        }
        if let Some(t) = ttl {
            conn.execute("UPDATE records SET ttl = ?1 WHERE id = ?2", params![t, id])?;
        }
        if let Some(d) = data {
            conn.execute("UPDATE records SET data = ?1 WHERE id = ?2", params![d, id])?;
        }
        if let Some(e) = enabled {
            conn.execute("UPDATE records SET enabled = ?1 WHERE id = ?2", params![e as i64, id])?;
        }
        conn.execute("UPDATE records SET updated_at = ?1 WHERE id = ?2", params![now(), id])?;
        let zone_id: i64 =
            conn.query_row("SELECT zone_id FROM records WHERE id = ?1", params![id], |r| r.get(0))?;
        Self::bump_serial(conn, zone_id)?;
        Ok(())
    }

    pub fn delete_record(conn: &Connection, id: i64) -> rusqlite::Result<Option<i64>> {
        let zone_id: Option<i64> = conn
            .query_row("SELECT zone_id FROM records WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        if let Some(zid) = zone_id {
            conn.execute("DELETE FROM records WHERE id = ?1", params![id])?;
            Self::bump_serial(conn, zid)?;
        }
        Ok(zone_id)
    }

    /// Bulk-insert imported records into a zone within one transaction.
    /// `records` is `(name, rtype, ttl, data)`. Optionally replaces existing
    /// records first. Returns the number inserted.
    pub fn import_records(
        conn: &mut Connection,
        zone_id: i64,
        replace: bool,
        records: &[(String, String, u32, String)],
    ) -> rusqlite::Result<usize> {
        let ts = now();
        let tx = conn.transaction()?;
        if replace {
            tx.execute("DELETE FROM records WHERE zone_id = ?1", params![zone_id])?;
        }
        let mut count = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO records (zone_id, view_id, name, rtype, ttl, data, enabled, created_at, updated_at)
                 VALUES (?1, NULL, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
            )?;
            for (name, rtype, ttl, data) in records {
                stmt.execute(params![zone_id, name, rtype, ttl, data, ts])?;
                count += 1;
            }
        }
        tx.execute(
            "UPDATE zones SET serial = serial + 1, updated_at = ?1 WHERE id = ?2",
            params![ts, zone_id],
        )?;
        tx.commit()?;
        Ok(count)
    }

    fn map_record(r: &rusqlite::Row, zone_name: &str) -> rusqlite::Result<DnsRecord> {
        let name: String = r.get(3)?;
        let fqdn = record_fqdn_string(&name, zone_name);
        Ok(DnsRecord {
            id: r.get(0)?,
            zone_id: r.get(1)?,
            view_id: r.get(2)?,
            name,
            fqdn,
            rtype: r.get(4)?,
            ttl: r.get(5)?,
            data: r.get(6)?,
            enabled: r.get::<_, i64>(7)? != 0,
            created_at: r.get(8)?,
            updated_at: r.get(9)?,
        })
    }

    // ----- settings --------------------------------------------------------

    pub fn get_settings(conn: &Connection) -> rusqlite::Result<Settings> {
        let json: Option<String> = conn
            .query_row("SELECT json FROM settings WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        match json {
            Some(j) => serde_json::from_str(&j).map_err(json_err),
            None => Ok(Settings::default()),
        }
    }

    pub fn put_settings(conn: &Connection, settings: &Settings) -> rusqlite::Result<()> {
        let json = serde_json::to_string(settings).map_err(json_err)?;
        conn.execute(
            "INSERT INTO settings (id, json) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            params![json],
        )?;
        Ok(())
    }

    // ----- blocklists ------------------------------------------------------

    pub fn list_blocklists(conn: &Connection) -> rusqlite::Result<Vec<Blocklist>> {
        let mut stmt = conn.prepare(
            "SELECT b.id, b.name, b.url, b.format, b.enabled, b.last_updated, b.last_error,
                    b.created_at,
                    (SELECT COUNT(*) FROM blocklist_entries e WHERE e.blocklist_id = b.id) AS cnt
             FROM blocklists b ORDER BY b.name ASC",
        )?;
        let rows = stmt
            .query_map([], Self::map_blocklist)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn blocklist(conn: &Connection, id: i64) -> rusqlite::Result<Option<Blocklist>> {
        conn.query_row(
            "SELECT b.id, b.name, b.url, b.format, b.enabled, b.last_updated, b.last_error,
                    b.created_at,
                    (SELECT COUNT(*) FROM blocklist_entries e WHERE e.blocklist_id = b.id) AS cnt
             FROM blocklists b WHERE b.id = ?1",
            params![id],
            Self::map_blocklist,
        )
        .optional()
    }

    pub fn create_blocklist(
        conn: &Connection,
        name: &str,
        url: &str,
        format: BlocklistFormat,
        enabled: bool,
    ) -> rusqlite::Result<i64> {
        conn.execute(
            "INSERT INTO blocklists (name, url, format, enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, url, enum_to_str(&format), enabled as i64, now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_blocklist(
        conn: &Connection,
        id: i64,
        name: Option<&str>,
        enabled: Option<bool>,
    ) -> rusqlite::Result<()> {
        if let Some(n) = name {
            conn.execute("UPDATE blocklists SET name = ?1 WHERE id = ?2", params![n, id])?;
        }
        if let Some(e) = enabled {
            conn.execute(
                "UPDATE blocklists SET enabled = ?1 WHERE id = ?2",
                params![e as i64, id],
            )?;
        }
        Ok(())
    }

    pub fn delete_blocklist(conn: &Connection, id: i64) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM blocklists WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Replace the cached entries of a blocklist with a freshly fetched set.
    pub fn replace_blocklist_entries(
        conn: &mut Connection,
        id: i64,
        domains: &[String],
        error: Option<&str>,
    ) -> rusqlite::Result<()> {
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM blocklist_entries WHERE blocklist_id = ?1", params![id])?;
        {
            let mut stmt =
                tx.prepare("INSERT INTO blocklist_entries (blocklist_id, domain) VALUES (?1, ?2)")?;
            for d in domains {
                stmt.execute(params![id, d])?;
            }
        }
        tx.execute(
            "UPDATE blocklists SET last_updated = ?1, last_error = ?2 WHERE id = ?3",
            params![now(), error, id],
        )?;
        tx.commit()
    }

    pub fn set_blocklist_error(conn: &Connection, id: i64, error: &str) -> rusqlite::Result<()> {
        conn.execute(
            "UPDATE blocklists SET last_error = ?1 WHERE id = ?2",
            params![error, id],
        )?;
        Ok(())
    }

    /// All domains from enabled blocklists, for building the in-memory filter.
    pub fn enabled_block_domains(conn: &Connection) -> rusqlite::Result<Vec<String>> {
        let mut stmt = conn.prepare(
            "SELECT e.domain FROM blocklist_entries e
             JOIN blocklists b ON b.id = e.blocklist_id
             WHERE b.enabled = 1",
        )?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn map_blocklist(r: &rusqlite::Row) -> rusqlite::Result<Blocklist> {
        let fmt: String = r.get(3)?;
        Ok(Blocklist {
            id: r.get(0)?,
            name: r.get(1)?,
            url: r.get(2)?,
            format: enum_from_str(&fmt).unwrap_or_default(),
            enabled: r.get::<_, i64>(4)? != 0,
            last_updated: r.get(5)?,
            last_error: r.get(6)?,
            created_at: r.get(7)?,
            entry_count: r.get(8)?,
        })
    }

    // ----- block rules -----------------------------------------------------

    pub fn list_block_rules(conn: &Connection) -> rusqlite::Result<Vec<BlockRule>> {
        let mut stmt = conn.prepare(
            "SELECT id, domain, action, comment, created_at FROM block_rules ORDER BY domain ASC",
        )?;
        let rows = stmt
            .query_map([], Self::map_block_rule)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn create_block_rule(
        conn: &Connection,
        domain: &str,
        action: RuleAction,
        comment: Option<&str>,
    ) -> rusqlite::Result<i64> {
        conn.execute(
            "INSERT INTO block_rules (domain, action, comment, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![domain, enum_to_str(&action), comment, now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn delete_block_rule(conn: &Connection, id: i64) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM block_rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    fn map_block_rule(r: &rusqlite::Row) -> rusqlite::Result<BlockRule> {
        let action: String = r.get(2)?;
        Ok(BlockRule {
            id: r.get(0)?,
            domain: r.get(1)?,
            action: enum_from_str(&action).unwrap_or(RuleAction::Deny),
            comment: r.get(3)?,
            created_at: r.get(4)?,
        })
    }

    // ----- rewrites --------------------------------------------------------

    pub fn list_rewrites(conn: &Connection) -> rusqlite::Result<Vec<Rewrite>> {
        let mut stmt = conn.prepare(
            "SELECT id, domain, target, enabled, comment, created_at FROM rewrites ORDER BY domain ASC",
        )?;
        let rows = stmt
            .query_map([], Self::map_rewrite)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn rewrite(conn: &Connection, id: i64) -> rusqlite::Result<Option<Rewrite>> {
        conn.query_row(
            "SELECT id, domain, target, enabled, comment, created_at FROM rewrites WHERE id = ?1",
            params![id],
            Self::map_rewrite,
        )
        .optional()
    }

    pub fn create_rewrite(
        conn: &Connection,
        domain: &str,
        target: &str,
        comment: Option<&str>,
    ) -> rusqlite::Result<i64> {
        conn.execute(
            "INSERT INTO rewrites (domain, target, enabled, comment, created_at)
             VALUES (?1, ?2, 1, ?3, ?4)",
            params![domain, target, comment, now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_rewrite(
        conn: &Connection,
        id: i64,
        domain: Option<&str>,
        target: Option<&str>,
        enabled: Option<bool>,
    ) -> rusqlite::Result<()> {
        if let Some(d) = domain {
            conn.execute("UPDATE rewrites SET domain = ?1 WHERE id = ?2", params![d, id])?;
        }
        if let Some(t) = target {
            conn.execute("UPDATE rewrites SET target = ?1 WHERE id = ?2", params![t, id])?;
        }
        if let Some(e) = enabled {
            conn.execute("UPDATE rewrites SET enabled = ?1 WHERE id = ?2", params![e as i64, id])?;
        }
        Ok(())
    }

    pub fn delete_rewrite(conn: &Connection, id: i64) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM rewrites WHERE id = ?1", params![id])?;
        Ok(())
    }

    fn map_rewrite(r: &rusqlite::Row) -> rusqlite::Result<Rewrite> {
        Ok(Rewrite {
            id: r.get(0)?,
            domain: r.get(1)?,
            target: r.get(2)?,
            enabled: r.get::<_, i64>(3)? != 0,
            comment: r.get(4)?,
            created_at: r.get(5)?,
        })
    }

    // ----- conditional forwards -------------------------------------------

    pub fn list_conditional_forwards(
        conn: &Connection,
    ) -> rusqlite::Result<Vec<ConditionalForward>> {
        let mut stmt = conn.prepare(
            "SELECT id, domain, forwarders, enabled, created_at
             FROM conditional_forwards ORDER BY domain ASC",
        )?;
        let rows = stmt
            .query_map([], Self::map_conditional)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn conditional_forward(
        conn: &Connection,
        id: i64,
    ) -> rusqlite::Result<Option<ConditionalForward>> {
        conn.query_row(
            "SELECT id, domain, forwarders, enabled, created_at
             FROM conditional_forwards WHERE id = ?1",
            params![id],
            Self::map_conditional,
        )
        .optional()
    }

    pub fn create_conditional_forward(
        conn: &Connection,
        domain: &str,
        forwarders: &[Forwarder],
    ) -> rusqlite::Result<i64> {
        let json = serde_json::to_string(forwarders).map_err(json_err)?;
        conn.execute(
            "INSERT INTO conditional_forwards (domain, forwarders, enabled, created_at)
             VALUES (?1, ?2, 1, ?3)",
            params![domain, json, now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_conditional_forward(
        conn: &Connection,
        id: i64,
        forwarders: Option<&[Forwarder]>,
        enabled: Option<bool>,
    ) -> rusqlite::Result<()> {
        if let Some(f) = forwarders {
            let json = serde_json::to_string(f).map_err(json_err)?;
            conn.execute(
                "UPDATE conditional_forwards SET forwarders = ?1 WHERE id = ?2",
                params![json, id],
            )?;
        }
        if let Some(e) = enabled {
            conn.execute(
                "UPDATE conditional_forwards SET enabled = ?1 WHERE id = ?2",
                params![e as i64, id],
            )?;
        }
        Ok(())
    }

    pub fn delete_conditional_forward(conn: &Connection, id: i64) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM conditional_forwards WHERE id = ?1", params![id])?;
        Ok(())
    }

    fn map_conditional(r: &rusqlite::Row) -> rusqlite::Result<ConditionalForward> {
        let json: String = r.get(2)?;
        let forwarders: Vec<Forwarder> = serde_json::from_str(&json).map_err(json_err)?;
        Ok(ConditionalForward {
            id: r.get(0)?,
            domain: r.get(1)?,
            forwarders,
            enabled: r.get::<_, i64>(3)? != 0,
            created_at: r.get(4)?,
        })
    }

    // ----- DNSSEC keys -----------------------------------------------------

    pub fn create_dnssec_key(
        conn: &Connection,
        zone_id: i64,
        algorithm: i64,
        secret: &str,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO dnssec_keys (zone_id, algorithm, secret, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(zone_id) DO UPDATE SET algorithm = excluded.algorithm,
                 secret = excluded.secret, created_at = excluded.created_at",
            params![zone_id, algorithm, secret, now()],
        )?;
        Ok(())
    }

    pub fn dnssec_secret(conn: &Connection, zone_id: i64) -> rusqlite::Result<Option<String>> {
        conn.query_row(
            "SELECT secret FROM dnssec_keys WHERE zone_id = ?1",
            params![zone_id],
            |r| r.get(0),
        )
        .optional()
    }

    pub fn delete_dnssec_key(conn: &Connection, zone_id: i64) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM dnssec_keys WHERE zone_id = ?1", params![zone_id])?;
        Ok(())
    }

    // ----- secondary zones -------------------------------------------------

    pub fn list_secondaries(conn: &Connection) -> rusqlite::Result<Vec<SecondaryZone>> {
        let mut stmt = conn.prepare(
            "SELECT s.zone_id, z.name, s.primary_addr, s.refresh_secs, z.serial,
                    (SELECT COUNT(*) FROM records r WHERE r.zone_id = z.id) AS rc,
                    s.last_check, s.last_error
             FROM secondary_zones s JOIN zones z ON z.id = s.zone_id
             ORDER BY z.name ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SecondaryZone {
                    zone_id: r.get(0)?,
                    name: r.get(1)?,
                    primary_addr: r.get(2)?,
                    refresh_secs: r.get(3)?,
                    serial: r.get(4)?,
                    record_count: r.get(5)?,
                    last_check: r.get(6)?,
                    last_error: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn create_secondary(
        conn: &Connection,
        zone_id: i64,
        primary_addr: &str,
        refresh_secs: i64,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO secondary_zones (zone_id, primary_addr, refresh_secs, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![zone_id, primary_addr, refresh_secs, now()],
        )?;
        Ok(())
    }

    pub fn set_secondary_status(
        conn: &Connection,
        zone_id: i64,
        last_error: Option<&str>,
        refresh_secs: Option<i64>,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "UPDATE secondary_zones SET last_check = ?1, last_error = ?2 WHERE zone_id = ?3",
            params![now(), last_error, zone_id],
        )?;
        if let Some(r) = refresh_secs {
            conn.execute(
                "UPDATE secondary_zones SET refresh_secs = ?1 WHERE zone_id = ?2",
                params![r, zone_id],
            )?;
        }
        Ok(())
    }

    /// Replace a secondary zone's SOA, serial, and records from a transfer.
    pub fn replace_secondary_zone(
        conn: &mut Connection,
        zone_id: i64,
        soa: &Soa,
        serial: u32,
        records: &[(String, String, u32, String)],
    ) -> rusqlite::Result<usize> {
        let soa_json = serde_json::to_string(soa).map_err(json_err)?;
        let ts = now();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE zones SET soa = ?1, serial = ?2, updated_at = ?3 WHERE id = ?4",
            params![soa_json, serial, ts, zone_id],
        )?;
        tx.execute("DELETE FROM records WHERE zone_id = ?1", params![zone_id])?;
        let mut count = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO records (zone_id, view_id, name, rtype, ttl, data, enabled, created_at, updated_at)
                 VALUES (?1, NULL, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
            )?;
            for (name, rtype, ttl, data) in records {
                stmt.execute(params![zone_id, name, rtype, ttl, data, ts])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }
}

/// Serialize a unit enum (with serde `rename_all`) to its string form.
fn enum_to_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(String::from))
        .unwrap_or_default()
}

fn enum_from_str<T: serde::de::DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}
