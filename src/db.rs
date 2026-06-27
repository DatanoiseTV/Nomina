//! SQLite persistence layer (Diesel ORM).
//!
//! The DNS hot path never touches this — it reads the in-memory [`crate::store`].
//! The database is the source of truth, mutated by the admin API and reloaded
//! into the store after each change. A single connection is guarded by a mutex
//! and all access is dispatched onto the blocking thread pool via [`Db::run`].

use std::sync::Arc;

use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::result::QueryResult;
use diesel::sql_types::{BigInt, Nullable, Text};
use diesel::sqlite::{Sqlite, SqliteConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use parking_lot::Mutex;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::AppError;
use crate::models::*;
use crate::schema::*;
use crate::stats::RecentQuery;

/// Migrations embedded into the binary, run on every [`Db::open`].
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<SqliteConnection>>,
}

/// A DynDNS token row including the secret hash (never serialized to the API).
pub struct DynDnsAuthRow {
    pub id: i64,
    pub secret_hash: String,
    pub hostnames: Vec<String>,
    pub view_id: Option<i64>,
    pub ttl: u32,
    pub enabled: bool,
}

/// Outcome of applying one DynDNS address update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynUpdate {
    /// A new record was created for the host.
    Created,
    /// An existing record's address changed.
    Updated,
    /// The host already pointed at this address.
    Unchanged,
    /// No local zone covers the hostname.
    NoZone,
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

/// Map a serde error encountered while (de)serializing a JSON column. Internal
/// only — surfaces as a 500, never a constraint conflict.
fn json_err(e: serde_json::Error) -> diesel::result::Error {
    diesel::result::Error::SerializationError(Box::new(e))
}

/// Map a malformed stored enum string (family/state) to a deserialization
/// error. Internal only — only reachable if the DB holds a value we never wrote.
#[allow(dead_code)] // used by the Phase 1 DHCP row decoders.
fn enum_err(what: &str) -> diesel::result::Error {
    diesel::result::Error::DeserializationError(format!("invalid stored {what}").into())
}

/// Parse a stored comma-separated hostname list into normalized FQDNs.
fn split_hostnames(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

/// Serialize a hostname list for storage (normalized, comma-separated).
fn join_hostnames(hostnames: &[String]) -> String {
    hostnames
        .iter()
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// Raw rows for the handful of reads kept as `sql_query` (correlated subqueries,
// joins, dynamic filters) so behaviour stays identical to the hand-written SQL.
// ---------------------------------------------------------------------------

#[derive(QueryableByName)]
struct ZoneRaw {
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = BigInt)]
    enabled: i64,
    #[diesel(sql_type = Text)]
    soa: String,
    #[diesel(sql_type = BigInt)]
    default_ttl: i64,
    #[diesel(sql_type = BigInt)]
    serial: i64,
    #[diesel(sql_type = Text)]
    created_at: String,
    #[diesel(sql_type = Text)]
    updated_at: String,
    #[diesel(sql_type = BigInt)]
    rc: i64,
    #[diesel(sql_type = Nullable<Text>)]
    primary_addr: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_check: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error: Option<String>,
    #[diesel(sql_type = BigInt)]
    dnssec: i64,
}

impl ZoneRaw {
    fn into_zone(self) -> QueryResult<Zone> {
        let soa: Soa = serde_json::from_str(&self.soa).map_err(json_err)?;
        Ok(Zone {
            id: self.id,
            name: self.name,
            enabled: self.enabled != 0,
            soa,
            default_ttl: self.default_ttl as u32,
            serial: self.serial as u32,
            created_at: self.created_at,
            updated_at: self.updated_at,
            record_count: self.rc,
            is_secondary: self.primary_addr.is_some(),
            primary_addr: self.primary_addr,
            last_check: self.last_check,
            last_error: self.last_error,
            dnssec: self.dnssec != 0,
        })
    }
}

const ZONE_SELECT: &str = "SELECT z.id AS id, z.name AS name, z.enabled AS enabled,
        z.soa AS soa, z.default_ttl AS default_ttl, z.serial AS serial,
        z.created_at AS created_at, z.updated_at AS updated_at,
        (SELECT COUNT(*) FROM records r WHERE r.zone_id = z.id) AS rc,
        s.primary_addr AS primary_addr, s.last_check AS last_check, s.last_error AS last_error,
        (SELECT EXISTS(SELECT 1 FROM dnssec_keys d WHERE d.zone_id = z.id)) AS dnssec
     FROM zones z LEFT JOIN secondary_zones s ON s.zone_id = z.id";

#[derive(QueryableByName)]
struct BlocklistRaw {
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Text)]
    url: String,
    #[diesel(sql_type = Text)]
    format: String,
    #[diesel(sql_type = BigInt)]
    enabled: i64,
    #[diesel(sql_type = Nullable<Text>)]
    last_updated: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error: Option<String>,
    #[diesel(sql_type = Text)]
    created_at: String,
    #[diesel(sql_type = BigInt)]
    cnt: i64,
}

impl BlocklistRaw {
    fn into_blocklist(self) -> Blocklist {
        Blocklist {
            id: self.id,
            name: self.name,
            url: self.url,
            format: enum_from_str(&self.format).unwrap_or_default(),
            enabled: self.enabled != 0,
            last_updated: self.last_updated,
            last_error: self.last_error,
            created_at: self.created_at,
            entry_count: self.cnt,
        }
    }
}

const BLOCKLIST_SELECT: &str = "SELECT b.id AS id, b.name AS name, b.url AS url,
        b.format AS format, b.enabled AS enabled, b.last_updated AS last_updated,
        b.last_error AS last_error, b.created_at AS created_at,
        (SELECT COUNT(*) FROM blocklist_entries e WHERE e.blocklist_id = b.id) AS cnt
     FROM blocklists b";

#[derive(QueryableByName)]
struct SecondaryRaw {
    #[diesel(sql_type = BigInt)]
    zone_id: i64,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Text)]
    primary_addr: String,
    #[diesel(sql_type = BigInt)]
    refresh_secs: i64,
    #[diesel(sql_type = BigInt)]
    serial: i64,
    #[diesel(sql_type = BigInt)]
    rc: i64,
    #[diesel(sql_type = Nullable<Text>)]
    last_check: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    tsig_key: Option<String>,
}

#[derive(QueryableByName)]
struct DomainRow {
    #[diesel(sql_type = Text)]
    domain: String,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    n: i64,
}

#[derive(QueryableByName)]
struct QlogRow {
    #[diesel(sql_type = Text)]
    at: String,
    #[diesel(sql_type = Text)]
    client: String,
    #[diesel(sql_type = Nullable<Text>)]
    view: Option<String>,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Text)]
    qtype: String,
    #[diesel(sql_type = Text)]
    outcome: String,
    #[diesel(sql_type = Text)]
    rcode: String,
}

#[derive(QueryableByName)]
struct DynRecRow {
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    view_id: Option<i64>,
    #[diesel(sql_type = Text)]
    data: String,
}

impl Db {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let url = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("database path is not valid UTF-8"))?;
        let mut conn = SqliteConnection::establish(url)?;
        Self::init(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let mut conn = SqliteConnection::establish(":memory:")?;
        Self::init(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Set pragmas and run the embedded migrations on a fresh connection.
    fn init(conn: &mut SqliteConnection) -> anyhow::Result<()> {
        conn.batch_execute("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("database migration failed: {e}"))?;
        Ok(())
    }

    /// Run a synchronous database closure on the blocking pool.
    pub async fn run<T, F>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut SqliteConnection) -> QueryResult<T> + Send + 'static,
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

    /// Like [`Db::run`]. Retained for call sites that need transactions; Diesel
    /// hands out `&mut SqliteConnection` to both.
    pub async fn run_mut<T, F>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut SqliteConnection) -> QueryResult<T> + Send + 'static,
        T: Send + 'static,
    {
        self.run(f).await
    }

    /// Synchronous access for startup paths (store load, bootstrap).
    pub fn with<T>(
        &self,
        f: impl FnOnce(&mut SqliteConnection) -> QueryResult<T>,
    ) -> QueryResult<T> {
        let mut guard = self.conn.lock();
        f(&mut guard)
    }

    // ----- users -----------------------------------------------------------

    pub fn user_count(conn: &mut SqliteConnection) -> QueryResult<i64> {
        users::table.count().get_result(conn)
    }

    pub fn create_user(
        conn: &mut SqliteConnection,
        username: &str,
        password_hash: &str,
        must_change: bool,
    ) -> QueryResult<i64> {
        diesel::insert_into(users::table)
            .values((
                users::username.eq(username),
                users::password_hash.eq(password_hash),
                users::must_change_password.eq(must_change),
                users::created_at.eq(now()),
            ))
            .returning(users::id)
            .get_result(conn)
    }

    pub fn user_by_username(
        conn: &mut SqliteConnection,
        username: &str,
    ) -> QueryResult<Option<UserRow>> {
        users::table
            .filter(users::username.eq(username))
            .select((
                users::id,
                users::username,
                users::password_hash,
                users::must_change_password,
                users::created_at,
            ))
            .first::<(i64, String, String, bool, String)>(conn)
            .optional()
            .map(|o| o.map(Self::user_from))
    }

    pub fn user_by_id(conn: &mut SqliteConnection, id: i64) -> QueryResult<Option<UserRow>> {
        users::table
            .filter(users::id.eq(id))
            .select((
                users::id,
                users::username,
                users::password_hash,
                users::must_change_password,
                users::created_at,
            ))
            .first::<(i64, String, String, bool, String)>(conn)
            .optional()
            .map(|o| o.map(Self::user_from))
    }

    pub fn set_password(conn: &mut SqliteConnection, id: i64, hash: &str) -> QueryResult<()> {
        diesel::update(users::table.filter(users::id.eq(id)))
            .set((
                users::password_hash.eq(hash),
                users::must_change_password.eq(false),
            ))
            .execute(conn)
            .map(|_| ())
    }

    fn user_from(t: (i64, String, String, bool, String)) -> UserRow {
        UserRow {
            id: t.0,
            username: t.1,
            password_hash: t.2,
            must_change_password: t.3,
            created_at: t.4,
        }
    }

    // ----- sessions --------------------------------------------------------

    pub fn create_session(
        conn: &mut SqliteConnection,
        id: &str,
        user_id: i64,
        csrf: &str,
        expires_at: OffsetDateTime,
    ) -> QueryResult<()> {
        diesel::insert_into(sessions::table)
            .values((
                sessions::id.eq(id),
                sessions::user_id.eq(user_id),
                sessions::csrf_token.eq(csrf),
                sessions::created_at.eq(now()),
                sessions::expires_at.eq(expires_at.format(&Rfc3339).unwrap_or_default()),
            ))
            .execute(conn)
            .map(|_| ())
    }

    pub fn session(conn: &mut SqliteConnection, id: &str) -> QueryResult<Option<SessionRow>> {
        sessions::table
            .filter(sessions::id.eq(id))
            .select((
                sessions::user_id,
                sessions::csrf_token,
                sessions::expires_at,
            ))
            .first::<(i64, String, String)>(conn)
            .optional()
            .map(|o| {
                o.map(|(user_id, csrf_token, exp)| {
                    let expires_at =
                        OffsetDateTime::parse(&exp, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH);
                    SessionRow {
                        user_id,
                        csrf_token,
                        expires_at,
                    }
                })
            })
    }

    pub fn delete_session(conn: &mut SqliteConnection, id: &str) -> QueryResult<()> {
        diesel::delete(sessions::table.filter(sessions::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    pub fn prune_sessions(conn: &mut SqliteConnection) -> QueryResult<()> {
        diesel::delete(sessions::table.filter(sessions::expires_at.lt(now())))
            .execute(conn)
            .map(|_| ())
    }

    // ----- views -----------------------------------------------------------

    pub fn list_views(conn: &mut SqliteConnection) -> QueryResult<Vec<View>> {
        views::table
            .select((
                views::id,
                views::name,
                views::networks,
                views::priority,
                views::is_default,
                views::created_at,
                views::countries,
                views::continents,
                views::asns,
            ))
            .order(views::priority.asc())
            .then_order_by(views::id.asc())
            .load::<(
                i64,
                String,
                String,
                i64,
                bool,
                String,
                String,
                String,
                String,
            )>(conn)?
            .into_iter()
            .map(Self::view_from)
            .collect()
    }

    pub fn view(conn: &mut SqliteConnection, id: i64) -> QueryResult<Option<View>> {
        views::table
            .filter(views::id.eq(id))
            .select((
                views::id,
                views::name,
                views::networks,
                views::priority,
                views::is_default,
                views::created_at,
                views::countries,
                views::continents,
                views::asns,
            ))
            .first::<(
                i64,
                String,
                String,
                i64,
                bool,
                String,
                String,
                String,
                String,
            )>(conn)
            .optional()?
            .map(Self::view_from)
            .transpose()
    }

    pub fn create_view(
        conn: &mut SqliteConnection,
        name: &str,
        networks: &[String],
        priority: i64,
        countries: &[String],
        continents: &[String],
        asns: &[u32],
    ) -> QueryResult<i64> {
        let json = serde_json::to_string(networks).map_err(json_err)?;
        let c = serde_json::to_string(countries).map_err(json_err)?;
        let cont = serde_json::to_string(continents).map_err(json_err)?;
        let a = serde_json::to_string(asns).map_err(json_err)?;
        diesel::insert_into(views::table)
            .values((
                views::name.eq(name),
                views::networks.eq(json),
                views::priority.eq(priority),
                views::is_default.eq(false),
                views::created_at.eq(now()),
                views::countries.eq(c),
                views::continents.eq(cont),
                views::asns.eq(a),
            ))
            .returning(views::id)
            .get_result(conn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_view(
        conn: &mut SqliteConnection,
        id: i64,
        name: Option<&str>,
        networks: Option<&[String]>,
        priority: Option<i64>,
        countries: Option<&[String]>,
        continents: Option<&[String]>,
        asns: Option<&[u32]>,
    ) -> QueryResult<()> {
        if let Some(name) = name {
            diesel::update(views::table.filter(views::id.eq(id)))
                .set(views::name.eq(name))
                .execute(conn)?;
        }
        if let Some(nets) = networks {
            let json = serde_json::to_string(nets).map_err(json_err)?;
            diesel::update(views::table.filter(views::id.eq(id)))
                .set(views::networks.eq(json))
                .execute(conn)?;
        }
        if let Some(p) = priority {
            diesel::update(views::table.filter(views::id.eq(id)))
                .set(views::priority.eq(p))
                .execute(conn)?;
        }
        if let Some(v) = countries {
            let json = serde_json::to_string(v).map_err(json_err)?;
            diesel::update(views::table.filter(views::id.eq(id)))
                .set(views::countries.eq(json))
                .execute(conn)?;
        }
        if let Some(v) = continents {
            let json = serde_json::to_string(v).map_err(json_err)?;
            diesel::update(views::table.filter(views::id.eq(id)))
                .set(views::continents.eq(json))
                .execute(conn)?;
        }
        if let Some(v) = asns {
            let json = serde_json::to_string(v).map_err(json_err)?;
            diesel::update(views::table.filter(views::id.eq(id)))
                .set(views::asns.eq(json))
                .execute(conn)?;
        }
        Ok(())
    }

    pub fn delete_view(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(views::table.filter(views::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    /// Ensure a default view exists (matches everything; lowest precedence).
    pub fn ensure_default_view(conn: &mut SqliteConnection) -> QueryResult<()> {
        let exists: i64 = views::table
            .filter(views::is_default.eq(true))
            .count()
            .get_result(conn)?;
        if exists == 0 {
            let json = serde_json::to_string(&["0.0.0.0/0", "::/0"]).map_err(json_err)?;
            diesel::insert_into(views::table)
                .values((
                    views::name.eq("default"),
                    views::networks.eq(json),
                    views::priority.eq(1000_i64),
                    views::is_default.eq(true),
                    views::created_at.eq(now()),
                ))
                .execute(conn)?;
        }
        Ok(())
    }

    fn view_from(
        t: (
            i64,
            String,
            String,
            i64,
            bool,
            String,
            String,
            String,
            String,
        ),
    ) -> QueryResult<View> {
        let networks: Vec<String> = serde_json::from_str(&t.2).map_err(json_err)?;
        let countries: Vec<String> = serde_json::from_str(&t.6).map_err(json_err)?;
        let continents: Vec<String> = serde_json::from_str(&t.7).map_err(json_err)?;
        let asns: Vec<u32> = serde_json::from_str(&t.8).map_err(json_err)?;
        Ok(View {
            id: t.0,
            name: t.1,
            networks,
            countries,
            continents,
            asns,
            priority: t.3,
            is_default: t.4,
            created_at: t.5,
        })
    }

    // ----- zones -----------------------------------------------------------

    pub fn list_zones(conn: &mut SqliteConnection) -> QueryResult<Vec<Zone>> {
        let sql = format!("{ZONE_SELECT} ORDER BY z.name ASC");
        diesel::sql_query(sql)
            .load::<ZoneRaw>(conn)?
            .into_iter()
            .map(ZoneRaw::into_zone)
            .collect()
    }

    pub fn zone(conn: &mut SqliteConnection, id: i64) -> QueryResult<Option<Zone>> {
        let sql = format!("{ZONE_SELECT} WHERE z.id = ?");
        diesel::sql_query(sql)
            .bind::<BigInt, _>(id)
            .get_result::<ZoneRaw>(conn)
            .optional()?
            .map(ZoneRaw::into_zone)
            .transpose()
    }

    pub fn create_zone(
        conn: &mut SqliteConnection,
        name: &str,
        soa: &Soa,
        default_ttl: u32,
    ) -> QueryResult<i64> {
        let soa_json = serde_json::to_string(soa).map_err(json_err)?;
        let ts = now();
        diesel::insert_into(zones::table)
            .values((
                zones::name.eq(name),
                zones::enabled.eq(true),
                zones::soa.eq(soa_json),
                zones::default_ttl.eq(default_ttl as i64),
                zones::serial.eq(1_i64),
                zones::created_at.eq(&ts),
                zones::updated_at.eq(&ts),
            ))
            .returning(zones::id)
            .get_result(conn)
    }

    pub fn update_zone(
        conn: &mut SqliteConnection,
        id: i64,
        enabled: Option<bool>,
        soa: Option<&Soa>,
        default_ttl: Option<u32>,
    ) -> QueryResult<()> {
        if let Some(e) = enabled {
            diesel::update(zones::table.filter(zones::id.eq(id)))
                .set(zones::enabled.eq(e))
                .execute(conn)?;
        }
        if let Some(soa) = soa {
            let soa_json = serde_json::to_string(soa).map_err(json_err)?;
            diesel::update(zones::table.filter(zones::id.eq(id)))
                .set(zones::soa.eq(soa_json))
                .execute(conn)?;
        }
        if let Some(ttl) = default_ttl {
            diesel::update(zones::table.filter(zones::id.eq(id)))
                .set(zones::default_ttl.eq(ttl as i64))
                .execute(conn)?;
        }
        Self::bump_serial(conn, id)?;
        Ok(())
    }

    pub fn delete_zone(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(zones::table.filter(zones::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    /// Increment the zone serial and update the timestamp. Called on any change
    /// to the zone or its records.
    pub fn bump_serial(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::update(zones::table.filter(zones::id.eq(id)))
            .set((
                zones::serial.eq(zones::serial + 1),
                zones::updated_at.eq(now()),
            ))
            .execute(conn)
            .map(|_| ())
    }

    // ----- records ---------------------------------------------------------

    pub fn list_records(conn: &mut SqliteConnection, zone_id: i64) -> QueryResult<Vec<DnsRecord>> {
        let zone_name: String = zones::table
            .filter(zones::id.eq(zone_id))
            .select(zones::name)
            .first(conn)?;
        let rows = records::table
            .filter(records::zone_id.eq(zone_id))
            .select(Self::RECORD_COLS)
            .order(records::name.asc())
            .then_order_by(records::rtype.asc())
            .load::<RecordTuple>(conn)?
            .into_iter()
            .map(|t| Self::record_from(t, &zone_name))
            .collect();
        Ok(rows)
    }

    pub fn record(conn: &mut SqliteConnection, id: i64) -> QueryResult<Option<DnsRecord>> {
        let zone_id: Option<i64> = records::table
            .filter(records::id.eq(id))
            .select(records::zone_id)
            .first(conn)
            .optional()?;
        let Some(zone_id) = zone_id else {
            return Ok(None);
        };
        let zone_name: String = zones::table
            .filter(zones::id.eq(zone_id))
            .select(zones::name)
            .first(conn)?;
        records::table
            .filter(records::id.eq(id))
            .select(Self::RECORD_COLS)
            .first::<RecordTuple>(conn)
            .optional()
            .map(|o| o.map(|t| Self::record_from(t, &zone_name)))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_record(
        conn: &mut SqliteConnection,
        zone_id: i64,
        view_id: Option<i64>,
        name: &str,
        rtype: &str,
        ttl: Option<u32>,
        data: &str,
    ) -> QueryResult<i64> {
        let ts = now();
        let id = diesel::insert_into(records::table)
            .values((
                records::zone_id.eq(zone_id),
                records::view_id.eq(view_id),
                records::name.eq(name),
                records::rtype.eq(rtype),
                records::ttl.eq(ttl.map(|t| t as i64)),
                records::data.eq(data),
                records::enabled.eq(true),
                records::created_at.eq(&ts),
                records::updated_at.eq(&ts),
            ))
            .returning(records::id)
            .get_result(conn)?;
        Self::bump_serial(conn, zone_id)?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_record(
        conn: &mut SqliteConnection,
        id: i64,
        view_id: Option<Option<i64>>,
        name: Option<&str>,
        ttl: Option<Option<u32>>,
        data: Option<&str>,
        enabled: Option<bool>,
    ) -> QueryResult<()> {
        if let Some(v) = view_id {
            diesel::update(records::table.filter(records::id.eq(id)))
                .set(records::view_id.eq(v))
                .execute(conn)?;
        }
        if let Some(n) = name {
            diesel::update(records::table.filter(records::id.eq(id)))
                .set(records::name.eq(n))
                .execute(conn)?;
        }
        if let Some(t) = ttl {
            diesel::update(records::table.filter(records::id.eq(id)))
                .set(records::ttl.eq(t.map(|v| v as i64)))
                .execute(conn)?;
        }
        if let Some(d) = data {
            diesel::update(records::table.filter(records::id.eq(id)))
                .set(records::data.eq(d))
                .execute(conn)?;
        }
        if let Some(e) = enabled {
            diesel::update(records::table.filter(records::id.eq(id)))
                .set(records::enabled.eq(e))
                .execute(conn)?;
        }
        diesel::update(records::table.filter(records::id.eq(id)))
            .set(records::updated_at.eq(now()))
            .execute(conn)?;
        let zone_id: i64 = records::table
            .filter(records::id.eq(id))
            .select(records::zone_id)
            .first(conn)?;
        Self::bump_serial(conn, zone_id)?;
        Ok(())
    }

    pub fn delete_record(conn: &mut SqliteConnection, id: i64) -> QueryResult<Option<i64>> {
        let zone_id: Option<i64> = records::table
            .filter(records::id.eq(id))
            .select(records::zone_id)
            .first(conn)
            .optional()?;
        if let Some(zid) = zone_id {
            diesel::delete(records::table.filter(records::id.eq(id))).execute(conn)?;
            Self::bump_serial(conn, zid)?;
        }
        Ok(zone_id)
    }

    /// The column tuple selected for a [`DnsRecord`].
    const RECORD_COLS: (
        records::id,
        records::zone_id,
        records::view_id,
        records::name,
        records::rtype,
        records::ttl,
        records::data,
        records::enabled,
        records::created_at,
        records::updated_at,
    ) = (
        records::id,
        records::zone_id,
        records::view_id,
        records::name,
        records::rtype,
        records::ttl,
        records::data,
        records::enabled,
        records::created_at,
        records::updated_at,
    );

    fn record_from(t: RecordTuple, zone_name: &str) -> DnsRecord {
        let fqdn = record_fqdn_string(&t.3, zone_name);
        DnsRecord {
            id: t.0,
            zone_id: t.1,
            view_id: t.2,
            name: t.3,
            fqdn,
            rtype: t.4,
            ttl: t.5.map(|v| v as u32),
            data: t.6,
            enabled: t.7,
            created_at: t.8,
            updated_at: t.9,
        }
    }

    // ----- DynDNS tokens ---------------------------------------------------

    pub fn list_dyndns_tokens(conn: &mut SqliteConnection) -> QueryResult<Vec<DynDnsToken>> {
        let tokens = dyndns_tokens::table
            .select((
                dyndns_tokens::id,
                dyndns_tokens::label,
                dyndns_tokens::username,
                dyndns_tokens::hostnames,
                dyndns_tokens::view_id,
                dyndns_tokens::ttl,
                dyndns_tokens::enabled,
                dyndns_tokens::last_update_at,
                dyndns_tokens::last_ip,
                dyndns_tokens::created_at,
            ))
            .order(dyndns_tokens::label.asc())
            .load::<(
                i64,
                String,
                String,
                String,
                Option<i64>,
                i64,
                bool,
                Option<String>,
                Option<String>,
                String,
            )>(conn)?
            .into_iter()
            .map(|t| DynDnsToken {
                id: t.0,
                label: t.1,
                username: t.2,
                hostnames: split_hostnames(&t.3),
                view_id: t.4,
                ttl: t.5 as u32,
                enabled: t.6,
                last_update_at: t.7,
                last_ip: t.8,
                created_at: t.9,
            })
            .collect();
        Ok(tokens)
    }

    pub fn create_dyndns_token(
        conn: &mut SqliteConnection,
        label: &str,
        username: &str,
        secret_hash: &str,
        hostnames: &[String],
        view_id: Option<i64>,
        ttl: u32,
    ) -> QueryResult<i64> {
        let hostnames = join_hostnames(hostnames);
        diesel::insert_into(dyndns_tokens::table)
            .values((
                dyndns_tokens::label.eq(label),
                dyndns_tokens::username.eq(username),
                dyndns_tokens::secret_hash.eq(secret_hash),
                dyndns_tokens::hostnames.eq(hostnames),
                dyndns_tokens::view_id.eq(view_id),
                dyndns_tokens::ttl.eq(ttl as i64),
                dyndns_tokens::enabled.eq(true),
                dyndns_tokens::created_at.eq(now()),
            ))
            .returning(dyndns_tokens::id)
            .get_result(conn)
    }

    pub fn delete_dyndns_token(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(dyndns_tokens::table.filter(dyndns_tokens::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    /// Look up a DynDNS token by its login username (the Basic-auth user).
    pub fn dyndns_auth(
        conn: &mut SqliteConnection,
        username: &str,
    ) -> QueryResult<Option<DynDnsAuthRow>> {
        dyndns_tokens::table
            .filter(dyndns_tokens::username.eq(username))
            .select((
                dyndns_tokens::id,
                dyndns_tokens::secret_hash,
                dyndns_tokens::hostnames,
                dyndns_tokens::view_id,
                dyndns_tokens::ttl,
                dyndns_tokens::enabled,
            ))
            .first::<(i64, String, String, Option<i64>, i64, bool)>(conn)
            .optional()
            .map(|o| {
                o.map(|t| DynDnsAuthRow {
                    id: t.0,
                    secret_hash: t.1,
                    hostnames: split_hostnames(&t.2),
                    view_id: t.3,
                    ttl: t.4 as u32,
                    enabled: t.5,
                })
            })
    }

    /// Record a successful update against a token (audit / UI display).
    pub fn touch_dyndns_token(conn: &mut SqliteConnection, id: i64, ip: &str) -> QueryResult<()> {
        diesel::update(dyndns_tokens::table.filter(dyndns_tokens::id.eq(id)))
            .set((
                dyndns_tokens::last_update_at.eq(now()),
                dyndns_tokens::last_ip.eq(ip),
            ))
            .execute(conn)
            .map(|_| ())
    }

    /// Upsert the A/AAAA record for `host_fqdn` to `ip` in the given view. Routes
    /// through `create_record`/`update_record`, so the zone serial is bumped on
    /// any change (secondaries/AXFR/DNSSEC see it); `Unchanged` bumps nothing.
    pub fn dyndns_set_address(
        conn: &mut SqliteConnection,
        host_fqdn: &str,
        ip: std::net::IpAddr,
        view_id: Option<i64>,
        ttl: u32,
    ) -> QueryResult<DynUpdate> {
        let host = host_fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
        // Longest-suffix match against configured zones.
        let zones = Self::list_zones(conn)?;
        let mut best: Option<(i64, String)> = None;
        for z in &zones {
            let zn = z.name.trim_end_matches('.').to_ascii_lowercase();
            let matches = host == zn || host.ends_with(&format!(".{zn}"));
            if matches
                && best
                    .as_ref()
                    .map(|(_, n)| zn.len() > n.len())
                    .unwrap_or(true)
            {
                best = Some((z.id, zn));
            }
        }
        let Some((zone_id, zone_name)) = best else {
            return Ok(DynUpdate::NoZone);
        };
        let rel = if host == zone_name {
            "@".to_string()
        } else {
            host[..host.len() - zone_name.len() - 1].to_string()
        };
        let rtype = if ip.is_ipv4() { "A" } else { "AAAA" };
        let data = ip.to_string();

        // Find an existing record at this owner/type in the same view. Kept as
        // sql_query to preserve the case-insensitive (COLLATE NOCASE) owner match.
        let existing = diesel::sql_query(
            "SELECT id, view_id, data FROM records
             WHERE zone_id = ? AND name = ? COLLATE NOCASE AND rtype = ?",
        )
        .bind::<BigInt, _>(zone_id)
        .bind::<Text, _>(&rel)
        .bind::<Text, _>(rtype)
        .load::<DynRecRow>(conn)?
        .into_iter()
        .find(|r| r.view_id == view_id);

        match existing {
            Some(r) if r.data == data => Ok(DynUpdate::Unchanged),
            Some(r) => {
                Self::update_record(conn, r.id, None, None, None, Some(&data), None)?;
                Ok(DynUpdate::Updated)
            }
            None => {
                Self::create_record(conn, zone_id, view_id, &rel, rtype, Some(ttl), &data)?;
                Ok(DynUpdate::Created)
            }
        }
    }

    /// Bulk-insert imported records into a zone within one transaction.
    /// `records` is `(name, rtype, ttl, data)`. Optionally replaces existing
    /// records first. Returns the number inserted.
    pub fn import_records(
        conn: &mut SqliteConnection,
        zone_id: i64,
        replace: bool,
        records: &[(String, String, u32, String)],
    ) -> QueryResult<usize> {
        let ts = now();
        conn.transaction(|conn| {
            if replace {
                diesel::delete(records::table.filter(records::zone_id.eq(zone_id)))
                    .execute(conn)?;
            }
            let mut count = 0;
            for (name, rtype, ttl, data) in records {
                diesel::insert_into(records::table)
                    .values((
                        records::zone_id.eq(zone_id),
                        records::view_id.eq(None::<i64>),
                        records::name.eq(name),
                        records::rtype.eq(rtype),
                        records::ttl.eq(*ttl as i64),
                        records::data.eq(data),
                        records::enabled.eq(true),
                        records::created_at.eq(&ts),
                        records::updated_at.eq(&ts),
                    ))
                    .execute(conn)?;
                count += 1;
            }
            diesel::update(zones::table.filter(zones::id.eq(zone_id)))
                .set((
                    zones::serial.eq(zones::serial + 1),
                    zones::updated_at.eq(&ts),
                ))
                .execute(conn)?;
            Ok(count)
        })
    }

    // ----- settings --------------------------------------------------------

    pub fn get_settings(conn: &mut SqliteConnection) -> QueryResult<Settings> {
        let json: Option<String> = settings::table
            .filter(settings::id.eq(1_i64))
            .select(settings::json)
            .first(conn)
            .optional()?;
        match json {
            Some(j) => serde_json::from_str(&j).map_err(json_err),
            None => Ok(Settings::default()),
        }
    }

    pub fn put_settings(conn: &mut SqliteConnection, settings: &Settings) -> QueryResult<()> {
        let json = serde_json::to_string(settings).map_err(json_err)?;
        diesel::insert_into(settings::table)
            .values((settings::id.eq(1_i64), settings::json.eq(&json)))
            .on_conflict(settings::id)
            .do_update()
            .set(settings::json.eq(&json))
            .execute(conn)
            .map(|_| ())
    }

    // ----- query log -------------------------------------------------------

    /// Batch-insert query-log entries in one transaction.
    pub fn insert_queries(conn: &mut SqliteConnection, entries: &[RecentQuery]) -> QueryResult<()> {
        conn.transaction(|conn| {
            for e in entries {
                diesel::insert_into(query_log::table)
                    .values((
                        query_log::at.eq(&e.at),
                        query_log::client.eq(&e.client),
                        query_log::view.eq(e.view.as_deref()),
                        query_log::name.eq(&e.name),
                        query_log::qtype.eq(&e.qtype),
                        query_log::outcome.eq(&e.outcome),
                        query_log::rcode.eq(&e.rcode),
                    ))
                    .execute(conn)?;
            }
            Ok(())
        })
    }

    /// Keep only the most recent `max_rows` query-log rows.
    pub fn prune_query_log(conn: &mut SqliteConnection, max_rows: i64) -> QueryResult<()> {
        diesel::sql_query(
            "DELETE FROM query_log WHERE id <= (SELECT COALESCE(MAX(id),0) FROM query_log) - ?",
        )
        .bind::<BigInt, _>(max_rows)
        .execute(conn)
        .map(|_| ())
    }

    /// A filtered/sorted/paginated page of the query log, plus the total match
    /// count. `sort` is one of at|name|client|qtype|outcome; `desc` reverses.
    #[allow(clippy::too_many_arguments)]
    pub fn query_log_page(
        conn: &mut SqliteConnection,
        search: Option<&str>,
        outcome: Option<&str>,
        qtype: Option<&str>,
        sort: &str,
        desc: bool,
        limit: i64,
        offset: i64,
    ) -> QueryResult<(Vec<RecentQuery>, i64)> {
        // All dynamic WHERE binds are Text, so we collect them in order and bind
        // the same sequence to both the COUNT and the page query.
        let mut wh = String::from(" WHERE 1=1");
        let mut binds: Vec<String> = Vec::new();
        if let Some(s) = search.filter(|s| !s.is_empty()) {
            wh.push_str(" AND (name LIKE ? OR client LIKE ?)");
            let pat = format!("%{s}%");
            binds.push(pat.clone());
            binds.push(pat);
        }
        if let Some(o) = outcome.filter(|s| !s.is_empty()) {
            wh.push_str(" AND outcome = ?");
            binds.push(o.to_string());
        }
        if let Some(t) = qtype.filter(|s| !s.is_empty()) {
            wh.push_str(" AND qtype = ?");
            binds.push(t.to_ascii_uppercase());
        }

        let mut count_q = diesel::sql_query(format!("SELECT COUNT(*) AS n FROM query_log{wh}"))
            .into_boxed::<Sqlite>();
        for b in &binds {
            count_q = count_q.bind::<Text, _>(b.clone());
        }
        let total = count_q.get_result::<CountRow>(conn)?.n;

        let col = match sort {
            "name" => "name",
            "client" => "client",
            "qtype" => "qtype",
            "outcome" => "outcome",
            _ => "id", // "at" — id is monotonic with time and cheaper
        };
        let dir = if desc { "DESC" } else { "ASC" };
        let page_sql = format!(
            "SELECT at, client, view, name, qtype, outcome, rcode FROM query_log{wh}
             ORDER BY {col} {dir} LIMIT ? OFFSET ?"
        );
        let mut page_q = diesel::sql_query(page_sql).into_boxed::<Sqlite>();
        for b in &binds {
            page_q = page_q.bind::<Text, _>(b.clone());
        }
        page_q = page_q.bind::<BigInt, _>(limit).bind::<BigInt, _>(offset);
        let rows = page_q
            .load::<QlogRow>(conn)?
            .into_iter()
            .map(|r| RecentQuery {
                at: r.at,
                client: r.client,
                view: r.view,
                name: r.name,
                qtype: r.qtype,
                outcome: r.outcome,
                rcode: r.rcode,
            })
            .collect();
        Ok((rows, total))
    }

    // ----- blocklists ------------------------------------------------------

    pub fn list_blocklists(conn: &mut SqliteConnection) -> QueryResult<Vec<Blocklist>> {
        let sql = format!("{BLOCKLIST_SELECT} ORDER BY b.name ASC");
        Ok(diesel::sql_query(sql)
            .load::<BlocklistRaw>(conn)?
            .into_iter()
            .map(BlocklistRaw::into_blocklist)
            .collect())
    }

    pub fn blocklist(conn: &mut SqliteConnection, id: i64) -> QueryResult<Option<Blocklist>> {
        let sql = format!("{BLOCKLIST_SELECT} WHERE b.id = ?");
        Ok(diesel::sql_query(sql)
            .bind::<BigInt, _>(id)
            .get_result::<BlocklistRaw>(conn)
            .optional()?
            .map(BlocklistRaw::into_blocklist))
    }

    pub fn create_blocklist(
        conn: &mut SqliteConnection,
        name: &str,
        url: &str,
        format: BlocklistFormat,
        enabled: bool,
    ) -> QueryResult<i64> {
        diesel::insert_into(blocklists::table)
            .values((
                blocklists::name.eq(name),
                blocklists::url.eq(url),
                blocklists::format.eq(enum_to_str(&format)),
                blocklists::enabled.eq(enabled),
                blocklists::created_at.eq(now()),
            ))
            .returning(blocklists::id)
            .get_result(conn)
    }

    pub fn update_blocklist(
        conn: &mut SqliteConnection,
        id: i64,
        name: Option<&str>,
        enabled: Option<bool>,
    ) -> QueryResult<()> {
        if let Some(n) = name {
            diesel::update(blocklists::table.filter(blocklists::id.eq(id)))
                .set(blocklists::name.eq(n))
                .execute(conn)?;
        }
        if let Some(e) = enabled {
            diesel::update(blocklists::table.filter(blocklists::id.eq(id)))
                .set(blocklists::enabled.eq(e))
                .execute(conn)?;
        }
        Ok(())
    }

    pub fn delete_blocklist(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(blocklists::table.filter(blocklists::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    /// Replace the cached entries of a blocklist with a freshly fetched set.
    pub fn replace_blocklist_entries(
        conn: &mut SqliteConnection,
        id: i64,
        domains: &[String],
        error: Option<&str>,
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            diesel::delete(blocklist_entries::table.filter(blocklist_entries::blocklist_id.eq(id)))
                .execute(conn)?;
            for d in domains {
                diesel::insert_into(blocklist_entries::table)
                    .values((
                        blocklist_entries::blocklist_id.eq(id),
                        blocklist_entries::domain.eq(d),
                    ))
                    .execute(conn)?;
            }
            diesel::update(blocklists::table.filter(blocklists::id.eq(id)))
                .set((
                    blocklists::last_updated.eq(now()),
                    blocklists::last_error.eq(error),
                ))
                .execute(conn)?;
            Ok(())
        })
    }

    pub fn set_blocklist_error(
        conn: &mut SqliteConnection,
        id: i64,
        error: &str,
    ) -> QueryResult<()> {
        diesel::update(blocklists::table.filter(blocklists::id.eq(id)))
            .set(blocklists::last_error.eq(error))
            .execute(conn)
            .map(|_| ())
    }

    /// All domains from enabled blocklists, for building the in-memory filter.
    pub fn enabled_block_domains(conn: &mut SqliteConnection) -> QueryResult<Vec<String>> {
        Ok(diesel::sql_query(
            "SELECT e.domain AS domain FROM blocklist_entries e
             JOIN blocklists b ON b.id = e.blocklist_id
             WHERE b.enabled = 1",
        )
        .load::<DomainRow>(conn)?
        .into_iter()
        .map(|r| r.domain)
        .collect())
    }

    // ----- block rules -----------------------------------------------------

    pub fn list_block_rules(conn: &mut SqliteConnection) -> QueryResult<Vec<BlockRule>> {
        Ok(block_rules::table
            .select((
                block_rules::id,
                block_rules::domain,
                block_rules::action,
                block_rules::comment,
                block_rules::created_at,
            ))
            .order(block_rules::domain.asc())
            .load::<(i64, String, String, Option<String>, String)>(conn)?
            .into_iter()
            .map(|t| BlockRule {
                id: t.0,
                domain: t.1,
                action: enum_from_str(&t.2).unwrap_or(RuleAction::Deny),
                comment: t.3,
                created_at: t.4,
            })
            .collect())
    }

    pub fn create_block_rule(
        conn: &mut SqliteConnection,
        domain: &str,
        action: RuleAction,
        comment: Option<&str>,
    ) -> QueryResult<i64> {
        diesel::insert_into(block_rules::table)
            .values((
                block_rules::domain.eq(domain),
                block_rules::action.eq(enum_to_str(&action)),
                block_rules::comment.eq(comment),
                block_rules::created_at.eq(now()),
            ))
            .returning(block_rules::id)
            .get_result(conn)
    }

    pub fn delete_block_rule(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(block_rules::table.filter(block_rules::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    // ----- rewrites --------------------------------------------------------

    pub fn list_rewrites(conn: &mut SqliteConnection) -> QueryResult<Vec<Rewrite>> {
        Ok(rewrites::table
            .select((
                rewrites::id,
                rewrites::domain,
                rewrites::target,
                rewrites::enabled,
                rewrites::comment,
                rewrites::created_at,
            ))
            .order(rewrites::domain.asc())
            .load::<(i64, String, String, bool, Option<String>, String)>(conn)?
            .into_iter()
            .map(Self::rewrite_from)
            .collect())
    }

    pub fn rewrite(conn: &mut SqliteConnection, id: i64) -> QueryResult<Option<Rewrite>> {
        rewrites::table
            .filter(rewrites::id.eq(id))
            .select((
                rewrites::id,
                rewrites::domain,
                rewrites::target,
                rewrites::enabled,
                rewrites::comment,
                rewrites::created_at,
            ))
            .first::<(i64, String, String, bool, Option<String>, String)>(conn)
            .optional()
            .map(|o| o.map(Self::rewrite_from))
    }

    pub fn create_rewrite(
        conn: &mut SqliteConnection,
        domain: &str,
        target: &str,
        comment: Option<&str>,
    ) -> QueryResult<i64> {
        diesel::insert_into(rewrites::table)
            .values((
                rewrites::domain.eq(domain),
                rewrites::target.eq(target),
                rewrites::enabled.eq(true),
                rewrites::comment.eq(comment),
                rewrites::created_at.eq(now()),
            ))
            .returning(rewrites::id)
            .get_result(conn)
    }

    pub fn update_rewrite(
        conn: &mut SqliteConnection,
        id: i64,
        domain: Option<&str>,
        target: Option<&str>,
        enabled: Option<bool>,
    ) -> QueryResult<()> {
        if let Some(d) = domain {
            diesel::update(rewrites::table.filter(rewrites::id.eq(id)))
                .set(rewrites::domain.eq(d))
                .execute(conn)?;
        }
        if let Some(t) = target {
            diesel::update(rewrites::table.filter(rewrites::id.eq(id)))
                .set(rewrites::target.eq(t))
                .execute(conn)?;
        }
        if let Some(e) = enabled {
            diesel::update(rewrites::table.filter(rewrites::id.eq(id)))
                .set(rewrites::enabled.eq(e))
                .execute(conn)?;
        }
        Ok(())
    }

    pub fn delete_rewrite(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(rewrites::table.filter(rewrites::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    fn rewrite_from(t: (i64, String, String, bool, Option<String>, String)) -> Rewrite {
        Rewrite {
            id: t.0,
            domain: t.1,
            target: t.2,
            enabled: t.3,
            comment: t.4,
            created_at: t.5,
        }
    }

    // ----- conditional forwards -------------------------------------------

    pub fn list_conditional_forwards(
        conn: &mut SqliteConnection,
    ) -> QueryResult<Vec<ConditionalForward>> {
        conditional_forwards::table
            .select((
                conditional_forwards::id,
                conditional_forwards::domain,
                conditional_forwards::forwarders,
                conditional_forwards::enabled,
                conditional_forwards::created_at,
            ))
            .order(conditional_forwards::domain.asc())
            .load::<(i64, String, String, bool, String)>(conn)?
            .into_iter()
            .map(Self::conditional_from)
            .collect()
    }

    pub fn conditional_forward(
        conn: &mut SqliteConnection,
        id: i64,
    ) -> QueryResult<Option<ConditionalForward>> {
        conditional_forwards::table
            .filter(conditional_forwards::id.eq(id))
            .select((
                conditional_forwards::id,
                conditional_forwards::domain,
                conditional_forwards::forwarders,
                conditional_forwards::enabled,
                conditional_forwards::created_at,
            ))
            .first::<(i64, String, String, bool, String)>(conn)
            .optional()?
            .map(Self::conditional_from)
            .transpose()
    }

    pub fn create_conditional_forward(
        conn: &mut SqliteConnection,
        domain: &str,
        forwarders: &[Forwarder],
    ) -> QueryResult<i64> {
        let json = serde_json::to_string(forwarders).map_err(json_err)?;
        diesel::insert_into(conditional_forwards::table)
            .values((
                conditional_forwards::domain.eq(domain),
                conditional_forwards::forwarders.eq(json),
                conditional_forwards::enabled.eq(true),
                conditional_forwards::created_at.eq(now()),
            ))
            .returning(conditional_forwards::id)
            .get_result(conn)
    }

    pub fn update_conditional_forward(
        conn: &mut SqliteConnection,
        id: i64,
        forwarders: Option<&[Forwarder]>,
        enabled: Option<bool>,
    ) -> QueryResult<()> {
        if let Some(f) = forwarders {
            let json = serde_json::to_string(f).map_err(json_err)?;
            diesel::update(conditional_forwards::table.filter(conditional_forwards::id.eq(id)))
                .set(conditional_forwards::forwarders.eq(json))
                .execute(conn)?;
        }
        if let Some(e) = enabled {
            diesel::update(conditional_forwards::table.filter(conditional_forwards::id.eq(id)))
                .set(conditional_forwards::enabled.eq(e))
                .execute(conn)?;
        }
        Ok(())
    }

    pub fn delete_conditional_forward(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(conditional_forwards::table.filter(conditional_forwards::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    fn conditional_from(t: (i64, String, String, bool, String)) -> QueryResult<ConditionalForward> {
        let forwarders: Vec<Forwarder> = serde_json::from_str(&t.2).map_err(json_err)?;
        Ok(ConditionalForward {
            id: t.0,
            domain: t.1,
            forwarders,
            enabled: t.3,
            created_at: t.4,
        })
    }

    // ----- DNSSEC keys -----------------------------------------------------

    pub fn create_dnssec_key(
        conn: &mut SqliteConnection,
        zone_id: i64,
        algorithm: i64,
        secret: &str,
        nsec3: bool,
        salt_hex: Option<&str>,
        iterations: i64,
    ) -> QueryResult<()> {
        let ts = now();
        diesel::insert_into(dnssec_keys::table)
            .values((
                dnssec_keys::zone_id.eq(zone_id),
                dnssec_keys::algorithm.eq(algorithm),
                dnssec_keys::secret.eq(secret),
                dnssec_keys::nsec3.eq(nsec3),
                dnssec_keys::salt.eq(salt_hex),
                dnssec_keys::iterations.eq(iterations),
                dnssec_keys::created_at.eq(&ts),
            ))
            .on_conflict(dnssec_keys::zone_id)
            .do_update()
            .set((
                dnssec_keys::algorithm.eq(algorithm),
                dnssec_keys::secret.eq(secret),
                dnssec_keys::nsec3.eq(nsec3),
                dnssec_keys::salt.eq(salt_hex),
                dnssec_keys::iterations.eq(iterations),
                dnssec_keys::created_at.eq(&ts),
            ))
            .execute(conn)
            .map(|_| ())
    }

    /// Returns `(secret_b64, nsec3, salt_hex, iterations)` for a signed zone.
    pub fn dnssec_config(
        conn: &mut SqliteConnection,
        zone_id: i64,
    ) -> QueryResult<Option<(String, bool, Option<String>, u16)>> {
        dnssec_keys::table
            .filter(dnssec_keys::zone_id.eq(zone_id))
            .select((
                dnssec_keys::secret,
                dnssec_keys::nsec3,
                dnssec_keys::salt,
                dnssec_keys::iterations,
            ))
            .first::<(String, bool, Option<String>, i64)>(conn)
            .optional()
            .map(|o| o.map(|(secret, nsec3, salt, iters)| (secret, nsec3, salt, iters as u16)))
    }

    pub fn delete_dnssec_key(conn: &mut SqliteConnection, zone_id: i64) -> QueryResult<()> {
        diesel::delete(dnssec_keys::table.filter(dnssec_keys::zone_id.eq(zone_id)))
            .execute(conn)
            .map(|_| ())
    }

    // ----- secondary zones -------------------------------------------------

    pub fn list_secondaries(conn: &mut SqliteConnection) -> QueryResult<Vec<SecondaryZone>> {
        Ok(diesel::sql_query(
            "SELECT s.zone_id AS zone_id, z.name AS name, s.primary_addr AS primary_addr,
                    s.refresh_secs AS refresh_secs, z.serial AS serial,
                    (SELECT COUNT(*) FROM records r WHERE r.zone_id = z.id) AS rc,
                    s.last_check AS last_check, s.last_error AS last_error, s.tsig_key AS tsig_key
             FROM secondary_zones s JOIN zones z ON z.id = s.zone_id
             ORDER BY z.name ASC",
        )
        .load::<SecondaryRaw>(conn)?
        .into_iter()
        .map(|r| SecondaryZone {
            zone_id: r.zone_id,
            name: r.name,
            primary_addr: r.primary_addr,
            refresh_secs: r.refresh_secs,
            serial: r.serial as u32,
            record_count: r.rc,
            last_check: r.last_check,
            last_error: r.last_error,
            tsig_key: r.tsig_key,
        })
        .collect())
    }

    pub fn secondary(conn: &mut SqliteConnection, zone_id: i64) -> QueryResult<Option<String>> {
        let row: Option<Option<String>> = secondary_zones::table
            .filter(secondary_zones::zone_id.eq(zone_id))
            .select(secondary_zones::tsig_key)
            .first::<Option<String>>(conn)
            .optional()?;
        Ok(row.flatten())
    }

    pub fn create_secondary(
        conn: &mut SqliteConnection,
        zone_id: i64,
        primary_addr: &str,
        refresh_secs: i64,
        tsig_key: Option<&str>,
    ) -> QueryResult<()> {
        diesel::insert_into(secondary_zones::table)
            .values((
                secondary_zones::zone_id.eq(zone_id),
                secondary_zones::primary_addr.eq(primary_addr),
                secondary_zones::refresh_secs.eq(refresh_secs),
                secondary_zones::tsig_key.eq(tsig_key),
                secondary_zones::created_at.eq(now()),
            ))
            .execute(conn)
            .map(|_| ())
    }

    pub fn set_secondary_status(
        conn: &mut SqliteConnection,
        zone_id: i64,
        last_error: Option<&str>,
        refresh_secs: Option<i64>,
    ) -> QueryResult<()> {
        diesel::update(secondary_zones::table.filter(secondary_zones::zone_id.eq(zone_id)))
            .set((
                secondary_zones::last_check.eq(now()),
                secondary_zones::last_error.eq(last_error),
            ))
            .execute(conn)?;
        if let Some(r) = refresh_secs {
            diesel::update(secondary_zones::table.filter(secondary_zones::zone_id.eq(zone_id)))
                .set(secondary_zones::refresh_secs.eq(r))
                .execute(conn)?;
        }
        Ok(())
    }

    /// Replace a secondary zone's SOA, serial, and records from a transfer.
    pub fn replace_secondary_zone(
        conn: &mut SqliteConnection,
        zone_id: i64,
        soa: &Soa,
        serial: u32,
        records: &[(String, String, u32, String)],
    ) -> QueryResult<usize> {
        let soa_json = serde_json::to_string(soa).map_err(json_err)?;
        let ts = now();
        conn.transaction(|conn| {
            diesel::update(zones::table.filter(zones::id.eq(zone_id)))
                .set((
                    zones::soa.eq(&soa_json),
                    zones::serial.eq(serial as i64),
                    zones::updated_at.eq(&ts),
                ))
                .execute(conn)?;
            diesel::delete(records::table.filter(records::zone_id.eq(zone_id))).execute(conn)?;
            let mut count = 0;
            for (name, rtype, ttl, data) in records {
                diesel::insert_into(records::table)
                    .values((
                        records::zone_id.eq(zone_id),
                        records::view_id.eq(None::<i64>),
                        records::name.eq(name),
                        records::rtype.eq(rtype),
                        records::ttl.eq(*ttl as i64),
                        records::data.eq(data),
                        records::enabled.eq(true),
                        records::created_at.eq(&ts),
                        records::updated_at.eq(&ts),
                    ))
                    .execute(conn)?;
                count += 1;
            }
            Ok(count)
        })
    }
}

// Phase 1 DHCP foundation: these query helpers are consumed by the later DHCP
// serving/API phases, so they have no in-crate caller yet (the unit tests below
// exercise them). The allow keeps the staged code warning-free.
#[allow(dead_code)]
impl Db {
    // ----- DHCP scopes -----------------------------------------------------

    pub fn list_dhcp_scopes(conn: &mut SqliteConnection) -> QueryResult<Vec<DhcpScope>> {
        dhcp_scopes::table
            .select(Self::DHCP_SCOPE_COLS)
            .order(dhcp_scopes::name.asc())
            .load::<DhcpScopeTuple>(conn)?
            .into_iter()
            .map(Self::dhcp_scope_from)
            .collect()
    }

    pub fn dhcp_scope(conn: &mut SqliteConnection, id: i64) -> QueryResult<Option<DhcpScope>> {
        dhcp_scopes::table
            .filter(dhcp_scopes::id.eq(id))
            .select(Self::DHCP_SCOPE_COLS)
            .first::<DhcpScopeTuple>(conn)
            .optional()?
            .map(Self::dhcp_scope_from)
            .transpose()
    }

    pub fn create_dhcp_scope(
        conn: &mut SqliteConnection,
        name: &str,
        enabled: bool,
        family: IpFamily,
        subnet: &str,
        range_start: &str,
        range_end: &str,
        lease_secs: u32,
        dns_register: bool,
        dns_zone: Option<&str>,
        server_id: Option<&str>,
        options: &[DhcpOption],
    ) -> QueryResult<i64> {
        let opts = serde_json::to_string(options).map_err(json_err)?;
        diesel::insert_into(dhcp_scopes::table)
            .values((
                dhcp_scopes::name.eq(name),
                dhcp_scopes::enabled.eq(enabled),
                dhcp_scopes::family.eq(enum_to_str(&family)),
                dhcp_scopes::subnet.eq(subnet),
                dhcp_scopes::range_start.eq(range_start),
                dhcp_scopes::range_end.eq(range_end),
                dhcp_scopes::lease_secs.eq(lease_secs as i64),
                dhcp_scopes::dns_register.eq(dns_register),
                dhcp_scopes::dns_zone.eq(dns_zone),
                dhcp_scopes::server_id.eq(server_id),
                dhcp_scopes::options.eq(opts),
                dhcp_scopes::created_at.eq(now()),
            ))
            .returning(dhcp_scopes::id)
            .get_result(conn)
    }

    pub fn update_dhcp_scope(
        conn: &mut SqliteConnection,
        id: i64,
        name: Option<&str>,
        enabled: Option<bool>,
        subnet: Option<&str>,
        range_start: Option<&str>,
        range_end: Option<&str>,
        lease_secs: Option<u32>,
        dns_register: Option<bool>,
        dns_zone: Option<Option<&str>>,
        server_id: Option<Option<&str>>,
        options: Option<&[DhcpOption]>,
    ) -> QueryResult<()> {
        if let Some(v) = name {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::name.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = enabled {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::enabled.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = subnet {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::subnet.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = range_start {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::range_start.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = range_end {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::range_end.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = lease_secs {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::lease_secs.eq(v as i64))
                .execute(conn)?;
        }
        if let Some(v) = dns_register {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::dns_register.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = dns_zone {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::dns_zone.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = server_id {
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::server_id.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = options {
            let json = serde_json::to_string(v).map_err(json_err)?;
            diesel::update(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
                .set(dhcp_scopes::options.eq(json))
                .execute(conn)?;
        }
        Ok(())
    }

    pub fn delete_dhcp_scope(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(dhcp_scopes::table.filter(dhcp_scopes::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    const DHCP_SCOPE_COLS: (
        dhcp_scopes::id,
        dhcp_scopes::name,
        dhcp_scopes::enabled,
        dhcp_scopes::family,
        dhcp_scopes::subnet,
        dhcp_scopes::range_start,
        dhcp_scopes::range_end,
        dhcp_scopes::lease_secs,
        dhcp_scopes::dns_register,
        dhcp_scopes::dns_zone,
        dhcp_scopes::options,
        dhcp_scopes::created_at,
        dhcp_scopes::server_id,
    ) = (
        dhcp_scopes::id,
        dhcp_scopes::name,
        dhcp_scopes::enabled,
        dhcp_scopes::family,
        dhcp_scopes::subnet,
        dhcp_scopes::range_start,
        dhcp_scopes::range_end,
        dhcp_scopes::lease_secs,
        dhcp_scopes::dns_register,
        dhcp_scopes::dns_zone,
        dhcp_scopes::options,
        dhcp_scopes::created_at,
        dhcp_scopes::server_id,
    );

    fn dhcp_scope_from(t: DhcpScopeTuple) -> QueryResult<DhcpScope> {
        let family = enum_from_str(&t.3).ok_or_else(|| enum_err("DHCP scope family"))?;
        let options: Vec<DhcpOption> = serde_json::from_str(&t.10).map_err(json_err)?;
        Ok(DhcpScope {
            id: t.0,
            name: t.1,
            enabled: t.2,
            family,
            subnet: t.4,
            range_start: t.5,
            range_end: t.6,
            lease_secs: t.7 as u32,
            dns_register: t.8,
            dns_zone: t.9,
            server_id: t.12,
            options,
            created_at: t.11,
        })
    }

    // ----- DHCP reservations ----------------------------------------------

    pub fn list_dhcp_reservations(
        conn: &mut SqliteConnection,
        scope_id: i64,
    ) -> QueryResult<Vec<DhcpReservation>> {
        dhcp_reservations::table
            .filter(dhcp_reservations::scope_id.eq(scope_id))
            .select((
                dhcp_reservations::id,
                dhcp_reservations::scope_id,
                dhcp_reservations::identifier,
                dhcp_reservations::ip,
                dhcp_reservations::hostname,
                dhcp_reservations::options,
                dhcp_reservations::created_at,
            ))
            .order(dhcp_reservations::ip.asc())
            .load::<(i64, i64, String, String, Option<String>, String, String)>(conn)?
            .into_iter()
            .map(Self::dhcp_reservation_from)
            .collect()
    }

    pub fn create_dhcp_reservation(
        conn: &mut SqliteConnection,
        scope_id: i64,
        identifier: &str,
        ip: &str,
        hostname: Option<&str>,
        options: &[DhcpOption],
    ) -> QueryResult<i64> {
        let opts = serde_json::to_string(options).map_err(json_err)?;
        diesel::insert_into(dhcp_reservations::table)
            .values((
                dhcp_reservations::scope_id.eq(scope_id),
                dhcp_reservations::identifier.eq(identifier.to_ascii_lowercase()),
                dhcp_reservations::ip.eq(ip),
                dhcp_reservations::hostname.eq(hostname),
                dhcp_reservations::options.eq(opts),
                dhcp_reservations::created_at.eq(now()),
            ))
            .returning(dhcp_reservations::id)
            .get_result(conn)
    }

    pub fn update_dhcp_reservation(
        conn: &mut SqliteConnection,
        id: i64,
        identifier: Option<&str>,
        ip: Option<&str>,
        hostname: Option<Option<&str>>,
        options: Option<&[DhcpOption]>,
    ) -> QueryResult<()> {
        if let Some(v) = identifier {
            diesel::update(dhcp_reservations::table.filter(dhcp_reservations::id.eq(id)))
                .set(dhcp_reservations::identifier.eq(v.to_ascii_lowercase()))
                .execute(conn)?;
        }
        if let Some(v) = ip {
            diesel::update(dhcp_reservations::table.filter(dhcp_reservations::id.eq(id)))
                .set(dhcp_reservations::ip.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = hostname {
            diesel::update(dhcp_reservations::table.filter(dhcp_reservations::id.eq(id)))
                .set(dhcp_reservations::hostname.eq(v))
                .execute(conn)?;
        }
        if let Some(v) = options {
            let json = serde_json::to_string(v).map_err(json_err)?;
            diesel::update(dhcp_reservations::table.filter(dhcp_reservations::id.eq(id)))
                .set(dhcp_reservations::options.eq(json))
                .execute(conn)?;
        }
        Ok(())
    }

    pub fn delete_dhcp_reservation(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(dhcp_reservations::table.filter(dhcp_reservations::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    fn dhcp_reservation_from(
        t: (i64, i64, String, String, Option<String>, String, String),
    ) -> QueryResult<DhcpReservation> {
        let options: Vec<DhcpOption> = serde_json::from_str(&t.5).map_err(json_err)?;
        Ok(DhcpReservation {
            id: t.0,
            scope_id: t.1,
            identifier: t.2,
            ip: t.3,
            hostname: t.4,
            options,
            created_at: t.6,
        })
    }

    // ----- DHCP leases -----------------------------------------------------

    pub fn list_dhcp_leases(
        conn: &mut SqliteConnection,
        scope_id: Option<i64>,
    ) -> QueryResult<Vec<DhcpLease>> {
        let cols = (
            dhcp_leases::id,
            dhcp_leases::scope_id,
            dhcp_leases::family,
            dhcp_leases::ip,
            dhcp_leases::identifier,
            dhcp_leases::hostname,
            dhcp_leases::starts_at,
            dhcp_leases::expires_at,
            dhcp_leases::state,
            dhcp_leases::created_at,
        );
        let rows = match scope_id {
            Some(sid) => dhcp_leases::table
                .filter(dhcp_leases::scope_id.eq(sid))
                .select(cols)
                .order(dhcp_leases::ip.asc())
                .load::<DhcpLeaseTuple>(conn)?,
            None => dhcp_leases::table
                .select(cols)
                .order(dhcp_leases::ip.asc())
                .load::<DhcpLeaseTuple>(conn)?,
        };
        rows.into_iter().map(Self::dhcp_lease_from).collect()
    }

    /// Insert or update a lease for `(scope_id, ip)`. Returns the lease id.
    pub fn upsert_dhcp_lease(
        conn: &mut SqliteConnection,
        scope_id: i64,
        family: IpFamily,
        ip: &str,
        identifier: &str,
        hostname: Option<&str>,
        starts_at: &str,
        expires_at: &str,
        state: LeaseState,
    ) -> QueryResult<i64> {
        let fam = enum_to_str(&family);
        let st = enum_to_str(&state);
        let ident = identifier.to_ascii_lowercase();
        diesel::insert_into(dhcp_leases::table)
            .values((
                dhcp_leases::scope_id.eq(scope_id),
                dhcp_leases::family.eq(&fam),
                dhcp_leases::ip.eq(ip),
                dhcp_leases::identifier.eq(&ident),
                dhcp_leases::hostname.eq(hostname),
                dhcp_leases::starts_at.eq(starts_at),
                dhcp_leases::expires_at.eq(expires_at),
                dhcp_leases::state.eq(&st),
                dhcp_leases::created_at.eq(now()),
            ))
            .on_conflict((dhcp_leases::scope_id, dhcp_leases::ip))
            .do_update()
            .set((
                dhcp_leases::family.eq(&fam),
                dhcp_leases::identifier.eq(&ident),
                dhcp_leases::hostname.eq(hostname),
                dhcp_leases::starts_at.eq(starts_at),
                dhcp_leases::expires_at.eq(expires_at),
                dhcp_leases::state.eq(&st),
            ))
            .returning(dhcp_leases::id)
            .get_result(conn)
    }

    pub fn delete_dhcp_lease(conn: &mut SqliteConnection, id: i64) -> QueryResult<()> {
        diesel::delete(dhcp_leases::table.filter(dhcp_leases::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    }

    /// Delete leases whose `expires_at` is before `now` (RFC3339). Returns the
    /// number removed.
    pub fn prune_expired_leases(conn: &mut SqliteConnection, now: &str) -> QueryResult<usize> {
        diesel::delete(dhcp_leases::table.filter(dhcp_leases::expires_at.lt(now))).execute(conn)
    }

    fn dhcp_lease_from(t: DhcpLeaseTuple) -> QueryResult<DhcpLease> {
        let family = enum_from_str(&t.2).ok_or_else(|| enum_err("DHCP lease family"))?;
        let state = enum_from_str(&t.8).ok_or_else(|| enum_err("DHCP lease state"))?;
        Ok(DhcpLease {
            id: t.0,
            scope_id: t.1,
            family,
            ip: t.3,
            identifier: t.4,
            hostname: t.5,
            starts_at: t.6,
            expires_at: t.7,
            state,
            created_at: t.9,
        })
    }
}

/// The column tuple type used for [`DhcpScope`] reads.
#[allow(dead_code)]
type DhcpScopeTuple = (
    i64,
    String,
    bool,
    String,
    String,
    String,
    String,
    i64,
    bool,
    Option<String>,
    String,
    String,
    Option<String>,
);

/// The column tuple type used for [`DhcpLease`] reads.
#[allow(dead_code)]
type DhcpLeaseTuple = (
    i64,
    i64,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
);

/// The column tuple type used for [`DnsRecord`] reads.
type RecordTuple = (
    i64,
    i64,
    Option<i64>,
    String,
    String,
    Option<i64>,
    String,
    bool,
    String,
    String,
);

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

#[cfg(test)]
mod dhcp_tests {
    use super::*;
    use crate::models::{DhcpOption, DhcpOptionKind};

    fn opt() -> DhcpOption {
        DhcpOption {
            code: 6,
            name: Some("Domain Name Server".into()),
            value: "192.168.1.1".into(),
            kind: DhcpOptionKind::IpList,
        }
    }

    #[test]
    fn scope_crud_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let id = Db::create_dhcp_scope(
                c,
                "lan",
                true,
                IpFamily::V4,
                "192.168.1.0/24",
                "192.168.1.100",
                "192.168.1.200",
                3600,
                true,
                Some("home.lan"),
                Some("192.168.1.1"),
                &[opt()],
            )?;
            let s = Db::dhcp_scope(c, id)?.expect("scope exists");
            assert_eq!(s.name, "lan");
            assert_eq!(s.family, IpFamily::V4);
            assert_eq!(s.range_end, "192.168.1.200");
            assert_eq!(s.lease_secs, 3600);
            assert!(s.dns_register);
            assert_eq!(s.dns_zone.as_deref(), Some("home.lan"));
            assert_eq!(s.server_id.as_deref(), Some("192.168.1.1"));
            assert_eq!(s.options.len(), 1);
            assert_eq!(s.options[0].code, 6);

            Db::update_dhcp_scope(
                c,
                id,
                Some("lan2"),
                Some(false),
                None,
                None,
                Some("192.168.1.250"),
                Some(7200),
                None,
                Some(None),
                Some(Some("192.168.1.2")),
                Some::<&[DhcpOption]>(&[]),
            )?;
            let s2 = Db::dhcp_scope(c, id)?.unwrap();
            assert_eq!(s2.name, "lan2");
            assert!(!s2.enabled);
            assert_eq!(s2.range_end, "192.168.1.250");
            assert_eq!(s2.lease_secs, 7200);
            assert_eq!(s2.dns_zone, None);
            assert_eq!(s2.server_id.as_deref(), Some("192.168.1.2"));
            assert!(s2.options.is_empty());

            assert_eq!(Db::list_dhcp_scopes(c)?.len(), 1);
            Db::delete_dhcp_scope(c, id)?;
            assert!(Db::dhcp_scope(c, id)?.is_none());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn reservation_crud_and_cascade() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let sid = Db::create_dhcp_scope(
                c,
                "lan",
                true,
                IpFamily::V4,
                "10.0.0.0/24",
                "10.0.0.10",
                "10.0.0.20",
                3600,
                false,
                None,
                None,
                &[],
            )?;
            let rid = Db::create_dhcp_reservation(
                c,
                sid,
                "AA:BB:CC:DD:EE:FF",
                "10.0.0.5",
                Some("printer"),
                &[],
            )?;
            let list = Db::list_dhcp_reservations(c, sid)?;
            assert_eq!(list.len(), 1);
            // Identifier is normalized lowercase on write.
            assert_eq!(list[0].identifier, "aa:bb:cc:dd:ee:ff");
            assert_eq!(list[0].hostname.as_deref(), Some("printer"));

            Db::update_dhcp_reservation(c, rid, None, Some("10.0.0.6"), Some(None), None)?;
            let list2 = Db::list_dhcp_reservations(c, sid)?;
            assert_eq!(list2[0].ip, "10.0.0.6");
            assert_eq!(list2[0].hostname, None);

            // Deleting the scope cascades to reservations (FK ON DELETE CASCADE).
            Db::delete_dhcp_scope(c, sid)?;
            assert!(Db::list_dhcp_reservations(c, sid)?.is_empty());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn lease_upsert_list_and_prune() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let sid = Db::create_dhcp_scope(
                c,
                "lan",
                true,
                IpFamily::V4,
                "10.0.0.0/24",
                "10.0.0.10",
                "10.0.0.20",
                3600,
                false,
                None,
                None,
                &[],
            )?;
            let id1 = Db::upsert_dhcp_lease(
                c,
                sid,
                IpFamily::V4,
                "10.0.0.10",
                "AA:BB:CC:00:00:01",
                Some("host-a"),
                "2026-01-01T00:00:00Z",
                "2999-01-01T00:00:00Z",
                LeaseState::Active,
            )?;
            // Re-upsert same (scope, ip) updates rather than inserts; same id.
            let id2 = Db::upsert_dhcp_lease(
                c,
                sid,
                IpFamily::V4,
                "10.0.0.10",
                "AA:BB:CC:00:00:02",
                None,
                "2026-01-01T00:00:00Z",
                "2999-01-01T00:00:00Z",
                LeaseState::Active,
            )?;
            assert_eq!(id1, id2);
            let all = Db::list_dhcp_leases(c, Some(sid))?;
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].identifier, "aa:bb:cc:00:00:02");

            // A second, already-expired lease.
            Db::upsert_dhcp_lease(
                c,
                sid,
                IpFamily::V4,
                "10.0.0.11",
                "AA:BB:CC:00:00:03",
                None,
                "2000-01-01T00:00:00Z",
                "2000-01-02T00:00:00Z",
                LeaseState::Expired,
            )?;
            assert_eq!(Db::list_dhcp_leases(c, None)?.len(), 2);

            let removed = Db::prune_expired_leases(c, "2026-06-26T00:00:00Z")?;
            assert_eq!(removed, 1);
            let rest = Db::list_dhcp_leases(c, Some(sid))?;
            assert_eq!(rest.len(), 1);
            assert_eq!(rest[0].ip, "10.0.0.10");
            Ok(())
        })
        .unwrap();
    }
}
