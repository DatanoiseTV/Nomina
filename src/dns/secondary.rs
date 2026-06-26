//! Secondary (slave) zones: pull a zone from a primary via AXFR, store it, and
//! re-transfer when the primary's SOA serial changes.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::rr::{Name, RData};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::db::Db;
use crate::dns::axfr;
use crate::models::{Soa, SUPPORTED_RECORD_TYPES};
use crate::state::{AppState, SharedState};

/// Parse a primary address as `ip` or `ip:port` (default port 53).
pub fn parse_primary(addr: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let ip: std::net::IpAddr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid primary address: {addr}"))?;
    Ok(SocketAddr::new(ip, 53))
}

/// Perform an AXFR from the primary and replace the secondary zone's contents.
/// Returns the number of records stored.
pub async fn transfer(
    state: &AppState,
    zone_id: i64,
    zone_name: &str,
    primary: SocketAddr,
    tsig_key: Option<&str>,
) -> anyhow::Result<usize> {
    let origin = Name::from_utf8(format!("{zone_name}."))?;
    let signer = tsig_key.and_then(|n| state.tsig_signer(n));
    let records = axfr::axfr_transfer(primary, &origin, signer.as_ref()).await?;

    let zone_lc = zone_name.trim_end_matches('.').to_ascii_lowercase();
    let mut soa_model: Option<Soa> = None;
    let mut serial = 0u32;
    let mut tuples: Vec<(String, String, u32, String)> = Vec::new();

    for rec in &records {
        if let RData::SOA(soa) = &rec.data {
            if soa_model.is_none() {
                serial = soa.serial;
                soa_model = Some(Soa {
                    primary_ns: soa.mname.to_string(),
                    admin_email: soa.rname.to_string(),
                    refresh: soa.refresh,
                    retry: soa.retry,
                    expire: soa.expire,
                    minimum: soa.minimum,
                });
            }
            continue; // SOA is managed via the zone, not stored as a record
        }
        let rtype = rec.record_type().to_string();
        if !SUPPORTED_RECORD_TYPES.contains(&rtype.as_str()) {
            continue;
        }
        let fqdn = rec.name.to_string();
        let f = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let name = if f == zone_lc {
            "@".to_string()
        } else if let Some(rel) = f.strip_suffix(&format!(".{zone_lc}")) {
            rel.to_string()
        } else {
            f
        };
        tuples.push((name, rtype, rec.ttl, rec.data.to_string()));
    }

    let soa_model = soa_model.ok_or_else(|| anyhow::anyhow!("transfer contained no SOA"))?;
    let refresh = (soa_model.refresh.max(60)) as i64;

    let count = state
        .db
        .run_mut(move |c| Db::replace_secondary_zone(c, zone_id, &soa_model, serial, &tuples))
        .await?;
    state
        .db
        .run(move |c| Db::set_secondary_status(c, zone_id, None, Some(refresh)))
        .await?;
    state.reload_store()?;
    Ok(count)
}

fn elapsed_secs(ts: &str) -> i64 {
    match OffsetDateTime::parse(ts, &Rfc3339) {
        Ok(t) => (OffsetDateTime::now_utc() - t).whole_seconds(),
        Err(_) => i64::MAX,
    }
}

/// Background loop: refresh due secondary zones based on their SOA serial.
pub async fn poll_loop(state: SharedState) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let secondaries = match state.db.run(Db::list_secondaries).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        for sec in secondaries {
            let due = match &sec.last_check {
                None => true,
                Some(ts) => elapsed_secs(ts) >= sec.refresh_secs,
            };
            if !due {
                continue;
            }
            let primary = match parse_primary(&sec.primary_addr) {
                Ok(p) => p,
                Err(e) => {
                    record_error(&state, sec.zone_id, &e.to_string()).await;
                    continue;
                }
            };
            let origin = match Name::from_utf8(format!("{}.", sec.name)) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let signer = sec.tsig_key.as_deref().and_then(|n| state.tsig_signer(n));

            match axfr::soa_serial(primary, &origin, signer.as_ref()).await {
                Ok(remote_serial) => {
                    if remote_serial != sec.serial {
                        match transfer(&state, sec.zone_id, &sec.name, primary, sec.tsig_key.as_deref())
                            .await
                        {
                            Ok(n) => tracing::info!(
                                zone = %sec.name,
                                serial = remote_serial,
                                "secondary refreshed ({n} records)"
                            ),
                            Err(e) => record_error(&state, sec.zone_id, &e.to_string()).await,
                        }
                    } else {
                        // Up to date; just stamp the check time.
                        let zid = sec.zone_id;
                        let _ = state
                            .db
                            .run(move |c| Db::set_secondary_status(c, zid, None, None))
                            .await;
                    }
                }
                Err(e) => record_error(&state, sec.zone_id, &e.to_string()).await,
            }
        }
    }
}

async fn record_error(state: &AppState, zone_id: i64, msg: &str) {
    tracing::warn!(zone_id, "secondary refresh failed: {msg}");
    let msg = msg.to_string();
    let _ = state
        .db
        .run(move |c| Db::set_secondary_status(c, zone_id, Some(&msg), None))
        .await;
}
