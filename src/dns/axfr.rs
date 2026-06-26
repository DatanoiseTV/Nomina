//! A minimal AXFR client used by secondary mode to pull a zone from a primary,
//! plus a SOA-serial probe to decide when to re-transfer. hickory 0.26 has no
//! high-level AXFR client, so this speaks the wire protocol directly.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::TSigner;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::dns::tsig::now_secs;

/// Encode a query, TSIG-signing it first if a signer is provided.
fn encode(mut msg: Message, signer: Option<&TSigner>) -> anyhow::Result<Vec<u8>> {
    if let Some(s) = signer {
        msg.finalize(s, now_secs())
            .map_err(|e| anyhow::anyhow!("TSIG sign: {e}"))?;
    }
    Ok(msg.to_vec()?)
}

const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RECORDS: usize = 2_000_000;

fn bind_addr(primary: SocketAddr) -> &'static str {
    if primary.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }
}

/// Query the primary for the zone's SOA serial (UDP).
pub async fn soa_serial(
    primary: SocketAddr,
    zone: &Name,
    signer: Option<&TSigner>,
) -> anyhow::Result<u32> {
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(zone.clone(), RecordType::SOA));
    let buf = encode(msg, signer)?;

    let sock = UdpSocket::bind(bind_addr(primary)).await?;
    sock.connect(primary).await?;
    tokio::time::timeout(TIMEOUT, sock.send(&buf)).await??;
    let mut resp = vec![0u8; 4096];
    let n = tokio::time::timeout(TIMEOUT, sock.recv(&mut resp)).await??;
    let answer = Message::from_vec(&resp[..n])?;
    for r in &answer.answers {
        if let RData::SOA(soa) = &r.data {
            return Ok(soa.serial);
        }
    }
    anyhow::bail!("primary returned no SOA for {zone}")
}

/// Perform a full AXFR transfer of `zone` from `primary` over TCP and return all
/// records (including the bracketing SOAs).
pub async fn axfr_transfer(
    primary: SocketAddr,
    zone: &Name,
    signer: Option<&TSigner>,
) -> anyhow::Result<Vec<Record>> {
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(zone.clone(), RecordType::AXFR));
    let buf = encode(msg, signer)?;

    let mut stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(primary)).await??;
    stream.write_u16(buf.len() as u16).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;

    let mut records: Vec<Record> = Vec::new();
    loop {
        let len = tokio::time::timeout(TIMEOUT, stream.read_u16()).await??;
        let mut mbuf = vec![0u8; len as usize];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut mbuf)).await??;
        let m = Message::from_vec(&mbuf)?;

        if records.is_empty()
            && m.answers.first().map(|r| r.record_type()) != Some(RecordType::SOA)
        {
            anyhow::bail!("AXFR did not begin with SOA (transfer refused?)");
        }
        records.extend(m.answers);
        if records.len() > MAX_RECORDS {
            anyhow::bail!("AXFR exceeded {MAX_RECORDS} records");
        }

        // The transfer ends with the closing SOA (the second SOA overall).
        if records.len() >= 2 && records.last().map(|r| r.record_type()) == Some(RecordType::SOA) {
            break;
        }
    }
    Ok(records)
}
