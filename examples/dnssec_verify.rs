//! Verify a Nomina-signed zone cryptographically (system `delv` on macOS lacks
//! ECDSA support). Queries the server with DO set, then validates the A RRset's
//! RRSIG against the apex DNSKEY using hickory's verifier.
//!
//! Usage: cargo run --example dnssec_verify -- <ip:port> <qname> <zone>

use std::net::SocketAddr;

use hickory_proto::dnssec::Verifier;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

async fn query(server: SocketAddr, name: &Name, rtype: RecordType) -> anyhow::Result<Message> {
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(4096);
    msg.edns = Some(edns);
    msg.add_query(Query::query(name.clone(), rtype));

    let buf = msg.to_vec()?;
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(server).await?;
    sock.send(&buf).await?;
    let mut resp = vec![0u8; 65535];
    let n = sock.recv(&mut resp).await?;
    Ok(Message::from_vec(&resp[..n])?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let server: SocketAddr = args.next().expect("ip:port").parse()?;
    let qname = Name::from_utf8(args.next().expect("qname"))?;
    let zone = Name::from_utf8(args.next().expect("zone"))?;

    let a = query(server, &qname, RecordType::A).await?;
    println!("A response: {} answers, rcode={:?}", a.answers.len(), a.response_code);
    let a_records: Vec<Record> = a
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::A)
        .cloned()
        .collect();
    let rrsig = a.answers.iter().find_map(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => Some(s.clone()),
        _ => None,
    });

    let dk = query(server, &zone, RecordType::DNSKEY).await?;
    println!("DNSKEY response: {} answers", dk.answers.len());
    let dnskey = dk.answers.iter().find_map(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
        _ => None,
    });

    let key = match (rrsig, &dnskey) {
        (Some(sig), Some(key)) => {
            match key.verify_rrsig(&qname, DNSClass::IN, &sig, a_records.iter()) {
                Ok(()) => println!("VALIDATED: A RRSIG verifies against the apex DNSKEY"),
                Err(e) => println!("INVALID positive: {e}"),
            }
            dnskey.clone()
        }
        (s, k) => {
            println!("missing material: rrsig={} dnskey={}", s.is_some(), k.is_some());
            None
        }
    };

    // Negative proof: a non-existent name must return a signed NSEC (black lies).
    let nx = Name::from_utf8(format!("zzdoesnotexist.{zone}"))?;
    let neg = query(server, &nx, RecordType::A).await?;
    println!(
        "negative response: rcode={:?} authority={}",
        neg.response_code,
        neg.authorities.len()
    );
    // The denial may be NSEC or NSEC3.
    let denial_type = if neg.authorities.iter().any(|r| r.record_type() == RecordType::NSEC3) {
        RecordType::NSEC3
    } else {
        RecordType::NSEC
    };
    let denial_records: Vec<Record> = neg
        .authorities
        .iter()
        .filter(|r| r.record_type() == denial_type)
        .cloned()
        .collect();
    // The NSEC/NSEC3 owner name (for NSEC3 it's the hashed name) is the RRSIG signer scope.
    let denial_owner = denial_records.first().map(|r| r.name.clone());
    let denial_sig = neg.authorities.iter().find_map(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == denial_type => {
            Some(s.clone())
        }
        _ => None,
    });
    match (denial_sig, denial_owner, key) {
        (Some(sig), Some(owner), Some(key)) => {
            match key.verify_rrsig(&owner, DNSClass::IN, &sig, denial_records.iter()) {
                Ok(()) => println!(
                    "VALIDATED: {denial_type} denial RRSIG verifies (negative answer authenticated)"
                ),
                Err(e) => println!("INVALID negative: {e}"),
            }
        }
        _ => println!("negative answer missing denial record/RRSIG"),
    }
    Ok(())
}
