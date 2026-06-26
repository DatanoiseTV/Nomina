//! TSIG (RFC 8945) helpers for authenticating zone transfers. Builds signers
//! for outgoing (secondary) requests and verifies incoming (AXFR-serving)
//! requests against configured keys.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hickory_proto::rr::Name;
use hickory_proto::rr::TSigner;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;

use crate::models::TsigKey;

const FUDGE: u16 = 300;

fn algorithm(s: &str) -> Option<TsigAlgorithm> {
    match s.trim().to_ascii_lowercase().as_str() {
        "hmac-sha1" => Some(TsigAlgorithm::HmacSha1),
        "hmac-sha256" | "hmac-sha-256" => Some(TsigAlgorithm::HmacSha256),
        "hmac-sha512" | "hmac-sha-512" => Some(TsigAlgorithm::HmacSha512),
        _ => None,
    }
}

/// Build a [`TSigner`] from a configured key.
pub fn build_signer(key: &TsigKey) -> anyhow::Result<TSigner> {
    let algo = algorithm(&key.algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported TSIG algorithm: {}", key.algorithm))?;
    let secret = STANDARD
        .decode(key.secret.trim())
        .map_err(|e| anyhow::anyhow!("invalid base64 TSIG secret: {e}"))?;
    let mut name = Name::from_utf8(&key.name)?;
    name.set_fqdn(true);
    TSigner::new(secret, algo, name, FUDGE).map_err(|e| anyhow::anyhow!("building TSIG signer: {e}"))
}

/// The current unix time for TSIG `finalize`.
pub fn now_secs() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as u64
}

/// Verify an incoming request's TSIG against configured keys. Returns the
/// matched key name on success.
pub fn verify_request(
    keys: &[TsigKey],
    request_bytes: &[u8],
    tsig: &hickory_proto::rr::Record<hickory_proto::rr::rdata::TSIG>,
) -> anyhow::Result<String> {
    // The TSIG record's owner name is the key name.
    let key_name = tsig.name.to_string();
    let key_name_norm = key_name.trim_end_matches('.').to_ascii_lowercase();

    let key = keys
        .iter()
        .find(|k| k.name.trim_end_matches('.').to_ascii_lowercase() == key_name_norm)
        .ok_or_else(|| anyhow::anyhow!("unknown TSIG key: {key_name}"))?;

    let signer = build_signer(key)?;
    signer
        .verify_message_byte(request_bytes, None, true)
        .map_err(|e| anyhow::anyhow!("TSIG verification failed: {e}"))?;
    Ok(key.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::RecordType;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = TsigKey {
            name: "xfer.key".into(),
            algorithm: "hmac-sha256".into(),
            // 32 zero bytes, base64.
            secret: STANDARD.encode([0u8; 32]),
        };
        let signer = build_signer(&key).unwrap();

        let mut msg = Message::new(1234, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_utf8("home.lan.").unwrap(),
            RecordType::AXFR,
        ));
        let _verifier = msg.finalize(&signer, now_secs()).unwrap();
        let bytes = msg.to_vec().unwrap();

        // The signed message must verify against the same key...
        let parsed = Message::from_vec(&bytes).unwrap();
        let tsig = parsed.signature().expect("signed");
        assert_eq!(
            verify_request(std::slice::from_ref(&key), &bytes, tsig).unwrap(),
            "xfer.key"
        );

        // ...and fail against a different key.
        let other = TsigKey {
            name: "xfer.key".into(),
            algorithm: "hmac-sha256".into(),
            secret: STANDARD.encode([1u8; 32]),
        };
        assert!(verify_request(std::slice::from_ref(&other), &bytes, tsig).is_err());
    }
}
