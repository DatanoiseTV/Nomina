//! Per-zone DNSSEC online signing with a single ECDSA P-256 combined signing
//! key (CSK). Signs positive RRsets and the DNSKEY, serves the apex DNSKEY, and
//! produces minimally-covering ("black lies", RFC 4470) signed NSEC for negative
//! answers so validating resolvers accept denials. DS is exported for the parent.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, RRSIG};
use hickory_proto::dnssec::{Algorithm, DigestType, DnssecSigner, SigningKey};
use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::rr::domain::Label;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use rustls::pki_types::PrivatePkcs8KeyDer;
use time::OffsetDateTime;

const ALGORITHM: Algorithm = Algorithm::ECDSAP256SHA256;
const SIG_VALIDITY_SECS: u64 = 14 * 86400;
const CLOCK_SKEW_SECS: i64 = 3600;

/// Generate a new signing key, returned as base64-encoded PKCS#8 DER for storage.
pub fn generate_secret() -> anyhow::Result<String> {
    let pkcs8 = EcdsaSigningKey::generate_pkcs8(ALGORITHM)
        .map_err(|e| anyhow::anyhow!("generating DNSSEC key: {e}"))?;
    Ok(STANDARD.encode(pkcs8.secret_pkcs8_der()))
}

/// A loaded per-zone signer.
pub struct ZoneSigner {
    signer: DnssecSigner,
    pub apex: Name,
    dnskey: DNSKEY,
    default_ttl: u32,
}

impl ZoneSigner {
    pub fn build(apex: Name, default_ttl: u32, secret_b64: &str) -> anyhow::Result<Self> {
        let der = STANDARD.decode(secret_b64)?;
        let pkcs8 = PrivatePkcs8KeyDer::from(der);
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, ALGORITHM)
            .map_err(|e| anyhow::anyhow!("loading DNSSEC key: {e}"))?;
        let pubkey = key
            .to_public_key()
            .map_err(|e| anyhow::anyhow!("deriving public key: {e}"))?;
        let dnskey = DNSKEY::from_key(&pubkey);
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            apex.clone(),
            Duration::from_secs(SIG_VALIDITY_SECS),
        );
        Ok(Self {
            signer,
            apex,
            dnskey,
            default_ttl,
        })
    }

    fn inception() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp() - CLOCK_SKEW_SECS)
            .unwrap_or_else(|_| OffsetDateTime::now_utc())
    }

    /// Produce an RRSIG record covering `records` (one RRset of `rtype` at `name`).
    fn sign_rrset(&self, name: &Name, rtype: RecordType, ttl: u32, records: &[Record]) -> Option<Record> {
        let mut rrset = RecordSet::new(name.clone(), rtype, 0);
        for r in records {
            rrset.insert(r.clone(), 0);
        }
        let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, Self::inception(), &self.signer).ok()?;
        Some(Record::from_rdata(
            name.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        ))
    }

    /// Append RRSIGs covering every RRset present in `records`.
    pub fn sign_records(&self, records: &mut Vec<Record>) {
        let mut groups: BTreeMap<(String, RecordType), Vec<Record>> = BTreeMap::new();
        for r in records.iter() {
            if r.record_type() == RecordType::RRSIG {
                continue;
            }
            groups
                .entry((r.name.to_string().to_ascii_lowercase(), r.record_type()))
                .or_default()
                .push(r.clone());
        }
        let mut sigs = Vec::new();
        for ((_, rtype), recs) in &groups {
            let ttl = recs[0].ttl;
            if let Some(sig) = self.sign_rrset(&recs[0].name, *rtype, ttl, recs) {
                sigs.push(sig);
            }
        }
        records.extend(sigs);
    }

    /// The apex DNSKEY record plus its RRSIG.
    pub fn dnskey_rrset(&self) -> Vec<Record> {
        let rec = Record::from_rdata(
            self.apex.clone(),
            self.default_ttl,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        );
        let mut out = vec![rec.clone()];
        if let Some(sig) = self.sign_rrset(&self.apex, RecordType::DNSKEY, self.default_ttl, &[rec]) {
            out.push(sig);
        }
        out
    }

    /// A minimally-covering NSEC (plus its RRSIG) proving the denial of `owner`.
    /// `present` lists the types that actually exist at `owner` (empty for an
    /// non-existent name).
    pub fn nsec_records(&self, owner: &Name, present: &[RecordType], ttl: u32) -> Vec<Record> {
        let next = Label::from_raw_bytes(&[0])
            .ok()
            .and_then(|l| owner.prepend_label(l).ok())
            .unwrap_or_else(|| owner.clone());
        let mut types: Vec<RecordType> = present.to_vec();
        types.push(RecordType::RRSIG);
        types.push(RecordType::NSEC);
        let nsec = NSEC::new(next, types);
        let nsec_rec = Record::from_rdata(owner.clone(), ttl, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
        let mut out = vec![nsec_rec.clone()];
        if let Some(sig) = self.sign_rrset(owner, RecordType::NSEC, ttl, &[nsec_rec]) {
            out.push(sig);
        }
        out
    }

    pub fn key_tag(&self) -> u16 {
        self.signer.calculate_key_tag().unwrap_or(0)
    }

    /// DNSKEY presentation (rdata text) for the zone apex.
    pub fn dnskey_text(&self) -> String {
        RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())).to_string()
    }

    /// DS record presentation (SHA-256) for the parent delegation.
    pub fn ds_text(&self) -> anyhow::Result<String> {
        let pubkey = self
            .signer
            .key()
            .to_public_key()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let ds: DS = DS::from_key(&pubkey, &self.apex, DigestType::SHA256)
            .map_err(|e| anyhow::anyhow!("building DS: {e}"))?;
        Ok(RData::DNSSEC(DNSSECRData::DS(ds)).to_string())
    }
}
