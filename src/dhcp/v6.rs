//! DHCPv6 message codec (RFC 8415).
//!
//! Parses and builds the 4-byte header (message type + 3-byte transaction id)
//! followed by the option TLV stream (2-byte code, 2-byte length, value).
//! Includes helpers for the Client/Server Identifier (DUID) options and the
//! IA_NA option with its nested IA Address. Parsing is total — malformed or
//! truncated input returns `Err`, never panics.

use std::net::Ipv6Addr;

const OPT_CLIENT_ID: u16 = 1;
const OPT_SERVER_ID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IA_ADDR: u16 = 5;

/// DHCPv6 message type (RFC 8415 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcp6MessageType {
    Solicit,
    Advertise,
    Request,
    Confirm,
    Renew,
    Rebind,
    Reply,
    Release,
    Decline,
    InformationRequest,
}

impl Dhcp6MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Solicit,
            2 => Self::Advertise,
            3 => Self::Request,
            4 => Self::Confirm,
            5 => Self::Renew,
            6 => Self::Rebind,
            7 => Self::Reply,
            8 => Self::Release,
            9 => Self::Decline,
            11 => Self::InformationRequest,
            _ => return None,
        })
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Solicit => 1,
            Self::Advertise => 2,
            Self::Request => 3,
            Self::Confirm => 4,
            Self::Renew => 5,
            Self::Rebind => 6,
            Self::Reply => 7,
            Self::Release => 8,
            Self::Decline => 9,
            Self::InformationRequest => 11,
        }
    }
}

/// A nested IA Address option (option 5) inside an IA_NA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaAddress {
    pub addr: Ipv6Addr,
    pub preferred: u32,
    pub valid: u32,
}

/// A parsed Identity Association for Non-temporary Addresses (option 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaNa {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub addresses: Vec<IaAddress>,
}

/// A parsed (or constructed) DHCPv6 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp6Message {
    pub msg_type: Dhcp6MessageType,
    pub transaction_id: [u8; 3],
    /// Options as `(code, value)` in wire order.
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Dhcp6Message {
    /// Construct an empty message of the given type and transaction id.
    pub fn new(msg_type: Dhcp6MessageType, transaction_id: [u8; 3]) -> Self {
        Self {
            msg_type,
            transaction_id,
            options: Vec::new(),
        }
    }

    /// Parse a DHCPv6 frame. Returns `Err` on any structural problem.
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 4 {
            return Err(format!("frame too short: {} bytes (need 4)", buf.len()));
        }
        let msg_type = Dhcp6MessageType::from_u8(buf[0])
            .ok_or_else(|| format!("unknown DHCPv6 message type {}", buf[0]))?;
        let transaction_id = [buf[1], buf[2], buf[3]];
        let options = parse_options(&buf[4..])?;
        Ok(Self {
            msg_type,
            transaction_id,
            options,
        })
    }

    /// Serialize the message: header then each option as code/len/value.
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.options.len() * 8);
        buf.push(self.msg_type.to_u8());
        buf.extend_from_slice(&self.transaction_id);
        for (code, value) in &self.options {
            push_option(&mut buf, *code, value);
        }
        buf
    }

    /// Raw value of an option by code, if present.
    pub fn option(&self, code: u16) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    /// Set or replace an option's value.
    pub fn set_option(&mut self, code: u16, value: Vec<u8>) {
        if let Some(slot) = self.options.iter_mut().find(|(c, _)| *c == code) {
            slot.1 = value;
        } else {
            self.options.push((code, value));
        }
    }

    /// Client DUID (option 1) as a lowercase hex string.
    pub fn client_duid(&self) -> Option<String> {
        self.option(OPT_CLIENT_ID).map(to_hex)
    }

    /// Server DUID (option 2) as a lowercase hex string.
    pub fn server_duid(&self) -> Option<String> {
        self.option(OPT_SERVER_ID).map(to_hex)
    }

    /// Parse the first IA_NA option (option 3) including any nested IA Address.
    pub fn ia_na(&self) -> Option<IaNa> {
        parse_ia_na(self.option(OPT_IA_NA)?).ok()
    }
}

/// Encode an IA_NA option value (option 3 payload): IAID, T1, T2, and the nested
/// IA Address (option 5) options.
pub fn encode_ia_na(ia: &IaNa) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + ia.addresses.len() * 28);
    out.extend_from_slice(&ia.iaid.to_be_bytes());
    out.extend_from_slice(&ia.t1.to_be_bytes());
    out.extend_from_slice(&ia.t2.to_be_bytes());
    for a in &ia.addresses {
        let mut val = Vec::with_capacity(24);
        val.extend_from_slice(&a.addr.octets());
        val.extend_from_slice(&a.preferred.to_be_bytes());
        val.extend_from_slice(&a.valid.to_be_bytes());
        push_option(&mut out, OPT_IA_ADDR, &val);
    }
    out
}

/// Build a DUID-LL (link-layer, type 3) from a hardware type and address.
pub fn duid_ll(hw_type: u16, link_layer: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + link_layer.len());
    out.extend_from_slice(&3u16.to_be_bytes()); // DUID-LL
    out.extend_from_slice(&hw_type.to_be_bytes());
    out.extend_from_slice(link_layer);
    out
}

fn push_option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    let len = value.len().min(u16::MAX as usize);
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(&value[..len]);
}

/// Parse the option TLV stream with full bounds checking.
fn parse_options(buf: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if i + 4 > buf.len() {
            return Err("truncated option header".into());
        }
        let code = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if i + len > buf.len() {
            return Err(format!(
                "option {code}: length {len} runs past end of buffer"
            ));
        }
        out.push((code, buf[i..i + len].to_vec()));
        i += len;
    }
    Ok(out)
}

fn parse_ia_na(buf: &[u8]) -> Result<IaNa, String> {
    if buf.len() < 12 {
        return Err("IA_NA too short".into());
    }
    let iaid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let t1 = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let t2 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let mut addresses = Vec::new();
    for (code, value) in parse_options(&buf[12..])? {
        if code == OPT_IA_ADDR {
            addresses.push(parse_ia_addr(&value)?);
        }
    }
    Ok(IaNa {
        iaid,
        t1,
        t2,
        addresses,
    })
}

fn parse_ia_addr(buf: &[u8]) -> Result<IaAddress, String> {
    if buf.len() < 24 {
        return Err("IA Address too short".into());
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&buf[..16]);
    Ok(IaAddress {
        addr: Ipv6Addr::from(octets),
        preferred: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
        valid: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
    })
}

fn to_hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_solicit() -> Dhcp6Message {
        let mut m = Dhcp6Message::new(Dhcp6MessageType::Solicit, [0xaa, 0xbb, 0xcc]);
        // Client DUID-LL over a MAC.
        m.set_option(
            OPT_CLIENT_ID,
            duid_ll(1, &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        );
        // IA_NA with no address yet (solicit).
        m.set_option(
            OPT_IA_NA,
            encode_ia_na(&IaNa {
                iaid: 1,
                t1: 0,
                t2: 0,
                addresses: vec![],
            }),
        );
        m
    }

    #[test]
    fn round_trips_solicit() {
        let m = sample_solicit();
        let buf = m.build();
        let parsed = Dhcp6Message::parse(&buf).unwrap();
        assert_eq!(parsed, m);
        assert_eq!(parsed.msg_type, Dhcp6MessageType::Solicit);
        assert_eq!(parsed.transaction_id, [0xaa, 0xbb, 0xcc]);
        // DUID-LL: type 3, hw 1, then the MAC.
        assert_eq!(
            parsed.client_duid().as_deref(),
            Some("00030001deadbeef0001")
        );
    }

    #[test]
    fn builds_advertise_and_reply_with_ia_na() {
        let ia = IaNa {
            iaid: 0x12345678,
            t1: 1800,
            t2: 2880,
            addresses: vec![IaAddress {
                addr: "2001:db8::abcd".parse().unwrap(),
                preferred: 3600,
                valid: 7200,
            }],
        };
        let mut adv = Dhcp6Message::new(Dhcp6MessageType::Advertise, [1, 2, 3]);
        adv.set_option(OPT_SERVER_ID, duid_ll(1, &[1, 2, 3, 4, 5, 6]));
        adv.set_option(OPT_IA_NA, encode_ia_na(&ia));

        let parsed = Dhcp6Message::parse(&adv.build()).unwrap();
        assert_eq!(parsed.msg_type, Dhcp6MessageType::Advertise);
        assert_eq!(
            parsed.server_duid().as_deref(),
            Some("00030001010203040506")
        );
        let got = parsed.ia_na().unwrap();
        assert_eq!(got, ia);
        assert_eq!(
            got.addresses[0].addr,
            "2001:db8::abcd".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(got.addresses[0].valid, 7200);

        // Same options, REPLY type.
        let mut reply = parsed.clone();
        reply.msg_type = Dhcp6MessageType::Reply;
        let reparsed = Dhcp6Message::parse(&reply.build()).unwrap();
        assert_eq!(reparsed.msg_type, Dhcp6MessageType::Reply);
        assert_eq!(reparsed.ia_na().unwrap(), ia);
    }

    #[test]
    fn rejects_short_and_unknown() {
        assert!(Dhcp6Message::parse(&[]).is_err());
        assert!(Dhcp6Message::parse(&[1, 2, 3]).is_err()); // < 4 bytes
        // Unknown message type 99.
        assert!(Dhcp6Message::parse(&[99, 0, 0, 0]).is_err());
    }

    #[test]
    fn rejects_truncated_options_without_panic() {
        // Valid header, then an option claiming 100 bytes with none present.
        let buf = vec![1, 0, 0, 0, 0x00, 0x01, 0x00, 0x64];
        assert!(Dhcp6Message::parse(&buf).is_err());
        // Truncated option header (only 2 of 4 header bytes).
        let buf2 = vec![1, 0, 0, 0, 0x00, 0x01];
        assert!(Dhcp6Message::parse(&buf2).is_err());
    }

    #[test]
    fn fuzz_random_bytes_never_panic() {
        let mut seed = 0x243f6a8885a308d3u64;
        for len in 0..300usize {
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
            let _ = Dhcp6Message::parse(&buf);
        }
    }
}
