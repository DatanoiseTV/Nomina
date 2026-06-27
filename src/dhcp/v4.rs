//! DHCPv4 / BOOTP message codec (RFC 2131 / RFC 2132).
//!
//! Parses and builds the fixed BOOTP header plus the TLV options that follow
//! the magic cookie. Parsing is total: every malformed or truncated input
//! returns `Err`, never panics.

use std::net::Ipv4Addr;

/// The DHCP magic cookie that precedes the options field (RFC 2132 §2).
pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Offset of the magic cookie within a BOOTP frame (end of the fixed header).
const COOKIE_OFFSET: usize = 236;
/// Minimum valid frame: fixed header + cookie.
const MIN_LEN: usize = COOKIE_OFFSET + 4;

const PAD: u8 = 0;
const END: u8 = 255;

const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQUEST_LIST: u8 = 55;
const OPT_CLIENT_ID: u8 = 61;

/// The DHCP message type carried in option 53.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcp4MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl Dhcp4MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }
}

/// A parsed (or constructed) DHCPv4 message.
#[derive(Debug, Clone)]
pub struct Dhcp4Message {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    /// Parsed options as `(code, value)` in wire order (PAD/END stripped).
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Default for Dhcp4Message {
    fn default() -> Self {
        Self {
            op: 2, // BOOTREPLY — the common case when we build messages
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: Vec::new(),
        }
    }
}

impl Dhcp4Message {
    /// Parse a DHCPv4 frame. Returns `Err` on any structural problem.
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < MIN_LEN {
            return Err(format!(
                "frame too short: {} bytes (need at least {MIN_LEN})",
                buf.len()
            ));
        }
        if buf[COOKIE_OFFSET..COOKIE_OFFSET + 4] != MAGIC_COOKIE {
            return Err("missing or invalid DHCP magic cookie".into());
        }

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&buf[28..44]);
        let mut sname = [0u8; 64];
        sname.copy_from_slice(&buf[44..108]);
        let mut file = [0u8; 128];
        file.copy_from_slice(&buf[108..236]);

        let options = parse_options(&buf[MIN_LEN..])?;

        Ok(Self {
            op: buf[0],
            htype: buf[1],
            hlen: buf[2],
            hops: buf[3],
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            secs: u16::from_be_bytes([buf[8], buf[9]]),
            flags: u16::from_be_bytes([buf[10], buf[11]]),
            ciaddr: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            yiaddr: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
            siaddr: Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]),
            giaddr: Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]),
            chaddr,
            sname,
            file,
            options,
        })
    }

    /// Serialize the message: fixed header, magic cookie, options, END marker.
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MIN_LEN + self.options.len() * 8 + 1);
        buf.push(self.op);
        buf.push(self.htype);
        buf.push(self.hlen);
        buf.push(self.hops);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.ciaddr.octets());
        buf.extend_from_slice(&self.yiaddr.octets());
        buf.extend_from_slice(&self.siaddr.octets());
        buf.extend_from_slice(&self.giaddr.octets());
        buf.extend_from_slice(&self.chaddr);
        buf.extend_from_slice(&self.sname);
        buf.extend_from_slice(&self.file);
        buf.extend_from_slice(&MAGIC_COOKIE);
        for (code, value) in &self.options {
            // PAD/END are structural and never stored as data options; skip any
            // accidental occurrences so the framing stays valid.
            if *code == PAD || *code == END {
                continue;
            }
            // Values longer than 255 bytes need option concatenation (RFC 3396),
            // which we don't emit; truncate defensively to keep framing valid.
            let len = value.len().min(255);
            buf.push(*code);
            buf.push(len as u8);
            buf.extend_from_slice(&value[..len]);
        }
        buf.push(END);
        buf
    }

    /// Raw value of an option by code, if present.
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    /// DHCP message type (option 53).
    pub fn message_type(&self) -> Option<Dhcp4MessageType> {
        self.option(OPT_MESSAGE_TYPE)
            .and_then(|v| v.first().copied())
            .and_then(Dhcp4MessageType::from_u8)
    }

    /// Requested IP address (option 50).
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.option(OPT_REQUESTED_IP).and_then(ipv4_from)
    }

    /// Server identifier (option 54).
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.option(OPT_SERVER_ID).and_then(ipv4_from)
    }

    /// Client identifier (option 61), raw bytes.
    pub fn client_id(&self) -> Option<&[u8]> {
        self.option(OPT_CLIENT_ID)
    }

    /// Requested host name (option 12), if valid UTF-8.
    pub fn hostname(&self) -> Option<String> {
        self.option(OPT_HOSTNAME)
            .and_then(|v| std::str::from_utf8(v).ok())
            .map(|s| s.trim_end_matches('\0').to_string())
    }

    /// Parameter request list (option 55), the requested option codes.
    pub fn parameter_request_list(&self) -> Option<&[u8]> {
        self.option(OPT_PARAM_REQUEST_LIST)
    }

    /// Client hardware address from `chaddr`/`hlen` as lowercase colon-hex.
    pub fn client_mac(&self) -> String {
        let n = (self.hlen as usize).min(16);
        self.chaddr[..n]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Set or replace an option's value.
    pub fn set_option(&mut self, code: u8, value: Vec<u8>) {
        if let Some(slot) = self.options.iter_mut().find(|(c, _)| *c == code) {
            slot.1 = value;
        } else {
            self.options.push((code, value));
        }
    }

    /// Set the DHCP message type (option 53).
    pub fn set_message_type(&mut self, mt: Dhcp4MessageType) {
        self.set_option(OPT_MESSAGE_TYPE, vec![mt.to_u8()]);
    }
}

/// Parse the TLV options region. Bounds are checked at every step; a length
/// field that runs past the buffer is an error rather than a panic.
fn parse_options(buf: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let code = buf[i];
        i += 1;
        match code {
            PAD => continue,
            END => break,
            _ => {}
        }
        if i >= buf.len() {
            return Err(format!("option {code}: missing length byte"));
        }
        let len = buf[i] as usize;
        i += 1;
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

fn ipv4_from(v: &[u8]) -> Option<Ipv4Addr> {
    if v.len() == 4 {
        Some(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_discover() -> Vec<u8> {
        let mut m = Dhcp4Message {
            op: 1, // BOOTREQUEST
            htype: 1,
            hlen: 6,
            xid: 0x12345678,
            flags: 0x8000,
            chaddr: {
                let mut c = [0u8; 16];
                c[..6].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
                c
            },
            ..Default::default()
        };
        m.set_message_type(Dhcp4MessageType::Discover);
        m.set_option(OPT_REQUESTED_IP, vec![192, 168, 1, 50]);
        m.set_option(OPT_CLIENT_ID, vec![1, 0xde, 0xad, 0xbe, 0xef, 0, 1]);
        m.set_option(OPT_HOSTNAME, b"laptop".to_vec());
        m.set_option(OPT_PARAM_REQUEST_LIST, vec![1, 3, 6, 15]);
        m.build()
    }

    #[test]
    fn parses_and_extracts_options() {
        let buf = sample_discover();
        let m = Dhcp4Message::parse(&buf).unwrap();
        assert_eq!(m.op, 1);
        assert_eq!(m.xid, 0x12345678);
        assert_eq!(m.message_type(), Some(Dhcp4MessageType::Discover));
        assert_eq!(m.requested_ip(), Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(
            m.client_id(),
            Some([1, 0xde, 0xad, 0xbe, 0xef, 0, 1].as_slice())
        );
        assert_eq!(m.hostname().as_deref(), Some("laptop"));
        assert_eq!(m.parameter_request_list(), Some([1, 3, 6, 15].as_slice()));
        assert_eq!(m.client_mac(), "de:ad:be:ef:00:01");
    }

    #[test]
    fn round_trips_parse_build_parse() {
        let buf = sample_discover();
        let m1 = Dhcp4Message::parse(&buf).unwrap();
        let buf2 = m1.build();
        let m2 = Dhcp4Message::parse(&buf2).unwrap();
        assert_eq!(m1.xid, m2.xid);
        assert_eq!(m1.chaddr, m2.chaddr);
        assert_eq!(m1.message_type(), m2.message_type());
        assert_eq!(m1.requested_ip(), m2.requested_ip());
        assert_eq!(m1.hostname(), m2.hostname());
        // Option sets must match exactly.
        let mut a = m1.options.clone();
        let mut b = m2.options.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn builds_offer_and_ack() {
        let mut offer = Dhcp4Message {
            op: 2,
            xid: 0xabcd,
            yiaddr: Ipv4Addr::new(192, 168, 1, 50),
            siaddr: Ipv4Addr::new(192, 168, 1, 1),
            ..Default::default()
        };
        offer.set_message_type(Dhcp4MessageType::Offer);
        offer.set_option(OPT_SERVER_ID, vec![192, 168, 1, 1]);
        offer.set_option(51, 86400u32.to_be_bytes().to_vec());
        let parsed = Dhcp4Message::parse(&offer.build()).unwrap();
        assert_eq!(parsed.message_type(), Some(Dhcp4MessageType::Offer));
        assert_eq!(parsed.yiaddr, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(parsed.server_id(), Some(Ipv4Addr::new(192, 168, 1, 1)));

        let mut ack = offer.clone();
        ack.set_message_type(Dhcp4MessageType::Ack);
        assert_eq!(
            Dhcp4Message::parse(&ack.build()).unwrap().message_type(),
            Some(Dhcp4MessageType::Ack)
        );
    }

    #[test]
    fn rejects_bad_magic_cookie() {
        let mut buf = sample_discover();
        buf[COOKIE_OFFSET] ^= 0xff;
        assert!(Dhcp4Message::parse(&buf).is_err());
    }

    #[test]
    fn rejects_truncated_input_without_panic() {
        // Far too short.
        assert!(Dhcp4Message::parse(&[0u8; 10]).is_err());
        assert!(Dhcp4Message::parse(&[]).is_err());
        // Valid header + cookie but an option claiming more bytes than remain.
        let mut buf = vec![0u8; MIN_LEN];
        buf[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
        buf.push(53); // option code
        buf.push(50); // claims 50 bytes
        buf.push(1); // ...but only one follows
        assert!(Dhcp4Message::parse(&buf).is_err());
        // Option code with no length byte at all.
        let mut buf2 = vec![0u8; MIN_LEN];
        buf2[COOKIE_OFFSET..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
        buf2.push(53);
        assert!(Dhcp4Message::parse(&buf2).is_err());
    }

    #[test]
    fn fuzz_random_bytes_never_panic() {
        // Deterministic pseudo-random smoke test: parsing must only ever return
        // Ok or Err, never panic, for arbitrary inputs of varying length.
        let mut seed = 0x9e3779b97f4a7c15u64;
        for len in 0..300usize {
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
            let _ = Dhcp4Message::parse(&buf);
        }
    }
}
