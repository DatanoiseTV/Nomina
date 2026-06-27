//! DHCP option registry and wire encoding.
//!
//! The registry catalogs well-known option codes so a UI can present named,
//! typed inputs while still allowing arbitrary codes. [`encode_option`] turns a
//! user-entered [`DhcpOption`] value into its on-the-wire byte form per its
//! [`DhcpOptionKind`]; it is shared by both the v4 and v6 codecs.

use std::net::IpAddr;

use crate::models::{DhcpOption, DhcpOptionKind};

/// A well-known option definition: its code, display name, and value kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionDef {
    pub code: u16,
    pub name: &'static str,
    pub kind: DhcpOptionKind,
}

use DhcpOptionKind::*;

/// DHCPv4 option catalog (RFC 2132 and common extensions). Not exhaustive —
/// arbitrary codes remain addable with an explicit kind.
static V4_CATALOG: &[OptionDef] = &[
    OptionDef {
        code: 1,
        name: "Subnet Mask",
        kind: Ip,
    },
    OptionDef {
        code: 2,
        name: "Time Offset",
        kind: U32,
    },
    OptionDef {
        code: 3,
        name: "Router",
        kind: IpList,
    },
    OptionDef {
        code: 4,
        name: "Time Server",
        kind: IpList,
    },
    OptionDef {
        code: 6,
        name: "Domain Name Server",
        kind: IpList,
    },
    OptionDef {
        code: 7,
        name: "Log Server",
        kind: IpList,
    },
    OptionDef {
        code: 12,
        name: "Host Name",
        kind: Text,
    },
    OptionDef {
        code: 15,
        name: "Domain Name",
        kind: Text,
    },
    OptionDef {
        code: 26,
        name: "Interface MTU",
        kind: U16,
    },
    OptionDef {
        code: 28,
        name: "Broadcast Address",
        kind: Ip,
    },
    OptionDef {
        code: 42,
        name: "NTP Servers",
        kind: IpList,
    },
    OptionDef {
        code: 44,
        name: "NetBIOS Name Servers",
        kind: IpList,
    },
    OptionDef {
        code: 46,
        name: "NetBIOS Node Type",
        kind: U8,
    },
    OptionDef {
        code: 47,
        name: "NetBIOS Scope",
        kind: Text,
    },
    OptionDef {
        code: 51,
        name: "Lease Time",
        kind: U32,
    },
    OptionDef {
        code: 54,
        name: "Server Identifier",
        kind: Ip,
    },
    OptionDef {
        code: 58,
        name: "Renewal (T1) Time",
        kind: U32,
    },
    OptionDef {
        code: 59,
        name: "Rebinding (T2) Time",
        kind: U32,
    },
    OptionDef {
        code: 66,
        name: "TFTP Server Name",
        kind: Text,
    },
    OptionDef {
        code: 67,
        name: "Bootfile Name",
        kind: Text,
    },
    OptionDef {
        code: 119,
        name: "Domain Search",
        kind: Text,
    },
    OptionDef {
        code: 121,
        name: "Classless Static Route",
        kind: Hex,
    },
];

/// DHCPv6 option catalog (RFC 3315/8415 and extensions). Codes whose wire form
/// is a nested TLV structure (e.g. NTP server, option 56) are typed `Hex` so the
/// raw bytes are entered verbatim rather than guessed.
static V6_CATALOG: &[OptionDef] = &[
    OptionDef {
        code: 7,
        name: "Preference",
        kind: U8,
    },
    OptionDef {
        code: 21,
        name: "SIP Servers Domain List",
        kind: Text,
    },
    OptionDef {
        code: 22,
        name: "SIP Servers IPv6 List",
        kind: IpList,
    },
    OptionDef {
        code: 23,
        name: "DNS Recursive Name Server",
        kind: IpList,
    },
    OptionDef {
        code: 24,
        name: "Domain Search List",
        kind: Text,
    },
    OptionDef {
        code: 27,
        name: "NIS Servers",
        kind: IpList,
    },
    OptionDef {
        code: 28,
        name: "NIS+ Servers",
        kind: IpList,
    },
    OptionDef {
        code: 29,
        name: "NIS Domain Name",
        kind: Text,
    },
    OptionDef {
        code: 31,
        name: "SNTP Servers",
        kind: IpList,
    },
    OptionDef {
        code: 56,
        name: "NTP Server",
        kind: Hex,
    },
];

/// The DHCPv4 well-known option catalog.
pub fn v4_catalog() -> &'static [OptionDef] {
    V4_CATALOG
}

/// The DHCPv6 well-known option catalog.
pub fn v6_catalog() -> &'static [OptionDef] {
    V6_CATALOG
}

/// Look up a well-known v4 option definition by code.
pub fn v4_def(code: u16) -> Option<&'static OptionDef> {
    V4_CATALOG.iter().find(|d| d.code == code)
}

/// Look up a well-known v6 option definition by code.
pub fn v6_def(code: u16) -> Option<&'static OptionDef> {
    V6_CATALOG.iter().find(|d| d.code == code)
}

/// Encode a [`DhcpOption`]'s value into its on-the-wire byte form per its kind.
///
/// - `Ip` → 4 bytes (v4) or 16 bytes (v6)
/// - `IpList` → addresses concatenated
/// - `U8`/`U16`/`U32` → big-endian integer
/// - `Bool` → a single `0x00`/`0x01` byte
/// - `Text` → UTF-8 bytes
/// - `Hex` → decoded hex (colons, spaces, dashes ignored)
pub fn encode_option(opt: &DhcpOption) -> Result<Vec<u8>, String> {
    match opt.kind {
        Ip => {
            let ip: IpAddr = opt
                .value
                .trim()
                .parse()
                .map_err(|_| format!("option {}: invalid IP `{}`", opt.code, opt.value))?;
            Ok(ip_bytes(ip))
        }
        IpList => {
            let mut out = Vec::new();
            for tok in opt
                .value
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
            {
                let ip: IpAddr = tok
                    .parse()
                    .map_err(|_| format!("option {}: invalid IP `{tok}`", opt.code))?;
                out.extend_from_slice(&ip_bytes(ip));
            }
            if out.is_empty() {
                return Err(format!("option {}: empty IP list", opt.code));
            }
            Ok(out)
        }
        U8 => {
            let v: u8 = parse_int(&opt.value, opt.code)?;
            Ok(vec![v])
        }
        U16 => {
            let v: u16 = parse_int(&opt.value, opt.code)?;
            Ok(v.to_be_bytes().to_vec())
        }
        U32 => {
            let v: u32 = parse_int(&opt.value, opt.code)?;
            Ok(v.to_be_bytes().to_vec())
        }
        Bool => Ok(vec![parse_bool(&opt.value, opt.code)? as u8]),
        Text => Ok(opt.value.as_bytes().to_vec()),
        Hex => decode_hex(&opt.value, opt.code),
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn parse_int<T: std::str::FromStr>(s: &str, code: u16) -> Result<T, String> {
    s.trim()
        .parse::<T>()
        .map_err(|_| format!("option {code}: invalid integer `{s}`"))
}

fn parse_bool(s: &str, code: u16) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("option {code}: invalid bool `{s}`")),
    }
}

/// Decode a hex string, ignoring colon/space/dash separators.
fn decode_hex(s: &str, code: u16) -> Result<Vec<u8>, String> {
    let clean: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-' | '\t' | '\n' | '\r'))
        .collect();
    if clean.len() % 2 != 0 {
        return Err(format!("option {code}: hex needs an even number of digits"));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let pair = &clean[i..i + 2];
        let b = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("option {code}: invalid hex `{pair}`"))?;
        out.push(b);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DhcpOption;

    fn opt(code: u16, value: &str, kind: DhcpOptionKind) -> DhcpOption {
        DhcpOption {
            code,
            name: None,
            value: value.into(),
            kind,
        }
    }

    #[test]
    fn encodes_ip_v4_and_v6() {
        assert_eq!(
            encode_option(&opt(1, "255.255.255.0", Ip)).unwrap(),
            vec![255, 255, 255, 0]
        );
        let v6 = encode_option(&opt(23, "2001:db8::1", Ip)).unwrap();
        assert_eq!(v6.len(), 16);
        assert_eq!(&v6[..2], &[0x20, 0x01]);
        assert_eq!(v6[15], 0x01);
    }

    #[test]
    fn encodes_ip_list() {
        let b = encode_option(&opt(6, "8.8.8.8, 1.1.1.1", IpList)).unwrap();
        assert_eq!(b, vec![8, 8, 8, 8, 1, 1, 1, 1]);
        // whitespace-separated also works
        let b2 = encode_option(&opt(6, "8.8.8.8 1.1.1.1", IpList)).unwrap();
        assert_eq!(b2, b);
        assert!(encode_option(&opt(6, "", IpList)).is_err());
    }

    #[test]
    fn encodes_integers_big_endian() {
        assert_eq!(encode_option(&opt(46, "8", U8)).unwrap(), vec![8]);
        assert_eq!(
            encode_option(&opt(26, "1500", U16)).unwrap(),
            vec![0x05, 0xDC]
        );
        assert_eq!(
            encode_option(&opt(51, "86400", U32)).unwrap(),
            vec![0x00, 0x01, 0x51, 0x80]
        );
        assert!(encode_option(&opt(46, "256", U8)).is_err());
    }

    #[test]
    fn encodes_bool() {
        assert_eq!(encode_option(&opt(19, "true", Bool)).unwrap(), vec![1]);
        assert_eq!(encode_option(&opt(19, "0", Bool)).unwrap(), vec![0]);
        assert!(encode_option(&opt(19, "maybe", Bool)).is_err());
    }

    #[test]
    fn encodes_text() {
        assert_eq!(
            encode_option(&opt(15, "home.lan", Text)).unwrap(),
            b"home.lan".to_vec()
        );
    }

    #[test]
    fn encodes_hex_with_separators() {
        assert_eq!(
            encode_option(&opt(121, "de:ad:be:ef", Hex)).unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(
            encode_option(&opt(121, "DEADBEEF", Hex)).unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(encode_option(&opt(121, "abc", Hex)).is_err());
        assert!(encode_option(&opt(121, "zz", Hex)).is_err());
    }

    #[test]
    fn arbitrary_unknown_code_roundtrips_via_hex() {
        // A code with no registry entry is still encodable with an explicit kind.
        let o = opt(250, "01:02:03", Hex);
        assert!(v4_def(o.code).is_none());
        assert_eq!(encode_option(&o).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn catalogs_are_well_formed() {
        assert!(v4_catalog().len() >= 20);
        assert!(!v6_catalog().is_empty());
        assert_eq!(v4_def(6).unwrap().kind, IpList);
        assert_eq!(v4_def(51).unwrap().kind, U32);
        assert_eq!(v6_def(23).unwrap().kind, IpList);
    }
}
