//! Downloading and parsing remote blocklists (hosts files / domain lists).

use std::net::IpAddr;
use std::time::Duration;

use crate::models::BlocklistFormat;

/// Best-effort discovery of this host's public IP via key-less echo services,
/// used to geolocate the server for the "distance travelled" counter.
pub async fn public_ip() -> Option<IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent(concat!("Nomina/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;
    for url in [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ] {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(text) = resp.text().await {
                if let Ok(ip) = text.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Fetch a blocklist URL and parse it into a deduplicated list of domains.
pub async fn fetch_blocklist(url: &str, format: BlocklistFormat) -> anyhow::Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("Nomina/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let text = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    Ok(parse_blocklist(&text, format))
}

/// Parse blocklist text. Lines beginning with `#` or `!` are comments. A `hosts`
/// file maps an IP to a domain (`0.0.0.0 ads.example.com`); a domain list has one
/// domain per line.
pub fn parse_blocklist(text: &str, format: BlocklistFormat) -> Vec<String> {
    let mut domains = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        // Strip inline comments.
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let candidate = match format {
            BlocklistFormat::Hosts => {
                let mut parts = line.split_whitespace();
                let first = parts.next().unwrap_or("");
                // `ip domain` -> take the domain; bare `domain` -> take it.
                parts.next().unwrap_or(first)
            }
            BlocklistFormat::Domains => line.split_whitespace().next().unwrap_or(""),
        };

        let domain = candidate.trim().trim_end_matches('.').to_ascii_lowercase();

        if domain.is_empty()
            || domain == "localhost"
            || domain == "localhost.localdomain"
            || domain == "broadcasthost"
            || !domain.contains('.')
        {
            continue;
        }
        if domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*'))
        {
            domains.push(domain);
        }
    }
    domains.sort_unstable();
    domains.dedup();
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_format() {
        let text = "# comment\n0.0.0.0 ads.example.com\n127.0.0.1 localhost\n0.0.0.0 track.foo.io # inline\n";
        let d = parse_blocklist(text, BlocklistFormat::Hosts);
        assert!(d.contains(&"ads.example.com".to_string()));
        assert!(d.contains(&"track.foo.io".to_string()));
        assert!(!d.contains(&"localhost".to_string()));
    }

    #[test]
    fn parses_domain_format() {
        let text = "ads.example.com\n! adblock comment\ntracker.net\n";
        let d = parse_blocklist(text, BlocklistFormat::Domains);
        assert_eq!(
            d,
            vec!["ads.example.com".to_string(), "tracker.net".to_string()]
        );
    }
}
