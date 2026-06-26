//! TLS material: load a configured certificate or generate a stable self-signed
//! one, and build rustls [`ServerConfig`]s (using the ring provider) for the web
//! UI, DoT, and DoH listeners.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::Config;

pub struct TlsMaterial {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Clone for TlsMaterial {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
        }
    }
}

/// Load configured TLS material, or generate and persist a self-signed
/// certificate under `data_dir`.
pub fn load_or_generate(config: &Config) -> anyhow::Result<TlsMaterial> {
    match (&config.tls.cert_path, &config.tls.key_path) {
        (Some(cert), Some(key)) => {
            if !cert.exists() || !key.exists() {
                anyhow::bail!(
                    "configured TLS cert/key not found: {} / {}",
                    cert.display(),
                    key.display()
                );
            }
            load_pem(cert, key)
        }
        _ => {
            let cert_path = config.data_dir.join("picons-cert.pem");
            let key_path = config.data_dir.join("picons-key.pem");
            if cert_path.exists() && key_path.exists() {
                load_pem(&cert_path, &key_path)
            } else if config.tls.auto_self_signed {
                generate_self_signed(&config.tls.hostname, &cert_path, &key_path)
            } else {
                anyhow::bail!(
                    "TLS required but no certificate configured and auto_self_signed is disabled"
                );
            }
        }
    }
}

fn load_pem(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsMaterial> {
    let mut cert_reader = BufReader::new(
        File::open(cert_path).with_context(|| format!("opening {}", cert_path.display()))?,
    );
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("opening {}", key_path.display()))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    Ok(TlsMaterial { certs, key })
}

fn generate_self_signed(
    hostname: &str,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> anyhow::Result<TlsMaterial> {
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut sans = vec![hostname.to_string(), "localhost".to_string()];
    sans.dedup();
    let certified = rcgen::generate_simple_self_signed(sans)?;

    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    std::fs::write(cert_path, &cert_pem)?;
    std::fs::write(key_path, &key_pem)?;
    // Lock down the private key file.
    set_key_perms(key_path);

    tracing::warn!(
        "generated self-signed certificate for {hostname} at {}",
        cert_path.display()
    );

    load_pem(cert_path, key_path)
}

#[cfg(unix)]
fn set_key_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_key_perms(_path: &Path) {}

/// Build a rustls [`ServerConfig`] for the given ALPN protocols. Relies on the
/// process-wide ring crypto provider installed at startup.
pub fn server_config(
    material: &TlsMaterial,
    alpn: &[&[u8]],
) -> anyhow::Result<Arc<ServerConfig>> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(material.certs.clone(), material.key.clone_key())?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}
