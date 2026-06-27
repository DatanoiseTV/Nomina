//! Minimal DNS-over-QUIC (RFC 9250) client for verifying the Nomina DoQ
//! listener. Accepts any server certificate (for self-signed test setups).
//!
//! Usage: cargo run --example doq_query -- <ip:port> <name> [A|AAAA|...]

use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mut args = std::env::args().skip(1);
    let addr: SocketAddr = args.next().expect("ip:port").parse()?;
    let name = Name::from_utf8(args.next().expect("name"))?;
    let rtype: RecordType = args
        .next()
        .unwrap_or_else(|| "A".into())
        .parse()
        .unwrap_or(RecordType::A);

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"doq".to_vec()];

    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let client_cfg = quinn::ClientConfig::new(Arc::new(qcc));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint.connect(addr, "nomina.local")?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    // DoQ: query id MUST be 0; message is length-prefixed (2 bytes, like TCP).
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name.clone(), rtype));
    let body = msg.to_vec()?;
    let mut framed = (body.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    send.write_all(&framed).await?;
    send.finish()?;

    let resp = recv.read_to_end(65535).await?;
    if resp.len() < 2 {
        anyhow::bail!("short DoQ response");
    }
    let answer = Message::from_vec(&resp[2..])?;
    println!("rcode={:?} answers={}", answer.response_code, answer.answers.len());
    for r in &answer.answers {
        println!("{} {} {}", r.name, r.record_type(), r.data);
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}
