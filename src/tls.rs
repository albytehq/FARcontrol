//! TLS for both planes (ADR-0004, v0.2): a self-signed certificate is
//! auto-generated in the data dir on first start (`cert.pem` + `key.pem`,
//! key mode 0600). Clients trust it by pinning — the cert file is handed to
//! the agent together with its token (both are enrollment material, TOFU).
//! This closes the v0.1 gap: HMAC protected authenticity + integrity, TLS now
//! adds confidentiality on the wire — no tunnel needed for cross-network use.

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::Path;

/// Generates the self-signed pair if missing; returns (cert, key) DER.
pub fn ensure_cert(dir: &Path) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path).context("cannot read cert.pem")?;
        let key_pem = std::fs::read_to_string(&key_path).context("cannot read key.pem")?;
        let cert = pem_first_block(&cert_pem, "CERTIFICATE")
            .ok_or_else(|| anyhow::anyhow!("cert.pem contains no CERTIFICATE block"))?;
        let key = pem_first_block(&key_pem, "PRIVATE KEY")
            .ok_or_else(|| anyhow::anyhow!("key.pem contains no PRIVATE KEY block"))?;
        return Ok((
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        ));
    }

    // Generate: 10-year self-signed cert covering localhost + loopback IPs.
    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".into(),
        "farcontrol".into(),
    ])
    .map_err(|e| anyhow::anyhow!("cert params: {e}"))?;
    use rcgen::SanType;
    for ip in ["127.0.0.1", "::1"] {
        let ip: std::net::IpAddr = ip.parse().unwrap();
        params.subject_alt_names.push(SanType::IpAddress(ip));
    }
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "farcontrol");
    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow::anyhow!("keygen: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow::anyhow!("self-signed cert: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    write_secret(&key_path, &key_pem)?;
    std::fs::write(&cert_path, &cert_pem).context("cannot write cert.pem")?;
    Ok((
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
    ))
}

fn write_secret(path: &Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Extracts + decodes the first `-----BEGIN <label>-----` block of a PEM file.
pub fn pem_first_block(pem: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin)? + begin.len();
    let stop = pem[start..].find(&end)? + start;
    let b64: String = pem[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.as_bytes()).ok()
}

/// ureq agent that trusts ONLY our pinned self-signed cert (TOFU — the cert
/// file travels with the token). Used by both CLI planes when the base URL
/// is https.
pub fn https_agent(cert_pem: &str, timeout: std::time::Duration) -> anyhow::Result<ureq::Agent> {
    let der = pem_first_block(cert_pem, "CERTIFICATE")
        .ok_or_else(|| anyhow::anyhow!("no CERTIFICATE block in cert"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(der))
        .map_err(|e| anyhow::anyhow!("bad cert: {e}"))?;
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(ureq::AgentBuilder::new()
        .timeout(timeout)
        .tls_config(std::sync::Arc::new(cfg))
        .build())
}
