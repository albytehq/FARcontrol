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

// ============================================================
// v1.1 (ADR-0025 §4): fingerprint TOFU for agent login
// ============================================================

/// DER → PEM (64-char wrapped) — used to persist a captured cert as the pin.
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The DER a TOFU capture records (shared with the caller for pinning).
pub type CapturedDer = std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>;

/// TOFU capture agent (ADR-0025 §4): accepts ANY server certificate ONCE and
/// records the presented DER so the caller can fingerprint + pin it (SSH
/// known_hosts model, research R4). NEVER carries secrets: the login flow does
/// a handshake-only probe with this agent, pins the captured cert, then sends
/// the password over the pinned channel.
pub fn capture_agent(timeout: std::time::Duration) -> anyhow::Result<(ureq::Agent, CapturedDer)> {
    use std::sync::{Arc, Mutex};
    #[derive(Debug)]
    struct CaptureVerifier(Arc<Mutex<Option<Vec<u8>>>>);
    impl rustls::client::danger::ServerCertVerifier for CaptureVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(end_entity.as_ref().to_vec());
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            use rustls::SignatureScheme::*;
            vec![ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, ED25519]
        }
        fn verify_tls12_signature(&self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            // Capture mode: the handshake signature itself is not verified — the
            // presented cert is only FINGERPRINTED, and secrets travel on the
            // pinned channel afterwards (ADR-0025 §4).
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
    }
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CaptureVerifier(captured.clone())))
        .with_no_client_auth();
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .tls_config(Arc::new(cfg))
        .build();
    Ok((agent, captured))
}

#[cfg(test)]
mod v11_tests {
    use super::*;

    #[test]
    fn pem_roundtrip() {
        let der = b"0123456789abcdef0123";
        let pem = der_to_pem(der, "CERTIFICATE");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(pem_first_block(&pem, "CERTIFICATE").unwrap(), der.to_vec());
    }

    #[test]
    fn fingerprint_of_generated_cert_is_stable() {
        // ensure_cert on a temp dir, then fingerprint twice → same digest
        let dir = std::env::temp_dir().join(format!("frtrol-fp-{}-{}", std::process::id(), crate::crypto::gen_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let (certs, _key) = ensure_cert(&dir).unwrap();
        let der = certs[0].as_ref().to_vec();
        let fp1 = crate::crypto::cert_fingerprint(&der);
        let fp2 = crate::crypto::cert_fingerprint(&der);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("SHA256:"));
        // different data → different fingerprint
        assert_ne!(fp1, crate::crypto::cert_fingerprint(b"other"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
