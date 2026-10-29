//! TLS for the dashboard (ADR 0006): rustls server config from operator
//! PEM files, and self-signed cert generation for field use.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::path::Path;
use std::sync::Arc;

/// Build a server config from a PEM cert chain and a PEM private key.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, String> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cert: {e}"))?;
    if certs.is_empty() {
        return Err("cert: no certificates found".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("key: {e}"))?;
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// [`server_config`] from `--cert` / `--key` files.
pub fn load(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let c = std::fs::read(cert).map_err(|e| format!("{}: {e}", cert.display()))?;
    let k = std::fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?;
    server_config(&c, &k).map_err(|e| format!("{} / {}: {e}", cert.display(), key.display()))
}

/// A self-signed cert valid for `hosts` (DNS names or IP addresses):
/// returns `(cert_pem, key_pem)`.
pub fn self_signed(hosts: &[String]) -> Result<(String, String), String> {
    let mut params = rcgen::CertificateParams::new(hosts.to_vec()).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "NetworkNinja");
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_loads() {
        let (c, k) = self_signed(&["localhost".into(), "127.0.0.1".into()]).unwrap();
        assert!(c.contains("BEGIN CERTIFICATE"));
        assert!(k.contains("PRIVATE KEY"));
        server_config(c.as_bytes(), k.as_bytes()).unwrap();
    }

    #[test]
    fn rejects_bad_pem() {
        let (c, _) = self_signed(&["localhost".into()]).unwrap();
        assert!(server_config(b"junk", b"junk").is_err());
        assert!(server_config(c.as_bytes(), b"junk").is_err());
    }
}
