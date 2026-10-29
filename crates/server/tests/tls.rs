//! ADR 0006: the dashboard over HTTPS + WSS with a self-signed cert.

use nn_server::web::{self, Hub};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

fn tls_hub() -> (SocketAddr, Arc<Hub>, Arc<ClientConfig>) {
    let (cert, key) = nn_server::tls::self_signed(&["localhost".into()]).unwrap();
    let server = nn_server::tls::server_config(cert.as_bytes(), key.as_bytes()).unwrap();
    let (addr, hub) = Hub::listen_tls("127.0.0.1:0", server).unwrap();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(cert.as_bytes()).unwrap())
        .unwrap();
    let client = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (addr, hub, Arc::new(client))
}

fn connect(addr: SocketAddr, cfg: &Arc<ClientConfig>) -> StreamOwned<ClientConnection, TcpStream> {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    StreamOwned::new(ClientConnection::new(Arc::clone(cfg), name).unwrap(), tcp)
}

#[test]
fn https_serves_index_and_state() {
    let (addr, hub, cfg) = tls_hub();
    hub.set_snapshot("{\"type\":\"state\"}".into());
    for (path, want) in [("/", "NetworkNinja"), ("/api/state", "{\"type\":\"state\"}")] {
        let mut s = connect(addr, &cfg);
        write!(s, "GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains(want), "{path}");
    }
}

#[test]
fn wss_handshake_snapshot_broadcast_and_ping() {
    let (addr, hub, cfg) = tls_hub();
    hub.set_snapshot("{\"type\":\"state\",\"entities\":[]}".into());
    let mut s = connect(addr, &cfg);
    write!(
        s,
        "GET /ws HTTP/1.1\r\nhost: x\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
        assert!(head.len() < 4096);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(head.contains("101 Switching Protocols"), "{head}");
    assert!(head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{head}");

    let f = web::read_frame(&mut s).unwrap().unwrap();
    assert!(String::from_utf8_lossy(&f.payload).contains("\"entities\":[]"));
    assert_eq!(hub.client_count(), 1);

    // Writer and reader share one TLS session: interleave both directions.
    for i in 0..20 {
        hub.broadcast(&format!("{{\"n\":{i}}}"));
        s.write_all(&[0x89, 0x84, 0xde, 0xad, 0xbe, 0xef, 0xae, 0xc4, 0xd0, 0x88])
            .unwrap();
        let mut got = Vec::new();
        for _ in 0..2 {
            let f = web::read_frame(&mut s).unwrap().unwrap();
            got.push((f.opcode, f.payload));
        }
        assert!(got.contains(&(0x1, format!("{{\"n\":{i}}}").into_bytes())), "{i}");
        assert!(got.contains(&(0xA, b"ping".to_vec())), "{i}");
    }

    drop(s);
    for _ in 0..50 {
        if hub.client_count() == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("client was not removed after disconnect");
}

#[test]
fn plaintext_client_is_not_served_on_tls_port() {
    let (addr, _hub, _cfg) = tls_hub();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET / HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    assert!(!String::from_utf8_lossy(&buf).contains("NetworkNinja"));
}
