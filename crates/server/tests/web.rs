//! The embedded dashboard server: WS handshake maths, frame codec, and an
//! end-to-end connect over a real socket.

use nn_rules::{Alert, AlertEvent, AlertState, Monitor, Rule, RuleConfig, Severity};
use nn_server::web::{alert_json, state_json, Hub};
use nn_state::{secs, EntityKey};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime};

// Re-exported internals for tests via the public test hooks below.
use nn_server::web;

fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

#[test]
fn serves_index_and_state() {
    let (addr, hub) = Hub::listen("127.0.0.1:0").unwrap();
    hub.set_snapshot("{\"type\":\"state\"}".into());

    let index = http_get(addr, "/");
    assert!(index.starts_with("HTTP/1.1 200"), "{index}");
    assert!(index.contains("NetworkNinja"));

    let state = http_get(addr, "/api/state");
    assert!(state.contains("{\"type\":\"state\"}"), "{state}");

    assert!(http_get(addr, "/nope").contains("404"));
    assert!(http_get(addr, "/api/state").contains("application/json"));
}

#[test]
fn websocket_handshake_snapshot_and_broadcast() {
    let (addr, hub) = Hub::listen("127.0.0.1:0").unwrap();
    hub.set_snapshot("{\"type\":\"state\",\"entities\":[]}".into());

    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET /ws HTTP/1.1\r\nhost: x\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n"
    )
    .unwrap();

    // RFC 6455's own example: that key accepts to s3pPLMBiTxaQ9kYGzzhZRbK+xOo=.
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

    // The stored snapshot arrives first.
    let f = web::read_frame(&mut s).unwrap().unwrap();
    assert_eq!(f.opcode, 0x1);
    assert!(String::from_utf8_lossy(&f.payload).contains("\"entities\":[]"));
    assert_eq!(hub.client_count(), 1);

    // Broadcasts arrive as text frames.
    hub.broadcast("{\"type\":\"alert\"}");
    let f = web::read_frame(&mut s).unwrap().unwrap();
    assert_eq!(f.opcode, 0x1);
    assert_eq!(String::from_utf8_lossy(&f.payload), "{\"type\":\"alert\"}");

    // A masked client ping gets a pong back ("ping" masked with 0xDEADBEEF).
    s.write_all(&[0x89, 0x84, 0xde, 0xad, 0xbe, 0xef, 0xae, 0xc4, 0xd0, 0x88])
        .unwrap();
    let f = web::read_frame(&mut s).unwrap().unwrap();
    assert_eq!(f.opcode, 0xA);
    assert_eq!(f.payload, b"ping");

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
fn alert_and_state_json() {
    let mut m = Monitor::new(RuleConfig::default());
    let e = AlertEvent {
        at: 123.5,
        state: AlertState::Firing,
        alert: Alert {
            rule: Rule::IdConflict,
            pack: "dis-base".into(),
            rule_id: "id-conflict".into(),
            key: EntityKey {
                exercise: 1,
                id: nn_decode::EntityId::new(1, 1, 2),
            },
            severity: Severity::Critical,
            since: 123.5,
            message: "claimed by \"two\" senders".into(),
        },
        reason: String::new(),
    };
    let j = alert_json(&e);
    assert!(j.contains("\"rule\":\"id-conflict\""), "{j}");
    assert!(j.contains("\"pack\":\"dis-base\""), "{j}");
    assert!(j.contains("\\\"two\\\""), "{j}");

    m.now = secs(SystemTime::now());
    let mut recent = VecDeque::new();
    recent.push_back(j);
    let s = state_json(&m, 12.0, 2, &["dis-base v1".to_string()], &recent);
    assert!(s.contains("\"type\":\"state\""), "{s}");
    assert!(s.contains("\"packs\":[\"dis-base v1\"]"), "{s}");
    assert!(s.contains("\"entities\":[]"), "{s}");
    assert!(s.contains("dis-base"), "{s}");
}

#[test]
fn event_log_sequences_and_pages() {
    let hub = Hub::new();
    let a = hub.log("info", &web::info_json(1.0, "started"));
    let b = hub.log("alert", "{\"at\":2,\"state\":\"firing\"}");
    assert!(a.starts_with("{\"seq\":1,\"kind\":\"info\""), "{a}");
    assert!(b.starts_with("{\"seq\":2,\"kind\":\"alert\""), "{b}");

    let tail = hub.log_tail(0, 500);
    assert!(
        tail.contains("\"seq\":1") && tail.contains("\"seq\":2") && tail.contains("\"latest\":2"),
        "{tail}"
    );
    // after=1 skips the first entry.
    let tail = hub.log_tail(1, 500);
    assert!(!tail.contains("\"seq\":1") && tail.contains("\"seq\":2"), "{tail}");
}

#[test]
fn event_log_over_http_and_on_disk() {
    let (addr, hub) = Hub::listen("127.0.0.1:0").unwrap();
    hub.log("info", &web::info_json(1.0, "first"));
    hub.log("error", &web::error_json(2.0, 3, "10.0.0.1:40000"));

    let body = http_get(addr, "/api/log?after=1");
    assert!(body.contains("\"seq\":2"), "{body}");
    assert!(!body.contains("\"seq\":1"), "{body}");
    assert!(body.contains("3 decode errors"), "{body}");

    // A --log file loads past runs and keeps their sequence numbers.
    let path = std::env::temp_dir().join(format!("nn-log-test-{}", std::process::id()));
    std::fs::write(
        &path,
        "{\"seq\":41,\"kind\":\"info\",\"at\":1,\"message\":\"old run\"}\n",
    )
    .unwrap();
    let hub2 = Hub::new();
    let n = hub2.open_log(&path).unwrap();
    assert_eq!(n, 1);
    let next = hub2.log("info", &web::info_json(3.0, "new run"));
    assert!(next.starts_with("{\"seq\":42"), "{next}");
    // The new entry was appended to the same file.
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"seq\":41") && text.contains("\"seq\":42"), "{text}");
    std::fs::remove_file(&path).unwrap();
}
