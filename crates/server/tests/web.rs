//! The embedded dashboard server: WS handshake maths, frame codec, and an
//! end-to-end connect over a real socket.

use nn_rules::{Alert, AlertEvent, AlertState, Monitor, Rule, RuleConfig, Severity};
use nn_server::web::{alert_json, apply_command, delta_json, state_json, Hub};
use nn_state::{secs, EntityKey};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
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
            sender: Some("10.0.0.7:4000".parse().unwrap()),
            kind: "two-senders",
            facts: vec![("first sender", "10.0.0.1:4000 \"a\"".into())],
        },
        reason: String::new(),
        pdu: None,
    };
    let j = alert_json(&e);
    // The event log adds "kind":"alert"; the alert mustn't bring its own.
    let logged = Hub::new().log("alert", &j);
    assert_eq!(logged.matches("\"kind\":").count(), 1, "{logged}");
    assert!(j.contains("\"rule\":\"id-conflict\""), "{j}");
    assert!(j.contains("\"pack\":\"dis-base\""), "{j}");
    assert!(j.contains("\\\"two\\\""), "{j}");
    assert!(
        j.contains(
            r#""rule_name":"id-conflict","finding":"two-senders","facts":[["first sender","10.0.0.1:4000 \"a\""]]"#
        ),
        "{j}"
    );

    m.now = secs(SystemTime::now());
    let mut recent = VecDeque::new();
    recent.push_back(j);
    let s = state_json(&m, 12.0, 2, &["dis-base v1".to_string()], &recent, None);
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

#[test]
fn client_commands_ack_and_mute() {
    let mut m = Monitor::new(RuleConfig::default());
    let key = EntityKey {
        exercise: 1,
        id: nn_decode::EntityId::new(1, 1, 2),
    };

    assert!(apply_command(&mut m, "{\"cmd\":\"bogus\"}").is_err());
    assert!(apply_command(&mut m, "not json").is_err());
    // Ack with no active alert is rejected.
    assert!(apply_command(
        &mut m,
        "{\"cmd\":\"ack\",\"rule\":\"entity-timeout\",\"entity\":\"1:1:2\",\"exercise\":1}"
    )
    .is_err());

    // Mute by entity, then by rule, then unmute.
    let out = apply_command(
        &mut m,
        "{\"cmd\":\"mute\",\"entity\":\"1:1:2\",\"exercise\":1,\"secs\":60}",
    )
    .unwrap();
    assert!(
        out.events.is_empty() && out.note.contains("muted 1:1:2"),
        "{}",
        out.note
    );
    assert!(m.engine.muted("entity-timeout", &key, m.now));
    assert!(m.engine.muted("header.pdu_type", &key, m.now));

    apply_command(
        &mut m,
        "{\"cmd\":\"mute_rule\",\"rule\":\"position-jump\",\"secs\":120}",
    )
    .unwrap();
    let other = EntityKey {
        exercise: 1,
        id: nn_decode::EntityId::new(9, 9, 9),
    };
    assert!(m.engine.muted("position-jump", &other, m.now));

    apply_command(&mut m, "{\"cmd\":\"unmute\",\"entity\":\"1:1:2\",\"exercise\":1}").unwrap();
    apply_command(&mut m, "{\"cmd\":\"unmute_rule\",\"rule\":\"position-jump\"}").unwrap();
    assert!(!m.engine.muted("entity-timeout", &key, m.now));
    assert!(!m.engine.muted("position-jump", &other, m.now));
}

fn datagram(pdu: &nn_decode::Pdu, t: f64) -> nn_capture::Datagram {
    nn_capture::Datagram {
        received_at: SystemTime::UNIX_EPOCH + Duration::from_secs_f64(1_800_000_000.0 + t),
        source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000)),
        destination: None,
        payload: nn_decode::encode_pdu(pdu),
        monotonic: None,
        listener: None,
    }
}

fn entity_state(n: u16) -> nn_decode::Pdu {
    nn_decode::Pdu {
        header: nn_decode::PduHeader::new(
            7,
            1,
            nn_decode::pdu_type::ENTITY_STATE,
            nn_decode::DisTimestamp::default(),
        ),
        body: nn_decode::PduBody::EntityState(nn_decode::EntityState {
            entity_id: nn_decode::EntityId::new(1, 1, n),
            force_id: 1,
            entity_type: Default::default(),
            alternative_entity_type: Default::default(),
            linear_velocity: Default::default(),
            location: Default::default(),
            orientation: Default::default(),
            appearance: 0,
            dead_reckoning: Default::default(),
            marking: Default::default(),
            capabilities: 0,
            variable_parameters: Vec::new(),
        }),
    }
}

#[test]
fn delta_sends_only_changed_entities() {
    let mut m = Monitor::new(RuleConfig::default());
    m.ingest(&datagram(&entity_state(1), 0.0));
    let mut prev = std::collections::BTreeMap::new();
    let packs = vec!["dis-base v1".to_string()];

    // First delta after an empty baseline carries the entity.
    let d = delta_json(&m, 1.0, 0, &packs, &mut prev, None);
    assert!(d.contains("\"type\":\"delta\""), "{d}");
    assert!(d.contains("\"1:1:1\""), "{d}");

    // Same table — nothing changed.
    let d = delta_json(&m, 2.0, 0, &packs, &mut prev, None);
    assert!(d.contains("\"ents\":[]"), "{d}");

    // A heartbeat bumps `seen` → the entity re-emits.
    m.ingest(&datagram(&entity_state(1), 5.0));
    let d = delta_json(&m, 6.0, 0, &packs, &mut prev, None);
    assert!(d.contains("\"1:1:1\""), "{d}");

    // A second entity arrives; only it ships in the next delta.
    m.ingest(&datagram(&entity_state(2), 7.0));
    let d = delta_json(&m, 8.0, 0, &packs, &mut prev, None);
    assert!(d.contains("\"1:1:2\"") && !d.contains("\"1:1:1\""), "{d}");

    // Full state still carries everything; `seen` replaces `age`.
    let s = state_json(&m, 8.0, 0, &packs, &VecDeque::new(), None);
    assert!(s.contains("\"seen\":") && !s.contains("\"age\":"), "{s}");
}

fn http(addr: std::net::SocketAddr, req: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

#[test]
fn login_logout_and_bearer_sessions() {
    let (addr, hub) = Hub::listen("127.0.0.1:0").unwrap();
    hub.set_snapshot("{\"type\":\"state\"}".into());
    let mut a = nn_server::auth::Auth::empty();
    a.set_user("ops", "p&ss w%rd");
    hub.set_auth(std::sync::Arc::new(a));

    // Gate: no token, bad token.
    assert!(http_get(addr, "/api/state").starts_with("HTTP/1.1 401"));
    assert!(http(
        addr,
        "GET /api/state HTTP/1.1\r\nhost: x\r\nauthorization: Bearer nope\r\n\r\n"
    )
    .starts_with("HTTP/1.1 401"));
    // The page itself is open.
    assert!(http_get(addr, "/").starts_with("HTTP/1.1 200"));

    // Credentials travel in the body, percent-encoded like a browser form.
    let login = |body: &str| {
        http(
            addr,
            &format!(
                "POST /api/login HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
    };
    assert!(login("user=ops&pass=wrong").starts_with("HTTP/1.1 401"));
    assert!(http(
        addr,
        "POST /api/login?user=ops&pass=p%26ss+w%25rd HTTP/1.1\r\nhost: x\r\n\r\n"
    )
    .starts_with("HTTP/1.1 401"));
    let ok = login("user=ops&pass=p%26ss+w%25rd");
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    let body = ok.split("\r\n\r\n").nth(1).unwrap();
    let token = body.split("\"token\":\"").nth(1).unwrap().split('"').next().unwrap();
    assert_eq!(token.len(), 40);
    assert!(body.contains("\"user\":\"ops\""));

    let bearer = format!("GET /api/state HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {token}\r\n\r\n");
    assert!(http(addr, &bearer).contains("{\"type\":\"state\"}"));
    // ?token= still works for the WebSocket path.
    assert!(http_get(addr, &format!("/api/state?token={token}")).starts_with("HTTP/1.1 200"));

    let out = http(
        addr,
        &format!("POST /api/logout HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {token}\r\n\r\n"),
    );
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(http(addr, &bearer).starts_with("HTTP/1.1 401"));
    let log = hub.log_tail(0, 10);
    assert!(log.contains("ops logged in") && log.contains("ops logged out"), "{log}");
}

#[test]
fn entity_detail_map_and_endpoint() {
    let mut m = Monitor::new(RuleConfig::default());
    m.ingest(&datagram(&entity_state(1), 0.0));
    m.ingest(&datagram(&entity_state(1), 5.0));
    let key = EntityKey {
        exercise: 1,
        id: nn_decode::EntityId::new(1, 1, 1),
    };
    m.engine.mute_entity(key, m.now + 300.0, m.now);
    let details = web::entity_details(&m);
    let d = details.get("ex1 1:1:1").expect("detail for 1:1:1");
    assert!(
        d.contains("\"id\":\"1:1:1\"") && d.contains("\"type\":{\"kind\":0,"),
        "{d}"
    );
    assert!(d.contains("\"sources\":[{\"addr\":\"10.0.0.1:5000\""), "{d}");
    assert!(d.contains("\"reports\":2") && d.contains("\"hb_mean\":5"), "{d}");
    assert!(d.contains("\"muted_until\":"), "{d}");
    assert!(d.contains("\"first_seen\":") && d.contains("\"dr\":"), "{d}");

    let (addr, hub) = Hub::listen("127.0.0.1:0").unwrap();
    hub.set_details(details);
    let r = http_get(addr, "/api/entity?ex=1&id=1:1:1");
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("\"sources\":["), "{r}");
    let r = http_get(addr, "/api/entity?ex=1&id=9:9:9");
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    let r = http_get(addr, "/api/entity?id=1:1:1");
    assert!(r.starts_with("HTTP/1.1 404"), "wrong exercise must not match: {r}");
}

#[test]
fn query_endpoint_reads_memory_then_store() {
    use nn_state::metrics::{Agg, Dim, Metric, Rollup};
    let (addr, hub) = Hub::listen("127.0.0.1:0").unwrap();
    let body = |r: &str| r.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();

    // Validation errors are 400s that say what was wrong.
    let r = http_get(addr, "/api/query?name=pdu.count&by=force");
    assert!(
        r.starts_with("HTTP/1.1 400") && r.contains("pdu.count has no dimension 'force'"),
        "{r}"
    );
    assert!(http_get(addr, "/api/query").contains("missing name"));

    // A stand-in serve loop answering from a Monitor's metrics: 60 s of
    // traffic from 10.0.0.1:5000, the last 30 s of it in memory.
    let mut m = Monitor::new(RuleConfig::default());
    for i in 0..60 {
        m.ingest(&datagram(&entity_state(1), i as f64));
    }
    let t0 = 1_800_000_000i64;
    let (tx, rx) = std::sync::mpsc::sync_channel::<web::QueryReq>(4);
    hub.set_query_sink(tx);
    let metrics = m.metrics.clone();
    std::thread::spawn(move || {
        while let Ok((q, reply)) = rx.recv() {
            let _ = reply.send(web::memory_cells(&metrics, &q));
        }
    });
    let r = http_get(
        addr,
        &format!(
            "/api/query?name=pdu.count&by=sender&agg=sum&window=60&from={t0}&to={}",
            t0 + 60
        ),
    );
    let b = body(&r);
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(
        b.contains("\"groups\":[{\"tags\":{\"sender\":\"10.0.0.1:5000\"},\"value\":60}]"),
        "{b}"
    );
    let r = http_get(
        addr,
        &format!(
            "/api/query?name=pdu.count&where.site=1&window=30&from={t0}&to={}",
            t0 + 60
        ),
    );
    assert!(
        body(&r).contains(&format!("\"points\":[[{t0},1],[{},1]]", t0 + 30)),
        "{r}"
    );

    // With a store: slots before the last flush come from SQLite, not memory.
    let path = std::env::temp_dir().join(format!("nn-query-test-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    hub.open_db(&path, "test").unwrap();
    let old = t0 - 3600;
    hub.write_rollup(
        &[Rollup {
            metric: Metric::PduCount,
            tags: vec![(Dim::Sender, "10.0.0.9:7000".into())],
            at: old,
            agg: Agg {
                n: 50,
                sum: 50.0,
                min: 1.0,
                max: 1.0,
            },
        }],
        t0 + 30,
    );
    let r = http_get(
        addr,
        &format!(
            "/api/query?name=pdu.count&by=sender&agg=sum&window=4000&from={old}&to={}",
            t0 + 60
        ),
    );
    let b = body(&r);
    // The old sender from disk, and only memory's last 30 s for the live one.
    assert!(
        b.contains("{\"tags\":{\"sender\":\"10.0.0.9:7000\"},\"value\":50}"),
        "{b}"
    );
    assert!(
        b.contains("{\"tags\":{\"sender\":\"10.0.0.1:5000\"},\"value\":30}"),
        "{b}"
    );
    assert_eq!(hub.sweep_metrics((old + 1) as f64), 1);
    std::fs::remove_file(&path).ok();

    // Behind --users the endpoint is gated like the rest of /api.
    hub.set_auth(std::sync::Arc::new(nn_server::auth::Auth::empty()));
    assert!(http_get(addr, "/api/query?name=pdu.count").starts_with("HTTP/1.1 401"));
}

#[test]
fn pdu_capture_stays_inside_its_budget() {
    use nn_server::pdustore::{read_pdus, PduStore};
    use std::sync::atomic::Ordering;
    let path = std::env::temp_dir().join(format!("nn-capture-test-{}.db", std::process::id()));
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
    let budget = 256 * 1024;
    let store = PduStore::open(&path, budget).unwrap();
    let stats = std::sync::Arc::clone(&store.stats);
    let raw = nn_decode::encode_pdu(&entity_state(7));
    // ~20,000 Entity State PDUs (~3 MB) in batches, well over the budget.
    for b in 0..100 {
        let rows = (0..200)
            .map(|i| nn_rules::Captured {
                at: 1_800_000_000.0 + (b * 200 + i) as f64 * 0.01,
                sender: "10.0.0.1:5000".parse().unwrap(),
                exercise: 1,
                pdu_type: nn_decode::pdu_type::ENTITY_STATE,
                entity: Some(nn_decode::EntityId::new(1, 1, 7)),
                tier: "1.2 all".into(),
                raw: raw.clone(),
            })
            .collect();
        store.submit(rows);
        std::thread::sleep(Duration::from_millis(2));
    }
    let hub = Hub::new();
    hub.set_capture(path.clone(), std::sync::Arc::clone(&stats));
    store.close();

    let (used, rows, evicted, written) = (
        stats.used.load(Ordering::Relaxed),
        stats.rows.load(Ordering::Relaxed),
        stats.evicted.load(Ordering::Relaxed),
        stats.written.load(Ordering::Relaxed),
    );
    assert_eq!(written + stats.dropped.load(Ordering::Relaxed), 20_000);
    assert!(used <= budget, "used {used} > budget {budget}");
    assert!(
        evicted > 0 && rows + evicted == written,
        "rows {rows} evicted {evicted} written {written}"
    );

    // What's left is the newest stretch, and it decodes.
    let all = read_pdus(&path, Some(1), Some("1:1:7"), 0.0, f64::MAX, 100_000).unwrap();
    assert_eq!(all.len() as u64, rows);
    assert!(all[0].at > 1_800_000_000.0, "oldest rows were evicted first");
    assert_eq!(all.last().unwrap().at, 1_800_000_000.0 + 19_999.0 * 0.01);
    assert!(all.iter().all(|p| p.pdu.is_ok() && p.tier == "1.2 all"));
    assert!(read_pdus(&path, Some(1), Some("9:9:9"), 0.0, f64::MAX, 10)
        .unwrap()
        .is_empty());

    // Over HTTP: stats and a drill-down for the entity.
    let (addr, h2) = Hub::listen("127.0.0.1:0").unwrap();
    assert!(http_get(addr, "/api/capture").contains("\"enabled\":false"));
    assert!(http_get(addr, "/api/pdus?id=1:1:7").starts_with("HTTP/1.1 400"));
    h2.set_capture(path.clone(), stats);
    let r = http_get(addr, "/api/capture");
    assert!(
        r.contains(&format!("\"budget\":{budget}")) && r.contains("\"evicted\":"),
        "{r}"
    );
    let r = http_get(addr, "/api/pdus?ex=1&id=1:1:7&from=1800000190&to=1800000200&limit=5");
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("\"count\":5"), "{r}");
    assert!(
        r.contains("\"type\":\"EntityState\"") && r.contains("\"entity\":\"1:1:7\"") && r.contains("\"lat\":"),
        "{r}"
    );
    drop(hub);
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

#[test]
fn events_summary_groups_violations_by_sender_and_migrates_old_stores() {
    let path = std::env::temp_dir().join(format!("nn-summary-test-{}.db", std::process::id()));
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
    // A store from before slice 2: no sender/pack/state columns, one alert.
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE events(id INTEGER PRIMARY KEY, run INTEGER, seq INTEGER, at REAL, kind TEXT,
                entity TEXT, rule TEXT, severity TEXT, exercise INTEGER, message TEXT, json TEXT);
             INSERT INTO events(run,seq,at,kind,entity,rule,severity,exercise,message,json) VALUES
               (1, 1, 100.0, 'alert', '1:1:9', 'entity-timeout', 'warning', 1, 'old',
                '{\"seq\":1,\"kind\":\"alert\",\"at\":100,\"state\":\"firing\",\"rule\":\"entity-timeout\"}');",
        )
        .unwrap();
    }
    let (addr, hub) = Hub::listen("127.0.0.1:0").unwrap();
    hub.open_db(&path, "test").unwrap();

    let ev = |rule: &str, entity: &str, sender: &str, sev: Severity, at: f64, state: AlertState| AlertEvent {
        at,
        state,
        alert: Alert {
            rule: Rule::PositionJump,
            pack: "dis-base".into(),
            rule_id: rule.into(),
            key: EntityKey {
                exercise: 1,
                id: entity.parse().unwrap(),
            },
            severity: sev,
            since: at,
            message: "m".into(),
            sender: Some(sender.parse().unwrap()),
            kind: "jump",
            facts: Vec::new(),
        },
        reason: String::new(),
        pdu: None,
    };
    let a = "10.0.1.10:40000";
    let b = "10.0.2.10:40000";
    for (rule, ent, snd, sev, at) in [
        ("position-jump", "1:1:3", a, Severity::Warning, 200.0),
        ("position-jump", "1:1:4", a, Severity::Warning, 210.0),
        ("id-conflict", "1:1:2", a, Severity::Critical, 220.0),
        ("entity-state.force_id", "2:1:1", b, Severity::Warning, 230.0),
    ] {
        hub.log("alert", &alert_json(&ev(rule, ent, snd, sev, at, AlertState::Firing)));
    }
    // A resolution is not a violation; a decode error is.
    hub.log(
        "alert",
        &alert_json(&ev(
            "position-jump",
            "1:1:3",
            a,
            Severity::Warning,
            205.0,
            AlertState::Resolved,
        )),
    );
    hub.log("error", &web::error_json(240.0, 1, b));
    // Live state: the conflict is still open; a third sender is clean.
    let mut senders = std::collections::BTreeMap::new();
    for (s, claim) in [(a, "1:1"), (b, "2:1"), ("10.0.3.10:40000", "3:1")] {
        senders.insert(
            s.to_string(),
            nn_server::summary::SenderInfo {
                claims: [claim.to_string()].into(),
                entities: 20,
                last_seen: 250.0,
            },
        );
    }
    let open = nn_server::store::Violation {
        at: 220.0,
        kind: "alert".into(),
        rule: Some("id-conflict".into()),
        entity: Some("1:1:2".into()),
        sender: Some(a.into()),
        severity: Some("critical".into()),
        exercise: Some(1),
        ..Default::default()
    };
    hub.set_conformance(vec![open], senders);

    let body = |q: &str| {
        let r = http_get(addr, &format!("/api/events/summary?{q}"));
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        r.split("\r\n\r\n").nth(1).unwrap().to_string()
    };
    let j = body("by=sender&since=0");
    assert!(
        j.contains(&format!("{{\"tags\":{{\"sender\":\"{a}\"}},\"total\":3,\"critical\":1,\"warning\":2,\"errors\":0,\"open\":1,\"first\":200.000,\"last\":220.000")),
        "{j}"
    );
    assert!(
        j.contains(&format!("{{\"tags\":{{\"sender\":\"{b}\"}},\"total\":2,")),
        "{j}"
    );
    // The pre-migration alert counts, under an unknown sender.
    assert!(j.contains("{\"tags\":{\"sender\":\"unknown\"},\"total\":1,"), "{j}");
    // Every live sender is listed with its claims, compliant ones included.
    assert!(
        j.contains("\"10.0.3.10:40000\":{\"claims\":[\"3:1\"],\"entities\":20"),
        "{j}"
    );
    assert!(j.contains("\"total\":6,"), "{j}");

    let j = body("by=sender,rule&since=150");
    assert!(
        j.contains(&format!(
            "{{\"tags\":{{\"sender\":\"{b}\",\"rule\":\"decode-error\"}},\"total\":1,"
        )),
        "{j}"
    );
    assert!(
        j.contains(&format!(
            "{{\"tags\":{{\"sender\":\"{a}\",\"rule\":\"position-jump\"}},\"total\":2,"
        )),
        "{j}"
    );
    assert!(!j.contains("unknown"), "since filters out the old alert: {j}");

    let j = body("by=rule&since=0&entity=1:1:2");
    assert!(
        j.contains(
            "{\"tags\":{\"rule\":\"id-conflict\"},\"total\":1,\"critical\":1,\"warning\":0,\"errors\":0,\"open\":1"
        ),
        "{j}"
    );
    assert!(
        !j.contains("\"senders\""),
        "senders only ride along when grouping by sender: {j}"
    );

    let r = http_get(addr, "/api/events/summary?by=colour");
    assert!(
        r.starts_with("HTTP/1.1 400") && r.contains("unknown dimension 'colour'"),
        "{r}"
    );
    // /api/log filters on the new sender column too.
    let r = http_get(addr, &format!("/api/log?sender={b}"));
    assert!(
        r.contains("force_id") && !r.contains("\"rule\":\"position-jump\""),
        "{r}"
    );

    drop(hub);
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

#[test]
fn explain_catalog_is_valid_json_with_every_entry() {
    let j = web::explain_json();
    let v: Vec<&str> = j.matches("{\"rule\":").collect();
    assert_eq!(v.len(), nn_rules::explain::catalog().len());
    assert!(
        j.contains(r#""rule":"emission","kind":"dropout","title":"Emitter went silent while still on""#),
        "{j}"
    );
    // Quotes in the text (a "fired" mine) arrive escaped.
    assert!(j.contains(r#"A mine or demolition was \"fired\""#), "{j}");
}

#[test]
fn dashboards_saved_listed_and_deleted() {
    let (addr, _hub) = Hub::listen("127.0.0.1:0").unwrap();
    let def = r#"{"version":1,"widgets":[{"title":"PDU rate","kind":"timeseries","q":{"name":"pdu.count","agg":"rate","by":["pdu_type"],"where":{},"span":3600,"window":0}}]}"#;
    let put = |name: &str, body: &str| {
        http(
            addr,
            &format!(
                "PUT /api/dashboards?name={name} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
    };
    let del = |name: &str| {
        http(
            addr,
            &format!("DELETE /api/dashboards?name={name} HTTP/1.1\r\nhost: x\r\n\r\n"),
        )
    };
    // Empty until one is saved.
    assert!(http_get(addr, "/api/dashboards").contains("\"dashboards\":[]"));
    // Bad names and bodies are rejected.
    assert!(put("", def).starts_with("HTTP/1.1 400"));
    assert!(put("bad%20name!", def).starts_with("HTTP/1.1 400"));
    assert!(put("ok", "not json").starts_with("HTTP/1.1 400"));
    assert!(put("ok", "{\"widgets\":").starts_with("HTTP/1.1 400"));
    assert!(put("ok", "{\"no_widgets\":1}").starts_with("HTTP/1.1 400"));
    assert!(put("ok", "{\"widgets\":[],\"x\":\"bad\x01\"}").starts_with("HTTP/1.1 400"));
    // Save, list, overwrite, delete — in memory when there is no --db.
    assert!(put("ops-view", def).starts_with("HTTP/1.1 200"));
    let list = http_get(addr, "/api/dashboards");
    assert!(
        list.contains("\"name\":\"ops-view\"") && list.contains("\"kind\":\"timeseries\""),
        "{list}"
    );
    assert!(put("ops-view", "{\"widgets\":[]}").starts_with("HTTP/1.1 200"));
    assert!(http_get(addr, "/api/dashboards").contains("\"widgets\":[]"));
    assert!(del("ops-view").starts_with("HTTP/1.1 200"));
    assert!(del("ops-view").starts_with("HTTP/1.1 404"));
    assert!(http_get(addr, "/api/dashboards").contains("\"dashboards\":[]"));
}

#[test]
fn sender_names_and_the_fix_report() {
    let hub = Hub::new();
    // Without --config, names hold until restart, and say so.
    let m = hub
        .sender_command(r#"{"cmd":"sender_set","simulation":"9:9","name":"JSAF \"B\""}"#)
        .unwrap();
    assert!(
        m.contains("named 9:9 'JSAF \"B\"'") && m.contains("until restart"),
        "{m}"
    );
    hub.sender_command(r#"{"cmd":"sender_set","address":"10.0.9.10","name":"VBS4 host"}"#)
        .unwrap();
    let j = hub.senders_json();
    assert!(
        j.contains(r#"{"simulation":"9:9","name":"JSAF \"B\""}"#) && j.contains(r#""config_file":null"#),
        "{j}"
    );
    assert!(hub
        .sender_command(r#"{"cmd":"sender_set","address":"vbs4","name":"x"}"#)
        .is_err());

    // Two of 9:9's entities time out; 8:1 has its own problem.
    let ev = |entity: &str, at: f64| AlertEvent {
        at,
        state: AlertState::Firing,
        alert: Alert {
            rule: Rule::EntityTimeout,
            pack: "dis-base".into(),
            rule_id: "entity-timeout".into(),
            key: EntityKey {
                exercise: 1,
                id: entity.parse().unwrap(),
            },
            severity: Severity::Warning,
            since: at,
            message: format!("{entity} sent no Entity State for 12.1 s"),
            sender: Some("10.0.9.10:3000".parse().unwrap()),
            kind: "silent",
            facts: vec![("silent for", "12.1 s".into())],
        },
        reason: String::new(),
        pdu: None,
    };
    for (e, at) in [("9:9:1", 100.0), ("9:9:2", 101.0), ("8:1:1", 102.0)] {
        hub.log("alert", &alert_json(&ev(e, at)));
    }
    let mut claims = std::collections::BTreeMap::new();
    claims.insert(
        "10.0.9.10:3000".to_string(),
        nn_server::summary::SenderInfo {
            claims: ["9:9".to_string()].into(),
            entities: 2,
            last_seen: 101.0,
        },
    );
    hub.set_conformance(Vec::new(), claims);

    let (md, ct) = hub.report("sim=9:9&since=0").unwrap();
    assert_eq!(ct, "text/markdown; charset=utf-8");
    assert!(
        md.starts_with("# NetworkNinja fix report: simulation 9:9 (JSAF \"B\")"),
        "{md}"
    );
    assert!(md.contains("10.0.9.10:3000 (VBS4 host)"), "{md}");
    assert!(
        md.contains("## 1. Entity stopped reporting") && md.contains("**Entities (2):** 9:9:1, 9:9:2"),
        "{md}"
    );
    assert!(
        md.contains("| silent for | 12.1 s |") && md.contains("**How to fix:**"),
        "{md}"
    );
    assert!(!md.contains("8:1:1"), "{md}");
    let (csv, ct) = hub.report("sim=9:9&since=0&format=csv").unwrap();
    assert_eq!((ct, csv.lines().count()), ("text/csv; charset=utf-8", 2), "{csv}");
    assert!(hub.report("since=0").unwrap_err().contains("sim=SITE:APP"));
    assert!(hub.report("sim=9:9&format=pdf").is_err());
}

#[test]
fn an_alerts_pdu_is_kept_for_api_evidence() {
    let hub = Hub::new();
    let mut e = AlertEvent {
        at: 50.0,
        state: AlertState::Firing,
        alert: Alert {
            rule: Rule::PduFamily,
            pack: "dis-base".into(),
            rule_id: "pdu-family".into(),
            key: EntityKey {
                exercise: 1,
                id: "1:1:0".parse().unwrap(),
            },
            severity: Severity::Warning,
            since: 50.0,
            message: "IFF from 1:1:0: protocol family 5".into(),
            sender: Some("10.0.1.10:3000".parse().unwrap()),
            kind: "family",
            facts: Vec::new(),
        },
        reason: String::new(),
        pdu: None,
    };
    // Without a PDU (a timeout, say) there is nothing to show.
    let plain = hub.log_alert(&e);
    assert!(!plain.contains("\"pdu\":"), "{plain}");
    assert!(hub.evidence_json(1).is_none());
    let bytes: Vec<u8> = vec![7, 1, 28, 5, 0, 0, 0, 0, 0, 16, 0, 0, 0, 1, 0, 1];
    e.pdu = Some(bytes.into());
    let entry = hub.log_alert(&e);
    assert!(
        entry.starts_with("{\"seq\":2,") && entry.contains("\"pdu\":16"),
        "{entry}"
    );
    let j = hub.evidence_json(2).expect("kept");
    assert!(
        j.contains("\"source\":\"10.0.1.10:3000\"") && j.contains("[\"PDU Type\",\"28 (IFF)\"]"),
        "{j}"
    );
    assert!(j.contains("\"hex\":\"0000  07 01 1c 05"), "{j}");
}
