//! The embedded dashboard server: HTTP/1.1 for the page and `/api/state`,
//! RFC 6455 WebSocket for the live feed. Hand-rolled like the rest of the
//! workspace over plain TCP or, with `serve --cert/--key`, rustls on the
//! same port (ADR 0006). Binds to localhost by default.

use nn_rules::{AlertEvent, AlertState, Monitor, MuteScope, Severity};
use nn_state::{geo, secs, EntityKey};
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use crate::auth::Auth;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

const INDEX_HTML: &str = include_str!("../../../web/index.html");
const MAPLIBRE_JS: &str = include_str!("../../../web/vendor/maplibre-gl.js");
const MAPLIBRE_CSS: &str = include_str!("../../../web/vendor/maplibre-gl.css");
const WORLD_GEOJSON: &str = include_str!("../../../web/world.geojson");
const NE_COASTLINE: &str = include_str!("../../../web/ne-coastline.json");
const NE_RIVERS: &str = include_str!("../../../web/ne-rivers_lake_centerlines.json");
const NE_LAKES: &str = include_str!("../../../web/ne-lakes.json");
/// Queued frames per client before it is dropped as too slow.
const CLIENT_QUEUE: usize = 128;
/// Log entries kept in memory for `/api/log` and new clients.
const LOG_CAP: usize = 2_000;
const MAX_HTTP_HEAD: usize = 16 * 1024;
const MAX_HTTP_BODY: usize = 64 * 1024;
const MAX_WS_PAYLOAD: u64 = 1 << 20;

/// The dashboard feed hub: WebSocket clients, the latest state push and the
/// event log (alerts, decode errors, server events) behind `/api/log`.
pub struct Hub {
    clients: Mutex<BTreeMap<u64, SyncSender<Vec<u8>>>>,
    next_id: AtomicU64,
    /// Last state JSON, replayed to each new client and served at /api/state.
    snapshot: Mutex<Option<String>>,
    /// Per-entity detail JSON (keyed by `EntityKey` display), rebuilt every
    /// state tick and served at /api/entity — too chatty for the delta feed.
    details: Mutex<BTreeMap<String, String>>,
    /// Event log: JSON entries each carrying `"seq"` and `"kind"`.
    log_buf: Mutex<VecDeque<String>>,
    seq: AtomicU64,
    /// `--log` file: every entry appended as one JSON line.
    log_file: Mutex<Option<std::fs::File>>,
    /// `--db` SQLite store and the current run id (ADR 0005).
    store: Mutex<Option<(crate::store::EventStore, i64)>>,
    /// `--runs` directory scanned for `.nnrec` recordings at /api/runs.
    runs_dir: Mutex<Option<std::path::PathBuf>>,
    /// Client commands (ack/mute) forwarded to the serve loop.
    cmd_tx: Mutex<Option<SyncSender<(String, String)>>>,
    auth: Mutex<Option<Arc<Auth>>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    pub fn new() -> Self {
        Hub {
            clients: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            snapshot: Mutex::new(None),
            details: Mutex::new(BTreeMap::new()),
            log_buf: Mutex::new(VecDeque::new()),
            seq: AtomicU64::new(0),
            log_file: Mutex::new(None),
            store: Mutex::new(None),
            runs_dir: Mutex::new(None),
            cmd_tx: Mutex::new(None),
            auth: Mutex::new(None),
        }
    }

    /// Bind `addr`, spawn the accept thread, return the bound address and hub.
    pub fn listen(addr: impl ToSocketAddrs) -> io::Result<(SocketAddr, Arc<Hub>)> {
        Self::listen_with(addr, None)
    }

    /// [`Hub::listen`] serving HTTPS + WSS: every accepted connection is
    /// wrapped in a rustls session (handshake runs on the connection thread).
    pub fn listen_tls(addr: impl ToSocketAddrs, tls: Arc<ServerConfig>) -> io::Result<(SocketAddr, Arc<Hub>)> {
        Self::listen_with(addr, Some(tls))
    }

    fn listen_with(addr: impl ToSocketAddrs, tls: Option<Arc<ServerConfig>>) -> io::Result<(SocketAddr, Arc<Hub>)> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        let hub = Arc::new(Hub::new());
        let h = Arc::clone(&hub);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let h = Arc::clone(&h);
                let tls = tls.clone();
                thread::spawn(move || match tls {
                    None => handle_conn(h, stream),
                    Some(cfg) => {
                        if let Ok(c) = ServerConnection::new(cfg) {
                            handle_conn(h, TlsStream::new(c, stream));
                        }
                    }
                });
            }
        });
        Ok((local, hub))
    }

    /// Queue a text message for every client; drop clients that fall behind.
    pub fn broadcast(&self, text: &str) {
        let frame = text_frame(text);
        let mut clients = self.clients.lock().unwrap();
        clients.retain(|_, tx| tx.try_send(frame.clone()).is_ok());
    }

    /// Store the state JSON served to new clients and `/api/state`.
    pub fn set_snapshot(&self, json: String) {
        *self.snapshot.lock().unwrap() = Some(json);
    }

    pub fn set_details(&self, details: BTreeMap<String, String>) {
        *self.details.lock().unwrap() = details;
    }

    /// Append a log entry — `fields` is a JSON object body — then broadcast
    /// it to every client and (if set) the log file. Returns the entry.
    pub fn log(&self, kind: &str, fields: &str) -> String {
        debug_assert!(fields.starts_with('{'));
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = format!("{{\"seq\":{seq},\"kind\":\"{kind}\",{}", &fields[1..]);
        {
            let mut q = self.log_buf.lock().unwrap();
            if q.len() >= LOG_CAP {
                q.pop_front();
            }
            q.push_back(entry.clone());
        }
        if let Some((store, run)) = self.store.lock().unwrap().as_ref() {
            store.insert(
                *run,
                seq,
                jnum(&entry, "at").unwrap_or(0.0),
                kind,
                jstr(&entry, "entity"),
                jstr(&entry, "rule"),
                jstr(&entry, "severity"),
                jnum(&entry, "exercise").map(|e| e as u8),
                jstr(&entry, "message"),
                &entry,
            );
        }
        if let Some(f) = self.log_file.lock().unwrap().as_mut() {
            use std::io::Write;
            let _ = writeln!(f, "{entry}");
        }
        self.broadcast(&entry);
        entry
    }

    /// `{"entries":[...],"latest":N}` — entries with seq > `after`, capped.
    pub fn log_tail(&self, after: u64, limit: usize) -> String {
        let q = self.log_buf.lock().unwrap();
        let entries: Vec<&String> = q.iter().filter(|e| seq_of(e) > after).take(limit).collect();
        format!(
            "{{\"entries\":[{}],\"latest\":{}}}",
            entries.iter().map(|e| e.as_str()).collect::<Vec<_>>().join(","),
            self.seq.load(Ordering::Relaxed)
        )
    }

    /// Load a `--log` file: previous runs' entries first (their seqs kept),
    /// then append everything new. Returns entries loaded.
    pub fn open_log(&self, path: &std::path::Path) -> io::Result<usize> {
        use std::io::{BufRead, BufReader};
        let mut loaded = 0;
        if let Ok(f) = std::fs::File::open(path) {
            let mut q = self.log_buf.lock().unwrap();
            let mut max_seq = 0;
            for line in BufReader::new(f).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                max_seq = max_seq.max(seq_of(&line));
                if q.len() >= LOG_CAP {
                    q.pop_front();
                }
                q.push_back(line);
                loaded += 1;
            }
            self.seq.fetch_max(max_seq, Ordering::Relaxed);
        }
        let f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        *self.log_file.lock().unwrap() = Some(f);
        Ok(loaded)
    }

    /// Open the SQLite event store and register a new run in it.
    /// Sequence numbering continues from the highest stored seq.
    pub fn open_db(&self, path: &std::path::Path, packs: &str) -> Result<(), String> {
        let store = crate::store::EventStore::open(path)?;
        let run = store.start_run(crate::web::now_secs(), packs)?;
        self.seq.fetch_max(store.max_seq(), Ordering::Relaxed);
        *self.store.lock().unwrap() = Some((store, run));
        Ok(())
    }

    /// Highest seq assigned so far.
    pub fn latest_seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// Query the SQLite store for /api/log. `None` when no store is open.
    fn db_query(&self, q: &crate::store::EventQuery) -> Option<Vec<String>> {
        self.store.lock().unwrap().as_ref().map(|(store, _)| store.query(q))
    }

    pub fn client_count(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    fn add_client(&self) -> (u64, Receiver<Vec<u8>>) {
        let (tx, rx) = sync_channel(CLIENT_QUEUE);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.clients.lock().unwrap().insert(id, tx);
        (id, rx)
    }

    fn remove_client(&self, id: u64) {
        self.clients.lock().unwrap().remove(&id);
    }

    /// The serve loop's command inbox: every client text frame lands here.
    pub fn set_command_sink(&self, tx: SyncSender<(String, String)>) {
        *self.cmd_tx.lock().unwrap() = Some(tx);
    }

    pub fn set_auth(&self, a: Arc<Auth>) {
        *self.auth.lock().unwrap() = Some(a);
    }

    fn auth(&self) -> Option<Arc<Auth>> {
        self.auth.lock().unwrap().clone()
    }

    fn send_command(&self, user: String, text: String) {
        if let Some(tx) = self.cmd_tx.lock().unwrap().as_ref() {
            let _ = tx.try_send((user, text));
        }
    }

    /// The directory `/api/runs` lists `.nnrec` recordings from.
    pub fn set_runs_dir(&self, dir: std::path::PathBuf) {
        *self.runs_dir.lock().unwrap() = Some(dir);
    }

    /// `{"runs":[{"name":…,"size":…,"mtime":…}]}` — recordings in the runs dir.
    fn runs_list(&self) -> String {
        let dir = self.runs_dir.lock().unwrap();
        let Some(dir) = dir.as_ref() else {
            return "{\"runs\":[]}".into();
        };
        let mut runs: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("nnrec") {
                    continue;
                }
                let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                let (size, mtime) = e
                    .metadata()
                    .map(|md| {
                        (
                            md.len(),
                            md.modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs_f64())
                                .unwrap_or(0.0),
                        )
                    })
                    .unwrap_or((0, 0.0));
                let dur = nn_recorder::Reader::open(&p).map(|r| r.duration).unwrap_or(0.0);
                runs.push(format!(
                    "{{\"name\":\"{}\",\"size\":{},\"mtime\":{},\"dur\":{}}}",
                    esc(&name),
                    size,
                    fnum(mtime),
                    fnum(dur)
                ));
            }
        }
        runs.sort_by(|a, b| b.cmp(a));
        format!("{{\"runs\":[{}]}}", runs.join(","))
    }
}

// --- HTTP -----------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(r: &mut impl Read) -> io::Result<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = r.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HTTP_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "headers too large"));
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]);
    let mut lines = head.lines();
    let mut parts = lines.next().unwrap_or_default().split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or_default().to_string(),
        parts.next().unwrap_or_default().to_string(),
    );
    if method.is_empty() || path.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request line"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut req = Request {
        method,
        path,
        headers,
        body: buf.split_off(head_end + 4),
    };
    let want: usize = req.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if want > MAX_HTTP_BODY {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
    }
    while req.body.len() < want {
        let n = r.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"));
        }
        req.body.extend_from_slice(&chunk[..n]);
    }
    req.body.truncate(want);
    Ok(req)
}

/// `name=value` from a query string or form body, percent-decoded.
fn param(pairs: &str, name: &str) -> Option<String> {
    pairs.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == name).then(|| pct_decode(v))
    })
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(x) => {
                        out.push(x);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The `"seq"` number of a log entry, which always leads the object.
fn seq_of(entry: &str) -> u64 {
    entry
        .strip_prefix("{\"seq\":")
        .and_then(|r| r.split(',').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

// --- Connections ----------------------------------------------------------

type TlsStream = StreamOwned<ServerConnection, TcpStream>;

/// A dashboard connection: plain TCP, or TLS over TCP.
trait Conn: Read + Write + Send + 'static {
    fn tcp(&self) -> &TcpStream;
    /// Independent reader and writer halves for the WebSocket threads.
    fn split(self) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)>;
    /// End the session cleanly (TLS close_notify) before the socket drops.
    fn close(&mut self) {}
}

impl Conn for TcpStream {
    fn tcp(&self) -> &TcpStream {
        self
    }
    fn split(self) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let w = self.try_clone()?;
        Ok((Box::new(self), Box::new(w)))
    }
}

impl Conn for TlsStream {
    fn tcp(&self) -> &TcpStream {
        &self.sock
    }
    fn split(self) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let wait = self.sock.try_clone()?;
        let s = Arc::new(Mutex::new(self));
        Ok((
            Box::new(TlsReader {
                s: Arc::clone(&s),
                wait,
            }),
            Box::new(TlsWriter(s)),
        ))
    }
    fn close(&mut self) {
        self.conn.send_close_notify();
        let _ = self.conn.complete_io(&mut self.sock);
    }
}

/// Read half of a shared TLS session. A rustls session can't be cloned like
/// a socket, so both halves share it behind a lock; the reader only holds
/// the lock for non-blocking reads and waits for data on a socket clone,
/// leaving the writer free in between. Idle waits keep the socket's read
/// timeout, as on plain TCP.
struct TlsReader {
    s: Arc<Mutex<TlsStream>>,
    wait: TcpStream,
}

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let r = {
                let mut s = self.s.lock().unwrap();
                s.sock.set_nonblocking(true)?;
                let r = s.read(buf);
                s.sock.set_nonblocking(false)?;
                r
            };
            match r {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.wait.peek(&mut [0u8; 1])?;
                }
                r => return r,
            }
        }
    }
}

struct TlsWriter(Arc<Mutex<TlsStream>>);

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

fn respond(mut s: impl Conn, status: &str, content_type: &str, body: &str) -> io::Result<()> {
    write!(
        s,
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\ncontent-type: {content_type}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )?;
    s.flush()?;
    s.close();
    Ok(())
}

fn handle_conn(hub: Arc<Hub>, mut s: impl Conn) {
    let _ = s.tcp().set_read_timeout(Some(Duration::from_secs(30)));
    let req = match read_request(&mut s) {
        Ok(r) => r,
        Err(_) => return,
    };
    let path = req.path.split(['?', '#']).next().unwrap_or("/");
    let query = req.path.split('?').nth(1).unwrap_or_default();
    let qparam = |name: &str| param(query, name);
    // Bearer-token gate: /api/* and /ws require a session when --users is set.
    // The token rides `Authorization: Bearer` or, for the WebSocket, `?token=`.
    let auth = hub.auth();
    let token = req
        .header("authorization")
        .and_then(|v| v.strip_prefix("Bearer ").map(str::to_string))
        .or_else(|| qparam("token"));
    let user = auth.as_ref().and_then(|a| token.as_deref().and_then(|t| a.check(t)));
    let open = path == "/api/login" || path == "/api/logout";
    if auth.is_some() && user.is_none() && ((path.starts_with("/api/") && !open) || path == "/ws") {
        let _ = respond(s, "401 Unauthorized", "application/json", "{\"need\":\"auth\"}");
        return;
    }
    match (req.method.as_str(), path) {
        ("POST", "/api/login") => {
            let form = String::from_utf8_lossy(&req.body);
            let ok = match (auth.as_ref(), param(&form, "user"), param(&form, "pass")) {
                (Some(a), Some(u), Some(p)) if a.verify(&u, &p) => Some((a.issue(&u), u)),
                _ => None,
            };
            match ok {
                Some((tok, u)) => {
                    hub.log("info", &info_json(now_secs(), &format!("{u} logged in")));
                    let _ = respond(
                        s,
                        "200 OK",
                        "application/json",
                        &format!("{{\"token\":\"{tok}\",\"user\":\"{u}\"}}"),
                    );
                }
                None => {
                    let _ = respond(
                        s,
                        "401 Unauthorized",
                        "application/json",
                        "{\"error\":\"bad credentials\"}",
                    );
                }
            }
        }
        ("POST", "/api/logout") => {
            if let (Some(a), Some(t)) = (auth.as_ref(), token.as_deref()) {
                if let Some(u) = a.revoke(t) {
                    hub.log("info", &info_json(now_secs(), &format!("{u} logged out")));
                }
            }
            let _ = respond(s, "200 OK", "application/json", "{\"ok\":true}");
        }
        ("GET", "/" | "/index.html") => {
            let _ = respond(s, "200 OK", "text/html; charset=utf-8", INDEX_HTML);
        }
        ("GET", "/vendor/maplibre-gl.js") => {
            let _ = respond(s, "200 OK", "text/javascript; charset=utf-8", MAPLIBRE_JS);
        }
        ("GET", "/vendor/maplibre-gl.css") => {
            let _ = respond(s, "200 OK", "text/css; charset=utf-8", MAPLIBRE_CSS);
        }
        ("GET", "/world.geojson") => {
            let _ = respond(s, "200 OK", "application/geo+json", WORLD_GEOJSON);
        }
        ("GET", "/ne/coastline") => {
            let _ = respond(s, "200 OK", "application/geo+json", NE_COASTLINE);
        }
        ("GET", "/ne/rivers") => {
            let _ = respond(s, "200 OK", "application/geo+json", NE_RIVERS);
        }
        ("GET", "/ne/lakes") => {
            let _ = respond(s, "200 OK", "application/geo+json", NE_LAKES);
        }
        ("GET", "/api/state") => {
            let body = hub.snapshot.lock().unwrap().clone().unwrap_or_else(|| "{}".into());
            let _ = respond(s, "200 OK", "application/json", &body);
        }
        ("GET", "/api/entity") => {
            let ex = qparam("ex").and_then(|v| v.parse::<u8>().ok()).unwrap_or(0);
            let key = qparam("id").map(|id| format!("ex{ex} {id}"));
            let body = key.and_then(|k| hub.details.lock().unwrap().get(&k).cloned());
            match body {
                Some(b) => {
                    let _ = respond(s, "200 OK", "application/json", &b);
                }
                None => {
                    let _ = respond(s, "404 Not Found", "application/json", "{\"error\":\"no such entity\"}");
                }
            }
        }
        ("GET", "/api/runs") => {
            let body = hub.runs_list();
            let _ = respond(s, "200 OK", "application/json", &body);
        }
        ("GET", "/api/log") => {
            let arg = |name: &str| -> Option<u64> {
                query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix(name).and_then(|v| v.parse().ok()))
            };
            let arg_s = |name: &str| qparam(name.trim_end_matches('='));
            let body = match hub.db_query(&crate::store::EventQuery {
                after: arg("after=").unwrap_or(0),
                kind: arg_s("kind="),
                rule: arg_s("rule="),
                entity: arg_s("entity="),
                text: arg_s("q="),
                limit: arg("limit=").unwrap_or(500) as usize,
            }) {
                Some(entries) => format!(
                    "{{\"entries\":[{}],\"latest\":{}}}",
                    entries.join(","),
                    hub.latest_seq()
                ),
                None => hub.log_tail(arg("after=").unwrap_or(0), arg("limit=").unwrap_or(500) as usize),
            };
            let _ = respond(s, "200 OK", "application/json", &body);
        }
        ("GET", "/ws") if is_ws_upgrade(&req) => ws_serve(hub, s, &req, user.unwrap_or_else(|| "operator".into())),
        ("GET", _) => {
            let _ = respond(s, "404 Not Found", "text/plain", "not found\n");
        }
        _ => {
            let _ = respond(s, "405 Method Not Allowed", "text/plain", "method not allowed\n");
        }
    }
}

fn is_ws_upgrade(req: &Request) -> bool {
    req.header("upgrade")
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
        && req.header("sec-websocket-key").is_some()
}

// --- WebSocket ------------------------------------------------------------

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn ws_serve(hub: Arc<Hub>, mut s: impl Conn, req: &Request, user: String) {
    let key = req.header("sec-websocket-key").unwrap_or_default();
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {}\r\n\r\n",
        base64(&sha1(format!("{key}{WS_GUID}").as_bytes()))
    );
    if s.write_all(response.as_bytes()).is_err() {
        return;
    }
    let (id, rx) = hub.add_client();
    // New clients see the current state immediately.
    if let Some(snap) = hub.snapshot.lock().unwrap().clone() {
        hub.broadcast_to(id, text_frame(&snap));
    }
    // Writer thread: drains the frame queue onto the socket.
    let (sock, (mut s, mut writer)) = match s.tcp().try_clone().and_then(|t| Ok((t, s.split()?))) {
        Ok(v) => v,
        Err(_) => {
            hub.remove_client(id);
            return;
        }
    };
    let write_done = thread::spawn(move || {
        while let Ok(frame) = rx.recv() {
            if writer.write_all(&frame).is_err() {
                break;
            }
        }
    });

    // Reader: pings, pongs, close, and client commands (ack/mute) forwarded
    // to the serve loop.
    loop {
        match read_frame(&mut s) {
            Ok(Some(f)) if f.opcode == 0x9 => hub.broadcast_to(id, frame(0xA, &f.payload)),
            Ok(Some(f)) if f.opcode == 0x8 => break,
            Ok(Some(f)) if f.opcode == 0x1 => {
                hub.send_command(user.clone(), String::from_utf8_lossy(&f.payload).to_string())
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    let _ = sock.shutdown(std::net::Shutdown::Both);
    hub.remove_client(id);
    let _ = write_done.join();
}

pub struct WsFrame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// One frame; `Ok(None)` on clean or mid-read disconnect.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<WsFrame>> {
    let mut h = [0u8; 2];
    if r.read_exact(&mut h).is_err() {
        return Ok(None);
    }
    let opcode = h[0] & 0x0f;
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b)?;
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b)?;
        len = u64::from_be_bytes(b);
    }
    if len > MAX_WS_PAYLOAD {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; len as usize];
    if r.read_exact(&mut payload).is_err() {
        return Ok(None);
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(Some(WsFrame { opcode, payload }))
}

fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x80 | opcode];
    let n = payload.len();
    if n < 126 {
        v.push(n as u8);
    } else if n <= 0xffff {
        v.push(126);
        v.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        v.push(127);
        v.extend_from_slice(&(n as u64).to_be_bytes());
    }
    v.extend_from_slice(payload);
    v
}

fn text_frame(s: &str) -> Vec<u8> {
    frame(0x1, s.as_bytes())
}

impl Hub {
    /// Send an encoded frame to one client; drop it if the queue is full.
    fn broadcast_to(&self, id: u64, f: Vec<u8>) {
        let mut clients = self.clients.lock().unwrap();
        if clients.get(&id).is_some_and(|tx| tx.try_send(f).is_err()) {
            clients.remove(&id);
        }
    }
}

pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bitlen = data.len() as u64 * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | c.get(2).copied().unwrap_or(0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

// --- JSON feed --------------------------------------------------------------

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn fnum(x: f64) -> String {
    if x.is_finite() {
        format!("{x:.6}")
    } else {
        "0".into()
    }
}

/// One alert event for the feed: `{type, at, state, severity, pack, rule, entity, exercise, message}`.
pub fn alert_json(e: &AlertEvent) -> String {
    let sev = match e.alert.severity {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
    };
    let state = match e.state {
        AlertState::Firing => "firing",
        AlertState::Resolved => "resolved",
    };
    format!(
        "{{\"at\":{},\"state\":\"{state}\",\"severity\":\"{sev}\",\"pack\":\"{}\",\"rule\":\"{}\",\"entity\":\"{}\",\"exercise\":{},\"message\":\"{}\"}}",
        fnum(e.at),
        esc(&e.alert.pack),
        esc(&e.alert.rule_id),
        esc(&e.alert.key.id.to_string()),
        e.alert.key.exercise,
        esc(&e.alert.message),
    )
}

/// A server event log entry body (`kind = "info"`).
pub fn info_json(at: f64, message: &str) -> String {
    format!("{{\"at\":{},\"message\":\"{}\"}}", fnum(at), esc(message))
}

/// A decode-error log entry body (`kind = "error"`).
pub fn error_json(at: f64, count: u64, source: &str) -> String {
    format!(
        "{{\"at\":{},\"count\":{count},\"source\":\"{}\",\"message\":\"{count} decode {} from {}\"}}",
        fnum(at),
        esc(source),
        if count == 1 { "error" } else { "errors" },
        esc(source),
    )
}

// --- client commands --------------------------------------------------------

/// `"key": "value"` string extraction from flat JSON (no nesting).
fn jstr<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let rest = text.split(&format!("\"{key}\"")).nth(1)?;
    rest.trim_start()
        .strip_prefix(':')?
        .trim_start()
        .strip_prefix('"')?
        .split('"')
        .next()
}

fn jnum(text: &str, key: &str) -> Option<f64> {
    let rest = text.split(&format!("\"{key}\"")).nth(1)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-'))
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// What a command wants the capture source to become (runs picker).
#[derive(Debug, Clone, PartialEq)]
pub enum Switch {
    /// Back to the live UDP listener.
    Live,
    /// Replay this `.nnrec` file (basename inside the runs dir).
    Replay(String),
    /// Change replay pacing.
    Speed(f64),
    /// Jump to this many seconds into the current recording.
    Seek(f64),
}

/// The outcome of one client command: alert events to log, a note for the
/// event feed, and optionally a capture-source switch.
pub struct CmdOut {
    pub events: Vec<AlertEvent>,
    pub note: String,
    pub switch: Option<Switch>,
}

fn note(msg: String) -> CmdOut {
    CmdOut {
        events: Vec::new(),
        note: msg,
        switch: None,
    }
}

/// One client command (ack, mute, unmute, replay, live, speed).
pub fn apply_command(m: &mut Monitor, text: &str) -> Result<CmdOut, String> {
    apply_command_by(m, text, "operator")
}

pub fn apply_command_by(m: &mut Monitor, text: &str, by: &str) -> Result<CmdOut, String> {
    let now = m.now;
    let cmd = jstr(text, "cmd").ok_or("missing \"cmd\"")?;
    let entity = |t: &str| -> Result<EntityKey, String> {
        let id: nn_decode::EntityId = jstr(t, "entity").ok_or("missing \"entity\"")?.parse()?;
        let exercise = jnum(t, "exercise").unwrap_or(0.0) as u8;
        Ok(EntityKey { exercise, id })
    };
    let dur = |t: &str| jnum(t, "secs").unwrap_or(300.0);
    match cmd {
        "ack" => {
            let rule = jstr(text, "rule").ok_or("missing \"rule\"")?;
            let key = entity(text)?;
            let ack_note = jstr(text, "note").unwrap_or("");
            if m.engine.ack(rule, key, by, ack_note, now) {
                Ok(note(format!("acknowledged {rule} on {}", key.id)))
            } else {
                Err(format!("no active {rule} alert on {}", key.id))
            }
        }
        "mute" => {
            let key = entity(text)?;
            let until = now + dur(text);
            let events = m.engine.mute_entity(key, until, now);
            Ok(CmdOut {
                events,
                note: format!("muted {} for {:.0} s", key.id, until - now),
                switch: None,
            })
        }
        "mute_rule" => {
            let rule = jstr(text, "rule").ok_or("missing \"rule\"")?;
            let until = now + dur(text);
            m.engine.mute_rule(rule, until);
            Ok(note(format!("muted rule {rule} for {:.0} s", until - now)))
        }
        "unmute" => {
            let key = entity(text)?;
            let n = m.engine.unmute(&MuteScope::Entity(key));
            Ok(note(format!("removed {n} mute(s) on {}", key.id)))
        }
        "unmute_rule" => {
            let rule = jstr(text, "rule").ok_or("missing \"rule\"")?;
            let n = m.engine.unmute(&MuteScope::Rule(rule.to_string()));
            Ok(note(format!("removed {n} mute(s) on {rule}")))
        }
        "replay" => {
            let file = jstr(text, "file").ok_or("missing \"file\"")?;
            if file.is_empty() || file.contains('/') || file.contains('\\') || file.contains("..") {
                return Err("bad file name".into());
            }
            Ok(CmdOut {
                events: vec![],
                note: format!("replaying {file}"),
                switch: Some(Switch::Replay(file.to_string())),
            })
        }
        "live" => Ok(CmdOut {
            events: vec![],
            note: "back to live capture".to_string(),
            switch: Some(Switch::Live),
        }),
        "speed" => {
            let x = jnum(text, "x").ok_or("missing \"x\"")?;
            if !(0.1..=64.0).contains(&x) {
                return Err("speed out of range".into());
            }
            Ok(CmdOut {
                events: vec![],
                note: format!("replay speed {x}x"),
                switch: Some(Switch::Speed(x)),
            })
        }
        "seek" => {
            let to = jnum(text, "to").ok_or("missing \"to\"")?;
            Ok(CmdOut {
                events: vec![],
                note: format!("seek to {to:.0} s"),
                switch: Some(Switch::Seek(to)),
            })
        }
        other => Err(format!("unknown command '{other}'")),
    }
}

/// The once-per-second aggregated state the dashboard renders.
/// One entity as the dashboard's JSON record. `seen` (not `age`) keeps the
/// string stable between heartbeats so the delta diff stays quiet.
fn entity_json(rec: &nn_state::EntityRecord, now: f64, timeout: f64) -> String {
    let k = rec.kinematics();
    let (lat, lon, alt) = geo::ecef_to_lla(&k.location);
    let speed =
        ((k.velocity.x * k.velocity.x + k.velocity.y * k.velocity.y + k.velocity.z * k.velocity.z) as f64).sqrt();
    let age = (now - rec.last_seen).max(0.0);
    format!(
        "{{\"id\":\"{}\",\"exercise\":{},\"marking\":\"{}\",\"force\":{},\"ek\":{},\"edom\":{},\"etype\":\"{}\",\"lat\":{},\"lon\":{},\"alt\":{},\"heading\":{},\"speed\":{},\"seen\":{},\"senders\":{},\"removed\":{},\"deactivated\":{},\"stale\":{},\"frozen\":{}}}",
        rec.key.id,
        rec.key.exercise,
        esc(&rec.marking),
        rec.force_id,
        rec.entity_type.kind,
        rec.entity_type.domain,
        rec.entity_type,
        fnum(lat),
        fnum(lon),
        fnum(alt),
        fnum(k.orientation.psi.to_degrees() as f64),
        fnum(speed),
        fnum(rec.last_seen),
        rec.sources.len(),
        rec.removed,
        rec.deactivated(),
        age > timeout,
        rec.appearance & nn_decode::appearance::FROZEN != 0,
    )
}

/// Everything the dashboard's detail panel shows for one entity: the
/// [`entity_json`] fields plus type breakdown, altitude, first seen, DR
/// algorithm, raw appearance, an entity mute if any, and one record per
/// sender (reports, heartbeat mean and jitter, the type it claimed).
fn entity_detail_json(rec: &nn_state::EntityRecord, now: f64, timeout: f64, muted_until: Option<f64>) -> String {
    let mut s = entity_json(rec, now, timeout);
    s.pop(); // reopen the object
    let t = &rec.entity_type;
    s.push_str(&format!(
        ",\"type\":{{\"kind\":{},\"domain\":{},\"country\":{},\"category\":{},\"subcategory\":{},\"specific\":{},\"extra\":{}}}",
        t.kind, t.domain, t.country, t.category, t.subcategory, t.specific, t.extra
    ));
    s.push_str(&format!(
        ",\"first_seen\":{},\"dr\":{},\"appearance\":{},\"last_source\":\"{}\"",
        fnum(rec.first_seen),
        rec.kinematics().algorithm,
        rec.appearance,
        rec.last_source
    ));
    if let Some(until) = muted_until {
        s.push_str(&format!(",\"muted_until\":{}", fnum(until)));
    }
    s.push_str(",\"sources\":[");
    let mut first = true;
    for (addr, src) in &rec.sources {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&format!(
            "{{\"addr\":\"{}\",\"first_seen\":{},\"seen\":{},\"reports\":{},\"hb_mean\":{},\"hb_sd\":{},\"etype\":\"{}\"}}",
            addr,
            fnum(src.first_seen),
            fnum(src.last_seen),
            src.reports,
            fnum(src.intervals.mean),
            fnum(src.intervals.variance().sqrt()),
            src.entity_type
        ));
    }
    s.push_str("]}");
    s
}

/// Detail JSON for every entity, keyed by `EntityKey` display (`ex1 1:2:3`),
/// for [`Hub::set_details`].
pub fn entity_details(m: &Monitor) -> BTreeMap<String, String> {
    let timeout = m.engine.config.timeout();
    let mutes = m.engine.mutes();
    m.table
        .entities
        .values()
        .map(|r| {
            let muted = mutes
                .iter()
                .filter(|mu| mu.scope == MuteScope::Entity(r.key) && mu.until > m.now)
                .map(|mu| mu.until)
                .fold(None, |acc: Option<f64>, u| Some(acc.map_or(u, |a| a.max(u))));
            (r.key.to_string(), entity_detail_json(r, m.now, timeout, muted))
        })
        .collect()
}

/// Rebuild the delta baseline from the monitor's entity table.
pub fn entity_baseline(m: &Monitor, prev: &mut std::collections::BTreeMap<String, String>) {
    let timeout = m.engine.config.timeout();
    prev.clear();
    for r in m.table.entities.values() {
        prev.insert(r.key.id.to_string(), entity_json(r, m.now, timeout));
    }
}

/// `{"type":"delta","ents":[changed/new],"gone":[ids],…}` plus the usual
/// header fields. `prev` is updated to the new baseline.
pub fn delta_json(
    m: &Monitor,
    uptime: f64,
    clients: usize,
    packs: &[String],
    prev: &mut std::collections::BTreeMap<String, String>,
    replay: Option<(f64, f64)>,
) -> String {
    let mut s = top_json(m, uptime, clients, packs, "delta");
    let timeout = m.engine.config.timeout();
    s.push_str(",\"ents\":[");
    let mut first = true;
    for r in m.table.entities.values() {
        let id = r.key.id.to_string();
        let j = entity_json(r, m.now, timeout);
        if prev.get(&id) == Some(&j) {
            continue;
        }
        prev.insert(id, j.clone());
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&j);
    }
    s.push_str("],\"gone\":[");
    let cur: std::collections::BTreeSet<String> = prev.keys().cloned().collect();
    first = true;
    for id in cur {
        if !m.table.entities.values().any(|r| r.key.id.to_string() == id) {
            prev.remove(&id);
            if !first {
                s.push(',');
            }
            first = false;
            s.push_str(&format!("\"{id}\""));
        }
    }
    if let Some((pos, dur)) = replay {
        s.push_str(&format!(",\"replay\":{{\"pos\":{},\"dur\":{}}}", fnum(pos), fnum(dur)));
    }
    s.push_str("]}");
    s
}

pub fn state_json(
    m: &Monitor,
    uptime: f64,
    clients: usize,
    packs: &[String],
    recent: &VecDeque<String>,
    replay: Option<(f64, f64)>,
) -> String {
    let mut s = String::with_capacity(8192);
    s.push_str(&top_json(m, uptime, clients, packs, "state"));
    s.push_str(",\"entities\":[");
    let timeout = m.engine.config.timeout();
    let mut first = true;
    for rec in m.table.entities.values() {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&entity_json(rec, m.now, timeout));
    }
    s.push_str("],\"recent\":[");
    s.push_str(&recent.iter().cloned().collect::<Vec<_>>().join(","));
    s.push(']');
    if let Some((pos, dur)) = replay {
        s.push_str(&format!(",\"replay\":{{\"pos\":{},\"dur\":{}}}", fnum(pos), fnum(dur)));
    }
    s.push('}');
    s
}

/// The fields every state/delta frame shares: clock, uptime, clients,
/// packs, totals, rates, exercises and active alerts.
fn top_json(m: &Monitor, uptime: f64, clients: usize, packs: &[String], kind: &str) -> String {
    let now = m.now;
    let w1 = m.metrics.window(now, 1);
    let w10 = m.metrics.window(now, 10);
    let mut s = String::with_capacity(4096);
    s.push_str("{\"type\":\"");
    s.push_str(kind);
    s.push_str("\",\"at\":");
    s.push_str(&fnum(now));
    s.push_str(",\"uptime\":");
    s.push_str(&fnum(uptime));
    s.push_str(",\"clients\":");
    s.push_str(&clients.to_string());
    s.push_str(",\"packs\":[");
    s.push_str(
        &packs
            .iter()
            .map(|p| format!("\"{}\"", esc(p)))
            .collect::<Vec<_>>()
            .join(","),
    );
    s.push(']');
    s.push_str(&format!(
        ",\"totals\":{{\"datagrams\":{},\"pdus\":{},\"errors\":{}}}",
        m.datagrams, m.pdus, m.decode_errors
    ));
    s.push_str(&format!(
        ",\"rates\":{{\"pdu_1s\":{},\"pdu_10s\":{},\"kb_10s\":{}}}",
        fnum(w1.pdu_rate()),
        fnum(w10.pdu_rate()),
        fnum(w10.byte_rate() / 1000.0)
    ));
    s.push_str(",\"exercises\":{");
    let mut first = true;
    for (id, ex) in &m.table.exercises {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&format!("\"{id}\":{{\"frozen\":{}}}", ex.frozen));
    }
    s.push('}');
    s.push_str(",\"alerts\":[");
    let mut first = true;
    for a in m.engine.active() {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&format!(
            "{{\"pack\":\"{}\",\"rule\":\"{}\",\"entity\":\"{}\",\"severity\":\"{}\",\"since\":{},\"message\":\"{}\"",
            esc(&a.pack),
            esc(&a.rule_id),
            esc(&a.key.id.to_string()),
            match a.severity {
                Severity::Critical => "critical",
                Severity::Warning => "warning",
            },
            fnum(a.since),
            esc(&a.message),
        ));
        if let Some(ack) = m.engine.ack_of(&a.rule_id, &a.key) {
            s.push_str(&format!(
                ",\"ack\":{{\"by\":\"{}\",\"note\":\"{}\",\"at\":{}}}",
                esc(&ack.by),
                esc(&ack.note),
                fnum(ack.at)
            ));
        }
        s.push('}');
    }
    s.push(']');
    s
}

/// Wall-clock seconds helper for the serve loop.
pub fn now_secs() -> f64 {
    secs(SystemTime::now())
}
