//! Persistent PDU capture (ADR 0009): the rows the pack's `[[capture]]`
//! tiers chose, with their wire bytes, in their own SQLite file
//! (`serve --capture FILE`), kept under a byte budget.
//!
//! A writer thread owns the connection and commits in batches, so the
//! capture loop never waits on the disk; if the writer falls behind, the
//! queue drops whole batches and counts them. The budget is measured from
//! SQLite's own page counts — live pages, indexes included — and the oldest
//! rows go first when it is exceeded.

use nn_rules::Captured;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Batches queued for the writer before new ones are dropped.
const QUEUE: usize = 4096;
/// Longest a kept PDU waits before its batch commits.
const COMMIT_EVERY: Duration = Duration::from_millis(500);
/// Evict down to this fraction of the budget, so eviction runs rarely.
const EVICT_TO: f64 = 0.9;

/// Counters shared with `/api/capture`.
#[derive(Debug, Default)]
pub struct CaptureStats {
    pub budget: AtomicU64,
    /// Bytes of live pages in the file (data and indexes).
    pub used: AtomicU64,
    pub rows: AtomicU64,
    /// Rows written since start.
    pub written: AtomicU64,
    /// Rows the tiers passed over (copied from the decider).
    pub skipped: AtomicU64,
    /// Rows lost because the writer fell behind.
    pub dropped: AtomicU64,
    /// Rows deleted to stay inside the budget.
    pub evicted: AtomicU64,
}

impl CaptureStats {
    pub fn json(&self, path: &Path) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "{{\"file\":\"{}\",\"budget\":{},\"used\":{},\"rows\":{},\"written\":{},\"skipped\":{},\"dropped\":{},\"evicted\":{}}}",
            path.display().to_string().replace('\\', "\\\\").replace('"', "\\\""),
            g(&self.budget),
            g(&self.used),
            g(&self.rows),
            g(&self.written),
            g(&self.skipped),
            g(&self.dropped),
            g(&self.evicted)
        )
    }
}

pub struct PduStore {
    tx: Option<SyncSender<Vec<Captured>>>,
    writer: Option<JoinHandle<()>>,
    pub stats: Arc<CaptureStats>,
    pub path: PathBuf,
}

fn open_conn(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pdus(
            id INTEGER PRIMARY KEY,
            at REAL NOT NULL,
            sender TEXT,
            exercise INTEGER,
            pdu_type INTEGER,
            entity TEXT,
            tier TEXT,
            raw BLOB);
        CREATE INDEX IF NOT EXISTS pdu_entity_at ON pdus(exercise, entity, at);
        CREATE INDEX IF NOT EXISTS pdu_at ON pdus(at);",
    )?;
    Ok(conn)
}

fn used_bytes(conn: &Connection) -> rusqlite::Result<u64> {
    let p = |name: &str| conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get::<_, i64>(0));
    Ok(((p("page_count")? - p("freelist_count")?) * p("page_size")?).max(0) as u64)
}

impl PduStore {
    /// Open (or create) the capture file and start its writer thread.
    /// `budget` is in bytes; an existing file over it is trimmed at once.
    pub fn open(path: &Path, budget: u64) -> Result<PduStore, String> {
        let conn = open_conn(path).map_err(|e| e.to_string())?;
        let stats = Arc::new(CaptureStats::default());
        stats.budget.store(budget, Ordering::Relaxed);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM pdus", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        stats.rows.store(rows as u64, Ordering::Relaxed);
        enforce_budget(&conn, &stats).map_err(|e| e.to_string())?;
        let (tx, rx) = sync_channel(QUEUE);
        let s = Arc::clone(&stats);
        let writer = std::thread::spawn(move || write_loop(conn, rx, s));
        Ok(PduStore {
            tx: Some(tx),
            writer: Some(writer),
            stats,
            path: path.to_path_buf(),
        })
    }

    /// Queue rows for the writer; never blocks. A full queue drops them.
    pub fn submit(&self, rows: Vec<Captured>) {
        if rows.is_empty() {
            return;
        }
        let n = rows.len() as u64;
        if let Some(tx) = &self.tx {
            if tx.try_send(rows).is_err() {
                self.stats.dropped.fetch_add(n, Ordering::Relaxed);
            }
        }
    }

    /// Commit everything queued and stop the writer.
    pub fn close(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.tx.take();
        if let Some(w) = self.writer.take() {
            let _ = w.join();
        }
    }
}

impl Drop for PduStore {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn write_loop(conn: Connection, rx: Receiver<Vec<Captured>>, stats: Arc<CaptureStats>) {
    let mut batch: Vec<Captured> = Vec::new();
    let mut since = Instant::now();
    loop {
        let done = match rx.recv_timeout(COMMIT_EVERY) {
            Ok(rows) => {
                if batch.is_empty() {
                    since = Instant::now();
                }
                batch.extend(rows);
                false
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => true,
        };
        if !batch.is_empty() && (done || since.elapsed() >= COMMIT_EVERY) {
            match insert(&conn, &batch) {
                Ok(()) => {
                    stats.written.fetch_add(batch.len() as u64, Ordering::Relaxed);
                    stats.rows.fetch_add(batch.len() as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    eprintln!("nn-server: capture write failed: {e}");
                    stats.dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
                }
            }
            batch.clear();
            if let Err(e) = enforce_budget(&conn, &stats) {
                eprintln!("nn-server: capture eviction failed: {e}");
            }
        }
        if done {
            break;
        }
    }
}

fn insert(conn: &Connection, rows: &[Captured]) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    {
        let mut st = tx.prepare_cached(
            "INSERT INTO pdus(at, sender, exercise, pdu_type, entity, tier, raw) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        )?;
        for r in rows {
            st.execute(params![
                r.at,
                r.sender.to_string(),
                r.exercise,
                r.pdu_type,
                r.entity.map(|e| e.to_string()),
                r.tier,
                r.raw
            ])?;
        }
    }
    tx.commit()
}

/// Delete the oldest rows, a tenth at a time, until the file's live pages
/// fit in [`EVICT_TO`] of the budget.
fn enforce_budget(conn: &Connection, stats: &CaptureStats) -> rusqlite::Result<()> {
    let budget = stats.budget.load(Ordering::Relaxed);
    let mut used = used_bytes(conn)?;
    if used > budget {
        while used as f64 > budget as f64 * EVICT_TO {
            let rows = stats.rows.load(Ordering::Relaxed);
            if rows == 0 {
                break;
            }
            let n = (rows / 10).max(1);
            let deleted = conn.execute(
                "DELETE FROM pdus WHERE id IN (SELECT id FROM pdus ORDER BY id LIMIT ?1)",
                params![n as i64],
            )? as u64;
            stats.rows.fetch_sub(deleted.min(rows), Ordering::Relaxed);
            stats.evicted.fetch_add(deleted, Ordering::Relaxed);
            used = used_bytes(conn)?;
            if deleted == 0 {
                break;
            }
        }
    }
    stats.used.store(used, Ordering::Relaxed);
    Ok(())
}

/// One stored PDU as `/api/pdus` returns it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPdu {
    pub at: f64,
    pub sender: String,
    pub tier: String,
    pub pdu: Result<nn_decode::Pdu, String>,
}

/// Stored PDUs for one entity (or all, with `entity = None`) in
/// `[from, to)`, oldest first, at most `limit`. Opens its own read
/// connection; WAL lets it run beside the writer.
pub fn read_pdus(
    path: &Path,
    exercise: Option<u8>,
    entity: Option<&str>,
    from: f64,
    to: f64,
    limit: usize,
) -> Result<Vec<StoredPdu>, String> {
    let conn =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| e.to_string())?;
    let mut st = conn
        .prepare(
            "SELECT at, sender, tier, raw FROM pdus
             WHERE at >= ?1 AND at < ?2
               AND (?3 IS NULL OR exercise = ?3) AND (?4 IS NULL OR entity = ?4)
             ORDER BY at LIMIT ?5",
        )
        .map_err(|e| e.to_string())?;
    let rows = st
        .query_map(params![from, to, exercise, entity, limit as i64], |r| {
            Ok((
                r.get::<_, f64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        let (at, sender, tier, raw) = r.map_err(|e| e.to_string())?;
        out.push(StoredPdu {
            at,
            sender,
            tier,
            pdu: nn_decode::decode_pdu(&raw).map_err(|e| e.to_string()),
        });
    }
    Ok(out)
}
