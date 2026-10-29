//! Persistent event storage in embedded SQLite (ADR 0005).
//!
//! The in-memory ring buffer stays the hot path; every logged entry is also
//! indexed here — one `events` row plus the raw entry JSON — so `/api/log`
//! can answer "every timeout on 1:1:2 last week" instead of "the last 2,000
//! events". One file per monitor; WAL mode for concurrent readers.
//!
//! `runs` marks run boundaries so the UI can tell yesterday's exercise from
//! today's; `recordings`/`pdus` from the ADR land with milestone 5.

use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Debug, Default)]
pub struct EventQuery {
    /// Only entries with seq greater than this.
    pub after: u64,
    pub kind: Option<String>,
    pub rule: Option<String>,
    pub entity: Option<String>,
    /// Substring match against entity, rule and message.
    pub text: Option<String>,
    pub limit: usize,
}

pub struct EventStore {
    conn: Connection,
}

impl EventStore {
    pub fn open(path: &Path) -> Result<EventStore, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS runs(
                id INTEGER PRIMARY KEY,
                started_at REAL,
                packs TEXT);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY,
                run INTEGER,
                seq INTEGER,
                at REAL,
                kind TEXT,
                entity TEXT,
                rule TEXT,
                severity TEXT,
                exercise INTEGER,
                message TEXT,
                json TEXT);
            CREATE INDEX IF NOT EXISTS ev_seq ON events(seq);
            CREATE INDEX IF NOT EXISTS ev_kind ON events(kind);
            CREATE INDEX IF NOT EXISTS ev_entity ON events(entity);
            CREATE INDEX IF NOT EXISTS ev_at ON events(at);",
        )
        .map_err(|e| e.to_string())?;
        Ok(EventStore { conn })
    }

    /// Start a new run row; returns its id (used as `run` on events).
    pub fn start_run(&self, at: f64, packs: &str) -> Result<i64, String> {
        self.conn
            .execute("INSERT INTO runs(started_at, packs) VALUES(?1, ?2)", params![at, packs])
            .map_err(|e| e.to_string())?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Index one log entry (its full JSON body is kept verbatim).
    pub fn insert(
        &self,
        run: i64,
        seq: u64,
        at: f64,
        kind: &str,
        entity: Option<&str>,
        rule: Option<&str>,
        severity: Option<&str>,
        exercise: Option<u8>,
        message: Option<&str>,
        json: &str,
    ) {
        let _ = self.conn.execute(
            "INSERT INTO events(run,seq,at,kind,entity,rule,severity,exercise,message,json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![run, seq as i64, at, kind, entity, rule, severity, exercise, message, json],
        );
    }

    /// Highest seq seen (all runs), so numbering continues across restarts.
    pub fn max_seq(&self) -> u64 {
        self.conn
            .query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as u64
    }

    /// Matching entries, oldest first, as their raw JSON.
    pub fn query(&self, q: &EventQuery) -> Vec<String> {
        let mut sql = String::from("SELECT json FROM events WHERE seq > ?1");
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(q.after as i64)];
        let push = |sql: &mut String, args: &mut Vec<Box<dyn rusqlite::types::ToSql>>, clause: &str, v: String| {
            args.push(Box::new(v));
            sql.push_str(&format!(" AND {} ?{}", clause, args.len()));
        };
        if let Some(k) = &q.kind {
            push(&mut sql, &mut args, "kind =", k.clone());
        }
        if let Some(r) = &q.rule {
            push(&mut sql, &mut args, "rule =", r.clone());
        }
        if let Some(e) = &q.entity {
            push(&mut sql, &mut args, "entity =", e.clone());
        }
        if let Some(t) = &q.text {
            push(
                &mut sql,
                &mut args,
                "(entity || ' ' || rule || ' ' || message) LIKE '%' ||",
                t.clone(),
            );
            sql.push_str(" || '%'");
        }
        sql.push_str(&format!(" ORDER BY id LIMIT {}", q.limit.min(5000)));
        let refs: Vec<&dyn rusqlite::types::ToSql> = args.iter().map(|a| a.as_ref()).collect();
        let mut st = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match st.query_map(refs.as_slice(), |r| r.get::<_, String>(0)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.flatten().collect()
    }
}
