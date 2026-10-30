//! Persistent event storage in embedded SQLite (ADR 0005).
//!
//! The in-memory ring buffer stays the hot path; every logged entry is also
//! indexed here — one `events` row plus the raw entry JSON — so `/api/log`
//! can answer "every timeout on 1:1:2 last week" instead of "the last 2,000
//! events". One file per monitor; WAL mode for concurrent readers.
//!
//! `runs` marks run boundaries so the UI can tell yesterday's exercise from
//! today's; `recordings`/`pdus` from the ADR land with milestone 5.
//!
//! Events carry `sender`, `pack` and `state` (ADR 0008 slice 2) so they
//! aggregate on the same tags as metrics; older files gain the columns on
//! open. [`EventStore::violations`] feeds the conformance summary.
//!
//! Metric rollups (ADR 0008): `series(id, name, tags)` names each tagged
//! series once; `samples(series, at, n, sum, min, max)` holds one row per
//! series per ten-second slot, swept after the retention period.

use nn_state::metrics::{decode_tags, encode_tags, Agg, Cell, Rollup};
use rusqlite::{params, Connection};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// One log entry to index; `json` is kept verbatim.
#[derive(Debug, Default)]
pub struct NewEvent<'a> {
    pub run: i64,
    pub seq: u64,
    pub at: f64,
    pub kind: &'a str,
    pub entity: Option<&'a str>,
    pub rule: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub exercise: Option<u8>,
    pub message: Option<&'a str>,
    pub sender: Option<&'a str>,
    pub pack: Option<&'a str>,
    /// `firing` / `resolved` for alerts.
    pub state: Option<&'a str>,
    pub json: &'a str,
}

/// A violation as the conformance summary counts it: an alert firing or a
/// decode error.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Violation {
    pub at: f64,
    /// `alert` or `error`.
    pub kind: String,
    pub rule: Option<String>,
    pub pack: Option<String>,
    pub entity: Option<String>,
    pub sender: Option<String>,
    pub severity: Option<String>,
    pub exercise: Option<u8>,
}

#[derive(Debug, Default)]
pub struct EventQuery {
    /// Only entries with seq greater than this.
    pub after: u64,
    pub kind: Option<String>,
    pub rule: Option<String>,
    pub entity: Option<String>,
    pub sender: Option<String>,
    /// Substring match against entity, rule and message.
    pub text: Option<String>,
    pub limit: usize,
}

pub struct EventStore {
    conn: Connection,
    /// `name|tags` → series id, so a flush doesn't look each one up.
    series_ids: RefCell<HashMap<String, i64>>,
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
            CREATE INDEX IF NOT EXISTS ev_at ON events(at);
            CREATE TABLE IF NOT EXISTS series(
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                tags TEXT NOT NULL,
                UNIQUE(name, tags));
            CREATE TABLE IF NOT EXISTS samples(
                series INTEGER NOT NULL,
                at INTEGER NOT NULL,
                n INTEGER, sum REAL, min REAL, max REAL);
            CREATE INDEX IF NOT EXISTS sm_series_at ON samples(series, at);
            CREATE INDEX IF NOT EXISTS sm_at ON samples(at);",
        )
        .map_err(|e| e.to_string())?;
        // Files from before slice 2 gain the tag columns in place.
        let have: Vec<String> = conn
            .prepare("PRAGMA table_info(events)")
            .and_then(|mut st| st.query_map([], |r| r.get::<_, String>(1))?.collect())
            .map_err(|e| e.to_string())?;
        for col in ["sender", "pack", "state"] {
            if !have.iter().any(|c| c == col) {
                conn.execute(&format!("ALTER TABLE events ADD COLUMN {col} TEXT"), [])
                    .map_err(|e| e.to_string())?;
            }
        }
        conn.execute_batch("CREATE INDEX IF NOT EXISTS ev_sender ON events(sender);")
            .map_err(|e| e.to_string())?;
        Ok(EventStore {
            conn,
            series_ids: RefCell::new(HashMap::new()),
        })
    }

    /// Start a new run row; returns its id (used as `run` on events).
    pub fn start_run(&self, at: f64, packs: &str) -> Result<i64, String> {
        self.conn
            .execute("INSERT INTO runs(started_at, packs) VALUES(?1, ?2)", params![at, packs])
            .map_err(|e| e.to_string())?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Index one log entry (its full JSON body is kept verbatim).
    pub fn insert(&self, e: &NewEvent) {
        let _ = self.conn.execute(
            "INSERT INTO events(run,seq,at,kind,entity,rule,severity,exercise,message,sender,pack,state,json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                e.run,
                e.seq as i64,
                e.at,
                e.kind,
                e.entity,
                e.rule,
                e.severity,
                e.exercise,
                e.message,
                e.sender,
                e.pack,
                e.state,
                e.json
            ],
        );
    }

    /// Alert firings and decode errors since `since`, optionally for one
    /// exercise or entity. Rows written before the `state` column existed
    /// are recognised from their JSON.
    pub fn violations(&self, since: f64, exercise: Option<u8>, entity: Option<&str>) -> Result<Vec<Violation>, String> {
        let mut st = self
            .conn
            .prepare_cached(
                "SELECT at, kind, rule, pack, entity, COALESCE(sender, json_extract(json, '$.source')),
                        severity, exercise
                 FROM events
                 WHERE at >= ?1
                   AND (kind = 'error'
                        OR (kind = 'alert' AND (state = 'firing'
                            OR (state IS NULL AND json LIKE '%\"state\":\"firing\"%'))))
                   AND (?2 IS NULL OR exercise = ?2)
                   AND (?3 IS NULL OR entity = ?3)
                 ORDER BY at",
            )
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(params![since, exercise, entity], |r| {
                Ok(Violation {
                    at: r.get(0)?,
                    kind: r.get(1)?,
                    rule: r.get(2)?,
                    pack: r.get(3)?,
                    entity: r.get(4)?,
                    sender: r.get(5)?,
                    severity: r.get(6)?,
                    exercise: r.get::<_, Option<i64>>(7)?.map(|x| x as u8),
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
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
        if let Some(s) = &q.sender {
            push(&mut sql, &mut args, "sender =", s.clone());
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

    fn series_id(&self, name: &str, tags: &str) -> rusqlite::Result<i64> {
        let key = format!("{name}|{tags}");
        if let Some(id) = self.series_ids.borrow().get(&key) {
            return Ok(*id);
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO series(name, tags) VALUES(?1, ?2)",
            params![name, tags],
        )?;
        let id = self.conn.query_row(
            "SELECT id FROM series WHERE name = ?1 AND tags = ?2",
            params![name, tags],
            |r| r.get(0),
        )?;
        self.series_ids.borrow_mut().insert(key, id);
        Ok(id)
    }

    /// Write one flush of ten-second rollups in a single transaction.
    pub fn write_rollup(&self, rows: &[Rollup]) -> Result<(), String> {
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        {
            let mut ins = tx
                .prepare_cached("INSERT INTO samples(series, at, n, sum, min, max) VALUES(?1,?2,?3,?4,?5,?6)")
                .map_err(|e| e.to_string())?;
            for r in rows {
                let id = self
                    .series_id(r.metric.name(), &encode_tags(&r.tags))
                    .map_err(|e| e.to_string())?;
                ins.execute(params![id, r.at, r.agg.n as i64, r.agg.sum, r.agg.min, r.agg.max])
                    .map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// Stored cells of metric `name` with `from <= at < to` whose tags pass
    /// `keep` (decoded once per series).
    pub fn metric_cells(
        &self,
        name: &str,
        from: i64,
        to: i64,
        keep: impl Fn(&nn_state::metrics::TagPairs) -> bool,
    ) -> Result<Vec<Cell>, String> {
        let mut st = self
            .conn
            .prepare_cached(
                "SELECT s.id, s.tags, m.at, m.n, m.sum, m.min, m.max
                 FROM series s JOIN samples m ON m.series = s.id
                 WHERE s.name = ?1 AND m.at >= ?2 AND m.at < ?3",
            )
            .map_err(|e| e.to_string())?;
        let mut rows = st.query(params![name, from, to]).map_err(|e| e.to_string())?;
        let mut tags: HashMap<i64, Option<Arc<nn_state::metrics::TagPairs>>> = HashMap::new();
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let id: i64 = r.get(0).map_err(|e| e.to_string())?;
            let t = match tags.get(&id) {
                Some(t) => t.clone(),
                None => {
                    let p = decode_tags(&r.get::<_, String>(1).map_err(|e| e.to_string())?);
                    let t = keep(&p).then(|| Arc::new(p));
                    tags.insert(id, t.clone());
                    t
                }
            };
            let Some(t) = t else { continue };
            let get = |i| r.get::<_, f64>(i).map_err(|e| e.to_string());
            out.push(Cell {
                at: r.get(2).map_err(|e| e.to_string())?,
                tags: t,
                agg: Agg {
                    n: r.get::<_, i64>(3).map_err(|e| e.to_string())? as u64,
                    sum: get(4)?,
                    min: get(5)?,
                    max: get(6)?,
                },
            });
        }
        Ok(out)
    }

    /// Drop samples older than `before` and series left without any.
    /// Returns the samples removed.
    pub fn sweep_samples(&self, before: i64) -> Result<usize, String> {
        let n = self
            .conn
            .execute("DELETE FROM samples WHERE at < ?1", params![before])
            .map_err(|e| e.to_string())?;
        if n > 0 {
            self.conn
                .execute(
                    "DELETE FROM series WHERE NOT EXISTS (SELECT 1 FROM samples WHERE samples.series = series.id)",
                    [],
                )
                .map_err(|e| e.to_string())?;
            self.series_ids.borrow_mut().clear();
        }
        Ok(n)
    }
}
