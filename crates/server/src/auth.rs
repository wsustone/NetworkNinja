//! Local accounts for `serve --users FILE`.
//!
//! Users file: one `user:pbkdf2:salt_hex:hash_hex` per line — PBKDF2-HMAC-SHA256,
//! [`PBKDF2_ROUNDS`] iterations, 16-byte random salt. Lines in the earlier
//! `user:salt_hex:hash_hex` form (iterated SHA-1) still verify; `passwd`
//! rewrites an account in the current scheme.
//!
//! Sessions are random bearer tokens in memory: `POST /api/login` (form body
//! `user=&pass=`) issues one; clients send it as `Authorization: Bearer` on
//! `/api/*` or `?token=` on `/ws`. A session ends after [`SESSION_IDLE`]
//! without use or at `POST /api/logout`.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::web::sha1;

/// Sessions idle this long are gone.
pub const SESSION_IDLE: Duration = Duration::from_secs(12 * 3600);
const PBKDF2_ROUNDS: u32 = 600_000;
const LEGACY_ROUNDS: u32 = 100_000;

enum Hash {
    Pbkdf2 { salt: Vec<u8>, hash: Vec<u8> },
    LegacySha1 { salt: String, hash: String },
}

pub struct Auth {
    users: HashMap<String, Hash>,
    sessions: Mutex<HashMap<String, (String, Instant)>>,
}

impl Auth {
    /// Empty store — `passwd` creates the file from scratch.
    pub fn empty() -> Auth {
        Auth {
            users: HashMap::new(),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    pub fn load(path: &Path) -> io::Result<Auth> {
        let mut a = Auth::empty();
        for (n, line) in fs::read_to_string(path)?.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = || io::Error::new(io::ErrorKind::InvalidData, format!("bad users line {}", n + 1));
            let f: Vec<&str> = line.split(':').collect();
            let (user, hash) = match f.as_slice() {
                [u, "pbkdf2", s, h] => (
                    *u,
                    Hash::Pbkdf2 {
                        salt: unhex(s).ok_or_else(bad)?,
                        hash: unhex(h).ok_or_else(bad)?,
                    },
                ),
                [u, s, h] => (
                    *u,
                    Hash::LegacySha1 {
                        salt: s.to_string(),
                        hash: h.to_string(),
                    },
                ),
                _ => return Err(bad()),
            };
            a.users.insert(user.to_string(), hash);
        }
        Ok(a)
    }

    pub fn set_user(&mut self, user: &str, pass: &str) {
        let salt = random(16);
        let hash = pbkdf2(&salt, pass);
        self.users.insert(user.to_string(), Hash::Pbkdf2 { salt, hash });
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let body: String = self
            .users
            .iter()
            .map(|(u, h)| match h {
                Hash::Pbkdf2 { salt, hash } => format!("{u}:pbkdf2:{}:{}\n", hex(salt), hex(hash)),
                Hash::LegacySha1 { salt, hash } => format!("{u}:{salt}:{hash}\n"),
            })
            .collect();
        fs::write(path, body)
    }

    pub fn verify(&self, user: &str, pass: &str) -> bool {
        match self.users.get(user) {
            Some(Hash::Pbkdf2 { salt, hash }) => aws_lc_rs::pbkdf2::verify(
                aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
                NonZeroU32::new(PBKDF2_ROUNDS).unwrap(),
                salt,
                pass.as_bytes(),
                hash,
            )
            .is_ok(),
            Some(Hash::LegacySha1 { salt, hash }) => {
                aws_lc_rs::constant_time::verify_slices_are_equal(legacy_hash(salt, pass).as_bytes(), hash.as_bytes())
                    .is_ok()
            }
            None => false,
        }
    }

    /// Issue a session token for a verified user.
    pub fn issue(&self, user: &str) -> String {
        let tok = hex(&random(20));
        let now = Instant::now();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, (_, seen)| now.duration_since(*seen) < SESSION_IDLE);
        s.insert(tok.clone(), (user.to_string(), now));
        tok
    }

    /// Resolve a bearer token to its user, refreshing its idle timer.
    pub fn check(&self, token: &str) -> Option<String> {
        self.check_at(token, Instant::now())
    }

    fn check_at(&self, token: &str, now: Instant) -> Option<String> {
        let mut s = self.sessions.lock().unwrap();
        let (user, seen) = s.get_mut(token)?;
        if now.duration_since(*seen) >= SESSION_IDLE {
            s.remove(token);
            return None;
        }
        *seen = now;
        Some(user.clone())
    }

    /// End a session; returns its user if it was live.
    pub fn revoke(&self, token: &str) -> Option<String> {
        self.sessions.lock().unwrap().remove(token).map(|(u, _)| u)
    }
}

fn pbkdf2(salt: &[u8], pass: &str) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    aws_lc_rs::pbkdf2::derive(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ROUNDS).unwrap(),
        salt,
        pass.as_bytes(),
        &mut out,
    );
    out
}

fn legacy_hash(salt: &str, pass: &str) -> String {
    let mut d = sha1(format!("{salt}{pass}").as_bytes());
    for _ in 1..LEGACY_ROUNDS {
        d = sha1(&[salt.as_bytes(), pass.as_bytes(), &d].concat());
    }
    hex(&d)
}

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    aws_lc_rs::rand::fill(&mut b).expect("system random source");
    b
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("nn-auth-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("users");
        let mut a = Auth::empty();
        a.set_user("ops", "hunter2");
        a.save(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("ops:pbkdf2:"), "{text}");
        let b = Auth::load(&path).unwrap();
        assert_eq!(b.len(), 1);
        assert!(b.verify("ops", "hunter2"));
        assert!(!b.verify("ops", "hunter3"));
        assert!(!b.verify("nobody", "hunter2"));
        let tok = b.issue("ops");
        assert_eq!(tok.len(), 40);
        assert_eq!(b.check(&tok).as_deref(), Some("ops"));
        assert_eq!(b.revoke(&tok).as_deref(), Some("ops"));
        assert!(b.check(&tok).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_lines_still_verify() {
        let dir = std::env::temp_dir().join(format!("nn-auth-legacy-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("users");
        std::fs::write(&path, format!("old:abcd:{}\n", legacy_hash("abcd", "pw"))).unwrap();
        let a = Auth::load(&path).unwrap();
        assert!(a.verify("old", "pw"));
        assert!(!a.verify("old", "pwx"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tokens_and_salts_are_random() {
        let a = Auth::empty();
        let t1 = a.issue("u");
        let t2 = a.issue("u");
        assert_ne!(t1, t2);
        assert_ne!(random(16), random(16));
    }

    #[test]
    fn sessions_expire_when_idle() {
        let a = Auth::empty();
        let tok = a.issue("u");
        let now = Instant::now();
        assert!(a.check_at(&tok, now + SESSION_IDLE / 2).is_some());
        assert!(a
            .check_at(&tok, now + SESSION_IDLE / 2 + SESSION_IDLE - Duration::from_secs(1))
            .is_some());
        assert!(a.check_at(&tok, now + SESSION_IDLE * 3).is_none());
        assert!(a.check(&tok).is_none());
    }
}
