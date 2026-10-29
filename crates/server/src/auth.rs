//! Local accounts for `serve --users FILE`.
//!
//! Users file: one `user:salt_hex:hash_hex` per line. The hash is 100k
//! iterations of SHA-1 over `salt || pass || digest` — deliberately
//! dependency-free and adequate for LAN credentials; ship TLS before
//! exposing this to a hostile network.
//!
//! Sessions are random bearer tokens in memory: `POST /api/login` issues
//! one; clients send it as `?token=` on `/api/*` and `/ws`.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Mutex;

use crate::web::sha1;

const ROUNDS: u32 = 100_000;

pub struct Auth {
    users: HashMap<String, (String, String)>,
    sessions: Mutex<HashMap<String, String>>,
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
        let mut users = HashMap::new();
        for (n, line) in fs::read_to_string(path)?.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.split(':');
            let (Some(u), Some(s), Some(h)) = (f.next(), f.next(), f.next()) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad users line {}", n + 1),
                ));
            };
            users.insert(u.to_string(), (s.to_string(), h.to_string()));
        }
        Ok(Auth {
            users,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn set_user(&mut self, user: &str, pass: &str) {
        let salt = token_hex();
        self.users
            .insert(user.to_string(), (salt.clone(), hash_pass(&salt, pass)));
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let body: String = self.users.iter().map(|(u, (s, h))| format!("{u}:{s}:{h}\n")).collect();
        fs::write(path, body)
    }

    pub fn verify(&self, user: &str, pass: &str) -> bool {
        let Some((salt, want)) = self.users.get(user) else {
            return false;
        };
        hash_pass(salt, pass) == *want
    }

    /// Issue a session token for a verified user.
    pub fn issue(&self, user: &str) -> String {
        let tok = token_hex();
        self.sessions.lock().unwrap().insert(tok.clone(), user.to_string());
        tok
    }

    /// Resolve a bearer token to its user.
    pub fn check(&self, token: &str) -> Option<String> {
        self.sessions.lock().unwrap().get(token).cloned()
    }
}

fn hash_pass(salt: &str, pass: &str) -> String {
    let mut d = sha1(format!("{salt}{pass}").as_bytes());
    for _ in 1..ROUNDS {
        d = sha1(&[salt.as_bytes(), pass.as_bytes(), &d].concat());
    }
    hex(&d)
}

fn token_hex() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id() as u128;
    hex(&sha1(&(n ^ (pid << 64)).to_be_bytes()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut a = Auth {
            users: HashMap::new(),
            sessions: Mutex::new(HashMap::new()),
        };
        a.set_user("alice", "s3cret");
        assert!(a.verify("alice", "s3cret"));
        assert!(!a.verify("alice", "wrong") && !a.verify("bob", "s3cret"));
        let tok = a.issue("alice");
        assert_eq!(a.check(&tok).as_deref(), Some("alice"));
        assert_eq!(a.check("bogus"), None);
    }
}
