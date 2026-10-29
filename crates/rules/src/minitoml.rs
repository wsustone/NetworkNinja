//! A deliberately small subset of TOML for rule packs (ADR 0003).
//!
//! Supported: `[section]` and `[[array-of-tables]]` headers with dotted
//! paths, `key = value` pairs, `#` comments, basic strings with `\"`, `\\`,
//! `\n`, `\t` escapes, integers (`_` separators allowed), floats, booleans
//! and single-line arrays of scalars. Not supported: multi-line anything,
//! inline tables, dates. That keeps the workspace dependency-free and the
//! pack format easy to audit.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Float(f64),
    Bool(bool),
    Array(Vec<Value>),
    Table(Table),
    /// `[[name]]` array of tables.
    Tables(Vec<Table>),
}

pub type Table = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Where `key = value` lines currently land: either a `[path]` table or the
/// last element of a `[[path]]` array of tables.
#[derive(Debug, Clone)]
enum Context {
    Table(Vec<String>),
    ArrayOfTables(Vec<String>),
}

pub fn parse(src: &str) -> Result<Table, ParseError> {
    let mut root = Table::new();
    let mut ctx: Option<Context> = None;
    for (i, raw) in src.lines().enumerate() {
        let line_no = i + 1;
        let line = strip_comment(raw).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if let Some(inner) = line.strip_prefix("[[") {
            let path = inner
                .strip_suffix("]]")
                .ok_or_else(|| err(line_no, "expected ']]'"))?
                .trim();
            let path = parse_path(path, line_no)?;
            resolve_aot(&mut root, &path, line_no)?.push(Table::new());
            ctx = Some(Context::ArrayOfTables(path));
        } else if let Some(inner) = line.strip_prefix('[') {
            let path = inner
                .strip_suffix(']')
                .ok_or_else(|| err(line_no, "expected ']'"))?
                .trim();
            let path = parse_path(path, line_no)?;
            table_at(&mut root, &path, line_no)?;
            ctx = Some(Context::Table(path));
        } else {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| err(line_no, "expected 'key = value' or a [section]"))?;
            let key = key.trim();
            if key.is_empty() {
                return Err(err(line_no, "empty key"));
            }
            for k in key.split('.') {
                if !bare_key(k) {
                    return Err(err(line_no, &format!("bad key '{key}'")));
                }
            }
            let value = parse_value(value.trim(), line_no)?;
            let table = match ctx.as_ref().ok_or_else(|| err(line_no, "key before any [section]"))? {
                Context::Table(path) => table_at(&mut root, path, line_no)?,
                Context::ArrayOfTables(path) => resolve_aot(&mut root, path, line_no)?
                    .last_mut()
                    .ok_or_else(|| err(line_no, "empty array of tables"))?,
            };
            insert(table, key, value, line_no)?;
        }
    }
    Ok(root)
}

fn err(line: usize, message: &str) -> ParseError {
    ParseError {
        line,
        message: message.to_string(),
    }
}

fn bare_key(k: &str) -> bool {
    !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn parse_path(path: &str, line: usize) -> Result<Vec<String>, ParseError> {
    let parts: Vec<String> = path.split('.').map(|p| p.trim().to_string()).collect();
    if parts.iter().all(|p| bare_key(p)) {
        Ok(parts)
    } else {
        Err(err(line, &format!("bad section name '[{path}]'")))
    }
}

/// Strip `#` comments outside string literals; errors are caught later by
/// the value parser, so an unterminated string just stops the strip.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '#' {
            return &line[..i];
        }
    }
    line
}

/// The `[[a.b.c]]` target: descend `a.b` as tables, return the table list
/// at `c`, creating it if needed.
fn resolve_aot<'a>(root: &'a mut Table, path: &[String], line: usize) -> Result<&'a mut Vec<Table>, ParseError> {
    let (last, parents) = path.split_last().ok_or_else(|| err(line, "empty section"))?;
    let table = table_at(root, parents, line)?;
    match table.entry(last.clone()).or_insert_with(|| Value::Tables(Vec::new())) {
        Value::Tables(ts) => Ok(ts),
        _ => Err(err(line, &format!("'{last}' is already a value"))),
    }
}

/// The `[a.b.c]` target: descend `path`, creating tables as needed.
fn table_at<'a>(root: &'a mut Table, path: &[String], line: usize) -> Result<&'a mut Table, ParseError> {
    let mut table = root;
    for seg in path {
        match table.entry(seg.clone()).or_insert_with(|| Value::Table(Table::new())) {
            Value::Table(t) => table = t,
            _ => return Err(err(line, &format!("'{seg}' is already a value"))),
        }
    }
    Ok(table)
}

/// Insert a possibly-dotted `key` under `table`.
fn insert(table: &mut Table, key: &str, value: Value, line: usize) -> Result<(), ParseError> {
    let mut parts = key.split('.').peekable();
    let mut t = table;
    while let Some(k) = parts.next() {
        if parts.peek().is_some() {
            match t.entry(k.to_string()).or_insert_with(|| Value::Table(Table::new())) {
                Value::Table(inner) => t = inner,
                _ => return Err(err(line, &format!("'{k}' is already a value"))),
            }
        } else if t.insert(k.to_string(), value.clone()).is_some() {
            return Err(err(line, &format!("duplicate key '{key}'")));
        }
    }
    Ok(())
}

fn parse_value(s: &str, line: usize) -> Result<Value, ParseError> {
    if s.is_empty() {
        return Err(err(line, "missing value"));
    }
    if s.starts_with('"') {
        return parse_string(s, line).map(Value::String);
    }
    if s.starts_with('[') {
        return parse_array(s, line).map(Value::Array);
    }
    match s {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    let cleaned: String = s.chars().filter(|c| *c != '_').collect();
    if let Ok(i) = cleaned.parse::<i64>() {
        return Ok(Value::Integer(i));
    }
    if cleaned.contains(['.', 'e', 'E']) {
        if let Ok(f) = cleaned.parse::<f64>() {
            return Ok(Value::Float(f));
        }
    }
    Err(err(line, &format!("bad value '{s}'")))
}

fn parse_string(s: &str, line: usize) -> Result<String, ParseError> {
    let mut out = String::new();
    let mut chars = s[1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let rest: String = chars.collect();
                if rest.trim().is_empty() {
                    return Ok(out);
                }
                return Err(err(line, &format!("trailing text after string: '{rest}'")));
            }
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                other => return Err(err(line, &format!("bad escape '\\{}'", other.unwrap_or(' ')))),
            },
            c => out.push(c),
        }
    }
    Err(err(line, "unterminated string"))
}

/// `[v1, v2, ...]` on one line. Elements are scalars only.
fn parse_array(s: &str, line: usize) -> Result<Vec<Value>, ParseError> {
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.trim_end().strip_suffix(']'))
        .ok_or_else(|| err(line, "arrays must close on the same line"))?;
    let mut out = Vec::new();
    for part in split_commas(inner, line)? {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(parse_value(part, line)?);
    }
    Ok(out)
}

/// Split at commas not inside strings.
fn split_commas(s: &str, line: usize) -> Result<Vec<&str>, ParseError> {
    let mut parts = Vec::new();
    let mut in_str = false;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == ',' {
            parts.push(&s[start..i]);
            start = i + 1;
        }
    }
    if in_str {
        return Err(err(line, "unterminated string in array"));
    }
    parts.push(&s[start..]);
    Ok(parts)
}
