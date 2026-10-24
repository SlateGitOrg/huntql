//! Zeek log input: file discovery, schema discovery and streaming readers
//! for the TSV and JSON formats (optionally gzip-compressed).

pub mod json;
pub mod tsv;

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::exec::{ExecError, Row, RowSource};
use crate::plan::SourceSpec;
use crate::planner::SchemaProvider;
use crate::schema::{self, Schema};
use crate::value::Type;

/// Per-reader decode counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadCounters {
    pub rows: u64,
    /// Rows skipped (wrong column count, invalid JSON).
    pub bad_rows: u64,
    /// Values that failed to parse and were treated as null.
    pub bad_values: u64,
}

impl ReadCounters {
    fn add(&mut self, other: ReadCounters) {
        self.rows += other.rows;
        self.bad_rows += other.bad_rows;
        self.bad_values += other.bad_values;
    }
}

/// Maps file column positions to schema column indexes.
#[derive(Debug, Clone)]
pub struct FieldMap {
    targets: Vec<Option<usize>>,
}

impl FieldMap {
    pub fn new(file_fields: &[String], schema_names: &[String]) -> Self {
        let pos: HashMap<&str, usize> = schema_names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), i))
            .collect();
        FieldMap {
            targets: file_fields
                .iter()
                .map(|f| pos.get(f.as_str()).copied())
                .collect(),
        }
    }

    pub fn target(&self, file_col: usize) -> Option<usize> {
        self.targets.get(file_col).copied().flatten()
    }
}

/// On-disk log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Tsv,
    Json,
}

fn open(path: &Path) -> std::io::Result<Box<dyn BufRead>> {
    let file = File::open(path)?;
    let inner: Box<dyn Read> = if path.extension().is_some_and(|e| e == "gz") {
        Box::new(flate2::read::MultiGzDecoder::new(file))
    } else {
        Box::new(file)
    };
    Ok(Box::new(BufReader::with_capacity(256 * 1024, inner)))
}

/// Sniff the format from the first non-whitespace byte.
pub fn detect(reader: &mut dyn BufRead) -> std::io::Result<Format> {
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(Format::Tsv);
        }
        match buf.iter().position(|b| !b.is_ascii_whitespace()) {
            Some(i) => {
                return Ok(if buf[i] == b'{' {
                    Format::Json
                } else {
                    Format::Tsv
                })
            }
            None => {
                let n = buf.len();
                reader.consume(n);
            }
        }
    }
}

/// Which log a file name belongs to: `conn.log`, `conn.00:00:00-01:00:00.log.gz`,
/// `conn.json`, `dns.ndjson`, ...
pub fn log_name_of(file_name: &str) -> Option<&str> {
    let base = file_name.strip_suffix(".gz").unwrap_or(file_name);
    let known_ext = [".log", ".json", ".ndjson", ".jsonl"];
    if !known_ext.iter().any(|e| base.ends_with(e)) {
        return None;
    }
    let name = base.split('.').next()?;
    (!name.is_empty()).then_some(name)
}

/// The set of log files available to a query, grouped by log name.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    files: BTreeMap<String, Vec<PathBuf>>,
}

impl Catalog {
    /// Discover logs in a directory (non-recursive).
    pub fn from_dir(dir: &Path) -> std::io::Result<Catalog> {
        let mut cat = Catalog::default();
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        entries.sort();
        for path in entries {
            let Some(fname) = path.file_name().and_then(|f| f.to_str()) else {
                continue;
            };
            if let Some(log) = log_name_of(fname) {
                cat.files
                    .entry(log.to_string())
                    .or_default()
                    .push(path.clone());
            }
        }
        log::debug!(
            "catalog for {}: {:?}",
            dir.display(),
            cat.files.keys().collect::<Vec<_>>()
        );
        Ok(cat)
    }

    /// Add one explicit file under a log name.
    pub fn add_file(&mut self, log: &str, path: PathBuf) {
        self.files.entry(log.to_string()).or_default().push(path);
    }

    pub fn files(&self, log: &str) -> &[PathBuf] {
        self.files.get(log).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Discover the columns of the first file of `log` that are not in the
    /// built-in schema (e.g. fields added by local Zeek scripts).
    fn extra_columns(&self, log: &str, base: &Schema) -> Vec<(String, Type)> {
        let Some(path) = self.files(log).first() else {
            return Vec::new();
        };
        let Ok(mut r) = open(path) else {
            return Vec::new();
        };
        let fields: Vec<(String, Type)> = match detect(&mut *r) {
            Ok(Format::Tsv) => match tsv::read_header(&mut *r) {
                Ok(h) => h
                    .fields
                    .iter()
                    .zip(
                        h.types
                            .iter()
                            .map(String::as_str)
                            .chain(std::iter::repeat("string")),
                    )
                    .map(|(f, t)| (f.clone(), Type::from_zeek(t)))
                    .collect(),
                Err(_) => Vec::new(),
            },
            Ok(Format::Json) => {
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    return Vec::new();
                }
                match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&line) {
                    Ok(obj) => obj
                        .iter()
                        .map(|(k, v)| (k.clone(), json::infer_type(k, v)))
                        .collect(),
                    Err(_) => Vec::new(),
                }
            }
            Err(_) => Vec::new(),
        };
        fields
            .into_iter()
            .filter(|(f, _)| base.index_of(f).is_none())
            .collect()
    }

    /// Open a row source for a planned scan.
    pub fn open_source(&self, spec: &SourceSpec) -> Result<LogSource, ExecError> {
        let files = self.files(&spec.log).to_vec();
        if files.is_empty() {
            return Err(ExecError::Source(format!(
                "no `{}` logs found (looked for {0}.log, {0}.*.log[.gz], {0}.json, {0}.ndjson)",
                spec.log
            )));
        }
        let mut needed = vec![spec.needed.is_none(); spec.schema.len()];
        if let Some(cols) = &spec.needed {
            for &c in cols {
                needed[c] = true;
            }
        }
        Ok(LogSource {
            files,
            next_file: 0,
            names: spec.schema.columns.iter().map(|c| c.name.clone()).collect(),
            types: spec.schema.columns.iter().map(|c| c.ty).collect(),
            needed,
            current: None,
            counters: ReadCounters::default(),
        })
    }
}

impl SchemaProvider for Catalog {
    fn schema(&self, log: &str) -> Option<Schema> {
        let mut s = schema::builtin(log).or_else(|| {
            // Unknown log types are allowed if files exist: schema comes
            // entirely from the header.
            (!self.files(log).is_empty()).then(Schema::default)
        })?;
        for (name, ty) in self.extra_columns(log, &s) {
            s.push(name, ty);
        }
        Some(s)
    }

    fn logs(&self) -> Vec<String> {
        let mut names: Vec<String> = schema::LOG_NAMES.iter().map(|s| s.to_string()).collect();
        for k in self.files.keys() {
            if !names.contains(k) {
                names.push(k.clone());
            }
        }
        names
    }
}

enum Reader {
    Tsv(tsv::TsvReader<Box<dyn BufRead>>),
    Json(json::JsonReader<Box<dyn BufRead>>),
}

/// Concatenated rows of every file for one log.
pub struct LogSource {
    files: Vec<PathBuf>,
    next_file: usize,
    names: Vec<String>,
    types: Vec<Type>,
    needed: Vec<bool>,
    current: Option<Reader>,
    counters: ReadCounters,
}

impl LogSource {
    /// Decode counters accumulated so far (finished files plus current).
    pub fn counters(&self) -> ReadCounters {
        let mut c = self.counters;
        match &self.current {
            Some(Reader::Tsv(r)) => c.add(r.counters),
            Some(Reader::Json(r)) => c.add(r.counters),
            None => {}
        }
        c
    }

    fn open_next(&mut self) -> Result<bool, ExecError> {
        if let Some(prev) = self.current.take() {
            self.counters.add(match prev {
                Reader::Tsv(r) => r.counters,
                Reader::Json(r) => r.counters,
            });
        }
        let Some(path) = self.files.get(self.next_file).cloned() else {
            return Ok(false);
        };
        self.next_file += 1;
        let name = path.display().to_string();
        let mut reader = open(&path).map_err(|e| ExecError::Source(format!("{name}: {e}")))?;
        let format = detect(&mut *reader).map_err(|e| ExecError::Source(format!("{name}: {e}")))?;
        log::debug!("reading {name} as {format:?}");
        let (names, types, needed) = (self.names.clone(), self.types.clone(), self.needed.clone());
        self.current = Some(match format {
            Format::Tsv => Reader::Tsv(tsv::TsvReader::new(reader, name, names, types, needed)),
            Format::Json => Reader::Json(json::JsonReader::new(reader, name, names, types, needed)),
        });
        Ok(true)
    }
}

impl RowSource for LogSource {
    fn next_row(&mut self) -> Result<Option<Row>, ExecError> {
        loop {
            let row = match &mut self.current {
                Some(Reader::Tsv(r)) => r.next_row()?,
                Some(Reader::Json(r)) => r.next_row()?,
                None => None,
            };
            if row.is_some() {
                return Ok(row);
            }
            if !self.open_next()? {
                return Ok(None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names() {
        assert_eq!(log_name_of("conn.log"), Some("conn"));
        assert_eq!(log_name_of("conn.00:00:00-01:00:00.log.gz"), Some("conn"));
        assert_eq!(log_name_of("dns.json"), Some("dns"));
        assert_eq!(log_name_of("x.ndjson"), Some("x"));
        assert_eq!(log_name_of("README.md"), None);
        assert_eq!(log_name_of(".log"), None);
    }

    #[test]
    fn detects_format() {
        let mut j = &b"  \n{\"a\":1}"[..];
        assert_eq!(detect(&mut j).unwrap(), Format::Json);
        let mut t = &b"#separator"[..];
        assert_eq!(detect(&mut t).unwrap(), Format::Tsv);
        let mut e = &b""[..];
        assert_eq!(detect(&mut e).unwrap(), Format::Tsv);
    }

    #[test]
    fn field_map() {
        let m = FieldMap::new(
            &["b".into(), "z".into(), "a".into()],
            &["a".into(), "b".into()],
        );
        assert_eq!(m.target(0), Some(1));
        assert_eq!(m.target(1), None);
        assert_eq!(m.target(2), Some(0));
        assert_eq!(m.target(9), None);
    }
}
