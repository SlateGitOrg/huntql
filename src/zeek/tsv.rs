//! Zeek ASCII (TSV) log reader.
//!
//! Handles the standard header directives (`#separator`, `#set_separator`,
//! `#empty_field`, `#unset_field`, `#fields`, `#types`, `#close`), Zeek's
//! `\xHH` string escaping, and decodes only the columns the plan needs.

use std::io::BufRead;

use super::{FieldMap, ReadCounters};
use crate::exec::{ExecError, Row};
use crate::value::{Type, Value};

/// Parsed TSV header.
#[derive(Debug, Clone, PartialEq)]
pub struct TsvHeader {
    pub separator: String,
    pub set_separator: String,
    pub empty_field: String,
    pub unset_field: String,
    pub path: Option<String>,
    pub fields: Vec<String>,
    pub types: Vec<String>,
}

impl Default for TsvHeader {
    fn default() -> Self {
        TsvHeader {
            separator: "\t".into(),
            set_separator: ",".into(),
            empty_field: "(empty)".into(),
            unset_field: "-".into(),
            path: None,
            fields: Vec::new(),
            types: Vec::new(),
        }
    }
}

/// Decode Zeek's `\xHH` escapes (used for separators and non-printables).
pub fn unescape(s: &str) -> String {
    if !s.contains("\\x") {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes.get(i + 1) == Some(&b'x') {
            if let Some(hex) = s.get(i + 2..i + 4) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl TsvHeader {
    /// Apply one `#...` header line. Returns false for unknown directives.
    pub fn apply(&mut self, line: &str) -> bool {
        let body = &line[1..];
        if let Some(rest) = body.strip_prefix("separator ") {
            self.separator = unescape(rest.trim_end());
            return true;
        }
        let Some((key, value)) = body.split_once(&*self.separator) else {
            return false;
        };
        let parts = || {
            value
                .split(&*self.separator)
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        match key {
            "set_separator" => self.set_separator = unescape(value),
            "empty_field" => self.empty_field = value.to_string(),
            "unset_field" => self.unset_field = value.to_string(),
            "path" => self.path = Some(value.to_string()),
            "fields" => self.fields = parts(),
            "types" => self.types = parts(),
            "open" | "close" => {}
            _ => return false,
        }
        true
    }
}

/// Read only the header of a TSV log (used for schema discovery).
pub fn read_header(reader: &mut dyn BufRead) -> std::io::Result<TsvHeader> {
    let mut header = TsvHeader::default();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let l = line.trim_end_matches(['\n', '\r']);
        if !l.starts_with('#') {
            break;
        }
        header.apply(l);
        if !header.fields.is_empty() && !header.types.is_empty() {
            break;
        }
    }
    Ok(header)
}

/// Streaming TSV row decoder for one file.
pub struct TsvReader<R: BufRead> {
    reader: R,
    name: String,
    header: TsvHeader,
    map: Option<FieldMap>,
    width: usize,
    needed: Vec<bool>,
    types: Vec<Type>,
    names: Vec<String>,
    line_no: u64,
    buf: String,
    pub counters: ReadCounters,
}

impl<R: BufRead> TsvReader<R> {
    /// `names`/`types` describe the target schema; `needed[i]` says whether
    /// column `i` must be decoded.
    pub fn new(
        reader: R,
        name: String,
        names: Vec<String>,
        types: Vec<Type>,
        needed: Vec<bool>,
    ) -> Self {
        TsvReader {
            reader,
            name,
            header: TsvHeader::default(),
            map: None,
            width: names.len(),
            needed,
            types,
            names,
            line_no: 0,
            buf: String::new(),
            counters: ReadCounters::default(),
        }
    }

    pub fn next_row(&mut self) -> Result<Option<Row>, ExecError> {
        loop {
            self.buf.clear();
            let n = self
                .reader
                .read_line(&mut self.buf)
                .map_err(|e| ExecError::Source(format!("{}: {e}", self.name)))?;
            if n == 0 {
                return Ok(None);
            }
            self.line_no += 1;
            let line = self.buf.trim_end_matches(['\n', '\r']);
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                let line = line.to_string();
                if self.header.apply(&line) && line.starts_with("#fields") {
                    self.map = Some(FieldMap::new(&self.header.fields, &self.names));
                }
                continue;
            }
            let Some(map) = &self.map else {
                return Err(ExecError::Source(format!(
                    "{}:{}: data before `#fields` header (is this a Zeek TSV log?)",
                    self.name, self.line_no
                )));
            };
            let mut row = vec![Value::Null; self.width];
            let mut cols = 0;
            for (file_col, raw) in line.split(&*self.header.separator).enumerate() {
                cols += 1;
                let Some(target) = map.target(file_col) else {
                    continue;
                };
                if !self.needed[target] || raw == self.header.unset_field {
                    continue;
                }
                let ty = self.types[target];
                row[target] = if raw == self.header.empty_field {
                    if ty == Type::Str {
                        Value::str("")
                    } else {
                        Value::Null
                    }
                } else if ty == Type::Str {
                    Value::str(&unescape(raw))
                } else {
                    match Value::parse_as(ty, raw) {
                        Some(v) => v,
                        None => {
                            self.counters.bad_values += 1;
                            if self.counters.bad_values <= 3 {
                                log::warn!(
                                    "{}:{}: cannot parse {raw:?} as {ty} for `{}`",
                                    self.name,
                                    self.line_no,
                                    self.names[target]
                                );
                            }
                            Value::Null
                        }
                    }
                };
            }
            if cols != self.header.fields.len() {
                self.counters.bad_rows += 1;
                if self.counters.bad_rows <= 3 {
                    log::warn!(
                        "{}:{}: expected {} columns, found {cols}; row skipped",
                        self.name,
                        self.line_no,
                        self.header.fields.len()
                    );
                }
                continue;
            }
            self.counters.rows += 1;
            return Ok(Some(row));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n\
#fields\tts\tid.orig_h\tid.resp_p\tservice\textra\n#types\ttime\taddr\tport\tstring\tstring\n\
1700000000.5\t10.0.0.1\t443\tssl\tx\n\
1700000001.0\t10.0.0.2\t-\t(empty)\ty\n\
notatime\t10.0.0.3\t80\ta\\x09b\tz\n\
1700000002.0\t10.0.0.4\n\
#close\t2023-11-14-22-00-00\n";

    fn reader() -> TsvReader<&'static [u8]> {
        let names = vec![
            "ts".into(),
            "id.orig_h".into(),
            "id.resp_p".into(),
            "service".into(),
        ];
        let types = vec![Type::Time, Type::Addr, Type::Int, Type::Str];
        TsvReader::new(
            LOG.as_bytes(),
            "conn.log".into(),
            names,
            types,
            vec![true, true, true, true],
        )
    }

    #[test]
    fn reads_rows_with_nulls_escapes_and_bad_lines() {
        let mut r = reader();
        let a = r.next_row().unwrap().unwrap();
        assert_eq!(a[0], Value::Time(1_700_000_000_500_000));
        assert_eq!(a[2], Value::Int(443));
        assert_eq!(a[3], Value::str("ssl"));
        let b = r.next_row().unwrap().unwrap();
        assert_eq!(b[2], Value::Null);
        assert_eq!(b[3], Value::str(""));
        let c = r.next_row().unwrap().unwrap();
        assert_eq!(c[0], Value::Null);
        assert_eq!(c[3], Value::str("a\tb"));
        assert!(r.next_row().unwrap().is_none());
        assert_eq!(r.counters.rows, 3);
        assert_eq!(r.counters.bad_values, 1);
        assert_eq!(r.counters.bad_rows, 1);
    }

    #[test]
    fn header_only_read() {
        let mut input = LOG.as_bytes();
        let h = read_header(&mut input).unwrap();
        assert_eq!(h.fields.len(), 5);
        assert_eq!(h.types[4], "string");
        assert_eq!(h.path.as_deref(), Some("conn"));
        assert_eq!(h.separator, "\t");
    }

    #[test]
    fn data_before_header_is_an_error() {
        let mut r = TsvReader::new(
            &b"1\t2\n"[..],
            "x.log".into(),
            vec!["a".into()],
            vec![Type::Int],
            vec![true],
        );
        let e = r.next_row().unwrap_err();
        assert!(e.to_string().contains("before `#fields`"));
    }

    #[test]
    fn unescape_handles_partial_sequences() {
        assert_eq!(unescape("a\\x41b"), "aAb");
        assert_eq!(unescape("\\xZZ"), "\\xZZ");
        assert_eq!(unescape("end\\x4"), "end\\x4");
        assert_eq!(unescape("plain"), "plain");
        let mut h = TsvHeader::default();
        assert!(!h.apply("#bogus\tx"));
        assert!(!h.apply("#nodelimiter"));
    }
}
