//! Zeek JSON (NDJSON) log reader: one object per line with flat dotted keys
//! (`"id.orig_h"`), timestamps as epoch numbers or ISO-8601 strings.

use std::collections::HashMap;
use std::io::BufRead;

use super::ReadCounters;
use crate::exec::{ExecError, Row};
use crate::timefmt;
use crate::value::{Subnet, Type, Value};

/// Convert one JSON value to a typed value; `None` means "present but
/// unparseable".
pub fn convert(ty: Type, v: &serde_json::Value) -> Option<Value> {
    use serde_json::Value as J;
    Some(match (ty, v) {
        (_, J::Null) => Value::Null,
        (Type::Str, J::String(s)) => Value::str(s),
        (Type::Str, J::Array(items)) => {
            let parts: Vec<String> = items
                .iter()
                .map(|i| match i {
                    J::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            Value::str(&parts.join(","))
        }
        (Type::Str, other) => Value::str(&other.to_string()),
        (Type::Int, J::Number(n)) => Value::Int(n.as_i64()?),
        (Type::Float, J::Number(n)) => Value::Float(n.as_f64()?),
        (Type::Bool, J::Bool(b)) => Value::Bool(*b),
        (Type::Time, J::Number(n)) => {
            Value::Time(timefmt::parse_seconds_to_micros(&n.to_string())?)
        }
        (Type::Time, J::String(s)) => Value::Time(timefmt::parse_epoch_or_iso(s)?),
        (Type::Duration, J::Number(n)) => {
            Value::Duration(timefmt::parse_seconds_to_micros(&n.to_string())?)
        }
        (Type::Addr, J::String(s)) => Value::Addr(s.parse().ok()?),
        (Type::Subnet, J::String(s)) => Value::Subnet(Subnet::parse(s)?),
        _ => return None,
    })
}

/// Map a serde_json value to the closest query type (for schema discovery).
pub fn infer_type(key: &str, v: &serde_json::Value) -> Type {
    use serde_json::Value as J;
    match v {
        J::Bool(_) => Type::Bool,
        J::Number(n) if n.is_i64() || n.is_u64() => Type::Int,
        J::Number(_) if key == "ts" => Type::Time,
        J::Number(_) => Type::Float,
        _ => Type::Str,
    }
}

pub struct JsonReader<R: BufRead> {
    reader: R,
    name: String,
    columns: HashMap<String, usize>,
    width: usize,
    types: Vec<Type>,
    needed: Vec<bool>,
    line_no: u64,
    buf: String,
    pub counters: ReadCounters,
}

impl<R: BufRead> JsonReader<R> {
    pub fn new(
        reader: R,
        name: String,
        names: Vec<String>,
        types: Vec<Type>,
        needed: Vec<bool>,
    ) -> Self {
        JsonReader {
            reader,
            name,
            width: names.len(),
            columns: names.into_iter().enumerate().map(|(i, n)| (n, i)).collect(),
            types,
            needed,
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
            let line = self.buf.trim();
            if line.is_empty() {
                continue;
            }
            let obj: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(line) {
                Ok(o) => o,
                Err(e) => {
                    self.counters.bad_rows += 1;
                    if self.counters.bad_rows <= 3 {
                        log::warn!(
                            "{}:{}: invalid JSON ({e}); row skipped",
                            self.name,
                            self.line_no
                        );
                    }
                    continue;
                }
            };
            let mut row = vec![Value::Null; self.width];
            for (key, val) in &obj {
                let Some(&i) = self.columns.get(key) else {
                    continue;
                };
                if !self.needed[i] {
                    continue;
                }
                row[i] = match convert(self.types[i], val) {
                    Some(v) => v,
                    None => {
                        self.counters.bad_values += 1;
                        if self.counters.bad_values <= 3 {
                            log::warn!(
                                "{}:{}: cannot convert `{key}` = {val}",
                                self.name,
                                self.line_no
                            );
                        }
                        Value::Null
                    }
                };
            }
            self.counters.rows += 1;
            return Ok(Some(row));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn converts_zeek_json_types() {
        assert_eq!(
            convert(Type::Time, &json!(1700000000.123456)),
            Some(Value::Time(1_700_000_000_123_456))
        );
        assert_eq!(
            convert(Type::Time, &json!("2023-11-14T22:13:20.000000Z")),
            Some(Value::Time(1_700_000_000_000_000))
        );
        assert_eq!(
            convert(Type::Duration, &json!(0.25)),
            Some(Value::Duration(250_000))
        );
        assert_eq!(
            convert(Type::Str, &json!(["a", "b", 3])),
            Some(Value::str("a,b,3"))
        );
        assert_eq!(convert(Type::Str, &json!(5)), Some(Value::str("5")));
        assert_eq!(convert(Type::Int, &json!(1.5)), None);
        assert_eq!(convert(Type::Float, &json!(1.5)), Some(Value::Float(1.5)));
        assert_eq!(convert(Type::Bool, &json!(true)), Some(Value::Bool(true)));
        assert_eq!(
            convert(Type::Addr, &json!("::1")),
            Some(Value::Addr("::1".parse().unwrap()))
        );
        assert_eq!(
            convert(Type::Subnet, &json!("10.0.0.0/8")).unwrap().ty(),
            Type::Subnet
        );
        assert_eq!(convert(Type::Addr, &json!(1)), None);
        assert_eq!(
            convert(Type::Int, &serde_json::Value::Null),
            Some(Value::Null)
        );
        assert_eq!(infer_type("ts", &json!(1.5)), Type::Time);
        assert_eq!(infer_type("x", &json!(1.5)), Type::Float);
        assert_eq!(infer_type("x", &json!(1)), Type::Int);
        assert_eq!(infer_type("x", &json!(true)), Type::Bool);
        assert_eq!(infer_type("x", &json!("s")), Type::Str);
    }

    #[test]
    fn reads_lines_and_skips_garbage() {
        let data = "{\"ts\":1700000000.5,\"id.orig_h\":\"10.0.0.1\",\"id.resp_p\":443}\n\nnot json\n{\"ts\":\"bad\",\"id.resp_p\":80,\"unknown\":1}\n";
        let mut r = JsonReader::new(
            data.as_bytes(),
            "conn.json".into(),
            vec!["ts".into(), "id.orig_h".into(), "id.resp_p".into()],
            vec![Type::Time, Type::Addr, Type::Int],
            vec![true, false, true],
        );
        let a = r.next_row().unwrap().unwrap();
        assert_eq!(a[0], Value::Time(1_700_000_000_500_000));
        assert_eq!(a[1], Value::Null, "column not needed");
        assert_eq!(a[2], Value::Int(443));
        let b = r.next_row().unwrap().unwrap();
        assert_eq!(b[0], Value::Null);
        assert!(r.next_row().unwrap().is_none());
        assert_eq!(
            (r.counters.rows, r.counters.bad_rows, r.counters.bad_values),
            (2, 1, 1)
        );
    }
}
