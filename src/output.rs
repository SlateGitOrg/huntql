//! Result formatters: aligned table (buffered), TSV and NDJSON (streaming).

use std::io::{self, Write};
use std::str::FromStr;

use crate::exec::{ExecError, Flow, Row, Sink};
use crate::schema::Schema;
use crate::value::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Tsv,
    Json,
}

impl FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "table" => Ok(OutputFormat::Table),
            "tsv" => Ok(OutputFormat::Tsv),
            "json" | "ndjson" => Ok(OutputFormat::Json),
            other => Err(format!(
                "unknown format `{other}` (expected table, tsv or json)"
            )),
        }
    }
}

/// Build a sink for the given format.
pub fn sink<'a>(
    format: OutputFormat,
    schema: &Schema,
    out: Box<dyn Write + 'a>,
) -> Box<dyn Sink + 'a> {
    let names: Vec<String> = schema.columns.iter().map(|c| c.name.clone()).collect();
    match format {
        OutputFormat::Table => Box::new(TableSink {
            names,
            rows: Vec::new(),
            out,
        }),
        OutputFormat::Tsv => Box::new(TsvSink {
            names,
            out,
            header_done: false,
        }),
        OutputFormat::Json => Box::new(JsonSink { names, out }),
    }
}

/// Map a write error to a flow decision: a closed pipe ends the query quietly.
fn handle(r: io::Result<()>) -> Result<Flow, ExecError> {
    match r {
        Ok(()) => Ok(Flow::Continue),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(Flow::Stop),
        Err(e) => Err(e.into()),
    }
}

/// Buffers all rows to compute column widths. Cells longer than 60 chars are
/// truncated with an ellipsis.
pub struct TableSink<'a> {
    names: Vec<String>,
    rows: Vec<Vec<String>>,
    out: Box<dyn Write + 'a>,
}

const MAX_CELL: usize = 60;

fn cell(v: &Value) -> String {
    let s = v.to_string().replace(['\t', '\n'], " ");
    if s.chars().count() > MAX_CELL {
        let mut t: String = s.chars().take(MAX_CELL - 1).collect();
        t.push('…');
        t
    } else {
        s
    }
}

impl Sink for TableSink<'_> {
    fn write(&mut self, row: Row) -> Result<Flow, ExecError> {
        self.rows.push(row.iter().map(cell).collect());
        Ok(Flow::Continue)
    }

    fn finish(&mut self) -> Result<(), ExecError> {
        let mut widths: Vec<usize> = self.names.iter().map(|n| n.chars().count()).collect();
        for r in &self.rows {
            for (w, c) in widths.iter_mut().zip(r) {
                *w = (*w).max(c.chars().count());
            }
        }
        let line = |cells: &[String]| -> String {
            cells
                .iter()
                .zip(&widths)
                .map(|(c, w)| format!("{c:<w$}"))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        };
        let mut text = String::new();
        text.push_str(&line(&self.names));
        text.push('\n');
        text.push_str(
            &widths
                .iter()
                .map(|w| "-".repeat(*w))
                .collect::<Vec<_>>()
                .join("  "),
        );
        text.push('\n');
        for r in &self.rows {
            text.push_str(&line(r));
            text.push('\n');
        }
        let n = self.rows.len();
        text.push_str(&format!("({n} row{})\n", if n == 1 { "" } else { "s" }));
        handle(
            self.out
                .write_all(text.as_bytes())
                .and_then(|_| self.out.flush()),
        )?;
        Ok(())
    }
}

pub struct TsvSink<'a> {
    names: Vec<String>,
    out: Box<dyn Write + 'a>,
    header_done: bool,
}

impl Sink for TsvSink<'_> {
    fn write(&mut self, row: Row) -> Result<Flow, ExecError> {
        if !self.header_done {
            self.header_done = true;
            let h = self.names.join("\t");
            if handle(writeln!(self.out, "{h}"))? == Flow::Stop {
                return Ok(Flow::Stop);
            }
        }
        let line: Vec<String> = row
            .iter()
            .map(|v| v.to_string().replace(['\t', '\n'], " "))
            .collect();
        handle(writeln!(self.out, "{}", line.join("\t")))
    }

    fn finish(&mut self) -> Result<(), ExecError> {
        if !self.header_done {
            self.header_done = true;
            handle(writeln!(self.out, "{}", self.names.join("\t")))?;
        }
        handle(self.out.flush())?;
        Ok(())
    }
}

/// Convert a value to JSON: times as ISO-8601 strings, durations as seconds.
pub fn to_json(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Int(i) => J::from(*i),
        Value::Float(f) => serde_json::Number::from_f64(*f).map_or(J::Null, J::Number),
        Value::Duration(us) => {
            serde_json::Number::from_f64(*us as f64 / 1e6).map_or(J::Null, J::Number)
        }
        other => J::String(other.to_string()),
    }
}

pub struct JsonSink<'a> {
    names: Vec<String>,
    out: Box<dyn Write + 'a>,
}

impl Sink for JsonSink<'_> {
    fn write(&mut self, row: Row) -> Result<Flow, ExecError> {
        let obj: serde_json::Map<String, serde_json::Value> = self
            .names
            .iter()
            .cloned()
            .zip(row.iter().map(to_json))
            .collect();
        handle(writeln!(self.out, "{}", serde_json::Value::Object(obj)))
    }

    fn finish(&mut self) -> Result<(), ExecError> {
        handle(self.out.flush())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Type;

    fn schema() -> Schema {
        let mut s = Schema::default();
        s.push("name", Type::Str);
        s.push("n", Type::Int);
        s
    }

    fn render(format: OutputFormat, rows: Vec<Row>) -> String {
        let mut buf = Vec::new();
        {
            let mut sink = sink(format, &schema(), Box::new(&mut buf));
            for r in rows {
                sink.write(r).unwrap();
            }
            sink.finish().unwrap();
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn table_alignment() {
        let out = render(
            OutputFormat::Table,
            vec![
                vec![Value::str("alpha"), Value::Int(1)],
                vec![Value::str("b"), Value::Null],
            ],
        );
        assert_eq!(out, "name   n\n-----  -\nalpha  1\nb      -\n(2 rows)\n");
        let long = "x".repeat(100);
        let out = render(
            OutputFormat::Table,
            vec![vec![Value::str(&long), Value::Int(1)]],
        );
        assert!(out.contains('…'));
        assert!(out.ends_with("(1 row)\n"));
    }

    #[test]
    fn tsv_and_json() {
        let out = render(
            OutputFormat::Tsv,
            vec![vec![Value::str("a\tb"), Value::Int(2)]],
        );
        assert_eq!(out, "name\tn\na b\t2\n");
        assert_eq!(render(OutputFormat::Tsv, vec![]), "name\tn\n");
        let out = render(
            OutputFormat::Json,
            vec![vec![Value::str("a"), Value::Int(2)]],
        );
        assert_eq!(out, "{\"n\":2,\"name\":\"a\"}\n");
        assert_eq!(to_json(&Value::Duration(1_500_000)), serde_json::json!(1.5));
        assert_eq!(to_json(&Value::Float(f64::NAN)), serde_json::Value::Null);
        assert_eq!(
            to_json(&Value::Time(0)),
            serde_json::json!("1970-01-01T00:00:00Z")
        );
        assert_eq!(to_json(&Value::Bool(true)), serde_json::json!(true));
        assert_eq!(to_json(&Value::Null), serde_json::Value::Null);
    }

    #[test]
    fn formats_parse() {
        assert_eq!("table".parse::<OutputFormat>(), Ok(OutputFormat::Table));
        assert_eq!("ndjson".parse::<OutputFormat>(), Ok(OutputFormat::Json));
        assert_eq!("tsv".parse::<OutputFormat>(), Ok(OutputFormat::Tsv));
        assert!("xml".parse::<OutputFormat>().is_err());
    }

    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn broken_pipe_stops_quietly() {
        let mut s = sink(OutputFormat::Tsv, &schema(), Box::new(Broken));
        assert_eq!(
            s.write(vec![Value::str("a"), Value::Int(1)]).unwrap(),
            Flow::Stop
        );
        let mut j = sink(OutputFormat::Json, &schema(), Box::new(Broken));
        assert_eq!(
            j.write(vec![Value::str("a"), Value::Int(1)]).unwrap(),
            Flow::Stop
        );
    }
}
