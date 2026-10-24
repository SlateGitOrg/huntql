//! Column schemas: built-in Zeek log layouts and the per-stage schema the
//! planner threads through a pipeline.

use crate::value::Type;

/// A named, typed column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub ty: Type,
}

impl Column {
    pub fn new(name: impl Into<String>, ty: Type) -> Self {
        Column {
            name: name.into(),
            ty,
        }
    }
}

/// Ordered list of columns; rows are `Vec<Value>` in the same order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Schema {
    pub columns: Vec<Column>,
}

/// Short names for the Zeek connection 4-tuple, valid on every log.
pub const ALIASES: &[(&str, &str)] = &[
    ("src", "id.orig_h"),
    ("sport", "id.orig_p"),
    ("dst", "id.resp_h"),
    ("dport", "id.resp_p"),
];

impl Schema {
    pub fn new(columns: Vec<Column>) -> Self {
        Schema { columns }
    }

    pub fn len(&self) -> usize {
        self.columns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    /// Exact-name lookup.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.name == name)
    }

    /// Lookup that also understands the 4-tuple aliases (`src`, `dport`, ...).
    pub fn resolve(&self, name: &str) -> Option<usize> {
        self.index_of(name).or_else(|| {
            ALIASES
                .iter()
                .find(|(alias, _)| *alias == name)
                .and_then(|(_, real)| self.index_of(real))
        })
    }

    /// Candidate names for "did you mean" suggestions.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.columns.iter().map(|c| c.name.as_str()).chain(
            ALIASES
                .iter()
                .filter(|(_, real)| self.index_of(real).is_some())
                .map(|(alias, _)| *alias),
        )
    }

    pub fn push(&mut self, name: impl Into<String>, ty: Type) -> usize {
        self.columns.push(Column::new(name, ty));
        self.columns.len() - 1
    }
}

/// The log types huntql knows out of the box.
pub const LOG_NAMES: &[&str] = &["conn", "dns", "http", "ssl"];

const ID_FIELDS: &[(&str, &str)] = &[
    ("ts", "time"),
    ("uid", "string"),
    ("id.orig_h", "addr"),
    ("id.orig_p", "port"),
    ("id.resp_h", "addr"),
    ("id.resp_p", "port"),
];

const CONN: &[(&str, &str)] = &[
    ("proto", "enum"),
    ("service", "string"),
    ("duration", "interval"),
    ("orig_bytes", "count"),
    ("resp_bytes", "count"),
    ("conn_state", "string"),
    ("local_orig", "bool"),
    ("local_resp", "bool"),
    ("missed_bytes", "count"),
    ("history", "string"),
    ("orig_pkts", "count"),
    ("orig_ip_bytes", "count"),
    ("resp_pkts", "count"),
    ("resp_ip_bytes", "count"),
    ("tunnel_parents", "set[string]"),
];

const DNS: &[(&str, &str)] = &[
    ("proto", "enum"),
    ("trans_id", "count"),
    ("rtt", "interval"),
    ("query", "string"),
    ("qclass", "count"),
    ("qclass_name", "string"),
    ("qtype", "count"),
    ("qtype_name", "string"),
    ("rcode", "count"),
    ("rcode_name", "string"),
    ("AA", "bool"),
    ("TC", "bool"),
    ("RD", "bool"),
    ("RA", "bool"),
    ("Z", "count"),
    ("answers", "vector[string]"),
    ("TTLs", "vector[interval]"),
    ("rejected", "bool"),
];

const HTTP: &[(&str, &str)] = &[
    ("trans_depth", "count"),
    ("method", "string"),
    ("host", "string"),
    ("uri", "string"),
    ("referrer", "string"),
    ("version", "string"),
    ("user_agent", "string"),
    ("origin", "string"),
    ("request_body_len", "count"),
    ("response_body_len", "count"),
    ("status_code", "count"),
    ("status_msg", "string"),
    ("info_code", "count"),
    ("info_msg", "string"),
    ("tags", "set[enum]"),
    ("username", "string"),
    ("password", "string"),
    ("proxied", "set[string]"),
    ("orig_fuids", "vector[string]"),
    ("orig_filenames", "vector[string]"),
    ("orig_mime_types", "vector[string]"),
    ("resp_fuids", "vector[string]"),
    ("resp_filenames", "vector[string]"),
    ("resp_mime_types", "vector[string]"),
];

const SSL: &[(&str, &str)] = &[
    ("version", "string"),
    ("cipher", "string"),
    ("curve", "string"),
    ("server_name", "string"),
    ("resumed", "bool"),
    ("last_alert", "string"),
    ("next_protocol", "string"),
    ("established", "bool"),
    ("ssl_history", "string"),
    ("cert_chain_fps", "vector[string]"),
    ("client_cert_chain_fps", "vector[string]"),
    ("subject", "string"),
    ("issuer", "string"),
    ("validation_status", "string"),
    ("ja3", "string"),
    ("ja3s", "string"),
];

/// Zeek field names and Zeek type names for a built-in log, in Zeek's
/// default column order. Used by both the reader and the log generator.
pub fn zeek_fields(log: &str) -> Option<Vec<(&'static str, &'static str)>> {
    let tail = match log {
        "conn" => CONN,
        "dns" => DNS,
        "http" => HTTP,
        "ssl" => SSL,
        _ => return None,
    };
    Some(ID_FIELDS.iter().chain(tail.iter()).copied().collect())
}

/// Built-in schema for a Zeek log.
pub fn builtin(log: &str) -> Option<Schema> {
    zeek_fields(log).map(|fields| {
        Schema::new(
            fields
                .into_iter()
                .map(|(n, t)| Column::new(n, Type::from_zeek(t)))
                .collect(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_schemas_resolve_aliases() {
        for log in LOG_NAMES {
            let s = builtin(log).unwrap();
            assert_eq!(s.resolve("src"), s.index_of("id.orig_h"));
            assert_eq!(s.columns[0].ty, Type::Time);
            assert!(s.names().any(|n| n == "dport"));
        }
        assert!(builtin("weird").is_none());
        let conn = builtin("conn").unwrap();
        assert_eq!(
            conn.columns[conn.resolve("duration").unwrap()].ty,
            Type::Duration
        );
        assert_eq!(conn.columns[conn.resolve("dport").unwrap()].ty, Type::Int);
        assert!(conn.resolve("nope").is_none());
    }

    #[test]
    fn aliases_only_offered_when_backing_field_exists() {
        let mut s = Schema::default();
        assert!(s.is_empty());
        s.push("count", Type::Int);
        assert_eq!(s.len(), 1);
        assert_eq!(s.names().collect::<Vec<_>>(), vec!["count"]);
    }
}
