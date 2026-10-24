//! Runtime values and their static types.
//!
//! Zeek's type system is mapped onto a small set of query types:
//!
//! | Zeek type                 | huntql type |
//! |---------------------------|-------------|
//! | `count`, `int`, `port`    | `int`       |
//! | `double`                  | `float`     |
//! | `time`                    | `time`      |
//! | `interval`                | `duration`  |
//! | `addr`                    | `addr`      |
//! | `subnet`                  | `subnet`    |
//! | `bool`                    | `bool`      |
//! | `string`, `enum`, sets, vectors | `string` (containers are kept as their comma-joined text) |

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::rc::Rc;

use crate::timefmt;

/// Static type of a column or expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    Bool,
    Int,
    Float,
    Str,
    /// Absolute timestamp (microseconds since the Unix epoch).
    Time,
    /// Time span in microseconds.
    Duration,
    Addr,
    Subnet,
    /// The type of the `null` literal; compatible with every type.
    Null,
}

impl Type {
    pub fn is_numeric(self) -> bool {
        matches!(self, Type::Int | Type::Float)
    }

    /// Parse a Zeek `#types` header entry into a query type.
    pub fn from_zeek(name: &str) -> Type {
        match name {
            "count" | "int" | "port" => Type::Int,
            "double" => Type::Float,
            "time" => Type::Time,
            "interval" => Type::Duration,
            "addr" => Type::Addr,
            "subnet" => Type::Subnet,
            "bool" => Type::Bool,
            _ => Type::Str,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Type::Bool => "bool",
            Type::Int => "int",
            Type::Float => "float",
            Type::Str => "string",
            Type::Time => "time",
            Type::Duration => "duration",
            Type::Addr => "addr",
            Type::Subnet => "subnet",
            Type::Null => "null",
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An IPv4/IPv6 network in CIDR notation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Subnet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Subnet {
    /// Parse `a.b.c.d/n` or `v6::/n`.
    pub fn parse(s: &str) -> Option<Subnet> {
        let (a, p) = s.split_once('/')?;
        let addr: IpAddr = a.parse().ok()?;
        let prefix: u8 = p.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Subnet { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(net) & mask) == (u128::from(*ip) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// A single runtime value. Strings are reference counted so that grouping
/// operators can keep keys without copying them.
#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    Time(i64),
    Duration(i64),
    Addr(IpAddr),
    Subnet(Subnet),
}

impl Value {
    pub fn str(s: &str) -> Value {
        Value::Str(Rc::from(s))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn ty(&self) -> Type {
        match self {
            Value::Null => Type::Null,
            Value::Bool(_) => Type::Bool,
            Value::Int(_) => Type::Int,
            Value::Float(_) => Type::Float,
            Value::Str(_) => Type::Str,
            Value::Time(_) => Type::Time,
            Value::Duration(_) => Type::Duration,
            Value::Addr(_) => Type::Addr,
            Value::Subnet(_) => Type::Subnet,
        }
    }

    /// Numeric view used by aggregations (`sum`, `avg`, ...). Durations and
    /// times are exposed in seconds.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::Duration(us) | Value::Time(us) => Some(*us as f64 / 1e6),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> bool {
        matches!(self, Value::Bool(true))
    }

    /// Parse a raw Zeek field (TSV text) into a value of type `ty`.
    /// Returns `Value::Null` for unparseable input; the reader counts those.
    pub fn parse_as(ty: Type, raw: &str) -> Option<Value> {
        Some(match ty {
            Type::Str => Value::str(raw),
            Type::Int => Value::Int(raw.parse().ok()?),
            Type::Float => Value::Float(raw.parse().ok()?),
            Type::Bool => match raw {
                "T" | "true" => Value::Bool(true),
                "F" | "false" => Value::Bool(false),
                _ => return None,
            },
            Type::Time => Value::Time(timefmt::parse_epoch_or_iso(raw)?),
            Type::Duration => Value::Duration(timefmt::parse_seconds_to_micros(raw)?),
            Type::Addr => Value::Addr(raw.parse().ok()?),
            Type::Subnet => Value::Subnet(Subnet::parse(raw)?),
            Type::Null => Value::Null,
        })
    }

    /// Total order used by `sort`: nulls first, then by type rank, then value.
    pub fn total_cmp(&self, other: &Value) -> Ordering {
        match (self, other) {
            (Value::Int(a), Value::Float(b)) => (*a as f64).total_cmp(b),
            (Value::Float(a), Value::Int(b)) => a.total_cmp(&(*b as f64)),
            _ => match self.rank().cmp(&other.rank()) {
                Ordering::Equal => self.cmp_same(other).unwrap_or(Ordering::Equal),
                o => o,
            },
        }
    }

    /// Comparison for `<`, `==`, ... in expressions. `None` if either side is
    /// null or the types are incomparable.
    pub fn partial_compare(&self, other: &Value) -> Option<Ordering> {
        match (self, other) {
            (Value::Null, _) | (_, Value::Null) => None,
            (Value::Int(a), Value::Float(b)) => (*a as f64).partial_cmp(b),
            (Value::Float(a), Value::Int(b)) => a.partial_cmp(&(*b as f64)),
            _ if self.rank() == other.rank() => self.cmp_same(other),
            _ => None,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::Int(_) | Value::Float(_) => 2,
            Value::Duration(_) => 3,
            Value::Time(_) => 4,
            Value::Addr(_) => 5,
            Value::Subnet(_) => 6,
            Value::Str(_) => 7,
        }
    }

    fn cmp_same(&self, other: &Value) -> Option<Ordering> {
        Some(match (self, other) {
            (Value::Null, Value::Null) => Ordering::Equal,
            (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
            (Value::Int(a), Value::Int(b)) => a.cmp(b),
            (Value::Float(a), Value::Float(b)) => a.total_cmp(b),
            (Value::Duration(a), Value::Duration(b)) | (Value::Time(a), Value::Time(b)) => a.cmp(b),
            (Value::Addr(a), Value::Addr(b)) => a.cmp(b),
            (Value::Subnet(a), Value::Subnet(b)) => (a.addr, a.prefix).cmp(&(b.addr, b.prefix)),
            (Value::Str(a), Value::Str(b)) => a.cmp(b),
            _ => return None,
        })
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Float(a), Value::Float(b)) => a.to_bits() == b.to_bits(),
            _ => self.rank() == other.rank() && self.cmp_same(other) == Some(Ordering::Equal),
        }
    }
}

impl Eq for Value {}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Value::Null => {}
            Value::Bool(b) => b.hash(state),
            Value::Int(i) | Value::Time(i) | Value::Duration(i) => i.hash(state),
            Value::Float(f) => f.to_bits().hash(state),
            Value::Str(s) => s.hash(state),
            Value::Addr(a) => a.hash(state),
            Value::Subnet(s) => s.hash(state),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("-"),
            Value::Bool(b) => f.write_str(if *b { "true" } else { "false" }),
            Value::Int(i) => write!(f, "{i}"),
            Value::Float(x) => {
                if x.fract() == 0.0 && x.abs() < 1e15 {
                    write!(f, "{x:.1}")
                } else {
                    write!(f, "{}", (x * 10_000.0).round() / 10_000.0)
                }
            }
            Value::Str(s) => f.write_str(s),
            Value::Time(us) => f.write_str(&timefmt::format_iso(*us)),
            Value::Duration(us) => f.write_str(&timefmt::format_duration(*us)),
            Value::Addr(a) => write!(f, "{a}"),
            Value::Subnet(s) => write!(f, "{s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_membership() {
        let s = Subnet::parse("10.0.0.0/8").unwrap();
        assert!(s.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!s.contains(&"11.1.2.3".parse().unwrap()));
        assert!(!s.contains(&"::1".parse().unwrap()));
        let all = Subnet::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(&"8.8.8.8".parse().unwrap()));
        let v6 = Subnet::parse("fe80::/10").unwrap();
        assert!(v6.contains(&"fe80::1".parse().unwrap()));
        assert!(Subnet::parse("10.0.0.0/33").is_none());
        assert!(Subnet::parse("nope/3").is_none());
        assert_eq!(s.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn zeek_parsing() {
        assert_eq!(Value::parse_as(Type::Int, "443"), Some(Value::Int(443)));
        assert_eq!(Value::parse_as(Type::Bool, "T"), Some(Value::Bool(true)));
        assert_eq!(Value::parse_as(Type::Bool, "x"), None);
        assert_eq!(
            Value::parse_as(Type::Duration, "1.5"),
            Some(Value::Duration(1_500_000))
        );
        assert_eq!(
            Value::parse_as(Type::Time, "1700000000.000001"),
            Some(Value::Time(1_700_000_000_000_001))
        );
        assert!(Value::parse_as(Type::Addr, "1.2.3").is_none());
        assert_eq!(Type::from_zeek("port"), Type::Int);
        assert_eq!(Type::from_zeek("set[string]"), Type::Str);
    }

    #[test]
    fn ordering_and_equality() {
        assert_eq!(
            Value::Int(2).total_cmp(&Value::Float(1.5)),
            Ordering::Greater
        );
        assert_eq!(Value::Null.total_cmp(&Value::Int(0)), Ordering::Less);
        assert_eq!(Value::Int(1).partial_compare(&Value::Null), None);
        assert_eq!(Value::str("a").partial_compare(&Value::Int(1)), None);
        assert_eq!(Value::Float(f64::NAN), Value::Float(f64::NAN));
        assert_ne!(Value::Int(1), Value::Time(1));
    }

    #[test]
    fn display() {
        assert_eq!(Value::Float(2.0).to_string(), "2.0");
        assert_eq!(Value::Float(0.123456).to_string(), "0.1235");
        assert_eq!(Value::Null.to_string(), "-");
        assert_eq!(Value::Duration(90_000_000).to_string(), "1m30s");
    }
}
