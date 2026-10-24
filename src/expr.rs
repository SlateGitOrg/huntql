//! Typed expressions (the output of type checking) and their evaluator.
//!
//! The planner lowers every [`crate::ast::Expr`] into a [`TExpr`] whose
//! field references are resolved to column indexes and whose static type is
//! known. Evaluation is then a straightforward tree walk over a row slice
//! with no name lookups or dynamic type dispatch beyond `Value` matching.
//!
//! Null semantics: arithmetic and functions propagate null; comparisons with
//! null are false (so `where` drops the row); `and`/`or` treat null as false.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::rc::Rc;

use regex::Regex;

use crate::value::{Subnet, Type, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

/// Built-in scalar functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    Len,
    Lower,
    Upper,
    Contains,
    StartsWith,
    EndsWith,
    IsPrivate,
    Coalesce,
    If,
    Round,
    Abs,
    ToString,
    Seconds,
    Hour,
    DayOfWeek,
    Bin,
    Sld,
    Entropy,
}

/// Name, arity and a one-line description for every scalar function.
pub const FUNCTIONS: &[(&str, Func, &str)] = &[
    ("len", Func::Len, "len(string) -> int: length in characters"),
    ("lower", Func::Lower, "lower(string) -> string"),
    ("upper", Func::Upper, "upper(string) -> string"),
    (
        "contains",
        Func::Contains,
        "contains(string, string) -> bool",
    ),
    (
        "startswith",
        Func::StartsWith,
        "startswith(string, string) -> bool",
    ),
    (
        "endswith",
        Func::EndsWith,
        "endswith(string, string) -> bool",
    ),
    (
        "is_private",
        Func::IsPrivate,
        "is_private(addr) -> bool: RFC 1918 / loopback / link-local / ULA",
    ),
    (
        "coalesce",
        Func::Coalesce,
        "coalesce(a, b) -> first non-null argument",
    ),
    (
        "if",
        Func::If,
        "if(bool, a, b) -> a when the condition holds, else b",
    ),
    ("round", Func::Round, "round(number) -> int"),
    ("abs", Func::Abs, "abs(number|duration) -> same type"),
    ("tostring", Func::ToString, "tostring(any) -> string"),
    ("seconds", Func::Seconds, "seconds(duration|time) -> float"),
    (
        "hour",
        Func::Hour,
        "hour(time) -> int: UTC hour of day 0-23",
    ),
    (
        "dayofweek",
        Func::DayOfWeek,
        "dayofweek(time) -> int: 0=Sunday .. 6=Saturday (UTC)",
    ),
    (
        "bin",
        Func::Bin,
        "bin(time, duration) -> time: floor to a bucket boundary",
    ),
    (
        "sld",
        Func::Sld,
        "sld(string) -> string: last two DNS labels (naive registered domain)",
    ),
    (
        "entropy",
        Func::Entropy,
        "entropy(string) -> float: Shannon entropy in bits per character",
    ),
];

impl Func {
    pub fn name(self) -> &'static str {
        FUNCTIONS
            .iter()
            .find(|(_, f, _)| *f == self)
            .map(|(n, _, _)| *n)
            .unwrap_or("?")
    }

    pub fn lookup(name: &str) -> Option<Func> {
        FUNCTIONS
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, f, _)| *f)
    }
}

#[derive(Debug, Clone)]
pub enum TExprKind {
    Const(Value),
    Col(usize),
    Not(Box<TExpr>),
    Neg(Box<TExpr>),
    And(Box<TExpr>, Box<TExpr>),
    Or(Box<TExpr>, Box<TExpr>),
    Cmp(CmpOp, Box<TExpr>, Box<TExpr>),
    Arith(ArithOp, Box<TExpr>, Box<TExpr>),
    Regex {
        expr: Box<TExpr>,
        re: Regex,
        negated: bool,
    },
    InSet {
        expr: Box<TExpr>,
        set: HashSet<Value>,
        negated: bool,
    },
    InSubnets {
        expr: Box<TExpr>,
        nets: Vec<Subnet>,
        negated: bool,
    },
    Call(Func, Vec<TExpr>),
}

/// A type-checked expression.
#[derive(Debug, Clone)]
pub struct TExpr {
    pub kind: TExprKind,
    pub ty: Type,
}

impl TExpr {
    pub fn new(kind: TExprKind, ty: Type) -> Self {
        TExpr { kind, ty }
    }

    pub fn constant(v: Value) -> Self {
        let ty = v.ty();
        TExpr::new(TExprKind::Const(v), ty)
    }

    /// Collect every column index this expression reads.
    pub fn columns(&self, out: &mut Vec<usize>) {
        match &self.kind {
            TExprKind::Const(_) => {}
            TExprKind::Col(i) => out.push(*i),
            TExprKind::Not(e) | TExprKind::Neg(e) => e.columns(out),
            TExprKind::And(a, b)
            | TExprKind::Or(a, b)
            | TExprKind::Cmp(_, a, b)
            | TExprKind::Arith(_, a, b) => {
                a.columns(out);
                b.columns(out);
            }
            TExprKind::Regex { expr, .. }
            | TExprKind::InSet { expr, .. }
            | TExprKind::InSubnets { expr, .. } => expr.columns(out),
            TExprKind::Call(_, args) => args.iter().for_each(|a| a.columns(out)),
        }
    }

    /// Rewrite column indexes (used when the planner prunes columns).
    pub fn remap(&mut self, map: &dyn Fn(usize) -> usize) {
        match &mut self.kind {
            TExprKind::Const(_) => {}
            TExprKind::Col(i) => *i = map(*i),
            TExprKind::Not(e) | TExprKind::Neg(e) => e.remap(map),
            TExprKind::And(a, b)
            | TExprKind::Or(a, b)
            | TExprKind::Cmp(_, a, b)
            | TExprKind::Arith(_, a, b) => {
                a.remap(map);
                b.remap(map);
            }
            TExprKind::Regex { expr, .. }
            | TExprKind::InSet { expr, .. }
            | TExprKind::InSubnets { expr, .. } => expr.remap(map),
            TExprKind::Call(_, args) => args.iter_mut().for_each(|a| a.remap(map)),
        }
    }

    pub fn is_const(&self) -> bool {
        matches!(self.kind, TExprKind::Const(_))
    }

    /// Evaluate against a row.
    pub fn eval(&self, row: &[Value]) -> Value {
        match &self.kind {
            TExprKind::Const(v) => v.clone(),
            TExprKind::Col(i) => row[*i].clone(),
            TExprKind::Not(e) => match e.eval(row) {
                Value::Bool(b) => Value::Bool(!b),
                _ => Value::Bool(false),
            },
            TExprKind::Neg(e) => match e.eval(row) {
                Value::Int(i) => Value::Int(i.wrapping_neg()),
                Value::Float(f) => Value::Float(-f),
                Value::Duration(d) => Value::Duration(d.wrapping_neg()),
                _ => Value::Null,
            },
            TExprKind::And(a, b) => Value::Bool(a.eval(row).as_bool() && b.eval(row).as_bool()),
            TExprKind::Or(a, b) => Value::Bool(a.eval(row).as_bool() || b.eval(row).as_bool()),
            TExprKind::Cmp(op, a, b) => {
                let (l, r) = (a.eval(row), b.eval(row));
                let Some(ord) = l.partial_compare(&r) else {
                    return Value::Bool(false);
                };
                Value::Bool(match op {
                    CmpOp::Eq => ord.is_eq(),
                    CmpOp::Ne => ord.is_ne(),
                    CmpOp::Lt => ord.is_lt(),
                    CmpOp::Le => ord.is_le(),
                    CmpOp::Gt => ord.is_gt(),
                    CmpOp::Ge => ord.is_ge(),
                })
            }
            TExprKind::Arith(op, a, b) => arith(*op, a.eval(row), b.eval(row)),
            TExprKind::Regex { expr, re, negated } => match expr.eval(row) {
                Value::Str(s) => Value::Bool(re.is_match(&s) != *negated),
                _ => Value::Bool(false),
            },
            TExprKind::InSet { expr, set, negated } => {
                let v = expr.eval(row);
                if v.is_null() {
                    return Value::Bool(false);
                }
                Value::Bool(set.contains(&normalize_num(v)) != *negated)
            }
            TExprKind::InSubnets {
                expr,
                nets,
                negated,
            } => match expr.eval(row) {
                Value::Addr(ip) => Value::Bool(nets.iter().any(|n| n.contains(&ip)) != *negated),
                _ => Value::Bool(false),
            },
            TExprKind::Call(f, args) => call(*f, args, row),
        }
    }
}

/// Integers that are members of a float set (and vice versa) are compared as
/// floats; the planner normalises set members the same way.
pub fn normalize_num(v: Value) -> Value {
    match v {
        Value::Int(i) => Value::Float(i as f64),
        other => other,
    }
}

fn arith(op: ArithOp, l: Value, r: Value) -> Value {
    use Value::*;
    match (op, l, r) {
        (_, Null, _) | (_, _, Null) => Null,
        (ArithOp::Add, Int(a), Int(b)) => Int(a.wrapping_add(b)),
        (ArithOp::Sub, Int(a), Int(b)) => Int(a.wrapping_sub(b)),
        (ArithOp::Mul, Int(a), Int(b)) => Int(a.wrapping_mul(b)),
        (ArithOp::Mod, Int(a), Int(b)) => {
            if b == 0 {
                Null
            } else {
                Int(a.wrapping_rem(b))
            }
        }
        (ArithOp::Add, Str(a), Str(b)) => Str(Rc::from(format!("{a}{b}"))),
        (ArithOp::Sub, Time(a), Time(b)) => Duration(a - b),
        (ArithOp::Add, Time(t), Duration(d)) | (ArithOp::Add, Duration(d), Time(t)) => Time(t + d),
        (ArithOp::Sub, Time(t), Duration(d)) => Time(t - d),
        (ArithOp::Add, Duration(a), Duration(b)) => Duration(a + b),
        (ArithOp::Sub, Duration(a), Duration(b)) => Duration(a - b),
        (ArithOp::Div, Duration(a), Duration(b)) => {
            if b == 0 {
                Null
            } else {
                Float(a as f64 / b as f64)
            }
        }
        (ArithOp::Mul, Duration(d), n) | (ArithOp::Mul, n, Duration(d)) => match n.as_f64() {
            Some(x) => Duration((d as f64 * x).round() as i64),
            None => Null,
        },
        (ArithOp::Div, Duration(d), n) => match n.as_f64() {
            Some(x) if x != 0.0 => Duration((d as f64 / x).round() as i64),
            _ => Null,
        },
        (op, a, b) => match (a.as_f64(), b.as_f64()) {
            (Some(x), Some(y)) => {
                let v = match op {
                    ArithOp::Add => x + y,
                    ArithOp::Sub => x - y,
                    ArithOp::Mul => x * y,
                    ArithOp::Div => {
                        if y == 0.0 {
                            return Null;
                        }
                        x / y
                    }
                    ArithOp::Mod => {
                        if y == 0.0 {
                            return Null;
                        }
                        x % y
                    }
                };
                Float(v)
            }
            _ => Null,
        },
    }
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n as f64;
            p * (1.0 / p).log2()
        })
        .sum()
}

fn call(f: Func, args: &[TExpr], row: &[Value]) -> Value {
    // Short-circuiting functions first.
    match f {
        Func::Coalesce => {
            return args
                .iter()
                .map(|a| a.eval(row))
                .find(|v| !v.is_null())
                .unwrap_or(Value::Null)
        }
        Func::If => {
            return if args[0].eval(row).as_bool() {
                args[1].eval(row)
            } else {
                args[2].eval(row)
            }
        }
        _ => {}
    }
    let vals: Vec<Value> = args.iter().map(|a| a.eval(row)).collect();
    if vals.iter().any(Value::is_null) {
        return Value::Null;
    }
    match (f, vals.as_slice()) {
        (Func::Len, [Value::Str(s)]) => Value::Int(s.chars().count() as i64),
        (Func::Lower, [Value::Str(s)]) => Value::str(&s.to_lowercase()),
        (Func::Upper, [Value::Str(s)]) => Value::str(&s.to_uppercase()),
        (Func::Contains, [Value::Str(a), Value::Str(b)]) => Value::Bool(a.contains(&**b)),
        (Func::StartsWith, [Value::Str(a), Value::Str(b)]) => Value::Bool(a.starts_with(&**b)),
        (Func::EndsWith, [Value::Str(a), Value::Str(b)]) => Value::Bool(a.ends_with(&**b)),
        (Func::IsPrivate, [Value::Addr(ip)]) => Value::Bool(is_private(ip)),
        (Func::Round, [v]) => v
            .as_f64()
            .map_or(Value::Null, |x| Value::Int(x.round() as i64)),
        (Func::Abs, [Value::Int(i)]) => Value::Int(i.wrapping_abs()),
        (Func::Abs, [Value::Float(x)]) => Value::Float(x.abs()),
        (Func::Abs, [Value::Duration(d)]) => Value::Duration(d.wrapping_abs()),
        (Func::ToString, [v]) => Value::str(&v.to_string()),
        (Func::Seconds, [v]) => v.as_f64().map_or(Value::Null, Value::Float),
        (Func::Hour, [Value::Time(t)]) => {
            Value::Int((t.div_euclid(1_000_000).rem_euclid(86_400)) / 3600)
        }
        (Func::DayOfWeek, [Value::Time(t)]) => {
            // 1970-01-01 was a Thursday (4).
            let days = t.div_euclid(86_400_000_000);
            Value::Int((days + 4).rem_euclid(7))
        }
        (Func::Bin, [Value::Time(t), Value::Duration(w)]) => {
            if *w <= 0 {
                Value::Null
            } else {
                Value::Time(t.div_euclid(*w) * *w)
            }
        }
        (Func::Sld, [Value::Str(s)]) => {
            let trimmed = s.trim_end_matches('.');
            let labels: Vec<&str> = trimmed.rsplitn(3, '.').collect();
            if labels.len() >= 2 {
                Value::str(&format!("{}.{}", labels[1], labels[0]))
            } else {
                Value::str(trimmed)
            }
        }
        (Func::Entropy, [Value::Str(s)]) => Value::Float(shannon_entropy(s)),
        _ => Value::Null,
    }
}

/// Display adapter that prints column references by name.
pub struct Named<'a> {
    expr: &'a TExpr,
    names: Option<&'a [String]>,
}

impl TExpr {
    /// Render with column names from `names` (indexes into the input schema).
    pub fn named<'a>(&'a self, names: &'a [String]) -> Named<'a> {
        Named {
            expr: self,
            names: Some(names),
        }
    }
}

impl fmt::Display for TExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_expr(self, None, f)
    }
}

impl fmt::Display for Named<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_expr(self.expr, self.names, f)
    }
}

fn write_expr<'a>(
    e: &'a TExpr,
    names: Option<&'a [String]>,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let sub = |x: &'a TExpr| Named { expr: x, names };
    match &e.kind {
        TExprKind::Const(Value::Str(s)) => write!(f, "{s:?}"),
        TExprKind::Const(v) => write!(f, "{v}"),
        TExprKind::Col(i) => match names.and_then(|n| n.get(*i)) {
            Some(name) => f.write_str(name),
            None => write!(f, "${i}"),
        },
        TExprKind::Not(x) => write!(f, "(not {})", sub(x)),
        TExprKind::Neg(x) => write!(f, "(-{})", sub(x)),
        TExprKind::And(a, b) => write!(f, "({} and {})", sub(a), sub(b)),
        TExprKind::Or(a, b) => write!(f, "({} or {})", sub(a), sub(b)),
        TExprKind::Cmp(op, a, b) => {
            let s = match op {
                CmpOp::Eq => "==",
                CmpOp::Ne => "!=",
                CmpOp::Lt => "<",
                CmpOp::Le => "<=",
                CmpOp::Gt => ">",
                CmpOp::Ge => ">=",
            };
            write!(f, "({} {s} {})", sub(a), sub(b))
        }
        TExprKind::Arith(op, a, b) => {
            let s = match op {
                ArithOp::Add => "+",
                ArithOp::Sub => "-",
                ArithOp::Mul => "*",
                ArithOp::Div => "/",
                ArithOp::Mod => "%",
            };
            write!(f, "({} {s} {})", sub(a), sub(b))
        }
        TExprKind::Regex { expr, re, negated } => {
            write!(
                f,
                "({} {} /{}/)",
                sub(expr),
                if *negated { "!~" } else { "=~" },
                re.as_str()
            )
        }
        TExprKind::InSet { expr, set, negated } => {
            write!(
                f,
                "({} {}in <{} values>)",
                sub(expr),
                if *negated { "not " } else { "" },
                set.len()
            )
        }
        TExprKind::InSubnets {
            expr,
            nets,
            negated,
        } => {
            let n: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
            write!(
                f,
                "({} {}in [{}])",
                sub(expr),
                if *negated { "not " } else { "" },
                n.join(", ")
            )
        }
        TExprKind::Call(func, args) => {
            let a: Vec<String> = args.iter().map(|a| sub(a).to_string()).collect();
            write!(f, "{}({})", func.name(), a.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: Value) -> Box<TExpr> {
        Box::new(TExpr::constant(v))
    }

    #[test]
    fn arithmetic_rules() {
        use Value::*;
        assert_eq!(arith(ArithOp::Add, Int(2), Int(3)), Int(5));
        assert_eq!(arith(ArithOp::Div, Int(3), Int(2)), Float(1.5));
        assert_eq!(arith(ArithOp::Div, Int(3), Int(0)), Null);
        assert_eq!(arith(ArithOp::Mod, Int(7), Int(0)), Null);
        assert_eq!(arith(ArithOp::Mod, Int(7), Int(4)), Int(3));
        assert_eq!(arith(ArithOp::Mod, Float(7.5), Int(2)), Float(1.5));
        assert_eq!(arith(ArithOp::Mod, Float(7.5), Int(0)), Null);
        assert_eq!(arith(ArithOp::Sub, Time(10), Time(4)), Duration(6));
        assert_eq!(arith(ArithOp::Add, Duration(1), Time(4)), Time(5));
        assert_eq!(arith(ArithOp::Sub, Time(5), Duration(1)), Time(4));
        assert_eq!(arith(ArithOp::Mul, Duration(10), Int(3)), Duration(30));
        assert_eq!(arith(ArithOp::Div, Duration(10), Int(4)), Duration(3));
        assert_eq!(arith(ArithOp::Div, Duration(10), Int(0)), Null);
        assert_eq!(arith(ArithOp::Div, Duration(10), Duration(4)), Float(2.5));
        assert_eq!(arith(ArithOp::Div, Duration(10), Duration(0)), Null);
        assert_eq!(arith(ArithOp::Add, Duration(1), Duration(2)), Duration(3));
        assert_eq!(arith(ArithOp::Sub, Duration(1), Duration(2)), Duration(-1));
        assert_eq!(
            arith(ArithOp::Add, Value::str("a"), Value::str("b")),
            Value::str("ab")
        );
        assert_eq!(arith(ArithOp::Mul, Float(1.5), Int(2)), Float(3.0));
        assert_eq!(arith(ArithOp::Sub, Int(1), Null), Null);
        assert_eq!(arith(ArithOp::Add, Bool(true), Int(1)), Null);
        assert_eq!(arith(ArithOp::Mul, Duration(1), Value::str("x")), Null);
    }

    #[test]
    fn comparisons_and_logic() {
        let row = vec![Value::Int(5), Value::Null];
        let gt = TExpr::new(
            TExprKind::Cmp(
                CmpOp::Gt,
                Box::new(TExpr::new(TExprKind::Col(0), Type::Int)),
                c(Value::Int(3)),
            ),
            Type::Bool,
        );
        assert_eq!(gt.eval(&row), Value::Bool(true));
        let null_cmp = TExpr::new(
            TExprKind::Cmp(
                CmpOp::Ne,
                Box::new(TExpr::new(TExprKind::Col(1), Type::Int)),
                c(Value::Int(3)),
            ),
            Type::Bool,
        );
        assert_eq!(null_cmp.eval(&row), Value::Bool(false));
        let not = TExpr::new(TExprKind::Not(Box::new(null_cmp.clone())), Type::Bool);
        assert_eq!(not.eval(&row), Value::Bool(true));
        let or = TExpr::new(
            TExprKind::Or(Box::new(null_cmp), Box::new(gt.clone())),
            Type::Bool,
        );
        assert_eq!(or.eval(&row), Value::Bool(true));
        let and = TExpr::new(TExprKind::And(Box::new(or), Box::new(gt)), Type::Bool);
        assert_eq!(and.eval(&row), Value::Bool(true));
        let mut cols = vec![];
        and.columns(&mut cols);
        assert_eq!(cols, vec![1, 0, 0]);
        for (op, expect) in [
            (CmpOp::Eq, false),
            (CmpOp::Ne, true),
            (CmpOp::Lt, false),
            (CmpOp::Le, false),
            (CmpOp::Ge, true),
        ] {
            let e = TExpr::new(
                TExprKind::Cmp(op, c(Value::Int(5)), c(Value::Float(3.0))),
                Type::Bool,
            );
            assert_eq!(e.eval(&row), Value::Bool(expect), "{op:?}");
        }
    }

    #[test]
    fn functions() {
        let row: Vec<Value> = vec![];
        let call1 = |f: Func, args: Vec<Value>| {
            TExpr::new(
                TExprKind::Call(f, args.into_iter().map(TExpr::constant).collect()),
                Type::Null,
            )
            .eval(&row)
        };
        assert_eq!(call1(Func::Len, vec![Value::str("héllo")]), Value::Int(5));
        assert_eq!(
            call1(Func::Lower, vec![Value::str("AbC")]),
            Value::str("abc")
        );
        assert_eq!(
            call1(Func::Upper, vec![Value::str("AbC")]),
            Value::str("ABC")
        );
        assert_eq!(
            call1(Func::Contains, vec![Value::str("abc"), Value::str("b")]),
            Value::Bool(true)
        );
        assert_eq!(
            call1(Func::StartsWith, vec![Value::str("abc"), Value::str("a")]),
            Value::Bool(true)
        );
        assert_eq!(
            call1(Func::EndsWith, vec![Value::str("abc"), Value::str("a")]),
            Value::Bool(false)
        );
        assert_eq!(
            call1(
                Func::IsPrivate,
                vec![Value::Addr("10.1.1.1".parse().unwrap())]
            ),
            Value::Bool(true)
        );
        assert_eq!(
            call1(
                Func::IsPrivate,
                vec![Value::Addr("8.8.8.8".parse().unwrap())]
            ),
            Value::Bool(false)
        );
        assert_eq!(
            call1(
                Func::IsPrivate,
                vec![Value::Addr("fd00::1".parse().unwrap())]
            ),
            Value::Bool(true)
        );
        assert_eq!(
            call1(
                Func::IsPrivate,
                vec![Value::Addr("2001:db8::1".parse().unwrap())]
            ),
            Value::Bool(false)
        );
        assert_eq!(
            call1(Func::Coalesce, vec![Value::Null, Value::Int(2)]),
            Value::Int(2)
        );
        assert_eq!(call1(Func::Coalesce, vec![Value::Null]), Value::Null);
        assert_eq!(
            call1(
                Func::If,
                vec![Value::Bool(false), Value::Int(1), Value::Int(2)]
            ),
            Value::Int(2)
        );
        assert_eq!(
            call1(
                Func::If,
                vec![Value::Bool(true), Value::Int(1), Value::Int(2)]
            ),
            Value::Int(1)
        );
        assert_eq!(call1(Func::Round, vec![Value::Float(2.6)]), Value::Int(3));
        assert_eq!(call1(Func::Abs, vec![Value::Int(-2)]), Value::Int(2));
        assert_eq!(
            call1(Func::Abs, vec![Value::Float(-2.5)]),
            Value::Float(2.5)
        );
        assert_eq!(
            call1(Func::Abs, vec![Value::Duration(-2)]),
            Value::Duration(2)
        );
        assert_eq!(call1(Func::ToString, vec![Value::Int(7)]), Value::str("7"));
        assert_eq!(
            call1(Func::Seconds, vec![Value::Duration(1_500_000)]),
            Value::Float(1.5)
        );
        let t = 1_700_000_000_000_000; // 2023-11-14T22:13:20Z, a Tuesday
        assert_eq!(call1(Func::Hour, vec![Value::Time(t)]), Value::Int(22));
        assert_eq!(call1(Func::DayOfWeek, vec![Value::Time(t)]), Value::Int(2));
        assert_eq!(
            call1(
                Func::Bin,
                vec![Value::Time(t + 5), Value::Duration(3_600_000_000)]
            ),
            Value::Time(1_699_999_200_000_000)
        );
        assert_eq!(
            call1(Func::Bin, vec![Value::Time(t), Value::Duration(0)]),
            Value::Null
        );
        assert_eq!(
            call1(Func::Sld, vec![Value::str("a.b.example.test.")]),
            Value::str("example.test")
        );
        assert_eq!(
            call1(Func::Sld, vec![Value::str("localhost")]),
            Value::str("localhost")
        );
        assert_eq!(
            call1(Func::Entropy, vec![Value::str("aaaa")]),
            Value::Float(0.0)
        );
        assert_eq!(
            call1(Func::Entropy, vec![Value::str("ab")]),
            Value::Float(1.0)
        );
        assert_eq!(call1(Func::Len, vec![Value::Null]), Value::Null);
        assert_eq!(call1(Func::Len, vec![Value::Int(1)]), Value::Null);
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(Func::lookup("entropy"), Some(Func::Entropy));
        assert_eq!(Func::Entropy.name(), "entropy");
    }

    #[test]
    fn sets_regex_subnets_and_display() {
        let row = vec![
            Value::Int(443),
            Value::str("evil.exe"),
            Value::Addr("10.0.0.5".parse().unwrap()),
        ];
        let col = |i, ty| Box::new(TExpr::new(TExprKind::Col(i), ty));
        let set: HashSet<Value> = [Value::Float(80.0), Value::Float(443.0)]
            .into_iter()
            .collect();
        let e = TExpr::new(
            TExprKind::InSet {
                expr: col(0, Type::Int),
                set,
                negated: false,
            },
            Type::Bool,
        );
        assert_eq!(e.eval(&row), Value::Bool(true));
        assert!(e.to_string().contains("in <2 values>"));
        let re = TExpr::new(
            TExprKind::Regex {
                expr: col(1, Type::Str),
                re: Regex::new(r"\.exe$").unwrap(),
                negated: true,
            },
            Type::Bool,
        );
        assert_eq!(re.eval(&row), Value::Bool(false));
        assert_eq!(re.to_string(), r"($1 !~ /\.exe$/)");
        let nets = vec![Subnet::parse("10.0.0.0/8").unwrap()];
        let sn = TExpr::new(
            TExprKind::InSubnets {
                expr: col(2, Type::Addr),
                nets,
                negated: false,
            },
            Type::Bool,
        );
        assert_eq!(sn.eval(&row), Value::Bool(true));
        assert_eq!(sn.to_string(), "($2 in [10.0.0.0/8])");
        let names: Vec<String> = ["port", "file", "host"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(sn.named(&names).to_string(), "(host in [10.0.0.0/8])");
        assert_eq!(re.named(&names).to_string(), r"(file !~ /\.exe$/)");
        let mut moved = sn.clone();
        moved.remap(&|i| i + 1);
        let mut cols = vec![];
        moved.columns(&mut cols);
        assert_eq!(cols, vec![3]);
        let neg = TExpr::new(TExprKind::Neg(c(Value::Duration(5))), Type::Duration);
        assert_eq!(neg.eval(&row), Value::Duration(-5));
        assert_eq!(neg.to_string(), "(-5us)");
        let negf = TExpr::new(TExprKind::Neg(c(Value::Float(1.5))), Type::Float);
        assert_eq!(negf.eval(&row), Value::Float(-1.5));
        let negs = TExpr::new(TExprKind::Neg(c(Value::str("x"))), Type::Null);
        assert_eq!(negs.eval(&row), Value::Null);
        let call = TExpr::new(
            TExprKind::Call(Func::Len, vec![TExpr::constant(Value::str("x"))]),
            Type::Int,
        );
        assert_eq!(call.to_string(), "len(\"x\")");
        assert!(TExpr::constant(Value::Int(1)).is_const());
    }
}
