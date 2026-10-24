//! Untyped syntax tree produced by the parser.
//!
//! Every node keeps the [`Span`] of the source text it came from so the
//! planner can point at the exact sub-expression that fails type checking.
//! `Display` pretty-prints a canonical form of the query; parsing the printed
//! text yields an equivalent tree (checked by a property test).

use std::fmt;

use crate::diag::Span;
use crate::value::Subnet;

#[derive(Debug, Clone, PartialEq)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Duration(i64),
    Ip(std::net::IpAddr),
    Cidr(Subnet),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Or,
    And,
    Eq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    Match,
    NotMatch,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

impl BinOp {
    pub fn symbol(self) -> &'static str {
        match self {
            BinOp::Or => "or",
            BinOp::And => "and",
            BinOp::Eq => "==",
            BinOp::NotEq => "!=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::Match => "=~",
            BinOp::NotMatch => "!~",
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Mod => "%",
        }
    }

    pub fn is_comparison(self) -> bool {
        matches!(
            self,
            BinOp::Eq | BinOp::NotEq | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprKind {
    Literal(Literal),
    Field(String),
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// `x in [a, b]` / `x not in 10.0.0.0/8`
    In {
        expr: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },
    Call(Ident, Vec<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

/// An aggregation inside `stats`: `count()`, `avg(duration) as d`.
#[derive(Debug, Clone, PartialEq)]
pub struct Agg {
    pub func: Ident,
    pub arg: Option<Expr>,
    pub alias: Option<Ident>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SortKey {
    pub field: Ident,
    pub descending: bool,
}

/// `key=value` option on hunting operators, e.g. `min_count=8`.
#[derive(Debug, Clone, PartialEq)]
pub struct Opt {
    pub name: Ident,
    pub value: Literal,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StageKind {
    Where(Expr),
    Fields {
        exclude: bool,
        fields: Vec<Ident>,
    },
    Eval(Vec<(Ident, Expr)>),
    Rename(Vec<(Ident, Ident)>),
    Stats {
        aggs: Vec<Agg>,
        by: Vec<Ident>,
    },
    Sort(Vec<SortKey>),
    Head(u64),
    Tail(u64),
    Dedup(Vec<Ident>),
    Stack {
        fields: Vec<Ident>,
        opts: Vec<Opt>,
    },
    Rare {
        field: Ident,
        by: Vec<Ident>,
        opts: Vec<Opt>,
    },
    FirstSeen {
        fields: Vec<Ident>,
        opts: Vec<Opt>,
    },
    Beacon {
        by: Vec<Ident>,
        opts: Vec<Opt>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stage {
    pub kind: StageKind,
    /// Span of the operator keyword (e.g. `stats`).
    pub name_span: Span,
    /// Span of the whole stage.
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub source: Ident,
    pub stages: Vec<Stage>,
    pub span: Span,
}

// ---------------------------------------------------------------------------
// Pretty printing
// ---------------------------------------------------------------------------

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Literal::Null => f.write_str("null"),
            Literal::Bool(b) => write!(f, "{b}"),
            Literal::Int(i) => write!(f, "{i}"),
            Literal::Float(x) => {
                if x.fract() == 0.0 && x.is_finite() {
                    write!(f, "{x:.1}")
                } else {
                    write!(f, "{x}")
                }
            }
            Literal::Str(s) => write_str_lit(f, s),
            Literal::Duration(us) => write!(f, "{us}us"),
            Literal::Ip(ip) if ip.is_ipv4() => write!(f, "{ip}"),
            Literal::Ip(ip) => write!(f, "\"{ip}\""),
            Literal::Cidr(c) => write!(f, "{c}"),
        }
    }
}

fn write_str_lit(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    f.write_str("\"")?;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\n' => f.write_str("\\n")?,
            '\t' => f.write_str("\\t")?,
            // A backslash followed by a char the lexer would treat as an
            // escape must itself be escaped; others are kept verbatim.
            '\\' => match chars.peek() {
                Some('n' | 't' | '\\' | '"' | '\'') | None => f.write_str("\\\\")?,
                _ => f.write_str("\\")?,
            },
            c => write!(f, "{c}")?,
        }
    }
    f.write_str("\"")
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ExprKind::Literal(l) => write!(f, "{l}"),
            ExprKind::Field(name) => f.write_str(name),
            ExprKind::Unary(UnOp::Not, e) => write!(f, "(not {e})"),
            ExprKind::Unary(UnOp::Neg, e) => write!(f, "(-{e})"),
            ExprKind::Binary(op, l, r) => write!(f, "({l} {} {r})", op.symbol()),
            ExprKind::In {
                expr,
                list,
                negated,
            } => {
                write!(f, "({expr} {}in [", if *negated { "not " } else { "" })?;
                write_list(f, list)?;
                f.write_str("])")
            }
            ExprKind::Call(name, args) => {
                write!(f, "{}(", name.name)?;
                write_list(f, args)?;
                f.write_str(")")
            }
        }
    }
}

fn write_list<T: fmt::Display>(f: &mut fmt::Formatter<'_>, items: &[T]) -> fmt::Result {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            f.write_str(", ")?;
        }
        write!(f, "{item}")?;
    }
    Ok(())
}

fn idents(ids: &[Ident]) -> String {
    ids.iter()
        .map(|i| i.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn opts(o: &[Opt]) -> String {
    o.iter()
        .map(|o| format!(" {}={}", o.name.name, o.value))
        .collect()
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            StageKind::Where(e) => write!(f, "where {e}"),
            StageKind::Fields { exclude, fields } => write!(
                f,
                "fields {}{}",
                if *exclude { "- " } else { "" },
                idents(fields)
            ),
            StageKind::Eval(assigns) => {
                f.write_str("eval ")?;
                let parts: Vec<String> = assigns
                    .iter()
                    .map(|(n, e)| format!("{} = {e}", n.name))
                    .collect();
                f.write_str(&parts.join(", "))
            }
            StageKind::Rename(pairs) => {
                f.write_str("rename ")?;
                let parts: Vec<String> = pairs
                    .iter()
                    .map(|(a, b)| format!("{} as {}", a.name, b.name))
                    .collect();
                f.write_str(&parts.join(", "))
            }
            StageKind::Stats { aggs, by } => {
                f.write_str("stats ")?;
                let parts: Vec<String> = aggs
                    .iter()
                    .map(|a| {
                        let arg = a.arg.as_ref().map(|e| e.to_string()).unwrap_or_default();
                        let alias = a
                            .alias
                            .as_ref()
                            .map(|n| format!(" as {}", n.name))
                            .unwrap_or_default();
                        format!("{}({arg}){alias}", a.func.name)
                    })
                    .collect();
                f.write_str(&parts.join(", "))?;
                if !by.is_empty() {
                    write!(f, " by {}", idents(by))?;
                }
                Ok(())
            }
            StageKind::Sort(keys) => {
                let parts: Vec<String> = keys
                    .iter()
                    .map(|k| format!("{}{}", if k.descending { "-" } else { "" }, k.field.name))
                    .collect();
                write!(f, "sort {}", parts.join(", "))
            }
            StageKind::Head(n) => write!(f, "head {n}"),
            StageKind::Tail(n) => write!(f, "tail {n}"),
            StageKind::Dedup(fields) => write!(f, "dedup {}", idents(fields)),
            StageKind::Stack { fields, opts: o } => {
                write!(f, "stack {}{}", idents(fields), opts(o))
            }
            StageKind::Rare { field, by, opts: o } => {
                write!(f, "rare {}", field.name)?;
                if !by.is_empty() {
                    write!(f, " by {}", idents(by))?;
                }
                f.write_str(&opts(o))
            }
            StageKind::FirstSeen { fields, opts: o } => {
                write!(f, "first_seen {}{}", idents(fields), opts(o))
            }
            StageKind::Beacon { by, opts: o } => {
                f.write_str("beacon")?;
                f.write_str(&opts(o))?;
                if !by.is_empty() {
                    write!(f, " by {}", idents(by))?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source.name)?;
        for s in &self.stages {
            write!(f, " | {s}")?;
        }
        Ok(())
    }
}
