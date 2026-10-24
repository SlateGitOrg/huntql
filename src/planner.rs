//! Type checker and planner: [`ast::Query`] -> [`Plan`].
//!
//! The planner walks the pipeline left to right, threading the current
//! [`Schema`] through each stage. Every field reference is resolved to a
//! column index, every expression gets a static [`Type`], literals are
//! coerced where the other operand demands it (`src == "fe80::1"` parses
//! the string as an address at plan time), and constant sub-expressions are
//! folded. All failures are [`Diagnostic`]s pointing at the offending span.
//!
//! After type checking, three rewrites run:
//! 1. adjacent `where` filters are merged into one conjunction;
//! 2. `sort ... | head k` becomes a bounded `TopK` heap (O(k) memory);
//! 3. column pruning: the scan only decodes source columns the pipeline
//!    actually reads.

use std::collections::HashSet;

use regex::Regex;

use crate::ast::{self, BinOp, ExprKind, Literal, StageKind, UnOp};
use crate::beacon::BeaconParams;
use crate::diag::{suggest, Diagnostic, Phase, Span};
use crate::expr::{normalize_num, ArithOp, CmpOp, Func, TExpr, TExprKind, FUNCTIONS};
use crate::plan::{AggFunc, AggSpec, Plan, PlanOp, SortSpec, SourceSpec};
use crate::schema::{self, Schema};
use crate::value::{Subnet, Type, Value};

/// Supplies source schemas (built-in Zeek layouts, possibly extended with
/// extra columns discovered in log headers).
pub trait SchemaProvider {
    fn schema(&self, log: &str) -> Option<Schema>;
    fn logs(&self) -> Vec<String>;
}

/// Provider for the four built-in Zeek logs.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinSchemas;

impl SchemaProvider for BuiltinSchemas {
    fn schema(&self, log: &str) -> Option<Schema> {
        schema::builtin(log)
    }

    fn logs(&self) -> Vec<String> {
        schema::LOG_NAMES.iter().map(|s| s.to_string()).collect()
    }
}

type PResult<T> = Result<T, Diagnostic>;

fn err(msg: impl Into<String>, span: Span) -> Diagnostic {
    Diagnostic::new(Phase::Plan, msg, span)
}

/// Type-check and plan a parsed query.
pub fn plan(query: &ast::Query, provider: &dyn SchemaProvider) -> PResult<Plan> {
    let log = &query.source.name;
    let Some(source_schema) = provider.schema(log) else {
        let logs = provider.logs();
        let mut d = err(format!("unknown log source `{log}`"), query.source.span);
        if let Some(s) = suggest(log, logs.iter().map(String::as_str)) {
            d = d.with_label(format!("did you mean `{s}`?"));
        } else {
            d = d.with_help(format!("available sources: {}", logs.join(", ")));
        }
        return Err(d);
    };
    let mut cur = source_schema.clone();
    let mut ops: Vec<(PlanOp, Schema)> = Vec::new();
    for stage in &query.stages {
        let (op, next) = plan_stage(stage, &cur)?;
        if let Some(op) = op {
            ops.push((op, next.clone()));
        }
        cur = next;
    }
    let mut notes = Vec::new();
    let ops = optimize(ops, &mut notes);
    let needed = needed_columns(&ops, source_schema.len());
    Ok(Plan {
        source: SourceSpec {
            log: log.clone(),
            schema: source_schema,
            needed,
        },
        ops,
        notes,
    })
}

// ---------------------------------------------------------------------------
// Stages
// ---------------------------------------------------------------------------

fn resolve(schema: &Schema, id: &ast::Ident) -> PResult<usize> {
    schema
        .resolve(&id.name)
        .ok_or_else(|| unknown_field(schema, &id.name, id.span))
}

fn unknown_field(schema: &Schema, name: &str, span: Span) -> Diagnostic {
    let d = err(format!("unknown field `{name}`"), span);
    match suggest(name, schema.names()) {
        Some(s) => d.with_label(format!("did you mean `{s}`?")),
        None => {
            let mut names: Vec<&str> = schema.names().collect();
            names.truncate(12);
            d.with_help(format!("fields here: {}", names.join(", ")))
        }
    }
}

fn check_new_name(schema: &Schema, id: &ast::Ident) -> PResult<()> {
    if schema.resolve(&id.name).is_some() {
        return Err(err(format!("field `{}` already exists", id.name), id.span)
            .with_help("choose a new name, or `rename` the existing field first"));
    }
    Ok(())
}

fn keys(schema: &Schema, ids: &[ast::Ident]) -> PResult<(Vec<usize>, Schema)> {
    let mut idx = Vec::new();
    let mut out = Schema::default();
    for id in ids {
        let i = resolve(schema, id)?;
        if out.index_of(&id.name).is_some() {
            return Err(err(format!("field `{}` listed twice", id.name), id.span));
        }
        idx.push(i);
        out.push(id.name.clone(), schema.columns[i].ty);
    }
    Ok((idx, out))
}

fn require_ts(schema: &Schema, stage: &ast::Stage, op: &str) -> PResult<usize> {
    match schema.index_of("ts") {
        Some(i) if schema.columns[i].ty == Type::Time => Ok(i),
        _ => Err(err(format!("`{op}` needs a `ts` column of type time"), stage.name_span)
            .with_help("an earlier `fields`, `stats` or hunting operator removed it; move this operator earlier")),
    }
}

fn plan_stage(stage: &ast::Stage, cur: &Schema) -> PResult<(Option<PlanOp>, Schema)> {
    Ok(match &stage.kind {
        StageKind::Where(e) => {
            let t = check_expr(e, cur)?;
            expect_type(&t, Type::Bool, e.span, "a `where` condition")?;
            if let TExprKind::Const(Value::Bool(true)) = t.kind {
                (None, cur.clone())
            } else {
                (Some(PlanOp::Filter(t)), cur.clone())
            }
        }
        StageKind::Fields { exclude, fields } => {
            if *exclude {
                let mut drop = HashSet::new();
                for f in fields {
                    drop.insert(resolve(cur, f)?);
                }
                let keep: Vec<usize> = (0..cur.len()).filter(|i| !drop.contains(i)).collect();
                if keep.is_empty() {
                    return Err(err("`fields -` would remove every column", stage.span));
                }
                let out = Schema::new(keep.iter().map(|&i| cur.columns[i].clone()).collect());
                (Some(PlanOp::Project(keep)), out)
            } else {
                let (idx, out) = keys(cur, fields)?;
                (Some(PlanOp::Project(idx)), out)
            }
        }
        StageKind::Eval(assigns) => {
            let mut out = cur.clone();
            let mut exprs = Vec::new();
            for (name, e) in assigns {
                check_new_name(&out, name)?;
                let t = check_expr(e, &out)?;
                let ty = if t.ty == Type::Null { Type::Str } else { t.ty };
                out.push(name.name.clone(), ty);
                exprs.push(t);
            }
            (Some(PlanOp::Extend(exprs)), out)
        }
        StageKind::Rename(pairs) => {
            let mut out = cur.clone();
            for (from, to) in pairs {
                let i = resolve(&out, from)?;
                check_new_name(&out, to)?;
                out.columns[i].name = to.name.clone();
            }
            // Pure schema change: no runtime operator.
            (None, out)
        }
        StageKind::Stats { aggs, by } => plan_stats(cur, aggs, by)?,
        StageKind::Sort(sort_keys) => {
            let mut specs = Vec::new();
            for k in sort_keys {
                specs.push(SortSpec {
                    col: resolve(cur, &k.field)?,
                    descending: k.descending,
                });
            }
            (Some(PlanOp::Sort(specs)), cur.clone())
        }
        StageKind::Head(n) => (Some(PlanOp::Head(*n)), cur.clone()),
        StageKind::Tail(n) => (Some(PlanOp::Tail(*n)), cur.clone()),
        StageKind::Dedup(fields) => {
            let (idx, _) = keys(cur, fields)?;
            (Some(PlanOp::Dedup(idx)), cur.clone())
        }
        StageKind::Stack { fields, opts } => {
            let o = Options::parse(opts, &[("limit", OptKind::Count)])?;
            let (idx, mut out) = keys(cur, fields)?;
            for (name, ty) in [
                ("count", Type::Int),
                ("pct", Type::Float),
                ("cum_pct", Type::Float),
            ] {
                out.push(name, ty);
            }
            (
                Some(PlanOp::Stack {
                    keys: idx,
                    limit: o.count("limit"),
                }),
                out,
            )
        }
        StageKind::Rare { field, by, opts } => {
            let o = Options::parse(opts, &[("limit", OptKind::Count)])?;
            let f = resolve(cur, field)?;
            let (by_idx, _) = keys(cur, by)?;
            let mut out = Schema::default();
            out.push(field.name.clone(), cur.columns[f].ty);
            out.push("count", Type::Int);
            if !by_idx.is_empty() {
                out.push("entities", Type::Int);
            }
            (
                Some(PlanOp::Rare {
                    field: f,
                    by: by_idx,
                    limit: o.count("limit").unwrap_or(10),
                }),
                out,
            )
        }
        StageKind::FirstSeen { fields, opts } => {
            let o = Options::parse(opts, &[("baseline", OptKind::Duration)])?;
            let ts = require_ts(cur, stage, "first_seen")?;
            let (idx, mut out) = keys(cur, fields)?;
            out.push("first_seen", Type::Time);
            out.push("last_seen", Type::Time);
            out.push("count", Type::Int);
            (
                Some(PlanOp::FirstSeen {
                    keys: idx,
                    ts,
                    baseline: o.duration("baseline"),
                }),
                out,
            )
        }
        StageKind::Beacon { by, opts } => {
            let o = Options::parse(
                opts,
                &[
                    ("min_count", OptKind::Count),
                    ("min_score", OptKind::Fraction),
                    ("max_events", OptKind::Count),
                ],
            )?;
            let ts = require_ts(cur, stage, "beacon")?;
            let default_keys;
            let by_ids: &[ast::Ident] = if by.is_empty() {
                default_keys = ["src", "dst", "dport"]
                    .iter()
                    .map(|n| ast::Ident {
                        name: n.to_string(),
                        span: stage.name_span,
                    })
                    .collect::<Vec<_>>();
                &default_keys
            } else {
                by
            };
            let (idx, mut out) = keys(cur, by_ids).map_err(|d| {
                if by.is_empty() {
                    d.with_help("by default `beacon` groups by src, dst, dport; pass `by <fields>` for other logs")
                } else {
                    d
                }
            })?;
            let defaults = BeaconParams::default();
            let mut params = BeaconParams {
                min_count: o
                    .count("min_count")
                    .map_or(defaults.min_count, |v| v as usize),
                min_score: o.fraction("min_score").unwrap_or(defaults.min_score),
                max_events: o
                    .count("max_events")
                    .map_or(defaults.max_events, |v| v as usize),
            };
            if params.min_count < 3 {
                return Err(err("`min_count` must be at least 3", o.span("min_count")));
            }
            if params.max_events < params.min_count {
                return Err(err(
                    "`max_events` must be at least `min_count`",
                    o.span("max_events"),
                ));
            }
            params.min_count = params.min_count.max(3);
            let bytes = cur
                .index_of("orig_bytes")
                .filter(|&i| cur.columns[i].ty.is_numeric());
            for (name, ty) in [
                ("count", Type::Int),
                ("period", Type::Duration),
                ("jitter", Type::Float),
                ("acf", Type::Float),
                ("score", Type::Float),
            ] {
                out.push(name, ty);
            }
            (
                Some(PlanOp::Beacon {
                    keys: idx,
                    ts,
                    bytes,
                    params,
                }),
                out,
            )
        }
    })
}

fn plan_stats(
    cur: &Schema,
    aggs: &[ast::Agg],
    by: &[ast::Ident],
) -> PResult<(Option<PlanOp>, Schema)> {
    let (key_idx, mut out) = keys(cur, by)?;
    let mut specs = Vec::new();
    for agg in aggs {
        let Some(func) = AggFunc::lookup(&agg.func.name) else {
            let mut d = err(
                format!("unknown aggregation `{}`", agg.func.name),
                agg.func.span,
            );
            if let Some(s) = suggest(&agg.func.name, AggFunc::NAMES.iter().copied()) {
                d = d.with_label(format!("did you mean `{s}`?"));
            } else {
                d = d.with_help(format!("aggregations: {}", AggFunc::NAMES.join(", ")));
            }
            return Err(d);
        };
        let arg = match &agg.arg {
            Some(e) => Some((check_expr(e, cur)?, e.span)),
            None => None,
        };
        let out_ty = match (func, &arg) {
            (AggFunc::Count, _) => Type::Int,
            (_, None) => {
                return Err(
                    err(format!("`{}` needs an argument", func.name()), agg.span)
                        .with_help(format!("e.g. `{}(duration)`", func.name())),
                )
            }
            (AggFunc::Dc, Some(_)) => Type::Int,
            (AggFunc::Min | AggFunc::Max | AggFunc::First | AggFunc::Last, Some((t, _))) => t.ty,
            (AggFunc::Sum, Some((t, sp))) => match t.ty {
                Type::Int | Type::Float | Type::Duration | Type::Null => t.ty,
                other => return Err(type_err(func, other, *sp)),
            },
            (AggFunc::Avg, Some((t, sp))) => match t.ty {
                Type::Int | Type::Float | Type::Null => Type::Float,
                Type::Duration => Type::Duration,
                other => return Err(type_err(func, other, *sp)),
            },
            (AggFunc::Stdev, Some((t, sp))) => match t.ty {
                Type::Int | Type::Float | Type::Duration | Type::Null => Type::Float,
                other => return Err(type_err(func, other, *sp)),
            },
        };
        let name = match (&agg.alias, &agg.arg) {
            (Some(a), _) => a.name.clone(),
            (None, None) => func.name().to_string(),
            (None, Some(e)) => match &e.kind {
                ExprKind::Field(f) => format!("{}_{}", func.name(), f),
                _ => func.name().to_string(),
            },
        };
        if out.index_of(&name).is_some() {
            return Err(err(format!("duplicate output column `{name}`"), agg.span)
                .with_help("give the aggregation a distinct name with `as <name>`"));
        }
        out.push(
            name,
            if out_ty == Type::Null {
                Type::Str
            } else {
                out_ty
            },
        );
        specs.push(AggSpec {
            func,
            arg: arg.map(|(t, _)| t),
        });
    }
    Ok((
        Some(PlanOp::Aggregate {
            keys: key_idx,
            aggs: specs,
        }),
        out,
    ))
}

fn type_err(func: AggFunc, ty: Type, span: Span) -> Diagnostic {
    err(
        format!("`{}` cannot aggregate values of type {ty}", func.name()),
        span,
    )
    .with_label("expected a number or duration")
}

// ---------------------------------------------------------------------------
// Operator options
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum OptKind {
    Count,
    Fraction,
    Duration,
}

struct Options<'a> {
    opts: &'a [ast::Opt],
}

impl<'a> Options<'a> {
    fn parse(opts: &'a [ast::Opt], allowed: &[(&str, OptKind)]) -> PResult<Self> {
        let mut seen = HashSet::new();
        for o in opts {
            let Some((_, kind)) = allowed.iter().find(|(n, _)| *n == o.name.name) else {
                let names: Vec<&str> = allowed.iter().map(|(n, _)| *n).collect();
                let mut d = err(format!("unknown option `{}`", o.name.name), o.name.span);
                d = match suggest(&o.name.name, names.iter().copied()) {
                    Some(s) => d.with_label(format!("did you mean `{s}`?")),
                    None => d.with_help(format!("options: {}", names.join(", "))),
                };
                return Err(d);
            };
            if !seen.insert(o.name.name.as_str()) {
                return Err(err(format!("option `{}` given twice", o.name.name), o.span));
            }
            let ok = match (kind, &o.value) {
                (OptKind::Count, Literal::Int(i)) => *i >= 0,
                (OptKind::Fraction, Literal::Float(f)) => (0.0..=1.0).contains(f),
                (OptKind::Fraction, Literal::Int(i)) => (0..=1).contains(i),
                (OptKind::Duration, Literal::Duration(d)) => *d >= 0,
                _ => false,
            };
            if !ok {
                let want = match kind {
                    OptKind::Count => "a non-negative integer",
                    OptKind::Fraction => "a number between 0 and 1",
                    OptKind::Duration => "a duration such as `6h`",
                };
                return Err(err(
                    format!("option `{}` expects {want}", o.name.name),
                    o.span,
                ));
            }
        }
        Ok(Options { opts })
    }

    fn get(&self, name: &str) -> Option<&ast::Opt> {
        self.opts.iter().find(|o| o.name.name == name)
    }

    fn span(&self, name: &str) -> Span {
        self.get(name).map(|o| o.span).unwrap_or_default()
    }

    fn count(&self, name: &str) -> Option<u64> {
        match self.get(name)?.value {
            Literal::Int(i) => u64::try_from(i).ok(),
            _ => None,
        }
    }

    fn fraction(&self, name: &str) -> Option<f64> {
        match self.get(name)?.value {
            Literal::Int(i) => Some(i as f64),
            Literal::Float(f) => Some(f),
            _ => None,
        }
    }

    fn duration(&self, name: &str) -> Option<i64> {
        match self.get(name)?.value {
            Literal::Duration(d) => Some(d),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

fn expect_type(t: &TExpr, want: Type, span: Span, what: &str) -> PResult<()> {
    if t.ty == want || t.ty == Type::Null {
        Ok(())
    } else {
        Err(err(format!("{what} must be {want}, found {}", t.ty), span))
    }
}

fn literal_value(l: &Literal) -> Value {
    match l {
        Literal::Null => Value::Null,
        Literal::Bool(b) => Value::Bool(*b),
        Literal::Int(i) => Value::Int(*i),
        Literal::Float(f) => Value::Float(*f),
        Literal::Str(s) => Value::str(s),
        Literal::Duration(d) => Value::Duration(*d),
        Literal::Ip(ip) => Value::Addr(*ip),
        Literal::Cidr(c) => Value::Subnet(*c),
    }
}

/// Fold a node whose children are all constants.
fn fold(t: TExpr) -> TExpr {
    let all_const = match &t.kind {
        TExprKind::Const(_) | TExprKind::Col(_) => return t,
        TExprKind::Not(e) | TExprKind::Neg(e) => e.is_const(),
        TExprKind::And(a, b)
        | TExprKind::Or(a, b)
        | TExprKind::Cmp(_, a, b)
        | TExprKind::Arith(_, a, b) => a.is_const() && b.is_const(),
        TExprKind::Regex { expr, .. }
        | TExprKind::InSet { expr, .. }
        | TExprKind::InSubnets { expr, .. } => expr.is_const(),
        TExprKind::Call(_, args) => args.iter().all(TExpr::is_const),
    };
    if all_const {
        let v = t.eval(&[]);
        let ty = if v.is_null() { t.ty } else { v.ty() };
        TExpr::new(TExprKind::Const(v), ty)
    } else {
        t
    }
}

/// Try to reinterpret a string constant as `target` (addr, time, subnet).
fn coerce_literal(t: TExpr, target: Type, span: Span) -> PResult<TExpr> {
    let TExprKind::Const(Value::Str(s)) = &t.kind else {
        return Ok(t);
    };
    let parsed = match target {
        Type::Addr => s.parse().ok().map(Value::Addr),
        Type::Time => crate::timefmt::parse_iso(s).map(Value::Time),
        Type::Subnet => Subnet::parse(s).map(Value::Subnet),
        _ => return Ok(t),
    };
    match parsed {
        Some(v) => Ok(TExpr::constant(v)),
        None => Err(
            err(format!("cannot parse {:?} as {target}", &**s), span).with_help(match target {
                Type::Time => "write times as ISO-8601, e.g. \"2024-01-31T12:00:00Z\"",
                Type::Subnet => "write subnets as a.b.c.d/n",
                _ => "write IPv4 addresses bare (10.0.0.1) or IPv6 as a string (\"fe80::1\")",
            }),
        ),
    }
}

fn comparable(a: Type, b: Type) -> bool {
    a == b || a == Type::Null || b == Type::Null || (a.is_numeric() && b.is_numeric())
}

/// Type-check an expression against a schema.
pub fn check_expr(e: &ast::Expr, schema: &Schema) -> PResult<TExpr> {
    let t = match &e.kind {
        ExprKind::Literal(l) => TExpr::constant(literal_value(l)),
        ExprKind::Field(name) => {
            let i = schema
                .resolve(name)
                .ok_or_else(|| unknown_field(schema, name, e.span))?;
            TExpr::new(TExprKind::Col(i), schema.columns[i].ty)
        }
        ExprKind::Unary(UnOp::Not, inner) => {
            let t = check_expr(inner, schema)?;
            expect_type(&t, Type::Bool, inner.span, "the operand of `not`")?;
            TExpr::new(TExprKind::Not(Box::new(t)), Type::Bool)
        }
        ExprKind::Unary(UnOp::Neg, inner) => {
            let t = check_expr(inner, schema)?;
            if !matches!(t.ty, Type::Int | Type::Float | Type::Duration | Type::Null) {
                return Err(err(
                    format!("cannot negate a value of type {}", t.ty),
                    e.span,
                ));
            }
            let ty = t.ty;
            TExpr::new(TExprKind::Neg(Box::new(t)), ty)
        }
        ExprKind::Binary(op, l, r) => check_binary(*op, l, r, e.span, schema)?,
        ExprKind::In {
            expr,
            list,
            negated,
        } => check_in(expr, list, *negated, schema)?,
        ExprKind::Call(name, args) => check_call(name, args, e.span, schema)?,
    };
    Ok(fold(t))
}

fn check_binary(
    op: BinOp,
    l: &ast::Expr,
    r: &ast::Expr,
    span: Span,
    schema: &Schema,
) -> PResult<TExpr> {
    let mut lt = check_expr(l, schema)?;
    let mut rt = check_expr(r, schema)?;
    match op {
        BinOp::And | BinOp::Or => {
            expect_type(
                &lt,
                Type::Bool,
                l.span,
                &format!("the left side of `{}`", op.symbol()),
            )?;
            expect_type(
                &rt,
                Type::Bool,
                r.span,
                &format!("the right side of `{}`", op.symbol()),
            )?;
            let kind = if op == BinOp::And {
                TExprKind::And(Box::new(lt), Box::new(rt))
            } else {
                TExprKind::Or(Box::new(lt), Box::new(rt))
            };
            Ok(TExpr::new(kind, Type::Bool))
        }
        BinOp::Match | BinOp::NotMatch => {
            expect_type(&lt, Type::Str, l.span, "the left side of a regex match")?;
            let TExprKind::Const(Value::Str(pat)) = &rt.kind else {
                return Err(err(
                    "the right side of a regex match must be a string literal",
                    r.span,
                ));
            };
            let re = Regex::new(pat).map_err(|e| {
                let msg = e.to_string();
                let last = msg.lines().last().unwrap_or("invalid regex").trim();
                let last = last.trim_start_matches("error: ").to_string();
                err(format!("invalid regular expression: {last}"), r.span)
            })?;
            Ok(TExpr::new(
                TExprKind::Regex {
                    expr: Box::new(lt),
                    re,
                    negated: op == BinOp::NotMatch,
                },
                Type::Bool,
            ))
        }
        _ if op.is_comparison() => {
            lt = coerce_literal(lt, rt.ty, l.span)?;
            rt = coerce_literal(rt, lt.ty, r.span)?;
            if !comparable(lt.ty, rt.ty) {
                let mut d = err(format!("cannot compare {} with {}", lt.ty, rt.ty), span)
                    .with_label(format!("`{}` vs `{}`", lt.ty, rt.ty));
                if lt.ty == Type::Duration || rt.ty == Type::Duration {
                    d = d.with_help("write durations with a unit, e.g. `duration > 30s`");
                } else if lt.ty == Type::Subnet || rt.ty == Type::Subnet {
                    d = d.with_help("test subnet membership with `in`, e.g. `src in 10.0.0.0/8`");
                }
                return Err(d);
            }
            let cmp = match op {
                BinOp::Eq => CmpOp::Eq,
                BinOp::NotEq => CmpOp::Ne,
                BinOp::Lt => CmpOp::Lt,
                BinOp::Le => CmpOp::Le,
                BinOp::Gt => CmpOp::Gt,
                _ => CmpOp::Ge,
            };
            Ok(TExpr::new(
                TExprKind::Cmp(cmp, Box::new(lt), Box::new(rt)),
                Type::Bool,
            ))
        }
        _ => {
            let aop = match op {
                BinOp::Add => ArithOp::Add,
                BinOp::Sub => ArithOp::Sub,
                BinOp::Mul => ArithOp::Mul,
                BinOp::Div => ArithOp::Div,
                _ => ArithOp::Mod,
            };
            let ty = arith_type(aop, lt.ty, rt.ty).ok_or_else(|| {
                err(
                    format!("cannot apply `{}` to {} and {}", op.symbol(), lt.ty, rt.ty),
                    span,
                )
            })?;
            Ok(TExpr::new(
                TExprKind::Arith(aop, Box::new(lt), Box::new(rt)),
                ty,
            ))
        }
    }
}

/// Result type of an arithmetic operator, or `None` if ill-typed.
pub fn arith_type(op: ArithOp, l: Type, r: Type) -> Option<Type> {
    use Type::*;
    Some(match (op, l, r) {
        (_, Null, x) | (_, x, Null) => x,
        (ArithOp::Div, a, b) if a.is_numeric() && b.is_numeric() => Float,
        (_, Int, Int) => Int,
        (_, a, b) if a.is_numeric() && b.is_numeric() => Float,
        (ArithOp::Add, Str, Str) => Str,
        (ArithOp::Sub, Time, Time) => Duration,
        (ArithOp::Add, Time, Duration) | (ArithOp::Add, Duration, Time) => Time,
        (ArithOp::Sub, Time, Duration) => Time,
        (ArithOp::Add | ArithOp::Sub, Duration, Duration) => Duration,
        (ArithOp::Div, Duration, Duration) => Float,
        (ArithOp::Mul, Duration, n) | (ArithOp::Mul, n, Duration) if n.is_numeric() => Duration,
        (ArithOp::Div, Duration, n) if n.is_numeric() => Duration,
        _ => return None,
    })
}

fn check_in(
    expr: &ast::Expr,
    list: &[ast::Expr],
    negated: bool,
    schema: &Schema,
) -> PResult<TExpr> {
    let t = check_expr(expr, schema)?;
    if list.is_empty() {
        return Ok(TExpr::constant(Value::Bool(negated)));
    }
    let mut items = Vec::new();
    for item in list {
        let mut it = check_expr(item, schema)?;
        if !it.is_const() {
            return Err(err("`in` lists may only contain constants", item.span));
        }
        if t.ty == Type::Addr {
            // Strings may be addresses or subnets.
            if let TExprKind::Const(Value::Str(s)) = &it.kind {
                it = if s.contains('/') {
                    coerce_literal(it, Type::Subnet, item.span)?
                } else {
                    coerce_literal(it, Type::Addr, item.span)?
                };
            }
        } else {
            it = coerce_literal(it, t.ty, item.span)?;
        }
        let TExprKind::Const(v) = it.kind else {
            unreachable!("checked constant")
        };
        let ok = comparable(t.ty, v.ty()) || (t.ty == Type::Addr && v.ty() == Type::Subnet);
        if !ok {
            return Err(err(
                format!(
                    "cannot test {} membership in a list containing {}",
                    t.ty,
                    v.ty()
                ),
                item.span,
            ));
        }
        items.push(v);
    }
    let any_subnet = items.iter().any(|v| matches!(v, Value::Subnet(_)));
    let kind = if any_subnet {
        let nets = items
            .into_iter()
            .filter_map(|v| match v {
                Value::Subnet(s) => Some(s),
                Value::Addr(a) => Some(Subnet {
                    addr: a,
                    prefix: if a.is_ipv4() { 32 } else { 128 },
                }),
                _ => None,
            })
            .collect();
        TExprKind::InSubnets {
            expr: Box::new(t),
            nets,
            negated,
        }
    } else {
        TExprKind::InSet {
            expr: Box::new(t),
            set: items.into_iter().map(normalize_num).collect(),
            negated,
        }
    };
    Ok(TExpr::new(kind, Type::Bool))
}

fn check_call(
    name: &ast::Ident,
    args: &[ast::Expr],
    span: Span,
    schema: &Schema,
) -> PResult<TExpr> {
    let Some(func) = Func::lookup(&name.name) else {
        let mut d = err(format!("unknown function `{}`", name.name), name.span);
        if AggFunc::lookup(&name.name).is_some() {
            d = d.with_help(format!(
                "`{}` is an aggregation; use it inside `stats`",
                name.name
            ));
        } else if let Some(s) = suggest(&name.name, FUNCTIONS.iter().map(|(n, _, _)| *n)) {
            d = d.with_label(format!("did you mean `{s}`?"));
        }
        return Err(d);
    };
    let typed: Vec<TExpr> = args
        .iter()
        .map(|a| check_expr(a, schema))
        .collect::<PResult<_>>()?;
    let sig = FUNCTIONS
        .iter()
        .find(|(_, f, _)| *f == func)
        .map(|(_, _, s)| *s)
        .unwrap_or("");
    let arity = |n: usize| -> PResult<()> {
        if typed.len() == n {
            Ok(())
        } else {
            Err(err(
                format!(
                    "`{}` takes {n} argument{}, got {}",
                    name.name,
                    if n == 1 { "" } else { "s" },
                    typed.len()
                ),
                span,
            )
            .with_help(sig.to_string()))
        }
    };
    let arg_is = |i: usize, ok: &dyn Fn(Type) -> bool| -> PResult<()> {
        let ty = typed[i].ty;
        if ty == Type::Null || ok(ty) {
            Ok(())
        } else {
            Err(err(
                format!("argument {} of `{}` has type {ty}", i + 1, name.name),
                args[i].span,
            )
            .with_help(sig.to_string()))
        }
    };
    let is = |want: Type| move |t: Type| t == want;
    let ret = match func {
        Func::Len | Func::Lower | Func::Upper | Func::Sld | Func::Entropy => {
            arity(1)?;
            arg_is(0, &is(Type::Str))?;
            match func {
                Func::Len => Type::Int,
                Func::Entropy => Type::Float,
                _ => Type::Str,
            }
        }
        Func::Contains | Func::StartsWith | Func::EndsWith => {
            arity(2)?;
            arg_is(0, &is(Type::Str))?;
            arg_is(1, &is(Type::Str))?;
            Type::Bool
        }
        Func::IsPrivate => {
            arity(1)?;
            arg_is(0, &is(Type::Addr))?;
            Type::Bool
        }
        Func::Coalesce => {
            if typed.is_empty() {
                return Err(err("`coalesce` needs at least one argument", span));
            }
            let ty = typed
                .iter()
                .map(|t| t.ty)
                .find(|t| *t != Type::Null)
                .unwrap_or(Type::Null);
            for i in 0..typed.len() {
                arg_is(i, &|t| t == ty)?;
            }
            ty
        }
        Func::If => {
            arity(3)?;
            arg_is(0, &is(Type::Bool))?;
            let ty = if typed[1].ty == Type::Null {
                typed[2].ty
            } else {
                typed[1].ty
            };
            arg_is(2, &|t| t == ty)?;
            ty
        }
        Func::Round => {
            arity(1)?;
            arg_is(0, &|t| t.is_numeric())?;
            Type::Int
        }
        Func::Abs => {
            arity(1)?;
            arg_is(0, &|t| t.is_numeric() || t == Type::Duration)?;
            typed[0].ty
        }
        Func::ToString => {
            arity(1)?;
            Type::Str
        }
        Func::Seconds => {
            arity(1)?;
            arg_is(0, &|t| t == Type::Duration || t == Type::Time)?;
            Type::Float
        }
        Func::Hour | Func::DayOfWeek => {
            arity(1)?;
            arg_is(0, &is(Type::Time))?;
            Type::Int
        }
        Func::Bin => {
            arity(2)?;
            arg_is(0, &is(Type::Time))?;
            arg_is(1, &is(Type::Duration))?;
            Type::Time
        }
    };
    Ok(TExpr::new(TExprKind::Call(func, typed), ret))
}

// ---------------------------------------------------------------------------
// Rewrites
// ---------------------------------------------------------------------------

fn optimize(ops: Vec<(PlanOp, Schema)>, notes: &mut Vec<String>) -> Vec<(PlanOp, Schema)> {
    let mut out: Vec<(PlanOp, Schema)> = Vec::with_capacity(ops.len());
    for (op, schema) in ops {
        match (out.last_mut(), op) {
            (Some((PlanOp::Filter(prev), _)), PlanOp::Filter(next)) => {
                let merged = TExpr::new(
                    TExprKind::And(Box::new(prev.clone()), Box::new(next)),
                    Type::Bool,
                );
                *prev = merged;
                notes.push("merged adjacent filters into one conjunction".into());
            }
            (Some((PlanOp::Sort(keys), _)), PlanOp::Head(k)) => {
                let keys = std::mem::take(keys);
                let (_, s) = out.pop().expect("last exists");
                out.push((PlanOp::TopK { keys, k }, s));
                notes.push(format!("fused sort + head {k} into a bounded top-k heap"));
            }
            (Some((PlanOp::TopK { k: prev, .. }, _)), PlanOp::Head(k)) => {
                *prev = (*prev).min(k);
            }
            (Some((PlanOp::Head(prev), _)), PlanOp::Head(k)) => {
                *prev = (*prev).min(k);
            }
            (_, op) => out.push((op, schema)),
        }
    }
    out
}

/// Source columns the pipeline reads, or `None` if all are needed (the
/// source schema reaches the output unchanged).
fn needed_columns(ops: &[(PlanOp, Schema)], width: usize) -> Option<Vec<usize>> {
    let mut used = Vec::new();
    let push_expr = |e: &TExpr, used: &mut Vec<usize>| e.columns(used);
    for (op, _) in ops {
        match op {
            PlanOp::Filter(e) => push_expr(e, &mut used),
            PlanOp::Extend(es) => es.iter().for_each(|e| push_expr(e, &mut used)),
            PlanOp::Sort(k) | PlanOp::TopK { keys: k, .. } => used.extend(k.iter().map(|s| s.col)),
            PlanOp::Dedup(k) => used.extend(k),
            PlanOp::Head(_) | PlanOp::Tail(_) => {}
            // Schema-replacing operators: everything downstream reads only
            // their outputs, so collection stops here.
            PlanOp::Project(c) => {
                used.extend(c);
                return Some(finish(used, width));
            }
            PlanOp::Aggregate { keys, aggs } => {
                used.extend(keys);
                for a in aggs {
                    if let Some(e) = &a.arg {
                        push_expr(e, &mut used);
                    }
                }
                return Some(finish(used, width));
            }
            PlanOp::Stack { keys, .. } => {
                used.extend(keys);
                return Some(finish(used, width));
            }
            PlanOp::Rare { field, by, .. } => {
                used.push(*field);
                used.extend(by);
                return Some(finish(used, width));
            }
            PlanOp::FirstSeen { keys, ts, .. } => {
                used.extend(keys);
                used.push(*ts);
                return Some(finish(used, width));
            }
            PlanOp::Beacon {
                keys, ts, bytes, ..
            } => {
                used.extend(keys);
                used.push(*ts);
                used.extend(bytes);
                return Some(finish(used, width));
            }
        }
    }
    None
}

fn finish(mut used: Vec<usize>, width: usize) -> Vec<usize> {
    used.retain(|&c| c < width);
    used.sort_unstable();
    used.dedup();
    used
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_query;

    fn plan_src(src: &str) -> Result<Plan, Diagnostic> {
        plan(&parse_query(src).unwrap(), &BuiltinSchemas)
    }

    fn ok(src: &str) -> Plan {
        plan_src(src).unwrap_or_else(|e| panic!("{}", e.render(src)))
    }

    fn fails(src: &str) -> Diagnostic {
        match plan_src(src) {
            Ok(p) => panic!("expected failure for {src}, got\n{p}"),
            Err(e) => e,
        }
    }

    #[test]
    fn canonical_query_plans_with_topk_and_pruning() {
        let p = ok("conn | where dport==443 | stats count() by src | sort -count | head 10");
        let text = p.to_string();
        assert!(text.contains("TopK k=10 [-count]"), "{text}");
        assert!(
            text.contains("decode 2 of 21 columns: id.orig_h, id.resp_p"),
            "{text}"
        );
        assert_eq!(
            p.output_schema()
                .columns
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            vec!["src", "count"]
        );
        assert!(p.notes.iter().any(|n| n.contains("top-k")));
    }

    #[test]
    fn filters_merge_and_constant_true_drops() {
        let p = ok("conn | where dport == 443 | where proto == \"tcp\" | where 1 < 2");
        assert_eq!(p.ops.len(), 1);
        assert!(p.notes.iter().any(|n| n.contains("merged")));
        assert!(p.source.needed.is_none());
        let p = ok("conn | head 5 | head 3");
        assert!(matches!(p.ops[0].0, PlanOp::Head(3)));
        let p = ok("conn | sort ts | head 5 | head 2");
        assert!(matches!(p.ops[0].0, PlanOp::TopK { k: 2, .. }));
    }

    #[test]
    fn literal_coercion() {
        ok("conn | where src == \"10.0.0.1\" and dst == \"fe80::1\"");
        ok("conn | where ts > \"2023-11-14T00:00:00Z\"");
        ok("conn | where src in [\"10.0.0.0/8\", 192.168.1.1] and dst not in 172.16.0.0/12");
        ok("conn | where dport in [80, 443, 8080.0]");
        let e = fails("conn | where src == \"nope\"");
        assert!(e.message.contains("cannot parse"), "{e:?}");
        let e = fails("conn | where ts > \"yesterday\"");
        assert!(e.help.unwrap().contains("ISO-8601"));
        let e = fails("conn | where src in [\"10.0.0.0/99\"]");
        assert!(e.help.unwrap().contains("subnets"));
    }

    #[test]
    fn type_errors_have_spans_and_help() {
        let src = "conn | where duration > 30";
        let e = fails(src);
        assert_eq!(&src[e.span.start..e.span.end], "duration > 30");
        assert!(e.help.unwrap().contains("30s"));

        let src = "conn | where dprt == 443";
        let e = fails(src);
        assert_eq!(&src[e.span.start..e.span.end], "dprt");
        assert_eq!(e.label.as_deref(), Some("did you mean `dport`?"));

        assert!(fails("conn | where src == 10.0.0.0/8")
            .help
            .unwrap()
            .contains("`in`"));
        assert!(fails("conn | where dport").message.contains("must be bool"));
        assert!(fails("conn | where not dport")
            .message
            .contains("operand of `not`"));
        assert!(fails("conn | where -proto == 1").message.contains("negate"));
        assert!(fails("conn | where dport == 1 and 5")
            .message
            .contains("right side"));
        assert!(fails("conn | where proto =~ \"(\"")
            .message
            .contains("invalid regular expression"));
        assert!(fails("conn | where proto =~ proto")
            .message
            .contains("string literal"));
        assert!(fails("conn | where dport =~ \"x\"")
            .message
            .contains("regex"));
        assert!(fails("conn | eval x = proto * 2")
            .message
            .contains("cannot apply"));
        assert!(fails("conn | where dport in [src]")
            .message
            .contains("constants"));
        assert!(fails("conn | where dport in [\"a\"]")
            .message
            .contains("membership"));
        assert!(fails("qux | head")
            .help
            .unwrap()
            .contains("available sources"));
        assert_eq!(
            fails("con | head").label.as_deref(),
            Some("did you mean `conn`?")
        );
        assert!(fails("conn | where zzzzzzzzzzz == 1")
            .help
            .unwrap()
            .contains("fields here"));
    }

    #[test]
    fn functions_check_arity_and_types() {
        ok("dns | eval e = entropy(query), d = sld(query), h = hour(ts), b = bin(ts, 1h) | where e > 3.5");
        ok("conn | eval p = is_private(dst), s = seconds(duration), r = round(1.6), a = abs(duration)");
        ok("conn | eval c = coalesce(service, \"none\"), i = if(dport == 443, \"tls\", \"other\")");
        ok("conn | eval t = tostring(dport), w = dayofweek(ts), l = len(uid), u = upper(proto)");
        ok("http | where contains(uri, \"/admin\") or startswith(host, \"x\") or endswith(host, \".test\")");
        assert!(fails("conn | eval x = len(dport)")
            .message
            .contains("argument 1"));
        assert!(fails("conn | eval x = len()")
            .message
            .contains("takes 1 argument"));
        assert!(fails("conn | eval x = lenn(uid)")
            .label
            .unwrap()
            .contains("len"));
        assert!(fails("conn | eval x = count()")
            .help
            .unwrap()
            .contains("aggregation"));
        assert!(fails("conn | eval x = coalesce()")
            .message
            .contains("at least one"));
        assert!(fails("conn | eval x = if(true, 1, \"a\")")
            .message
            .contains("argument 3"));
        assert!(fails("conn | eval x = bin(ts, 5)")
            .message
            .contains("argument 2"));
    }

    #[test]
    fn constant_folding() {
        let p = ok("conn | eval x = 1 + 2 * 3, y = len(\"abc\"), z = -(2)");
        let PlanOp::Extend(es) = &p.ops[0].0 else {
            panic!()
        };
        assert!(es.iter().all(TExpr::is_const));
        assert_eq!(es[0].eval(&[]), Value::Int(7));
        assert_eq!(es[2].eval(&[]), Value::Int(-2));
        let p = ok("conn | where dport in []");
        assert!(matches!(&p.ops[0].0, PlanOp::Filter(t) if t.is_const()));
    }

    #[test]
    fn stage_schemas() {
        let p = ok("conn | fields - uid, history | rename src as client | eval kb = orig_bytes / 1024 \
                    | stats count(), avg(kb), sum(duration), dc(dst) as peers, min(ts), max(ts), stdev(orig_bytes), \
                    first(proto), last(proto) by client");
        let names: Vec<_> = p
            .output_schema()
            .columns
            .iter()
            .map(|c| c.name.clone())
            .collect();
        assert_eq!(
            names,
            vec![
                "client",
                "count",
                "avg_kb",
                "sum_duration",
                "peers",
                "min_ts",
                "max_ts",
                "stdev_orig_bytes",
                "first_proto",
                "last_proto"
            ]
        );
        let tys: Vec<_> = p.output_schema().columns.iter().map(|c| c.ty).collect();
        assert_eq!(tys[3], Type::Duration);
        assert_eq!(tys[5], Type::Time);
        assert_eq!(p.source.needed.as_ref().unwrap().len(), 19);
        let p = ok("conn | fields src, dport | dedup src | tail 3");
        assert_eq!(p.output_schema().len(), 2);
        let p = ok("conn | stats avg(duration) as d");
        assert_eq!(p.output_schema().columns[0].ty, Type::Duration);
    }

    #[test]
    fn stage_errors() {
        assert!(fails("conn | fields - ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig, local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes, tunnel_parents").message.contains("every column"));
        assert!(fails("conn | fields src, src").message.contains("twice"));
        assert!(fails("conn | eval proto = 1")
            .message
            .contains("already exists"));
        assert!(fails("conn | rename src as dst")
            .message
            .contains("already exists"));
        assert!(fails("conn | stats sum()")
            .message
            .contains("needs an argument"));
        assert!(fails("conn | stats sum(proto)")
            .message
            .contains("cannot aggregate"));
        assert!(fails("conn | stats avg(proto)")
            .message
            .contains("cannot aggregate"));
        assert!(fails("conn | stats stdev(src)")
            .message
            .contains("cannot aggregate"));
        assert!(fails("conn | stats count(), count()")
            .help
            .unwrap()
            .contains("as <name>"));
        assert_eq!(
            fails("conn | stats cnt()").label.as_deref(),
            Some("did you mean `count`?")
        );
        assert!(fails("conn | stats zzzzzz()")
            .help
            .unwrap()
            .contains("aggregations"));
        assert!(fails("conn | sort nope").message.contains("unknown field"));
        assert!(fails("conn | stats count() by src | first_seen src")
            .message
            .contains("`ts`"));
        assert!(fails("conn | fields src | beacon").message.contains("`ts`"));
    }

    #[test]
    fn hunting_operators() {
        let p = ok("ssl | stack server_name limit=5");
        assert_eq!(p.output_schema().columns.last().unwrap().name, "cum_pct");
        let p = ok("http | rare user_agent by src limit=3");
        assert_eq!(p.output_schema().len(), 3);
        let p = ok("http | rare user_agent");
        assert_eq!(p.output_schema().len(), 2);
        let p = ok("dns | first_seen query baseline=6h");
        assert!(p.to_string().contains("baseline=6h"));
        let p = ok("conn | beacon min_count=5 min_score=0.6");
        let text = p.to_string();
        assert!(
            text.contains("Beacon [id.orig_h, id.resp_h, id.resp_p] min_count=5 min_score=0.6"),
            "{text}"
        );
        assert!(text.contains("orig_bytes"), "{text}");
        ok("dns | beacon by src, query max_events=100");
        ok("conn | beacon min_score=1");
        assert!(fails("conn | beacon min_count=2")
            .message
            .contains("at least 3"));
        assert!(fails("conn | beacon max_events=5")
            .message
            .contains("at least `min_count`"));
        assert!(fails("conn | beacon min_score=1.5")
            .message
            .contains("between 0 and 1"));
        assert_eq!(
            fails("conn | beacon min_cnt=5").label.as_deref(),
            Some("did you mean `min_count`?")
        );
        assert!(fails("conn | stack src zzzzzzz=1")
            .help
            .unwrap()
            .contains("options: limit"));
        assert!(fails("conn | stack src limit=1 limit=2")
            .message
            .contains("twice"));
        assert!(fails("conn | first_seen src baseline=5")
            .message
            .contains("duration"));
        assert!(fails("conn | stats count() by dport | beacon by dport")
            .message
            .contains("`ts`"));
        let e = fails("conn | fields ts, uid | beacon");
        assert!(e.help.unwrap().contains("by default"));
    }
}
