//! Physical query plans.
//!
//! A [`Plan`] is a linear pipeline of [`PlanOp`]s over typed rows. Each
//! operator addresses columns of its *input* schema by index; the planner
//! records the output schema after every step so `explain` can show it.

use std::fmt;

use crate::beacon::BeaconParams;
use crate::expr::TExpr;
use crate::schema::Schema;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggFunc {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    /// Distinct count (exact; memory grows with distinct values per group).
    Dc,
    Stdev,
    First,
    Last,
}

impl AggFunc {
    pub fn lookup(name: &str) -> Option<AggFunc> {
        Some(match name {
            "count" => AggFunc::Count,
            "sum" => AggFunc::Sum,
            "avg" | "mean" => AggFunc::Avg,
            "min" => AggFunc::Min,
            "max" => AggFunc::Max,
            "dc" | "distinct_count" => AggFunc::Dc,
            "stdev" => AggFunc::Stdev,
            "first" => AggFunc::First,
            "last" => AggFunc::Last,
            _ => return None,
        })
    }

    pub const NAMES: &'static [&'static str] = &[
        "count", "sum", "avg", "min", "max", "dc", "stdev", "first", "last",
    ];

    pub fn name(self) -> &'static str {
        match self {
            AggFunc::Count => "count",
            AggFunc::Sum => "sum",
            AggFunc::Avg => "avg",
            AggFunc::Min => "min",
            AggFunc::Max => "max",
            AggFunc::Dc => "dc",
            AggFunc::Stdev => "stdev",
            AggFunc::First => "first",
            AggFunc::Last => "last",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AggSpec {
    pub func: AggFunc,
    pub arg: Option<TExpr>,
}

/// Sort key: column index and direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortSpec {
    pub col: usize,
    pub descending: bool,
}

#[derive(Debug, Clone)]
pub enum PlanOp {
    Filter(TExpr),
    /// Keep only these input columns, in this order.
    Project(Vec<usize>),
    /// Append one computed column per expression.
    Extend(Vec<TExpr>),
    Aggregate {
        keys: Vec<usize>,
        aggs: Vec<AggSpec>,
    },
    Sort(Vec<SortSpec>),
    /// `sort ... | head k` fused into a bounded heap.
    TopK {
        keys: Vec<SortSpec>,
        k: u64,
    },
    Head(u64),
    Tail(u64),
    Dedup(Vec<usize>),
    Stack {
        keys: Vec<usize>,
        limit: Option<u64>,
    },
    Rare {
        field: usize,
        by: Vec<usize>,
        limit: u64,
    },
    FirstSeen {
        keys: Vec<usize>,
        ts: usize,
        baseline: Option<i64>,
    },
    Beacon {
        keys: Vec<usize>,
        ts: usize,
        bytes: Option<usize>,
        params: BeaconParams,
    },
}

impl PlanOp {
    /// True for operators that must see their whole input before emitting.
    pub fn is_blocking(&self) -> bool {
        !matches!(
            self,
            PlanOp::Filter(_)
                | PlanOp::Project(_)
                | PlanOp::Extend(_)
                | PlanOp::Head(_)
                | PlanOp::Dedup(_)
        )
    }

    /// Memory class shown by `explain`.
    pub fn memory(&self) -> &'static str {
        match self {
            PlanOp::Filter(_) | PlanOp::Project(_) | PlanOp::Extend(_) | PlanOp::Head(_) => "O(1)",
            PlanOp::TopK { .. } | PlanOp::Tail(_) => "O(k)",
            PlanOp::Sort(_) => "O(n) rows",
            PlanOp::Dedup(_) => "O(distinct keys)",
            PlanOp::Aggregate { .. } | PlanOp::Stack { .. } | PlanOp::FirstSeen { .. } => {
                "O(groups)"
            }
            PlanOp::Rare { .. } => "O(distinct value x entity pairs)",
            PlanOp::Beacon { .. } => "O(groups x max_events)",
        }
    }
}

/// Where the rows come from.
#[derive(Debug, Clone)]
pub struct SourceSpec {
    pub log: String,
    pub schema: Schema,
    /// Source columns that must be decoded; others are left null. `None`
    /// means all columns are needed.
    pub needed: Option<Vec<usize>>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub source: SourceSpec,
    /// Operators paired with the schema they output.
    pub ops: Vec<(PlanOp, Schema)>,
    /// Human-readable notes about rewrites the planner applied.
    pub notes: Vec<String>,
}

impl Plan {
    pub fn output_schema(&self) -> &Schema {
        self.ops
            .last()
            .map(|(_, s)| s)
            .unwrap_or(&self.source.schema)
    }
}

fn cols(schema: &Schema, idx: &[usize]) -> String {
    idx.iter()
        .map(|&i| {
            schema
                .columns
                .get(i)
                .map(|c| c.name.as_str())
                .unwrap_or("?")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn sort_keys(schema: &Schema, keys: &[SortSpec]) -> String {
    keys.iter()
        .map(|k| {
            format!(
                "{}{}",
                if k.descending { "-" } else { "" },
                schema
                    .columns
                    .get(k.col)
                    .map(|c| c.name.as_str())
                    .unwrap_or("?")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src = &self.source;
        let decoded = match &src.needed {
            None => format!("all {} columns", src.schema.len()),
            Some(n) => format!(
                "{} of {} columns: {}",
                n.len(),
                src.schema.len(),
                cols(&src.schema, n)
            ),
        };
        writeln!(f, "Scan {} (decode {decoded})", src.log)?;
        let mut input = &src.schema;
        for (op, out) in &self.ops {
            let names: Vec<String> = input.columns.iter().map(|c| c.name.clone()).collect();
            let desc = match op {
                PlanOp::Filter(e) => format!("Filter {}", e.named(&names)),
                PlanOp::Project(c) => format!("Project [{}]", cols(input, c)),
                PlanOp::Extend(exprs) => {
                    let start = input.len();
                    // Later expressions may reference columns added earlier.
                    let out_names: Vec<String> =
                        out.columns.iter().map(|c| c.name.clone()).collect();
                    let parts: Vec<String> = exprs
                        .iter()
                        .enumerate()
                        .map(|(i, e)| {
                            format!("{} = {}", out.columns[start + i].name, e.named(&out_names))
                        })
                        .collect();
                    format!("Extend [{}]", parts.join(", "))
                }
                PlanOp::Aggregate { keys, aggs } => {
                    let a: Vec<String> = aggs
                        .iter()
                        .map(|a| {
                            format!(
                                "{}({})",
                                a.func.name(),
                                a.arg
                                    .as_ref()
                                    .map(|e| e.named(&names).to_string())
                                    .unwrap_or_default()
                            )
                        })
                        .collect();
                    format!("Aggregate [{}] by [{}]", a.join(", "), cols(input, keys))
                }
                PlanOp::Sort(k) => format!("Sort [{}]", sort_keys(input, k)),
                PlanOp::TopK { keys, k } => format!("TopK k={k} [{}]", sort_keys(input, keys)),
                PlanOp::Head(n) => format!("Head {n}"),
                PlanOp::Tail(n) => format!("Tail {n}"),
                PlanOp::Dedup(k) => format!("Dedup [{}]", cols(input, k)),
                PlanOp::Stack { keys, limit } => format!(
                    "Stack [{}]{}",
                    cols(input, keys),
                    limit.map(|l| format!(" limit={l}")).unwrap_or_default()
                ),
                PlanOp::Rare { field, by, limit } => format!(
                    "Rare {} by [{}] limit={limit}",
                    cols(input, &[*field]),
                    cols(input, by)
                ),
                PlanOp::FirstSeen { keys, baseline, .. } => format!(
                    "FirstSeen [{}]{}",
                    cols(input, keys),
                    baseline
                        .map(|b| format!(" baseline={}", crate::timefmt::format_duration(b)))
                        .unwrap_or_default()
                ),
                PlanOp::Beacon { keys, params, .. } => format!(
                    "Beacon [{}] min_count={} min_score={} max_events={}",
                    cols(input, keys),
                    params.min_count,
                    params.min_score,
                    params.max_events
                ),
            };
            let kind = if op.is_blocking() {
                "blocking"
            } else {
                "streaming"
            };
            writeln!(f, "  -> {desc}  ({kind}, mem {})", op.memory())?;
            input = out;
        }
        let out: Vec<String> = self
            .output_schema()
            .columns
            .iter()
            .map(|c| format!("{}:{}", c.name, c.ty))
            .collect();
        write!(f, "Output [{}]", out.join(", "))?;
        for n in &self.notes {
            write!(f, "\nnote: {n}")?;
        }
        Ok(())
    }
}
