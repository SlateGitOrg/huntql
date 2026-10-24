//! Push-based streaming executor.
//!
//! Rows flow from a [`RowSource`] through a chain of [`Operator`]s into a
//! [`Sink`]. Streaming operators (`where`, `eval`, `fields`, `head`) hold no
//! rows; blocking operators keep only their aggregate state and emit on
//! [`Operator::finish`]. Any operator may answer [`Flow::Stop`] (e.g. `head`
//! after its last row), which stops the scan early.
//!
//! Memory is bounded by [`ExecOptions::max_groups`]: a grouping operator that
//! would exceed it fails with [`ExecError::GroupLimit`] instead of growing
//! without bound. [`ExecStats::peak_state`] reports the largest number of
//! rows/groups held at once, which the bounded-memory tests assert on.

mod agg;
mod hunt;
mod ops;

use std::fmt;
use std::time::{Duration, Instant};

use crate::plan::{Plan, PlanOp};
use crate::value::Value;

pub type Row = Vec<Value>;

/// Whether upstream should keep producing rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Stop,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("{op}: group limit of {limit} exceeded")]
    GroupLimit { op: &'static str, limit: usize },
    #[error("{0}")]
    Source(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Runtime limits.
#[derive(Debug, Clone, Copy)]
pub struct ExecOptions {
    /// Maximum distinct groups/rows any single blocking operator may hold.
    pub max_groups: usize,
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            max_groups: 2_000_000,
        }
    }
}

/// Counters reported after a run.
#[derive(Debug, Clone, Default)]
pub struct ExecStats {
    pub rows_scanned: u64,
    pub rows_emitted: u64,
    /// Largest total number of rows/groups retained by operators at once.
    pub peak_state: usize,
    pub elapsed: Duration,
    /// True if the scan ended early because the pipeline asked to stop.
    pub stopped_early: bool,
}

impl fmt::Display for ExecStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scanned {} rows, emitted {}, peak state {} rows/groups, {:.1} ms{}",
            self.rows_scanned,
            self.rows_emitted,
            self.peak_state,
            self.elapsed.as_secs_f64() * 1e3,
            if self.stopped_early {
                " (stopped early)"
            } else {
                ""
            }
        )
    }
}

/// Producer of input rows (laid out per the plan's source schema).
pub trait RowSource {
    /// Next row, `Ok(None)` at end of input.
    fn next_row(&mut self) -> Result<Option<Row>, ExecError>;
}

/// In-memory row source, used by tests and the evaluation harness.
pub struct VecSource {
    rows: std::vec::IntoIter<Row>,
}

impl VecSource {
    pub fn new(rows: Vec<Row>) -> Self {
        VecSource {
            rows: rows.into_iter(),
        }
    }
}

impl RowSource for VecSource {
    fn next_row(&mut self) -> Result<Option<Row>, ExecError> {
        Ok(self.rows.next())
    }
}

/// Consumer of result rows.
pub trait Sink {
    fn write(&mut self, row: Row) -> Result<Flow, ExecError>;
    fn finish(&mut self) -> Result<(), ExecError> {
        Ok(())
    }
}

/// Collects results in memory.
#[derive(Debug, Default)]
pub struct CollectSink {
    pub rows: Vec<Row>,
}

impl Sink for CollectSink {
    fn write(&mut self, row: Row) -> Result<Flow, ExecError> {
        self.rows.push(row);
        Ok(Flow::Continue)
    }
}

/// Downstream of an operator: the rest of the chain plus the sink.
pub trait Emit {
    fn emit(&mut self, row: Row) -> Result<Flow, ExecError>;
}

/// A physical operator instance.
pub trait Operator {
    fn push(&mut self, row: Row, out: &mut dyn Emit) -> Result<Flow, ExecError>;
    fn finish(&mut self, _out: &mut dyn Emit) -> Result<(), ExecError> {
        Ok(())
    }
    /// Rows or groups currently retained.
    fn state_size(&self) -> usize {
        0
    }
}

struct Chain<'a> {
    ops: &'a mut [Box<dyn Operator>],
    sink: &'a mut dyn Sink,
    emitted: &'a mut u64,
}

impl Emit for Chain<'_> {
    fn emit(&mut self, row: Row) -> Result<Flow, ExecError> {
        match self.ops.split_first_mut() {
            None => {
                *self.emitted += 1;
                self.sink.write(row)
            }
            Some((first, rest)) => first.push(
                row,
                &mut Chain {
                    ops: rest,
                    sink: self.sink,
                    emitted: self.emitted,
                },
            ),
        }
    }
}

/// Instantiate runtime operators for a plan.
pub fn build_operators(plan: &Plan, opts: ExecOptions) -> Vec<Box<dyn Operator>> {
    plan.ops
        .iter()
        .map(|(op, out_schema)| -> Box<dyn Operator> {
            let limit = opts.max_groups;
            match op {
                PlanOp::Filter(e) => Box::new(ops::Filter(e.clone())),
                PlanOp::Project(cols) => Box::new(ops::Project(cols.clone())),
                PlanOp::Extend(exprs) => Box::new(ops::Extend(exprs.clone())),
                PlanOp::Head(n) => Box::new(ops::Head::new(*n)),
                PlanOp::Tail(n) => Box::new(ops::Tail::new(*n, limit)),
                PlanOp::Sort(keys) => Box::new(ops::Sort::new(keys.clone(), limit)),
                PlanOp::TopK { keys, k } => Box::new(ops::TopK::new(keys.clone(), *k, limit)),
                PlanOp::Dedup(keys) => Box::new(ops::Dedup::new(keys.clone(), limit)),
                PlanOp::Aggregate { keys, aggs } => {
                    let out_types = out_schema.columns[keys.len()..]
                        .iter()
                        .map(|c| c.ty)
                        .collect();
                    Box::new(agg::Aggregate::new(
                        keys.clone(),
                        aggs.clone(),
                        out_types,
                        limit,
                    ))
                }
                PlanOp::Stack { keys, limit: l } => {
                    Box::new(hunt::Stack::new(keys.clone(), *l, limit))
                }
                PlanOp::Rare {
                    field,
                    by,
                    limit: l,
                } => Box::new(hunt::Rare::new(*field, by.clone(), *l, limit)),
                PlanOp::FirstSeen { keys, ts, baseline } => {
                    Box::new(hunt::FirstSeen::new(keys.clone(), *ts, *baseline, limit))
                }
                PlanOp::Beacon {
                    keys,
                    ts,
                    bytes,
                    params,
                } => Box::new(hunt::Beacon::new(keys.clone(), *ts, *bytes, *params, limit)),
            }
        })
        .collect()
}

/// Execute `plan` over `source`, writing results to `sink`.
pub fn execute(
    plan: &Plan,
    source: &mut dyn RowSource,
    sink: &mut dyn Sink,
    opts: ExecOptions,
) -> Result<ExecStats, ExecError> {
    let start = Instant::now();
    let mut ops = build_operators(plan, opts);
    let mut stats = ExecStats::default();
    let mut emitted = 0u64;
    let state = |ops: &[Box<dyn Operator>]| ops.iter().map(|o| o.state_size()).sum::<usize>();
    while let Some(row) = source.next_row()? {
        stats.rows_scanned += 1;
        let flow = Chain {
            ops: &mut ops,
            sink,
            emitted: &mut emitted,
        }
        .emit(row)?;
        if stats.rows_scanned % 1024 == 0 {
            stats.peak_state = stats.peak_state.max(state(&ops));
        }
        if flow == Flow::Stop {
            stats.stopped_early = true;
            break;
        }
    }
    stats.peak_state = stats.peak_state.max(state(&ops));
    // Finish operators in order; each flushes into the remainder of the chain.
    for i in 0..ops.len() {
        let (head, rest) = ops.split_at_mut(i + 1);
        head[i].finish(&mut Chain {
            ops: rest,
            sink,
            emitted: &mut emitted,
        })?;
        stats.peak_state = stats.peak_state.max(state(&ops));
    }
    sink.finish()?;
    stats.rows_emitted = emitted;
    stats.elapsed = start.elapsed();
    log::debug!("execution finished: {stats}");
    Ok(stats)
}

/// Check a group count against the limit.
pub(crate) fn check_limit(op: &'static str, len: usize, limit: usize) -> Result<(), ExecError> {
    if len > limit {
        Err(ExecError::GroupLimit { op, limit })
    } else {
        Ok(())
    }
}
