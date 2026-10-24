//! Hash aggregation for `stats`.
//!
//! Groups are kept in first-seen order (a `HashMap` from key to slot in a
//! `Vec`), which makes output deterministic without an extra sort. Memory is
//! O(groups) except for `dc`, which keeps the distinct values per group.

use std::collections::{HashMap, HashSet};

use super::{check_limit, ops::emit_all, Emit, ExecError, Flow, Operator, Row};
use crate::plan::{AggFunc, AggSpec};
use crate::value::{Type, Value};

#[derive(Debug, Clone)]
enum State {
    Count(i64),
    Sum {
        int: i64,
        float: f64,
        n: u64,
    },
    Avg {
        sum: f64,
        n: u64,
    },
    Extreme(Option<Value>),
    Dc(HashSet<Value>),
    /// Welford's online variance.
    Stdev {
        n: u64,
        mean: f64,
        m2: f64,
    },
    First(Option<Value>),
    Last(Option<Value>),
}

impl State {
    fn new(f: AggFunc) -> State {
        match f {
            AggFunc::Count => State::Count(0),
            AggFunc::Sum => State::Sum {
                int: 0,
                float: 0.0,
                n: 0,
            },
            AggFunc::Avg => State::Avg { sum: 0.0, n: 0 },
            AggFunc::Min | AggFunc::Max => State::Extreme(None),
            AggFunc::Dc => State::Dc(HashSet::new()),
            AggFunc::Stdev => State::Stdev {
                n: 0,
                mean: 0.0,
                m2: 0.0,
            },
            AggFunc::First => State::First(None),
            AggFunc::Last => State::Last(None),
        }
    }

    /// Fold one value in; returns how many values became newly retained
    /// (only `dc` retains values).
    fn update(&mut self, func: AggFunc, v: Option<Value>) -> usize {
        // `count()` with no argument counts rows; otherwise nulls are skipped.
        let v = match v {
            None => {
                if let State::Count(c) = self {
                    *c += 1;
                }
                return 0;
            }
            Some(Value::Null) => return 0,
            Some(v) => v,
        };
        match self {
            State::Count(c) => *c += 1,
            State::Sum { int, float, n } => {
                match &v {
                    Value::Int(i) | Value::Duration(i) => *int = int.wrapping_add(*i),
                    other => *float += other.as_f64().unwrap_or(0.0),
                }
                *n += 1;
            }
            State::Avg { sum, n } => {
                if let Some(x) = v.as_f64() {
                    *sum += x;
                    *n += 1;
                }
            }
            State::Extreme(cur) => {
                let replace = match cur {
                    None => true,
                    Some(c) => {
                        let o = v.total_cmp(c);
                        if func == AggFunc::Min {
                            o.is_lt()
                        } else {
                            o.is_gt()
                        }
                    }
                };
                if replace {
                    *cur = Some(v);
                }
            }
            State::Dc(set) => return usize::from(set.insert(v)),
            State::Stdev { n, mean, m2 } => {
                if let Some(x) = v.as_f64() {
                    *n += 1;
                    let d = x - *mean;
                    *mean += d / *n as f64;
                    *m2 += d * (x - *mean);
                }
            }
            State::First(cur) => {
                if cur.is_none() {
                    *cur = Some(v);
                }
            }
            State::Last(cur) => *cur = Some(v),
        }
        0
    }

    fn finish(self, out_ty: Type) -> Value {
        match self {
            State::Count(c) => Value::Int(c),
            State::Sum { int, float, n } => match out_ty {
                _ if n == 0 => Value::Null,
                Type::Int => Value::Int(int),
                Type::Duration => Value::Duration(int),
                _ => Value::Float(float + int as f64),
            },
            State::Avg { sum, n } => {
                if n == 0 {
                    Value::Null
                } else if out_ty == Type::Duration {
                    // Durations are accumulated in seconds by `as_f64`.
                    Value::Duration((sum / n as f64 * 1e6).round() as i64)
                } else {
                    Value::Float(sum / n as f64)
                }
            }
            State::Extreme(v) | State::First(v) | State::Last(v) => v.unwrap_or(Value::Null),
            State::Dc(set) => Value::Int(set.len() as i64),
            State::Stdev { n, m2, .. } => {
                if n < 2 {
                    Value::Null
                } else {
                    Value::Float((m2 / (n - 1) as f64).sqrt())
                }
            }
        }
    }
}

pub struct Aggregate {
    keys: Vec<usize>,
    aggs: Vec<AggSpec>,
    out_types: Vec<Type>,
    index: HashMap<Vec<Value>, usize>,
    groups: Vec<(Vec<Value>, Vec<State>)>,
    /// Distinct values held by `dc` states.
    retained: usize,
    limit: usize,
}

impl Aggregate {
    pub fn new(keys: Vec<usize>, aggs: Vec<AggSpec>, out_types: Vec<Type>, limit: usize) -> Self {
        Aggregate {
            keys,
            aggs,
            out_types,
            index: HashMap::new(),
            groups: Vec::new(),
            retained: 0,
            limit,
        }
    }

    fn fresh(&self) -> Vec<State> {
        self.aggs.iter().map(|a| State::new(a.func)).collect()
    }
}

impl Operator for Aggregate {
    fn push(&mut self, row: Row, _out: &mut dyn Emit) -> Result<Flow, ExecError> {
        let key: Vec<Value> = self.keys.iter().map(|&i| row[i].clone()).collect();
        let slot = match self.index.get(&key) {
            Some(&s) => s,
            None => {
                let s = self.groups.len();
                check_limit("stats", s + 1, self.limit)?;
                let fresh = self.fresh();
                self.groups.push((key.clone(), fresh));
                self.index.insert(key, s);
                s
            }
        };
        let states = &mut self.groups[slot].1;
        for (state, spec) in states.iter_mut().zip(&self.aggs) {
            let v = spec.arg.as_ref().map(|e| e.eval(&row));
            self.retained += state.update(spec.func, v);
        }
        Ok(Flow::Continue)
    }

    fn finish(&mut self, out: &mut dyn Emit) -> Result<(), ExecError> {
        // A global aggregation over zero rows still yields one row (count 0).
        if self.keys.is_empty() && self.groups.is_empty() {
            self.groups.push((Vec::new(), self.fresh()));
        }
        let out_types = self.out_types.clone();
        let groups = std::mem::take(&mut self.groups);
        self.index.clear();
        self.retained = 0;
        emit_all(
            groups.into_iter().map(|(mut key, states)| {
                key.extend(
                    states
                        .into_iter()
                        .zip(&out_types)
                        .map(|(s, ty)| s.finish(*ty)),
                );
                key
            }),
            out,
        )
    }

    fn state_size(&self) -> usize {
        self.groups.len() + self.retained
    }
}
