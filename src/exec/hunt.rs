//! Threat-hunting operators: `stack`, `rare`, `first_seen`, `beacon`.

use std::collections::{HashMap, HashSet};

use super::{check_limit, ops::emit_all, Emit, ExecError, Flow, Operator, Row};
use crate::beacon::{score_series, BeaconParams};
use crate::value::Value;

/// Insertion-ordered map from group key to state.
struct Groups<T> {
    index: HashMap<Vec<Value>, usize>,
    items: Vec<(Vec<Value>, T)>,
    op: &'static str,
    limit: usize,
}

impl<T> Groups<T> {
    fn new(op: &'static str, limit: usize) -> Self {
        Groups {
            index: HashMap::new(),
            items: Vec::new(),
            op,
            limit,
        }
    }

    fn entry(&mut self, key: Vec<Value>, init: impl FnOnce() -> T) -> Result<&mut T, ExecError> {
        let slot = match self.index.get(&key) {
            Some(&s) => s,
            None => {
                let s = self.items.len();
                check_limit(self.op, s + 1, self.limit)?;
                self.items.push((key.clone(), init()));
                self.index.insert(key, s);
                s
            }
        };
        Ok(&mut self.items[slot].1)
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn take(&mut self) -> Vec<(Vec<Value>, T)> {
        self.index.clear();
        std::mem::take(&mut self.items)
    }
}

fn key_of(row: &[Value], cols: &[usize]) -> Vec<Value> {
    cols.iter().map(|&i| row[i].clone()).collect()
}

fn cmp_keys(a: &[Value], b: &[Value]) -> std::cmp::Ordering {
    a.iter()
        .zip(b)
        .map(|(x, y)| x.total_cmp(y))
        .find(|o| o.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

/// Long-tail frequency analysis ("stacking"): count each distinct key and
/// list the rarest first with their share of the total.
pub struct Stack {
    keys: Vec<usize>,
    limit: Option<u64>,
    groups: Groups<u64>,
    total: u64,
}

impl Stack {
    pub fn new(keys: Vec<usize>, limit: Option<u64>, max_groups: usize) -> Self {
        Stack {
            keys,
            limit,
            groups: Groups::new("stack", max_groups),
            total: 0,
        }
    }
}

impl Operator for Stack {
    fn push(&mut self, row: Row, _out: &mut dyn Emit) -> Result<Flow, ExecError> {
        *self.groups.entry(key_of(&row, &self.keys), || 0)? += 1;
        self.total += 1;
        Ok(Flow::Continue)
    }

    fn finish(&mut self, out: &mut dyn Emit) -> Result<(), ExecError> {
        let mut items = self.groups.take();
        items.sort_by(|(ka, ca), (kb, cb)| ca.cmp(cb).then_with(|| cmp_keys(ka, kb)));
        let total = self.total.max(1) as f64;
        let mut cum = 0u64;
        let limit = self
            .limit
            .map_or(usize::MAX, |l| usize::try_from(l).unwrap_or(usize::MAX));
        emit_all(
            items.into_iter().take(limit).map(|(mut key, count)| {
                cum += count;
                key.push(Value::Int(count as i64));
                key.push(Value::Float(round4(count as f64 / total * 100.0)));
                key.push(Value::Float(round4(cum as f64 / total * 100.0)));
                key
            }),
            out,
        )
    }

    fn state_size(&self) -> usize {
        self.groups.len()
    }
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

/// Least-common values of a field, optionally ranked by how many distinct
/// entities (e.g. hosts) produced them.
pub struct Rare {
    field: usize,
    by: Vec<usize>,
    limit: u64,
    groups: Groups<(u64, HashSet<Vec<Value>>)>,
    pairs: usize,
}

impl Rare {
    pub fn new(field: usize, by: Vec<usize>, limit: u64, max_groups: usize) -> Self {
        Rare {
            field,
            by,
            limit,
            groups: Groups::new("rare", max_groups),
            pairs: 0,
        }
    }
}

impl Operator for Rare {
    fn push(&mut self, row: Row, _out: &mut dyn Emit) -> Result<Flow, ExecError> {
        let value = row[self.field].clone();
        if value.is_null() {
            return Ok(Flow::Continue);
        }
        let entity = key_of(&row, &self.by);
        let track = !self.by.is_empty();
        let (count, set) = self.groups.entry(vec![value], || (0, HashSet::new()))?;
        *count += 1;
        if track && set.insert(entity) {
            self.pairs += 1;
            check_limit("rare", self.pairs, self.groups.limit)?;
        }
        Ok(Flow::Continue)
    }

    fn finish(&mut self, out: &mut dyn Emit) -> Result<(), ExecError> {
        let track = !self.by.is_empty();
        let mut items: Vec<(Vec<Value>, u64, usize)> = self
            .groups
            .take()
            .into_iter()
            .map(|(k, (c, set))| (k, c, set.len()))
            .collect();
        self.pairs = 0;
        items.sort_by(|a, b| {
            a.2.cmp(&b.2)
                .then(a.1.cmp(&b.1))
                .then_with(|| cmp_keys(&a.0, &b.0))
        });
        let limit = usize::try_from(self.limit).unwrap_or(usize::MAX);
        emit_all(
            items
                .into_iter()
                .take(limit)
                .map(|(mut key, count, entities)| {
                    key.push(Value::Int(count as i64));
                    if track {
                        key.push(Value::Int(entities as i64));
                    }
                    key
                }),
            out,
        )
    }

    fn state_size(&self) -> usize {
        self.groups.len() + self.pairs
    }
}

/// First and last sighting of every key; with `baseline`, only keys first
/// seen after the baseline window (measured from the earliest timestamp in
/// the input) are reported — i.e. "new in the hunt window".
pub struct FirstSeen {
    keys: Vec<usize>,
    ts: usize,
    baseline: Option<i64>,
    groups: Groups<(i64, i64, u64)>,
    min_ts: Option<i64>,
}

impl FirstSeen {
    pub fn new(keys: Vec<usize>, ts: usize, baseline: Option<i64>, max_groups: usize) -> Self {
        FirstSeen {
            keys,
            ts,
            baseline,
            groups: Groups::new("first_seen", max_groups),
            min_ts: None,
        }
    }
}

impl Operator for FirstSeen {
    fn push(&mut self, row: Row, _out: &mut dyn Emit) -> Result<Flow, ExecError> {
        let Value::Time(t) = row[self.ts] else {
            return Ok(Flow::Continue);
        };
        self.min_ts = Some(self.min_ts.map_or(t, |m| m.min(t)));
        let entry = self.groups.entry(key_of(&row, &self.keys), || (t, t, 0))?;
        entry.0 = entry.0.min(t);
        entry.1 = entry.1.max(t);
        entry.2 += 1;
        Ok(Flow::Continue)
    }

    fn finish(&mut self, out: &mut dyn Emit) -> Result<(), ExecError> {
        let cutoff = match (self.baseline, self.min_ts) {
            (Some(b), Some(m)) => Some(m.saturating_add(b)),
            _ => None,
        };
        let mut items: Vec<_> = self
            .groups
            .take()
            .into_iter()
            .filter(|(_, (first, _, _))| cutoff.is_none_or(|c| *first > c))
            .collect();
        items.sort_by(|a, b| a.1 .0.cmp(&b.1 .0).then_with(|| cmp_keys(&a.0, &b.0)));
        emit_all(
            items.into_iter().map(|(mut key, (first, last, count))| {
                key.push(Value::Time(first));
                key.push(Value::Time(last));
                key.push(Value::Int(count as i64));
                key
            }),
            out,
        )
    }

    fn state_size(&self) -> usize {
        self.groups.len()
    }
}

struct Series {
    ts: Vec<i64>,
    sizes: Vec<f64>,
    count: usize,
}

/// Periodicity scoring per group; see [`crate::beacon`].
pub struct Beacon {
    keys: Vec<usize>,
    ts: usize,
    bytes: Option<usize>,
    params: BeaconParams,
    groups: Groups<Series>,
    stored: usize,
}

impl Beacon {
    pub fn new(
        keys: Vec<usize>,
        ts: usize,
        bytes: Option<usize>,
        params: BeaconParams,
        max_groups: usize,
    ) -> Self {
        Beacon {
            keys,
            ts,
            bytes,
            params,
            groups: Groups::new("beacon", max_groups),
            stored: 0,
        }
    }
}

impl Operator for Beacon {
    fn push(&mut self, row: Row, _out: &mut dyn Emit) -> Result<Flow, ExecError> {
        let Value::Time(t) = row[self.ts] else {
            return Ok(Flow::Continue);
        };
        let size = self.bytes.and_then(|i| row[i].as_f64());
        let cap = self.params.max_events;
        let s = self.groups.entry(key_of(&row, &self.keys), || Series {
            ts: Vec::new(),
            sizes: Vec::new(),
            count: 0,
        })?;
        s.count += 1;
        if s.ts.len() < cap {
            s.ts.push(t);
            if let Some(sz) = size {
                s.sizes.push(sz);
            }
            self.stored += 1;
        }
        Ok(Flow::Continue)
    }

    fn finish(&mut self, out: &mut dyn Emit) -> Result<(), ExecError> {
        let p = self.params;
        let mut scored: Vec<(Vec<Value>, crate::beacon::BeaconScore)> = self
            .groups
            .take()
            .into_iter()
            .filter(|(_, s)| s.count >= p.min_count)
            .filter_map(|(key, mut s)| {
                score_series(&mut s.ts, &s.sizes, s.count, p.min_count).map(|sc| (key, sc))
            })
            .filter(|(_, sc)| sc.score >= p.min_score)
            .collect();
        self.stored = 0;
        scored.sort_by(|a, b| {
            b.1.score
                .total_cmp(&a.1.score)
                .then_with(|| cmp_keys(&a.0, &b.0))
        });
        emit_all(
            scored.into_iter().map(|(mut key, sc)| {
                key.push(Value::Int(sc.count as i64));
                key.push(Value::Duration(sc.period_us));
                key.push(Value::Float(round4(sc.jitter)));
                key.push(Value::Float(round4(sc.s_acf)));
                key.push(Value::Float(round4(sc.score)));
                key
            }),
            out,
        )
    }

    fn state_size(&self) -> usize {
        self.groups.len() + self.stored
    }
}
