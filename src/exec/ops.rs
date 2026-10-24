//! Relational operators: filter, project, extend, head, tail, sort, top-k,
//! dedup.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet, VecDeque};
use std::rc::Rc;

use super::{check_limit, Emit, ExecError, Flow, Operator, Row};
use crate::expr::TExpr;
use crate::plan::SortSpec;
use crate::value::Value;

pub struct Filter(pub TExpr);

impl Operator for Filter {
    fn push(&mut self, row: Row, out: &mut dyn Emit) -> Result<Flow, ExecError> {
        if self.0.eval(&row).as_bool() {
            out.emit(row)
        } else {
            Ok(Flow::Continue)
        }
    }
}

pub struct Project(pub Vec<usize>);

impl Operator for Project {
    fn push(&mut self, mut row: Row, out: &mut dyn Emit) -> Result<Flow, ExecError> {
        let projected = self
            .0
            .iter()
            .map(|&i| std::mem::replace(&mut row[i], Value::Null))
            .collect();
        out.emit(projected)
    }
}

/// Appends computed columns; each expression sees the columns added before it.
pub struct Extend(pub Vec<TExpr>);

impl Operator for Extend {
    fn push(&mut self, mut row: Row, out: &mut dyn Emit) -> Result<Flow, ExecError> {
        for e in &self.0 {
            let v = e.eval(&row);
            row.push(v);
        }
        out.emit(row)
    }
}

pub struct Head {
    remaining: u64,
}

impl Head {
    pub fn new(n: u64) -> Self {
        Head { remaining: n }
    }
}

impl Operator for Head {
    fn push(&mut self, row: Row, out: &mut dyn Emit) -> Result<Flow, ExecError> {
        if self.remaining == 0 {
            return Ok(Flow::Stop);
        }
        self.remaining -= 1;
        let flow = out.emit(row)?;
        Ok(if self.remaining == 0 {
            Flow::Stop
        } else {
            flow
        })
    }
}

/// Keeps the last `n` rows in a ring buffer: O(min(n, rows)) memory, capped
/// by `limit` (`--max-groups`) like every other blocking operator.
pub struct Tail {
    n: usize,
    buf: VecDeque<Row>,
    limit: usize,
}

impl Tail {
    pub fn new(n: u64, limit: usize) -> Self {
        Tail {
            n: usize::try_from(n).unwrap_or(usize::MAX),
            buf: VecDeque::new(),
            limit,
        }
    }
}

impl Operator for Tail {
    fn push(&mut self, row: Row, _out: &mut dyn Emit) -> Result<Flow, ExecError> {
        if self.n == 0 {
            return Ok(Flow::Continue);
        }
        if self.buf.len() == self.n {
            self.buf.pop_front();
        }
        self.buf.push_back(row);
        check_limit("tail", self.buf.len(), self.limit)?;
        Ok(Flow::Continue)
    }

    fn finish(&mut self, out: &mut dyn Emit) -> Result<(), ExecError> {
        emit_all(self.buf.drain(..), out)
    }

    fn state_size(&self) -> usize {
        self.buf.len()
    }
}

pub(crate) fn emit_all(
    rows: impl IntoIterator<Item = Row>,
    out: &mut dyn Emit,
) -> Result<(), ExecError> {
    for row in rows {
        if out.emit(row)? == Flow::Stop {
            break;
        }
    }
    Ok(())
}

/// Compare two rows by sort keys (nulls first ascending).
pub fn compare_rows(keys: &[SortSpec], a: &[Value], b: &[Value]) -> Ordering {
    for k in keys {
        let o = a[k.col].total_cmp(&b[k.col]);
        let o = if k.descending { o.reverse() } else { o };
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

/// Full materializing sort (stable).
pub struct Sort {
    keys: Vec<SortSpec>,
    rows: Vec<Row>,
    limit: usize,
}

impl Sort {
    pub fn new(keys: Vec<SortSpec>, limit: usize) -> Self {
        Sort {
            keys,
            rows: Vec::new(),
            limit,
        }
    }
}

impl Operator for Sort {
    fn push(&mut self, row: Row, _out: &mut dyn Emit) -> Result<Flow, ExecError> {
        self.rows.push(row);
        check_limit("sort", self.rows.len(), self.limit)?;
        Ok(Flow::Continue)
    }

    fn finish(&mut self, out: &mut dyn Emit) -> Result<(), ExecError> {
        let keys = &self.keys;
        self.rows.sort_by(|a, b| compare_rows(keys, a, b));
        emit_all(self.rows.drain(..), out)
    }

    fn state_size(&self) -> usize {
        self.rows.len()
    }
}

/// Heap entry ordered by sort keys, then arrival sequence (for stability).
struct Ranked {
    row: Row,
    seq: u64,
    keys: Rc<[SortSpec]>,
}

impl PartialEq for Ranked {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Ranked {}

impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ranked {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_rows(&self.keys, &self.row, &other.row).then(self.seq.cmp(&other.seq))
    }
}

/// Bounded top-k: a max-heap of the k best rows seen so far, O(k) memory and
/// O(n log k) time. Produces exactly what a stable sort + head k would.
/// The heap is capped by `limit` (`--max-groups`), so a huge `k` cannot lift
/// the cap that an unfused `sort` would enforce.
pub struct TopK {
    keys: Rc<[SortSpec]>,
    k: usize,
    heap: BinaryHeap<Ranked>,
    seq: u64,
    limit: usize,
}

impl TopK {
    pub fn new(keys: Vec<SortSpec>, k: u64, limit: usize) -> Self {
        TopK {
            keys: keys.into(),
            k: usize::try_from(k).unwrap_or(usize::MAX),
            heap: BinaryHeap::new(),
            seq: 0,
            limit,
        }
    }
}

impl Operator for TopK {
    fn push(&mut self, row: Row, _out: &mut dyn Emit) -> Result<Flow, ExecError> {
        if self.k == 0 {
            return Ok(Flow::Continue);
        }
        let entry = Ranked {
            row,
            seq: self.seq,
            keys: Rc::clone(&self.keys),
        };
        self.seq += 1;
        if self.heap.len() < self.k {
            self.heap.push(entry);
            check_limit("sort", self.heap.len(), self.limit)?;
        } else if let Some(mut worst) = self.heap.peek_mut() {
            if entry < *worst {
                *worst = entry;
            }
        }
        Ok(Flow::Continue)
    }

    fn finish(&mut self, out: &mut dyn Emit) -> Result<(), ExecError> {
        let sorted = std::mem::take(&mut self.heap).into_sorted_vec();
        emit_all(sorted.into_iter().map(|r| r.row), out)
    }

    fn state_size(&self) -> usize {
        self.heap.len()
    }
}

/// Emits the first row for each distinct key; streaming, O(distinct keys).
pub struct Dedup {
    keys: Vec<usize>,
    seen: HashSet<Vec<Value>>,
    limit: usize,
}

impl Dedup {
    pub fn new(keys: Vec<usize>, limit: usize) -> Self {
        Dedup {
            keys,
            seen: HashSet::new(),
            limit,
        }
    }
}

impl Operator for Dedup {
    fn push(&mut self, row: Row, out: &mut dyn Emit) -> Result<Flow, ExecError> {
        let key: Vec<Value> = self.keys.iter().map(|&i| row[i].clone()).collect();
        if self.seen.insert(key) {
            check_limit("dedup", self.seen.len(), self.limit)?;
            out.emit(row)
        } else {
            Ok(Flow::Continue)
        }
    }

    fn state_size(&self) -> usize {
        self.seen.len()
    }
}
