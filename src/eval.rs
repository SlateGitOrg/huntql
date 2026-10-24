//! Beacon-detection evaluation on generated scenarios.
//!
//! Protocol: generate independent scenarios for a *training* seed range and a
//! disjoint *held-out* seed range. Every `(src, dst, dport)` channel with at
//! least `min_count` connections is scored; a channel is positive iff it was
//! planted as a beacon. The decision threshold for each scorer is chosen to
//! maximise F1 on the training seeds only, then precision / recall / F1 are
//! reported on the held-out seeds. Planted beacons that never reach
//! `min_count` connections count as false negatives.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::ops::RangeInclusive;

use crate::beacon::{score_series, BeaconScore, Scorer};
use crate::gen::{generate, GenConfig, NegativeKind, PlantedBeacon};
use crate::value::Value;

#[derive(Debug, Clone)]
pub struct EvalConfig {
    pub train: RangeInclusive<u64>,
    pub test: RangeInclusive<u64>,
    pub gen: GenConfig,
    pub min_count: usize,
}

impl Default for EvalConfig {
    fn default() -> Self {
        EvalConfig {
            train: 1..=20,
            test: 5001..=5050,
            gen: GenConfig::default(),
            min_count: 10,
        }
    }
}

type Key = (String, String, i64);

/// One scored channel.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub key: Key,
    pub score: BeaconScore,
    pub beacon: Option<PlantedBeacon>,
    pub negative: Option<NegativeKind>,
}

/// All candidates of one scenario plus the planted beacons that were too
/// sparse to be scored.
#[derive(Debug, Clone, Default)]
pub struct ScenarioResult {
    pub candidates: Vec<Candidate>,
    pub unscored: Vec<PlantedBeacon>,
}

/// Group the scenario's conn rows by channel and score each one with the
/// same function the `beacon` operator uses.
pub fn score_scenario(seed: u64, cfg: &EvalConfig) -> ScenarioResult {
    let gen = GenConfig {
        seed,
        ..cfg.gen.clone()
    };
    let scn = generate(&gen);
    let (schema, rows) = &scn.logs["conn"];
    let idx = |n: &str| schema.resolve(n).expect("conn field");
    let (ts_i, src_i, dst_i, dport_i, bytes_i) = (
        idx("ts"),
        idx("src"),
        idx("dst"),
        idx("dport"),
        idx("orig_bytes"),
    );
    let mut groups: HashMap<Key, (Vec<i64>, Vec<f64>)> = HashMap::new();
    for r in rows {
        let (Value::Time(t), Value::Addr(s), Value::Addr(d), Value::Int(p)) =
            (&r[ts_i], &r[src_i], &r[dst_i], &r[dport_i])
        else {
            continue;
        };
        let g = groups
            .entry((s.to_string(), d.to_string(), *p))
            .or_default();
        g.0.push(*t);
        if let Some(b) = r[bytes_i].as_f64() {
            g.1.push(b);
        }
    }
    let planted: HashMap<Key, &PlantedBeacon> = scn
        .truth
        .beacons
        .iter()
        .map(|b| ((b.src.clone(), b.dst.clone(), i64::from(b.dport)), b))
        .collect();
    let negatives: HashMap<Key, NegativeKind> = scn
        .truth
        .hard_negatives
        .iter()
        .map(|n| ((n.src.clone(), n.dst.clone(), i64::from(n.dport)), n.kind))
        .collect();
    let mut keys: Vec<Key> = groups.keys().cloned().collect();
    keys.sort();
    let mut result = ScenarioResult::default();
    let mut scored = HashSet::new();
    for key in keys {
        let (mut ts, sizes) = groups.remove(&key).expect("key exists");
        let n = ts.len();
        if n < cfg.min_count {
            continue;
        }
        if let Some(score) = score_series(&mut ts, &sizes, n, cfg.min_count) {
            scored.insert(key.clone());
            result.candidates.push(Candidate {
                beacon: planted.get(&key).map(|b| (*b).clone()),
                negative: negatives.get(&key).copied(),
                key,
                score,
            });
        }
    }
    for (k, b) in planted {
        if !scored.contains(&k) {
            result.unscored.push(b.clone());
        }
    }
    result
        .unscored
        .sort_by(|a, b| a.src.cmp(&b.src).then(a.dst.cmp(&b.dst)));
    result
}

/// Confusion counts at a threshold.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Counts {
    pub tp: usize,
    pub fp: usize,
    pub fn_: usize,
}

impl Counts {
    pub fn precision(&self) -> f64 {
        ratio(self.tp, self.tp + self.fp)
    }
    pub fn recall(&self) -> f64 {
        ratio(self.tp, self.tp + self.fn_)
    }
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

fn ratio(a: usize, b: usize) -> f64 {
    if b == 0 {
        0.0
    } else {
        a as f64 / b as f64
    }
}

pub fn counts(results: &[ScenarioResult], scorer: Scorer, threshold: f64) -> Counts {
    let mut c = Counts::default();
    for r in results {
        for cand in &r.candidates {
            let hit = cand.score.score_with(scorer) >= threshold;
            match (cand.beacon.is_some(), hit) {
                (true, true) => c.tp += 1,
                (true, false) => c.fn_ += 1,
                (false, true) => c.fp += 1,
                (false, false) => {}
            }
        }
        c.fn_ += r.unscored.len();
    }
    c
}

/// Threshold maximising F1 (ties -> higher threshold, i.e. fewer alerts).
pub fn best_threshold(results: &[ScenarioResult], scorer: Scorer) -> f64 {
    let mut thresholds: Vec<f64> = results
        .iter()
        .flat_map(|r| r.candidates.iter().map(|c| c.score.score_with(scorer)))
        .collect();
    thresholds.sort_by(f64::total_cmp);
    thresholds.dedup();
    let mut best = (f64::NEG_INFINITY, 1.0);
    for t in thresholds {
        let f1 = counts(results, scorer, t).f1();
        if f1 >= best.0 {
            best = (f1, t);
        }
    }
    best.1
}

/// Average precision of the ranking (area under the PR curve, step-wise),
/// with unscored planted beacons counted as never retrieved.
pub fn average_precision(results: &[ScenarioResult], scorer: Scorer) -> f64 {
    let mut all: Vec<(f64, bool)> = results
        .iter()
        .flat_map(|r| {
            r.candidates
                .iter()
                .map(|c| (c.score.score_with(scorer), c.beacon.is_some()))
        })
        .collect();
    let positives = all.iter().filter(|(_, p)| *p).count()
        + results.iter().map(|r| r.unscored.len()).sum::<usize>();
    if positives == 0 {
        return 0.0;
    }
    all.sort_by(|a, b| b.0.total_cmp(&a.0));
    let (mut tp, mut ap) = (0usize, 0.0);
    for (i, (_, pos)) in all.iter().enumerate() {
        if *pos {
            tp += 1;
            ap += tp as f64 / (i + 1) as f64;
        }
    }
    ap / positives as f64
}

/// Full report as Markdown.
pub fn run(cfg: &EvalConfig) -> String {
    let train: Vec<ScenarioResult> = cfg.train.clone().map(|s| score_scenario(s, cfg)).collect();
    let test: Vec<ScenarioResult> = cfg.test.clone().map(|s| score_scenario(s, cfg)).collect();
    report(cfg, &train, &test)
}

pub fn report(cfg: &EvalConfig, train: &[ScenarioResult], test: &[ScenarioResult]) -> String {
    let mut out = String::new();
    let n_pos = |rs: &[ScenarioResult]| -> usize {
        rs.iter()
            .map(|r| r.candidates.iter().filter(|c| c.beacon.is_some()).count() + r.unscored.len())
            .sum()
    };
    let n_cand = |rs: &[ScenarioResult]| -> usize { rs.iter().map(|r| r.candidates.len()).sum() };
    let _ = writeln!(
        out,
        "Beacon detection: train seeds {}..={} ({} scenarios, {} planted beacons, {} scored channels); \
         held-out seeds {}..={} ({} scenarios, {} planted beacons, {} scored channels). \
         {}h per scenario, {} hosts, min_count={}.\n",
        cfg.train.start(),
        cfg.train.end(),
        train.len(),
        n_pos(train),
        n_cand(train),
        cfg.test.start(),
        cfg.test.end(),
        test.len(),
        n_pos(test),
        n_cand(test),
        cfg.gen.hours,
        cfg.gen.hosts,
        cfg.min_count
    );
    let _ = writeln!(
        out,
        "| scorer | threshold (from train) | precision | recall | F1 | avg precision |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    let mut combined_t = 0.0;
    for (name, scorer) in [
        ("combined (huntql default)", Scorer::Combined),
        ("interval-only (MAD + skew)", Scorer::IntervalOnly),
        ("ACF-only", Scorer::AcfOnly),
    ] {
        let t = best_threshold(train, scorer);
        if scorer == Scorer::Combined {
            combined_t = t;
        }
        let c = counts(test, scorer, t);
        let _ = writeln!(
            out,
            "| {name} | {t:.3} | {:.3} | {:.3} | {:.3} | {:.3} |",
            c.precision(),
            c.recall(),
            c.f1(),
            average_precision(test, scorer)
        );
    }

    // Recall breakdowns on held-out data for the combined scorer.
    let planted: Vec<(PlantedBeacon, bool)> = test
        .iter()
        .flat_map(|r| {
            r.candidates
                .iter()
                .filter_map(|c| c.beacon.clone().map(|b| (b, c.score.score >= combined_t)))
                .chain(r.unscored.iter().map(|b| (b.clone(), false)))
        })
        .collect();
    let table = |out: &mut String,
                 title: &str,
                 key: &dyn Fn(&PlantedBeacon) -> String,
                 order: &dyn Fn(&PlantedBeacon) -> f64| {
        let mut rows: Vec<(f64, String, usize, usize)> = Vec::new();
        for (b, hit) in &planted {
            let k = key(b);
            match rows.iter_mut().find(|r| r.1 == k) {
                Some(r) => {
                    r.2 += 1;
                    r.3 += usize::from(*hit);
                }
                None => rows.push((order(b), k, 1, usize::from(*hit))),
            }
        }
        rows.sort_by(|a, b| a.0.total_cmp(&b.0));
        let _ = writeln!(out, "\n| {title} | planted | detected | recall |");
        let _ = writeln!(out, "|---|---|---|---|");
        for (_, k, n, d) in rows {
            let _ = writeln!(out, "| {k} | {n} | {d} | {:.2} |", ratio(d, n));
        }
    };
    let _ = writeln!(
        out,
        "\nHeld-out recall of the combined scorer at threshold {combined_t:.3}:"
    );
    table(
        &mut out,
        "jitter",
        &|b| format!("{:.0}%", b.jitter * 100.0),
        &|b| b.jitter,
    );
    table(
        &mut out,
        "period",
        &|b| crate::timefmt::format_duration((b.period_s * 1e6) as i64),
        &|b| b.period_s,
    );
    table(
        &mut out,
        "condition",
        &|b| {
            match (b.interleave > 0.0, b.dropout > 0.0) {
                (false, false) => "clean",
                (false, true) => "dropped check-ins",
                (true, false) => "interleaved noise",
                (true, true) => "interleaved + dropped",
            }
            .to_string()
        },
        &|b| f64::from(u8::from(b.interleave > 0.0)) * 2.0 + f64::from(u8::from(b.dropout > 0.0)),
    );

    // False positives by negative kind.
    let mut fp: Vec<(&str, usize, usize)> = vec![
        ("poller (Poisson)", 0, 0),
        ("sync client (log-normal)", 0, 0),
        ("browsing", 0, 0),
    ];
    for r in test {
        for c in r.candidates.iter().filter(|c| c.beacon.is_none()) {
            let i = match c.negative {
                Some(NegativeKind::Poller) => 0,
                Some(NegativeKind::SyncClient) => 1,
                None => 2,
            };
            fp[i].1 += 1;
            fp[i].2 += usize::from(c.score.score >= combined_t);
        }
    }
    let _ = writeln!(
        out,
        "\n| benign channel kind | scored channels | false positives | FP rate |"
    );
    let _ = writeln!(out, "|---|---|---|---|");
    for (k, n, f) in fp {
        let _ = writeln!(out, "| {k} | {n} | {f} | {:.3} |", ratio(f, n));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> EvalConfig {
        EvalConfig {
            train: 1..=2,
            test: 3..=4,
            gen: GenConfig {
                hours: 6.0,
                hosts: 8,
                beacons: 4,
                ..GenConfig::default()
            },
            min_count: 8,
        }
    }

    #[test]
    fn metrics() {
        let c = Counts {
            tp: 3,
            fp: 1,
            fn_: 1,
        };
        assert_eq!(c.precision(), 0.75);
        assert_eq!(c.recall(), 0.75);
        assert!((c.f1() - 0.75).abs() < 1e-12);
        assert_eq!(Counts::default().f1(), 0.0);
        assert_eq!(average_precision(&[], Scorer::Combined), 0.0);
    }

    #[test]
    fn end_to_end_report() {
        let cfg = tiny();
        let report = run(&cfg);
        assert!(report.contains("| combined (huntql default) |"), "{report}");
        assert!(report.contains("| jitter | planted | detected | recall |"));
        assert!(report.contains("| browsing |"));
        let r = score_scenario(1, &cfg);
        assert!(r.candidates.iter().any(|c| c.beacon.is_some()));
        let t = best_threshold(std::slice::from_ref(&r), Scorer::Combined);
        assert!((0.0..=1.0).contains(&t));
    }
}
