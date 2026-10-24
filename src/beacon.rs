//! Beacon (periodic connection) scoring.
//!
//! Given the timestamps of every connection in a group (by default the
//! `src, dst, dport` triple), [`score_series`] estimates how strongly the
//! group behaves like a timer-driven implant check-in. Four features, each
//! normalised to `[0, 1]` where 1 means "perfectly periodic":
//!
//! 1. **Interval jitter** `s_jit = (1 - min(1, (MAD/median) / 0.7)) * m/(m+4)`
//!    over the `m` inter-arrival times. `MAD/median` is about 0.69 for a
//!    memoryless (Poisson) process and `j/4 / (1 - j/2)` for "sleep minus up to
//!    j" jitter, so 0.7 maps Poisson traffic to ~0. The `m/(m+4)` factor
//!    shrinks estimates made from a handful of intervals.
//! 2. **Interval symmetry** `s_skew = (1 - |Bowley skewness|) * m/(m+4)` —
//!    uniform sleep jitter is symmetric; human and Poisson traffic is
//!    right-skewed.
//! 3. **Autocorrelation** `s_acf`, in two stages:
//!    * *Candidates*: connection times are binned (bin = median interval / 10,
//!      at most `max(1024, 64 n)` and 2^17 bins), bursts are collapsed to one
//!      event, and the pair-count autocorrelation `c(k) = sum x_t x_{t+k}` of
//!      the occupancy series is computed by FFT in `O(L log L)`. Each lag is
//!      ranked by its pair mass in a ±8% window against the mean pair rate in
//!      the "valley" `[k/3, 2k/3]`: periodic traffic forms a hill with an
//!      empty valley. The six best lags plus the median interval become
//!      candidate periods.
//!    * *Verification* (exact, on the event list): for candidate `P`, the
//!      share of check-ins followed by another within `P ± 15%`, against the
//!      mean share at the off-period lags `0.4P, 0.6P, 1.4P, 1.6P` (the
//!      channel's own chance level, which absorbs burstiness and diurnal
//!      rate changes). `s_acf = (hit - off) / (1 - off)`, shrunk by
//!      `e/(e+8)` for `e` eligible check-ins; lags where `off > 0.5` are
//!      uninformative and skipped.
//!
//!    Unlike interval statistics, this survives interleaved noise
//!    connections and missed check-ins: the beacon's own period-spaced pairs
//!    still line up, so it also yields a better period estimate (the median
//!    matched gap) for noisy channels.
//! 4. **Size consistency** `s_size = 1 - min(1, MAD/median)` of bytes sent,
//!    when a bytes column is available.
//!
//! The final score is
//! `0.5 * max(s_jit, s_acf) + 0.2 * min(s_jit, s_acf) + 0.15 * s_skew + 0.15 * s_size`
//! (divided by 0.85 without a bytes column). Either periodicity view can carry a beacon; agreement adds a
//! bonus. Feature design was iterated on training seeds only; the default
//! threshold is chosen on training seeds by `huntql eval`, which reports
//! metrics on disjoint held-out seeds.

use std::f64::consts::PI;

/// Tunables for the `beacon` operator.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeaconParams {
    /// Groups with fewer connections are not scored.
    pub min_count: usize,
    /// Groups scoring below this are dropped from the output.
    pub min_score: f64,
    /// Per-group timestamp cap (bounds memory); later events still count
    /// toward `count` but are not stored.
    pub max_events: usize,
}

/// Default `min_score`, chosen by `huntql eval` on the training seeds
/// (see DECISIONS.md); held-out results are reported in the README.
pub const DEFAULT_MIN_SCORE: f64 = 0.5;

impl Default for BeaconParams {
    fn default() -> Self {
        BeaconParams {
            min_count: 10,
            min_score: DEFAULT_MIN_SCORE,
            max_events: 20_000,
        }
    }
}

/// Feature breakdown and final score for one group.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeaconScore {
    /// Connections observed (including any beyond `max_events`).
    pub count: usize,
    /// Estimated period in microseconds.
    pub period_us: i64,
    /// MAD / median of inter-arrival times.
    pub jitter: f64,
    pub s_jit: f64,
    pub s_skew: f64,
    pub s_acf: f64,
    pub s_size: Option<f64>,
    pub score: f64,
}

/// Which features contribute to the final score. `Combined` is the operator's
/// behaviour; the single-feature variants exist for the evaluation's ablation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scorer {
    Combined,
    IntervalOnly,
    AcfOnly,
}

impl BeaconScore {
    pub fn score_with(&self, scorer: Scorer) -> f64 {
        match scorer {
            Scorer::Combined => self.score,
            Scorer::IntervalOnly => 0.7 * self.s_jit + 0.3 * self.s_skew,
            Scorer::AcfOnly => self.s_acf,
        }
    }
}

/// Quantile by linear interpolation on a sorted slice.
pub fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let pos = q.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    let frac = pos - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

/// Median absolute deviation around the median.
pub fn mad(sorted: &[f64]) -> f64 {
    let m = quantile(sorted, 0.5);
    let mut dev: Vec<f64> = sorted.iter().map(|x| (x - m).abs()).collect();
    dev.sort_by(f64::total_cmp);
    quantile(&dev, 0.5)
}

/// Score a group's connection timestamps (microseconds, any order) and
/// optional per-connection byte counts. `total_count` is the number of
/// connections seen, which may exceed `ts.len()` if storage was capped.
/// Returns `None` when there are too few distinct intervals to say anything.
pub fn score_series(
    ts: &mut [i64],
    sizes: &[f64],
    total_count: usize,
    min_count: usize,
) -> Option<BeaconScore> {
    ts.sort_unstable();
    let intervals: Vec<f64> = ts
        .windows(2)
        .map(|w| (w[1] - w[0]) as f64)
        .filter(|d| *d > 0.0)
        .collect();
    if intervals.len() + 1 < min_count.max(3) {
        return None;
    }
    let mut sorted = intervals.clone();
    sorted.sort_by(f64::total_cmp);
    let median = quantile(&sorted, 0.5);
    if median <= 0.0 {
        return None;
    }
    let q1 = quantile(&sorted, 0.25);
    let q3 = quantile(&sorted, 0.75);
    let jitter = mad(&sorted) / median;
    // Interval statistics from a handful of intervals are noisy; shrink them
    // toward 0 by m / (m + 4) for m intervals.
    let m = sorted.len() as f64;
    let support = m / (m + 4.0);
    let s_jit = (1.0 - jitter / 0.7).clamp(0.0, 1.0) * support;
    let bowley = if q3 - q1 > 0.0 {
        (q1 + q3 - 2.0 * median) / (q3 - q1)
    } else {
        0.0
    };
    let s_skew = (1.0 - bowley.abs()).clamp(0.0, 1.0) * support;

    let acf = acf_periodicity(ts, median);
    let (s_acf, acf_period) = acf.unwrap_or((0.0, median));

    let s_size = if sizes.len() >= 3 {
        let mut s: Vec<f64> = sizes.to_vec();
        s.sort_by(f64::total_cmp);
        let m = quantile(&s, 0.5);
        Some(if m > 0.0 {
            (1.0 - (mad(&s) / m).min(1.0)).clamp(0.0, 1.0)
        } else if s.iter().all(|x| *x == 0.0) {
            1.0
        } else {
            0.0
        })
    } else {
        None
    };

    let hi = s_jit.max(s_acf);
    let lo = s_jit.min(s_acf);
    let score = match s_size {
        Some(sz) => 0.5 * hi + 0.2 * lo + 0.15 * s_skew + 0.15 * sz,
        None => (0.5 * hi + 0.2 * lo + 0.15 * s_skew) / 0.85,
    };
    // Report the ACF period when the autocorrelation view is the stronger one,
    // since the median interval is corrupted by interleaved noise.
    let period = if s_acf > s_jit { acf_period } else { median };
    Some(BeaconScore {
        count: total_count.max(ts.len()),
        period_us: period.round() as i64,
        jitter,
        s_jit,
        s_skew,
        s_acf,
        s_size,
        score: score.clamp(0.0, 1.0),
    })
}

/// Maximum bins in the binned count series.
const MAX_BINS: usize = 1 << 17;

/// Autocorrelation periodicity strength and the period (µs) at the best lag.
/// `ts` must be sorted.
fn acf_periodicity(ts: &[i64], median_interval: f64) -> Option<(f64, f64)> {
    let first = *ts.first()?;
    let last = *ts.last()?;
    let span = (last - first) as f64;
    if span <= 0.0 {
        return None;
    }
    let n = ts.len();
    let bin_cap = MAX_BINS.min((64 * n).max(1024));
    let width = (median_interval / 10.0).max(span / bin_cap as f64).max(1.0);
    let bins = (span / width).floor() as usize + 1;
    let mut x = vec![0.0f64; bins];
    // Burst collapsing: keep only bins that start a cluster (no event in the
    // two preceding bins). A burst of connections then counts as one event,
    // so two bursts cannot produce n*m "periodic" pairs. Beacon check-ins are
    // ~10 bins apart, so they are unaffected.
    let mut events: Vec<i64> = Vec::with_capacity(ts.len());
    let mut last_bin: Option<usize> = None;
    for &t in ts {
        let b = ((((t - first) as f64) / width) as usize).min(bins - 1);
        if last_bin.is_none_or(|l| b > l + 2) {
            x[b] = 1.0;
            events.push(t);
        }
        last_bin = Some(b);
    }
    if events.len() < 4 {
        return Some((0.0, median_interval));
    }
    // Raw pair counts c(k) = sum_t x_t x_{t+k}, via FFT (zero-padded, so no wrap).
    let raw = autocorr_fft(&x);
    let max_lag = bins / 3;
    if max_lag < 3 {
        return Some((0.0, median_interval));
    }
    // Prefix sums over lags for O(1) window sums.
    let mut pre = vec![0.0; raw.len() + 1];
    for (k, c) in raw.iter().enumerate() {
        pre[k + 1] = pre[k] + c;
    }
    let pairs = |lo: usize, hi: usize| pre[hi + 1] - pre[lo];
    // Candidate generation: pair mass in a +-8% lag window around k relative
    // to the mean pair rate over the "valley" [k/3, 2k/3]. Periodic traffic
    // forms a hill at its period with an empty valley; bursty or diurnal
    // traffic does not. The ratio only ranks candidates.
    let mut cands: Vec<(f64, usize)> = Vec::new();
    for k in 3..=max_lag {
        let h = ((k as f64) * 0.08).round().max(1.0) as usize;
        let (lo, hi) = (k - h.min(k - 1), (k + h).min(raw.len() - 1));
        let (vlo, vhi) = (
            k.div_ceil(3).max(1),
            ((2 * k) / 3).min(lo.saturating_sub(1)),
        );
        if vhi < vlo {
            continue;
        }
        let rate = pairs(vlo, vhi) / (vhi - vlo + 1) as f64;
        let base = rate * (hi - lo + 1) as f64;
        let obs = pairs(lo, hi);
        if obs >= 3.0 {
            cands.push((obs / (base + 1.0), k));
        }
    }
    cands.sort_by(|a, b| b.0.total_cmp(&a.0));
    let mut periods: Vec<f64> = cands
        .iter()
        .take(6)
        .map(|&(_, k)| k as f64 * width)
        .collect();
    periods.push(median_interval);
    // Verification on the event list itself (exact, no binning): the share of
    // check-ins followed by another one within +-15% of P, against the mean
    // share at off-period lags 0.4P, 0.6P, 1.4P, 1.6P (the channel's own
    // chance level). A timer scores ~1; bursty, diurnal or Poisson traffic
    // hits off-period lags about as often as P.
    let span_us = span;
    let mut best = (0.0f64, median_interval);
    for p in periods {
        // Require at least four repetitions within the observed span.
        if p <= 0.0 || p * 4.0 > span_us {
            continue;
        }
        let (hit, gap, eligible) = hit_fraction(&events, p, 0.15);
        if eligible < MIN_VERIFY_EVENTS {
            continue;
        }
        let off = OFF_LAGS
            .iter()
            .map(|m| hit_fraction(&events, m * p, 0.15).0)
            .sum::<f64>()
            / OFF_LAGS.len() as f64;
        // If chance alone fills most windows, the lag is uninformative (the
        // channel is dense relative to the window width).
        if off > 0.5 {
            continue;
        }
        // Shrink toward 0 when few check-ins support the estimate.
        let support = eligible as f64 / (eligible as f64 + 8.0);
        let score = ((hit - off) / (1.0 - off)).clamp(0.0, 1.0) * support;
        if score > best.0 {
            best = (score, gap);
        }
    }
    Some(best)
}

/// Fewest eligible check-ins for an autocorrelation verdict.
const MIN_VERIFY_EVENTS: usize = 8;

/// Off-period lags (as multiples of the candidate period) whose hit rate
/// estimates the chance level for this channel.
const OFF_LAGS: [f64; 4] = [0.4, 0.6, 1.4, 1.6];

/// Fraction of events (among those at least `(1 + tol) p` before the last
/// event) that have a successor at a lag within `p * (1 +- tol)`, the median
/// of those matched lags (a refined period estimate), and the number of
/// eligible events.
fn hit_fraction(events: &[i64], p: f64, tol: f64) -> (f64, f64, usize) {
    let last = *events.last().unwrap_or(&0) as f64;
    let (lo_off, hi_off) = (p * (1.0 - tol), p * (1.0 + tol));
    let mut j = 0usize;
    let (mut eligible, mut hits) = (0usize, 0usize);
    let mut gaps = Vec::new();
    for (i, &t) in events.iter().enumerate() {
        let t = t as f64;
        if t + hi_off > last {
            break;
        }
        eligible += 1;
        j = j.max(i + 1);
        while j < events.len() && (events[j] as f64) < t + lo_off {
            j += 1;
        }
        if j < events.len() && (events[j] as f64) <= t + hi_off {
            hits += 1;
            gaps.push(events[j] as f64 - t);
        }
    }
    if eligible == 0 {
        return (0.0, p, 0);
    }
    gaps.sort_by(f64::total_cmp);
    let gap = if gaps.is_empty() {
        p
    } else {
        quantile(&gaps, 0.5)
    };
    (hits as f64 / eligible as f64, gap, eligible)
}

/// Linear (non-circular) autocorrelation `c(k) = sum_t x_t x_{t+k}` for
/// `k = 0..x.len()`, computed as `IFFT(|FFT(x)|^2)` on a zero-padded buffer.
pub fn autocorr_fft(x: &[f64]) -> Vec<f64> {
    let n = x.len();
    if n == 0 {
        return Vec::new();
    }
    let size = (2 * n).next_power_of_two();
    let mut re = vec![0.0; size];
    let mut im = vec![0.0; size];
    re[..n].copy_from_slice(x);
    fft(&mut re, &mut im, false);
    for i in 0..size {
        re[i] = re[i] * re[i] + im[i] * im[i];
        im[i] = 0.0;
    }
    fft(&mut re, &mut im, true);
    re.truncate(n);
    // Round away FFT noise; inputs are integer counts so outputs are integers.
    re.iter().map(|v| v.round()).collect()
}

/// In-place iterative radix-2 Cooley-Tukey FFT. `re.len()` must be a power
/// of two. The inverse transform is scaled by `1/n`.
pub fn fft(re: &mut [f64], im: &mut [f64], inverse: bool) {
    let n = re.len();
    debug_assert!(n.is_power_of_two() && im.len() == n);
    // Bit-reversal permutation.
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }
    let sign = if inverse { 1.0 } else { -1.0 };
    let mut len = 2;
    while len <= n {
        let ang = sign * 2.0 * PI / len as f64;
        let (wr, wi) = (ang.cos(), ang.sin());
        for start in (0..n).step_by(len) {
            let (mut cr, mut ci) = (1.0, 0.0);
            for k in 0..len / 2 {
                let a = start + k;
                let b = a + len / 2;
                let tr = re[b] * cr - im[b] * ci;
                let ti = re[b] * ci + im[b] * cr;
                re[b] = re[a] - tr;
                im[b] = im[a] - ti;
                re[a] += tr;
                im[a] += ti;
                let ncr = cr * wr - ci * wi;
                ci = cr * wi + ci * wr;
                cr = ncr;
            }
        }
        len <<= 1;
    }
    if inverse {
        let s = 1.0 / n as f64;
        re.iter_mut().for_each(|v| *v *= s);
        im.iter_mut().for_each(|v| *v *= s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::rng::Rng;

    const S: i64 = 1_000_000;

    fn periodic(n: usize, period: i64, jitter: f64, rng: &mut Rng) -> Vec<i64> {
        let mut t = 0i64;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(t);
            let j = 1.0 + jitter * (2.0 * rng.next_f64() - 1.0);
            t += (period as f64 * j) as i64;
        }
        out
    }

    fn poisson(n: usize, mean: i64, rng: &mut Rng) -> Vec<i64> {
        let mut t = 0i64;
        (0..n)
            .map(|_| {
                t += (rng.exp(mean as f64)) as i64 + 1;
                t
            })
            .collect()
    }

    #[test]
    fn fft_autocorrelation_matches_naive() {
        let x = [1.0, 0.0, 2.0, 0.0, 1.0, 3.0, 0.0];
        let fast = autocorr_fft(&x);
        for k in 0..x.len() {
            let naive: f64 = (0..x.len() - k).map(|t| x[t] * x[t + k]).sum();
            assert_eq!(fast[k], naive, "lag {k}");
        }
        assert!(autocorr_fft(&[]).is_empty());
    }

    #[test]
    fn perfect_timer_scores_near_one() {
        let mut ts: Vec<i64> = (0..200).map(|i| i * 60 * S).collect();
        let sizes = vec![512.0; 200];
        let s = score_series(&mut ts, &sizes, 200, 10).unwrap();
        assert!(s.score > 0.95, "{s:?}");
        assert!(s.s_acf > 0.9, "{s:?}");
        assert_eq!(s.period_us, 60 * S);
        assert_eq!(s.jitter, 0.0);
    }

    #[test]
    fn poisson_scores_low_and_jitter_degrades_gracefully() {
        let mut rng = Rng::new(7);
        let mut p = poisson(300, 60 * S, &mut rng);
        let ps = score_series(&mut p, &[], 300, 10).unwrap();
        let mut b = periodic(300, 60 * S, 0.3, &mut rng);
        let bs = score_series(&mut b, &[], 300, 10).unwrap();
        assert!(ps.score < 0.5, "poisson {ps:?}");
        assert!(bs.score > ps.score + 0.2, "beacon {bs:?} vs {ps:?}");
        assert!((ps.jitter - 0.69).abs() < 0.15, "{ps:?}");
    }

    #[test]
    fn acf_survives_interleaved_noise() {
        let mut rng = Rng::new(11);
        let mut ts = periodic(240, 300 * S, 0.05, &mut rng);
        let end = *ts.last().unwrap();
        // Add 240 random extra connections on the same channel.
        for _ in 0..240 {
            ts.push((rng.next_f64() * end as f64) as i64);
        }
        let s = score_series(&mut ts, &[], 480, 10).unwrap();
        assert!(s.s_acf > s.s_jit, "{s:?}");
        assert!(s.s_acf > 0.3, "{s:?}");
        let err = (s.period_us - 300 * S).abs() as f64 / (300 * S) as f64;
        assert!(err < 0.1, "period {:?}", s.period_us);
    }

    #[test]
    fn too_few_events() {
        let mut ts = vec![0, S, 2 * S];
        assert!(score_series(&mut ts, &[], 3, 10).is_none());
        let mut same = vec![5; 20];
        assert!(score_series(&mut same, &[], 20, 10).is_none());
    }

    #[test]
    fn size_feature() {
        let mut ts: Vec<i64> = (0..50).map(|i| i * 10 * S).collect();
        let zeros = vec![0.0; 50];
        let s = score_series(&mut ts.clone(), &zeros, 50, 10).unwrap();
        assert_eq!(s.s_size, Some(1.0));
        let mut mixed = vec![0.0; 50];
        mixed[0] = 5.0;
        mixed[1] = 9.0;
        mixed[2] = 1.0;
        let _ = score_series(&mut ts, &mixed, 50, 10).unwrap();
    }

    #[test]
    fn quantiles() {
        let v = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(quantile(&v, 0.5), 2.5);
        assert_eq!(quantile(&v, 0.0), 1.0);
        assert_eq!(quantile(&v, 1.0), 4.0);
        assert!(quantile(&[], 0.5).is_nan());
        assert_eq!(mad(&[1.0, 1.0, 2.0, 2.0, 4.0, 6.0, 9.0]), 1.0);
    }

    #[test]
    fn scorer_variants() {
        let mut ts: Vec<i64> = (0..30).map(|i| i * 10 * S).collect();
        let s = score_series(&mut ts, &[], 30, 10).unwrap();
        assert_eq!(s.score_with(Scorer::Combined), s.score);
        // 29 perfect intervals: features are shrunk by 29 / (29 + 4).
        assert!((s.s_jit - 29.0 / 33.0).abs() < 1e-9);
        assert!((s.score_with(Scorer::IntervalOnly) - 29.0 / 33.0).abs() < 1e-9);
        assert_eq!(s.score_with(Scorer::AcfOnly), s.s_acf);
    }
}
