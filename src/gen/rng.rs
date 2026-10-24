//! Small deterministic PRNG (SplitMix64) so generated datasets are
//! byte-identical for a given seed on every platform, without a `rand`
//! dependency whose stream could change between versions.

#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// Derive an independent stream (e.g. one per generated host).
    pub fn fork(&mut self, salt: u64) -> Rng {
        Rng::new(self.next_u64() ^ salt.wrapping_mul(0xD1B5_4A32_D192_ED03))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform integer in `[lo, hi)`. Panics if `hi <= lo`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(hi > lo, "empty range");
        lo + self.next_u64() % (hi - lo)
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.next_f64() < p
    }

    /// Exponential variate with the given mean.
    pub fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.next_f64()).ln()
    }

    /// Standard normal variate (Box-Muller).
    pub fn normal(&mut self) -> f64 {
        let u1 = (1.0 - self.next_f64()).max(f64::MIN_POSITIVE);
        let u2 = self.next_f64();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.range(0, items.len() as u64) as usize]
    }

    /// Index drawn from a Zipf-like distribution over `n` items (rank 0 most
    /// popular), exponent 1.
    pub fn zipf(&mut self, n: usize) -> usize {
        let h: f64 = (1..=n).map(|k| 1.0 / k as f64).sum();
        let mut target = self.next_f64() * h;
        for k in 1..=n {
            target -= 1.0 / k as f64;
            if target <= 0.0 {
                return k - 1;
            }
        }
        n - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_in_range() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut r = Rng::new(1);
        for _ in 0..1000 {
            let f = r.next_f64();
            assert!((0.0..1.0).contains(&f));
            let x = r.range(5, 9);
            assert!((5..9).contains(&x));
            assert!(r.zipf(10) < 10);
            assert!(r.exp(3.0) >= 0.0);
        }
        let mean: f64 = (0..20_000).map(|_| r.exp(2.0)).sum::<f64>() / 20_000.0;
        assert!((mean - 2.0).abs() < 0.1, "{mean}");
        let nm: f64 = (0..20_000).map(|_| r.normal()).sum::<f64>() / 20_000.0;
        assert!(nm.abs() < 0.05, "{nm}");
        let mut f = r.fork(3);
        let _ = f.next_u64();
        assert!(*r.pick(&[1, 2, 3]) <= 3);
        let hits = (0..1000).filter(|_| r.chance(0.25)).count();
        assert!((150..350).contains(&hits));
    }
}
