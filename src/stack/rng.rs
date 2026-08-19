// A tiny deterministic random number generator, for `--drop-pct`.
//
// This is xorshift64*: three shifts and a multiply. It is nowhere near good
// enough for anything security-related, and that is fine — the only question
// being asked is "should this frame vanish?", and the whole point of a lab is
// that you can seed it and get the same run twice. Pulling in a real RNG crate
// would add a dependency to answer a question a dozen lines already answer.

pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    pub fn from_entropy() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        Self::new(nanos)
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x >> 32) as u32
    }
}

pub fn drop_pct_hit(pct: u8, rng: &mut SeededRng) -> bool {
    if pct == 0 {
        return false;
    }
    if pct >= 100 {
        return true;
    }
    (rng.next_u32() % 100) < u32::from(pct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_pct_zero_never_hundred_always_fifty_is_deterministic() {
        let mut rng = SeededRng::new(42);
        for _ in 0..32 {
            assert!(!drop_pct_hit(0, &mut rng));
        }
        let mut rng = SeededRng::new(42);
        for _ in 0..32 {
            assert!(drop_pct_hit(100, &mut rng));
        }
        let mut a = SeededRng::new(7);
        let mut b = SeededRng::new(7);
        let seq_a: Vec<bool> = (0..20).map(|_| drop_pct_hit(50, &mut a)).collect();
        let seq_b: Vec<bool> = (0..20).map(|_| drop_pct_hit(50, &mut b)).collect();
        assert_eq!(seq_a, seq_b);
        assert!(seq_a.iter().any(|h| *h) && seq_a.iter().any(|h| !*h));
    }
}
