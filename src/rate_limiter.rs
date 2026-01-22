// Copied from qunet

use std::{sync::LazyLock, time::Instant};

#[derive(Debug, Clone)]
pub struct RateLimiter {
    max: u32,
    tokens: u32,
    ns_to_refill_one: u64,
    last_refill_time: u64,
    pow2_shift: Option<u32>,
}

fn time() -> u64 {
    static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
    let elapsed = Instant::now().duration_since(*EPOCH);
    elapsed.as_nanos() as u64
}

impl RateLimiter {
    pub fn new(per_sec: u32, max: u32) -> Self {
        assert!(
            max > 0 && per_sec > 0,
            "per_sec and max must be greater than 0"
        );

        // instead of 1 second, use 2^30 nanoseconds, so that if per_sec is a power of two, we can skip the division :)
        let ns_to_refill_one = 1_073_741_824u64 / per_sec as u64;

        Self::new_precise(ns_to_refill_one, max)
    }

    /// Create a rate limiter with a more precise refill rate
    /// Pass how many nanoseconds it takes to refill one token
    pub fn new_precise(mut ns_to_refill_one: u64, max: u32) -> Self {
        assert!(max > 0, "max must be greater than 0");

        if ns_to_refill_one == 0 {
            ns_to_refill_one = 1;
        }

        let pow2_shift = if ns_to_refill_one.is_power_of_two() {
            Some(ns_to_refill_one.trailing_zeros())
        } else {
            None
        };

        Self {
            max,
            tokens: max,
            ns_to_refill_one,
            last_refill_time: time(),
            pow2_shift,
        }
    }

    pub fn new_unlimited() -> Self {
        Self::new(u32::MAX, u32::MAX)
    }

    /// Returns whether a token was available, false means rate limit was exceeded
    /// Will handle refilling the bucket as well
    pub fn consume(&mut self) -> bool {
        self.catch_up();

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn catch_up(&mut self) {
        let now = time();
        let elapsed_ns = now - self.last_refill_time;

        let full_ticks = if let Some(shift) = self.pow2_shift {
            elapsed_ns >> shift
        } else {
            elapsed_ns / self.ns_to_refill_one
        };

        if full_ticks == 0 {
            return;
        }

        // for fairness, set to consumed * period instead of `now`, so nothing gets lost
        self.last_refill_time += full_ticks * self.ns_to_refill_one;
        self.tokens = self
            .tokens
            .saturating_add(full_ticks.try_into().unwrap_or(u32::MAX))
            .min(self.max);
    }
}
