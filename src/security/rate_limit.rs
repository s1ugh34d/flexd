use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<Mutex<HashMap<String, TokenBucket>>>,
    max_tokens: usize,
    refill_interval: Duration,
}

struct TokenBucket {
    tokens: usize,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(max_tokens: usize, window: Duration) -> Self {
        RateLimiter {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_tokens,
            refill_interval: window,
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let bucket = state.entry(key.to_string()).or_insert_with(|| TokenBucket {
            tokens: self.max_tokens,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill);
        if elapsed >= self.refill_interval {
            bucket.tokens = self.max_tokens;
            bucket.last_refill = now;
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }

    pub fn cleanup_stale(&self, max_age: Duration) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        state.retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}
