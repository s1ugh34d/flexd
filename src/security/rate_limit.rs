//! HTTP/2 reset-flood (Rapid Reset, CVE-2023-44487) rate limiting.
//!
//! An HTTP/2 peer can open a stream and immediately reset it, making the server
//! do per-request work for free; at scale this is a denial-of-service. Each
//! connection gets a [`ResetTracker`](crate::security::rate_limit::ResetTracker)
//! that counts cancelled streams within a sliding window and signals when the
//! configured rate is exceeded, at which
//! point the serving loop terminates the connection with a GOAWAY (Invariant 20).

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-connection HTTP/2 stream-reset tracker — Invariant 20 (Rapid Reset).
///
/// hyper does not surface RST_STREAM frames directly, but a stream the peer
/// resets shows up as its request future being dropped before a response was
/// produced. Each such cancellation is recorded here; exceeding `max` within
/// `window` marks the connection for termination (GOAWAY via graceful
/// shutdown in the serving loop). One tracker exists per connection, so the
/// mutex is uncontended and poisoning is absorbed rather than propagated.
pub struct ResetTracker {
    max: usize,
    window: Duration,
    state: Mutex<WindowState>,
}

struct WindowState {
    count: usize,
    started: Instant,
}

impl ResetTracker {
    /// Create a tracker allowing up to `max` resets per `window` before
    /// [`record_reset`](Self::record_reset) signals termination.
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            state: Mutex::new(WindowState {
                count: 0,
                started: Instant::now(),
            }),
        }
    }

    /// Record one cancelled stream. Returns true when the configured rate is
    /// exceeded and the connection must be terminated.
    pub fn record_reset(&self) -> bool {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        if now.duration_since(st.started) > self.window {
            st.count = 0;
            st.started = now;
        }
        st.count += 1;
        st.count > self.max
    }

    /// Current count inside the active window (for tests/metrics).
    pub fn current(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_limit_not_terminated() {
        // Contract scenario 24: 5 or fewer resets are unaffected.
        let t = ResetTracker::new(10, Duration::from_secs(3));
        for _ in 0..5 {
            assert!(!t.record_reset());
        }
    }

    #[test]
    fn burst_over_limit_terminated() {
        // Contract scenario 24: 15 resets within the window terminate the connection.
        let t = ResetTracker::new(10, Duration::from_secs(3));
        let mut killed = false;
        for _ in 0..15 {
            killed = t.record_reset();
        }
        assert!(killed);
    }

    #[test]
    fn window_expiry_resets_count() {
        let t = ResetTracker::new(2, Duration::from_millis(10));
        assert!(!t.record_reset());
        assert!(!t.record_reset());
        std::thread::sleep(Duration::from_millis(20));
        // New window: counting restarts.
        assert!(!t.record_reset());
    }
}
