//! Global connection and memory-pressure limits.
//!
//! Two coarse back-pressure controls that the accept loops consult before
//! taking on a new connection: a process-wide concurrent-connection cap
//! (Invariant 64) tracked by an atomic counter, and a memory-pressure check
//! (Invariant 66) that reads `/proc/meminfo` on Linux. Together they let the
//! server shed load instead of falling over when overwhelmed.
//!
//! The connection counter is acquired with
//! [`acquire_connection`](crate::security::limits::acquire_connection) and
//! released with
//! [`release_connection`](crate::security::limits::release_connection); in the
//! server these are paired by an RAII guard so a dropped connection always
//! decrements the count.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Global connection counter (Invariant 64: Bounded request queues)
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
const MAX_CONNECTIONS: usize = 10000;

/// Memory pressure threshold (Invariant 66) — accept loops reject new
/// connections when less than this fraction of system memory is available.
pub const MEMORY_PRESSURE_THRESHOLD: f64 = 0.05; // 5% free

/// Whether the active-connection count has reached the global cap.
pub fn is_overloaded() -> bool {
    ACTIVE_CONNECTIONS.load(Ordering::Relaxed) >= MAX_CONNECTIONS
}

/// Try to reserve a connection slot.
///
/// Returns `true` if a slot was taken (the caller must later call
/// [`release_connection`]), or `false` if the cap was already reached — in
/// which case nothing is reserved and the connection should be rejected.
pub fn acquire_connection() -> bool {
    let prev = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    if prev >= MAX_CONNECTIONS {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        false
    } else {
        true
    }
}

/// Release a slot previously reserved by [`acquire_connection`].
pub fn release_connection() {
    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
}

/// Whether available system memory has dropped below `threshold` (a fraction in
/// `0.0..=1.0`, e.g. [`MEMORY_PRESSURE_THRESHOLD`]).
///
/// Reads `/proc/meminfo` on Linux. On other platforms, or if the file cannot
/// be read, returns `false` (fail open — never block traffic on a missing
/// metric).
pub fn check_memory_pressure(threshold: f64) -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = std::fs::read_to_string("/proc/meminfo") {
            let mut mem_available = 0u64;
            let mut mem_total = 0u64;
            for line in info.lines() {
                if line.starts_with("MemAvailable:") {
                    mem_available = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                }
                if line.starts_with("MemTotal:") {
                    mem_total = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                }
            }
            if mem_total > 0 {
                let free_ratio = mem_available as f64 / mem_total as f64;
                return free_ratio < threshold;
            }
        }
    }
    false
}

/// Current number of active connections (for metrics and tests).
pub fn get_active_connections() -> usize {
    ACTIVE_CONNECTIONS.load(Ordering::Relaxed)
}
