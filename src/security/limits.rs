use std::sync::atomic::{AtomicUsize, Ordering};

/// Global connection counter (Invariant 64: Bounded request queues)
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
const MAX_CONNECTIONS: usize = 10000;

/// Memory pressure threshold (Invariant 66)
#[allow(dead_code)]
const MEMORY_PRESSURE_THRESHOLD: f64 = 0.05; // 5% free

pub fn is_overloaded() -> bool {
    ACTIVE_CONNECTIONS.load(Ordering::Relaxed) >= MAX_CONNECTIONS
}

pub fn acquire_connection() -> bool {
    let prev = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    if prev >= MAX_CONNECTIONS {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        false
    } else {
        true
    }
}

pub fn release_connection() {
    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
}

/// Check memory pressure via /proc/meminfo on Linux
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

pub fn get_active_connections() -> usize {
    ACTIVE_CONNECTIONS.load(Ordering::Relaxed)
}
