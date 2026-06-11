//! Upstream load balancing and connect-failure failover.
//!
//! [`Balancer`](crate::balance::Balancer) selects a server from an
//! [`UpstreamRef`](crate::config::UpstreamRef) pool for each proxied request,
//! honoring per-server weights and one of three strategies configured via
//! `strategy`:
//!
//! - **`round-robin`** — rotate through servers, weighted by their `weight`.
//! - **`least-conn`** — pick the server with the lowest weighted in-flight
//!   load, tracked via [`InflightGuard`](crate::balance::InflightGuard).
//! - **`ip-hash`** — map the client IP to a stable server, so a given client
//!   reliably reaches the same backend.
//!
//! [`Balancer::candidates`](crate::balance::Balancer::candidates) returns an
//! *ordered* list: the strategy's primary pick first, then the remaining
//! servers as failover targets, so a server that refuses a TCP connection can
//! be skipped without abandoning the request.

use crate::config::{HttpBlock, UpstreamRef};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Runtime state for one named upstream pool.
struct PoolState {
    rr_cursor: AtomicUsize,
    /// In-flight request gauge per server (parallel to `servers`), used by
    /// the least-conn strategy.
    inflight: Vec<AtomicUsize>,
}

/// Load balancer covering the three configured strategies (`round-robin`,
/// `least-conn`, `ip-hash`) with per-server weights. State is keyed by
/// upstream name and rebuilt on config reload along with the handler.
pub struct Balancer {
    pools: HashMap<String, Arc<PoolState>>,
}

/// Decrements the chosen server's in-flight gauge when the proxied request
/// finishes (or fails), keeping least-conn accounting correct.
pub struct InflightGuard {
    pool: Arc<PoolState>,
    idx: usize,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Some(g) = self.pool.inflight.get(self.idx) {
            g.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn weight_of(upstream: &UpstreamRef, idx: usize) -> u64 {
    upstream.servers.get(idx).map(|s| s.weight.max(1) as u64).unwrap_or(1)
}

fn total_weight(upstream: &UpstreamRef) -> u64 {
    upstream.servers.iter().map(|s| s.weight.max(1) as u64).sum::<u64>().max(1)
}

/// Map a point in [0, total_weight) onto a server index by cumulative weight.
fn index_for_point(upstream: &UpstreamRef, point: u64) -> usize {
    let mut cumulative = 0u64;
    for (i, server) in upstream.servers.iter().enumerate() {
        cumulative += server.weight.max(1) as u64;
        if point < cumulative {
            return i;
        }
    }
    0
}

fn hash_ip(ip: IpAddr) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
    hasher.finish()
}

impl Balancer {
    /// Collect every upstream pool reachable from this block: the shared
    /// `upstreams` list, per-location inline upstreams, and the CONNECT pool.
    pub fn new(block: &HttpBlock) -> Self {
        let mut pools = HashMap::new();
        {
            let mut add = |u: &UpstreamRef| {
                pools.entry(u.name.clone()).or_insert_with(|| {
                    Arc::new(PoolState {
                        rr_cursor: AtomicUsize::new(0),
                        inflight: u.servers.iter().map(|_| AtomicUsize::new(0)).collect(),
                    })
                });
            };
            for u in &block.upstreams {
                add(u);
            }
            for loc in &block.locations {
                if let Some(u) = &loc.handler.upstream {
                    add(u);
                }
            }
            if let Some(u) = &block.connect_upstream {
                add(u);
            }
        }
        Self { pools }
    }

    /// Build one for a standalone upstream (stream/mail proxying).
    pub fn for_upstream(upstream: &UpstreamRef) -> Self {
        let mut pools = HashMap::new();
        pools.insert(
            upstream.name.clone(),
            Arc::new(PoolState {
                rr_cursor: AtomicUsize::new(0),
                inflight: upstream.servers.iter().map(|_| AtomicUsize::new(0)).collect(),
            }),
        );
        Self { pools }
    }

    fn pool(&self, name: &str, servers: usize) -> Arc<PoolState> {
        self.pools.get(name).cloned().unwrap_or_else(|| {
            // Unknown pool (shouldn't happen — pools are built from the same
            // block): fall back to ephemeral state so selection still works.
            Arc::new(PoolState {
                rr_cursor: AtomicUsize::new(0),
                inflight: (0..servers).map(|_| AtomicUsize::new(0)).collect(),
            })
        })
    }

    /// Ordered candidate indices for this request: the strategy's pick first,
    /// then the remaining servers as connect-failure failover targets.
    pub fn candidates(&self, upstream: &UpstreamRef, client: IpAddr) -> Vec<usize> {
        let n = upstream.servers.len();
        if n == 0 {
            return Vec::new();
        }
        if n == 1 {
            return vec![0];
        }
        let pool = self.pool(&upstream.name, n);

        match upstream.strategy.as_str() {
            "least-conn" => {
                let mut order: Vec<usize> = (0..n).collect();
                order.sort_by(|&a, &b| {
                    let load = |i: usize| {
                        let inflight =
                            pool.inflight.get(i).map(|g| g.load(Ordering::Relaxed)).unwrap_or(0);
                        // Weighted load: (inflight + 1) / weight, compared via
                        // cross-multiplication to stay in integers.
                        (inflight as u64 + 1, weight_of(upstream, i))
                    };
                    let (la, wa) = load(a);
                    let (lb, wb) = load(b);
                    (la * wb).cmp(&(lb * wa))
                });
                order
            }
            "ip-hash" => {
                let primary = index_for_point(upstream, hash_ip(client) % total_weight(upstream));
                ring_order(primary, n)
            }
            // "round-robin" and anything else (validated at config load)
            _ => {
                let tick = pool.rr_cursor.fetch_add(1, Ordering::Relaxed) as u64;
                let primary = index_for_point(upstream, tick % total_weight(upstream));
                ring_order(primary, n)
            }
        }
    }

    /// Mark `idx` in-flight for least-conn accounting; the returned guard
    /// decrements on drop.
    pub fn track(&self, upstream: &UpstreamRef, idx: usize) -> InflightGuard {
        let pool = self.pool(&upstream.name, upstream.servers.len());
        if let Some(g) = pool.inflight.get(idx) {
            g.fetch_add(1, Ordering::Relaxed);
        }
        InflightGuard { pool, idx }
    }
}

/// `primary` first, then the rest of the ring in order — gives failover a
/// deterministic, non-repeating sweep of all servers.
fn ring_order(primary: usize, n: usize) -> Vec<usize> {
    (0..n).map(|off| (primary + off) % n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{UpstreamRef, UpstreamServer};

    fn upstream(strategy: &str, weights: &[u32]) -> UpstreamRef {
        UpstreamRef {
            name: "test".into(),
            servers: weights
                .iter()
                .enumerate()
                .map(|(i, &w)| UpstreamServer {
                    address: format!("10.0.0.{}:80", i + 1),
                    weight: w,
                })
                .collect(),
            strategy: strategy.into(),
        }
    }

    fn balancer_for(u: &UpstreamRef) -> Balancer {
        Balancer::for_upstream(u)
    }

    #[test]
    fn round_robin_rotates_evenly() {
        let u = upstream("round-robin", &[1, 1]);
        let b = balancer_for(&u);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let picks: Vec<usize> = (0..4).map(|_| b.candidates(&u, ip)[0]).collect();
        assert_eq!(picks, vec![0, 1, 0, 1]);
    }

    #[test]
    fn round_robin_honors_weights() {
        let u = upstream("round-robin", &[3, 1]);
        let b = balancer_for(&u);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let picks: Vec<usize> = (0..8).map(|_| b.candidates(&u, ip)[0]).collect();
        assert_eq!(picks.iter().filter(|&&i| i == 0).count(), 6);
        assert_eq!(picks.iter().filter(|&&i| i == 1).count(), 2);
    }

    #[test]
    fn ip_hash_is_sticky_per_client() {
        let u = upstream("ip-hash", &[1, 1, 1]);
        let b = balancer_for(&u);
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        let first = b.candidates(&u, ip)[0];
        for _ in 0..10 {
            assert_eq!(b.candidates(&u, ip)[0], first);
        }
    }

    #[test]
    fn least_conn_prefers_idle_server() {
        let u = upstream("least-conn", &[1, 1]);
        let b = balancer_for(&u);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let _busy = b.track(&u, 0);
        assert_eq!(b.candidates(&u, ip)[0], 1);
    }

    #[test]
    fn inflight_guard_releases_on_drop() {
        let u = upstream("least-conn", &[1, 1]);
        let b = balancer_for(&u);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        {
            let _busy = b.track(&u, 0);
        }
        // Guard dropped — both idle again, cross-multiplied loads tie, index 0 wins.
        assert_eq!(b.candidates(&u, ip)[0], 0);
    }

    #[test]
    fn candidates_cover_every_server_once() {
        let u = upstream("round-robin", &[1, 2, 3]);
        let b = balancer_for(&u);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let mut order = b.candidates(&u, ip);
        order.sort_unstable();
        assert_eq!(order, vec![0, 1, 2]);
    }
}
