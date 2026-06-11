//! SSRF- and rebinding-aware DNS resolution for hostname upstreams.
//!
//! Reverse-proxy targets may be hostnames, and a hostname's address can change
//! between requests — or be attacker-controlled (DNS rebinding). This module
//! provides [`PinningResolver`](crate::resolver::PinningResolver), which
//! resolves names through Tokio, checks
//! *every* returned address against the operator's allowlist before any
//! connection is made, and caches vetted answers for a TTL. It plugs into
//! `hyper`'s `HttpConnector` via a `tower_service::Service<Name>` impl, so the
//! pooled proxy client gets this checking transparently (Invariants 41 & 42).

use crate::security::upstream_filter;
use hyper_util::client::legacy::connect::dns::Name;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Upper bound on cached hostnames so a pathological config cannot grow the
/// cache without limit. Upstream sets are small; this is purely defensive.
const MAX_CACHE_ENTRIES: usize = 4096;

/// DNS resolver enforcing Invariants 41 & 42 for hostname upstreams.
///
/// Every DNS answer is checked against the restricted-range policy *before*
/// the connector may use it, so a name that suddenly resolves to 127.0.0.1
/// (DNS rebinding) fails closed instead of redirecting traffic. Vetted
/// answers are cached for `ttl` and reused, pinning subsequent connections to
/// addresses that passed the check; pooled connections in the shared client
/// keep using the socket they were vetted with.
#[derive(Clone)]
pub struct PinningResolver {
    allowed: Arc<Vec<ipnetwork::IpNetwork>>,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    ttl: Duration,
}

struct CacheEntry {
    addrs: Vec<SocketAddr>,
    expires: Instant,
}

impl PinningResolver {
    /// Create a resolver that admits only addresses inside `allowed` (the
    /// operator's `upstream_allowed_networks`, parsed to CIDRs) and caches
    /// vetted answers for `ttl`. An empty `allowed` list rejects every
    /// restricted-range address while still permitting public ones.
    pub fn new(allowed: Vec<ipnetwork::IpNetwork>, ttl: Duration) -> Self {
        Self {
            allowed: Arc::new(allowed),
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    fn cached(&self, host: &str) -> Option<Vec<SocketAddr>> {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        match cache.get(host) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.addrs.clone()),
            Some(_) => {
                cache.remove(host);
                None
            }
            None => None,
        }
    }

    fn store(&self, host: String, addrs: Vec<SocketAddr>) {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(
            host,
            CacheEntry {
                addrs,
                expires: Instant::now() + self.ttl,
            },
        );
    }

    /// Resolve and vet a hostname. Public so the CONNECT handler can reuse the
    /// same pinning + filtering for tunnel targets.
    ///
    /// On a cache hit, the previously vetted addresses are returned directly.
    /// On a miss, the name is resolved and every answer is checked; the call
    /// fails closed if *any* address is restricted and not allowlisted.
    ///
    /// # Errors
    ///
    /// - [`io::ErrorKind::NotFound`] if the name resolves to no addresses.
    /// - [`io::ErrorKind::PermissionDenied`] if any resolved address is in a
    ///   restricted range outside the allowlist (Invariant 41/42).
    /// - Any underlying resolver I/O error.
    pub async fn resolve_checked(&self, host: &str) -> io::Result<Vec<SocketAddr>> {
        if let Some(addrs) = self.cached(host) {
            return Ok(addrs);
        }

        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0u16)).await?.collect();

        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses resolved for '{}'", host),
            ));
        }
        // Fail closed if *any* answer is restricted: a mixed public/private
        // answer set is exactly what a rebinding or split-horizon leak looks
        // like, and partial filtering would still let the attacker steer
        // retries toward the private address.
        for sa in &addrs {
            if !upstream_filter::ip_allowed(sa.ip(), &self.allowed) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "upstream '{}' resolved to restricted address {} (Invariant 41/42)",
                        host,
                        sa.ip()
                    ),
                ));
            }
        }

        self.store(host.to_string(), addrs.clone());
        Ok(addrs)
    }
}

/// hyper-util's `Resolve` is sealed but blanket-implemented for any
/// `tower_service::Service<Name>` yielding socket addresses, so this impl is
/// what plugs the resolver into `HttpConnector::new_with_resolver`.
impl tower_service::Service<Name> for PinningResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, io::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let addrs = this.resolve_checked(name.as_str()).await?;
            Ok(addrs.into_iter())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_literal_rejected_without_allowlist() {
        let r = PinningResolver::new(vec![], Duration::from_secs(30));
        let err = r.resolve_checked("127.0.0.1").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn loopback_literal_allowed_with_allowlist() {
        let r = PinningResolver::new(
            vec!["127.0.0.0/8".parse().unwrap()],
            Duration::from_secs(30),
        );
        let addrs = r.resolve_checked("127.0.0.1").await.unwrap();
        assert!(!addrs.is_empty());
    }

    #[tokio::test]
    async fn vetted_answers_are_cached() {
        let r = PinningResolver::new(
            vec!["127.0.0.0/8".parse().unwrap()],
            Duration::from_secs(30),
        );
        r.resolve_checked("127.0.0.1").await.unwrap();
        assert!(r.cached("127.0.0.1").is_some());
    }

    #[tokio::test]
    async fn expired_entries_are_dropped() {
        let r = PinningResolver::new(
            vec!["127.0.0.0/8".parse().unwrap()],
            Duration::from_millis(1),
        );
        r.resolve_checked("127.0.0.1").await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(r.cached("127.0.0.1").is_none());
    }
}
