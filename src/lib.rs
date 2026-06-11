#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
//!
//! # Library overview
//!
//! The `flexd` binary is a thin `main` wrapper; everything it does lives in
//! this library so the request pipeline can be unit- and integration-tested
//! without binding a socket. The public surface is organized as follows.
//!
//! ## Lifecycle
//!
//! - [`config`] — the typed configuration schema. [`config::Config::load`]
//!   parses TOML (or JSON) and runs [`config::Config::validate`], which rejects
//!   an unsafe or contradictory configuration *before* any socket is bound.
//! - [`server`] — [`server::Server`] owns the accept loops for every listener
//!   (TCP, TLS, and QUIC/HTTP3), connection accounting, graceful shutdown, and
//!   the background certificate-renewal task.
//! - [`handler`] — [`handler::HandlerService`] is the per-block request
//!   pipeline shared by all three protocol entry points: security checks,
//!   routing, rewrites, GeoIP, static serving, and proxying.
//!
//! ## Routing and proxying
//!
//! - [`balance`] — weighted load balancing (`round-robin`, `least-conn`,
//!   `ip-hash`) with deterministic connect-failure failover.
//! - [`proxy`] — the pooled upstream HTTP client.
//! - [`resolver`] — a DNS resolver that vets every answer against the
//!   SSRF allowlist *before* a connection is made (DNS-rebinding defense).
//! - [`rewrite`] — regex rewrite and redirect rules.
//! - [`absplit`] — weighted A/B traffic splitting with optional sticky sessions.
//! - [`static_file`] — path-traversal-safe static file serving.
//! - [`geoip`] — MaxMind GeoIP lookups.
//!
//! ## TLS and certificates
//!
//! - [`tls`] — rustls acceptor and QUIC config construction.
//! - [`acme`] — automatic certificate issuance and renewal (RFC 8555).
//!
//! ## Hardening ([`security`])
//!
//! The [`security`] modules implement the request-handling invariants that make
//! flexd safe to expose directly to the internet — host-header policy, header
//! and framing validation, SSRF filtering of upstream targets, connection and
//! memory limits, HTTP/2 reset-flood rate limiting, and privilege dropping.
//! Each item references the numbered contract invariant it enforces.
//!
//! # A note on "Invariant N" references
//!
//! Doc comments throughout the crate cite numbered invariants (e.g.
//! "Invariant 41") and contract criteria (e.g. "C53"). These refer to the
//! project's security contract — the enumerated properties the server is
//! required to uphold. The numbers are stable identifiers for those
//! requirements, not line numbers or error codes.

/// Weighted A/B traffic splitting with optional sticky session assignment.
pub mod absplit;
/// Automatic TLS certificate issuance and renewal via ACME (RFC 8555).
pub mod acme;
/// Upstream load balancing strategies and connect-failure failover.
pub mod balance;
/// Typed configuration schema, parsing, and startup validation.
pub mod config;
/// MaxMind GeoIP database lookups for request geolocation.
pub mod geoip;
/// The per-block request pipeline shared by HTTP/1, HTTP/2, and HTTP/3.
pub mod handler;
/// Combined-format access logging with control-character stripping.
pub mod logging;
/// Pooled upstream HTTP client used by the reverse proxy.
pub mod proxy;
/// SSRF- and rebinding-aware DNS resolver for hostname upstreams.
pub mod resolver;
/// Regex-based rewrite and redirect rules.
pub mod rewrite;
/// Accept loops, connection accounting, and lifecycle management.
pub mod server;
/// Path-traversal-safe static file serving.
pub mod static_file;
/// rustls / QUIC TLS configuration construction.
pub mod tls;
/// Request-handling hardening: the building blocks of flexd's security model.
pub mod security {
    /// Header normalization, hop-by-hop stripping, and trusted-proxy policy.
    pub mod headers;
    /// `Host` header validation against the configured policy.
    pub mod host_policy;
    /// Global connection and memory-pressure limits.
    pub mod limits;
    /// Post-bind privilege dropping on Unix.
    pub mod privilege;
    /// Per-connection HTTP/2 stream-reset (Rapid Reset) rate limiting.
    pub mod rate_limit;
    /// SSRF filtering of upstream and CONNECT targets.
    pub mod upstream_filter;
    /// Request-URI validation (encoded traversal, overlong UTF-8, …).
    pub mod uri_validate;
}
