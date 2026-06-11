//! `Host` header validation (Invariant 22).
//!
//! Accepting requests for arbitrary `Host` values invites cache poisoning and
//! routing confusion, so each block enforces a `host_header_policy`:
//! `"strict"` (the default) requires a match against `server_name`, `"list"`
//! additionally accepts `allowed_hosts`, and `"any"` disables the check.
//! [`validate_host`](crate::security::host_policy::validate_host) applies the
//! configured policy, with `*.example.com` wildcard support and correct
//! handling of bracketed IPv6 authorities.

use crate::config::HttpBlock;
use crate::security::upstream_filter::split_host_port;

/// Validate the request Host header per the block policy (Invariant 22).
///
/// `strict` requires a match against `server_name`; `list` accepts
/// `allowed_hosts` or `server_name`; `any` accepts everything. Host parsing
/// goes through [`split_host_port`] so bracketed IPv6 hosts are handled.
pub fn validate_host(host: Option<&str>, block: &HttpBlock) -> bool {
    match block.host_header_policy.as_str() {
        "any" => true,
        "list" => {
            let Some(host) = host else { return false };
            let (host_only, _) = split_host_port(host);
            let host_only = host_only.to_lowercase();
            let in_allowed = block
                .allowed_hosts
                .as_ref()
                .map(|hosts| hosts.iter().any(|h| h.eq_ignore_ascii_case(&host_only)))
                .unwrap_or(false);
            in_allowed
                || block
                    .server_name
                    .iter()
                    .any(|p| matches_name(&host_only, p))
        }
        // "strict" (and anything else — config validation rejects unknowns)
        _ => {
            let Some(host) = host else { return false };
            let (host_only, _) = split_host_port(host);
            let host_only = host_only.to_lowercase();
            block
                .server_name
                .iter()
                .any(|p| matches_name(&host_only, p))
        }
    }
}

fn matches_name(host: &str, pattern: &str) -> bool {
    let pattern = pattern.to_lowercase();
    if host == pattern {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        return host.ends_with(suffix) || host == rest;
    }
    false
}
