//! Header hygiene at the proxy boundary.
//!
//! Two jobs, both essential to proxying safely:
//!
//! - **Hop-by-hop stripping**
//!   ([`strip_hop_by_hop`](crate::security::headers::strip_hop_by_hop),
//!   [`normalize_headers`](crate::security::headers::normalize_headers)) —
//!   per-connection headers (RFC 9110 §7.6.1) and any names a peer nominates
//!   via `Connection:` are removed in both directions, so they cannot leak
//!   through or be used to smuggle internal headers (Invariant 44).
//! - **Trusted-proxy attribution**
//!   ([`apply_forwarding_policy`](crate::security::headers::apply_forwarding_policy))
//!   — `X-Forwarded-*` and `Forwarded` headers are honored only from CIDRs the
//!   operator trusts; from everyone else they are dropped and rewritten from the
//!   real client address, so upstreams never see forged client attribution
//!   (Invariants 23 & 43).
//!
//! [`redact_sensitive_headers`](crate::security::headers::redact_sensitive_headers)
//! and [`validate_header_values`](crate::security::headers::validate_header_values)
//! support safe logging and CR/LF rejection respectively.

use http::{HeaderMap, HeaderName, HeaderValue};
use std::net::IpAddr;

/// Hop-by-hop headers per RFC 9110 §7.6.1 (Invariant 44)
const HOP_BY_HOP: &[&str] = &[
    "connection", "keep-alive", "transfer-encoding", "te",
    "trailer", "upgrade", "proxy-authorization", "proxy-authenticate",
];

/// Headers that may never be removed via `Connection:` nomination — letting a
/// peer nominate these would let it corrupt routing or framing downstream.
const NOMINATION_EXEMPT: &[&str] = &["host", "content-length"];

/// Strip hop-by-hop headers before proxying in either direction (Invariant 44).
///
/// Connection-nominated headers are collected *before* the Connection header
/// itself is removed; removing it first loses the nomination list and lets
/// `Connection: x-internal` smuggle x-internal through.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let nominated: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty() && !NOMINATION_EXEMPT.contains(&t.as_str()))
        .collect();

    for token in nominated {
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            headers.remove(&name);
        }
    }
    for &name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Client-attribution headers governed by the trusted-proxy boundary (Invariant 43).
const ATTRIBUTION: &[&str] = &[
    "x-forwarded-for",
    "forwarded",
    "x-real-ip",
    "x-forwarded-host",
    "x-forwarded-proto",
];

/// Invariants 23 & 43 — enforce the trusted-proxy boundary and stamp standard
/// forwarding headers before a request goes upstream.
///
/// When `client` matches a `trusted_proxies` CIDR, its incoming attribution
/// headers are honored and the client address is appended to X-Forwarded-For.
/// Otherwise every attribution header is dropped and rewritten from scratch so
/// upstreams never see client-forged values.
pub fn apply_forwarding_policy(
    headers: &mut HeaderMap,
    client: IpAddr,
    scheme: &str,
    original_host: Option<&HeaderValue>,
    trusted_proxies: &[ipnetwork::IpNetwork],
) {
    let trusted = trusted_proxies.iter().any(|n| n.contains(client));

    let prior_xff: Option<String> = if trusted {
        let joined = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        (!joined.is_empty()).then_some(joined)
    } else {
        for &name in ATTRIBUTION {
            headers.remove(name);
        }
        None
    };

    let xff = match prior_xff {
        Some(prev) => format!("{}, {}", prev, client),
        None => client.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert("x-forwarded-for", v);
    }
    if !headers.contains_key("x-real-ip") {
        if let Ok(v) = HeaderValue::from_str(&client.to_string()) {
            headers.insert("x-real-ip", v);
        }
    }
    if !headers.contains_key("x-forwarded-proto") {
        if let Ok(v) = HeaderValue::from_str(scheme) {
            headers.insert("x-forwarded-proto", v);
        }
    }
    if !headers.contains_key("x-forwarded-host") {
        if let Some(host) = original_host {
            headers.insert("x-forwarded-host", host.clone());
        }
    }
}

/// Normalize headers before proxying (Invariant 23). Header names are already
/// lowercase in the `http` crate; this enforces hop-by-hop removal.
pub fn normalize_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
}

/// Redact sensitive headers for logging (Invariant 52)
pub fn redact_sensitive_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    const SENSITIVE: &[&str] = &[
        "authorization", "cookie", "proxy-authorization", "set-cookie",
    ];

    headers
        .iter()
        .map(|(name, value)| {
            let name_str = name.as_str().to_lowercase();
            let value_str = if SENSITIVE.contains(&name_str.as_str()) {
                "[REDACTED]".to_string()
            } else {
                value.to_str().unwrap_or("[INVALID]").to_string()
            };
            (name_str, value_str)
        })
        .collect()
}

/// Validate no CR/LF in header values (Invariant 26)
pub fn validate_header_values(headers: &HeaderMap) -> bool {
    headers.iter().all(|(_, v)| {
        v.to_str().map(|s| !s.contains('\r') && !s.contains('\n')).unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn connection_nominated_headers_are_stripped() {
        let mut h = hm(&[
            ("connection", "close, x-internal-secret"),
            ("x-internal-secret", "token"),
            ("x-kept", "yes"),
        ]);
        strip_hop_by_hop(&mut h);
        assert!(h.get("x-internal-secret").is_none());
        assert!(h.get("connection").is_none());
        assert_eq!(h.get("x-kept").unwrap(), "yes");
    }

    #[test]
    fn nomination_cannot_remove_host_or_content_length() {
        let mut h = hm(&[
            ("connection", "host, content-length"),
            ("host", "example.com"),
            ("content-length", "5"),
        ]);
        strip_hop_by_hop(&mut h);
        assert!(h.get("host").is_some());
        assert!(h.get("content-length").is_some());
    }

    #[test]
    fn standard_hop_by_hop_removed() {
        let mut h = hm(&[
            ("transfer-encoding", "chunked"),
            ("keep-alive", "timeout=5"),
            ("upgrade", "h2c"),
            ("proxy-authorization", "Basic xxx"),
        ]);
        strip_hop_by_hop(&mut h);
        assert!(h.is_empty());
    }

    #[test]
    fn untrusted_client_attribution_rewritten() {
        let mut h = hm(&[
            ("x-forwarded-for", "1.2.3.4"),
            ("x-real-ip", "1.2.3.4"),
            ("x-forwarded-proto", "https"),
        ]);
        let client: IpAddr = "203.0.113.7".parse().unwrap();
        apply_forwarding_policy(&mut h, client, "http", None, &[]);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "203.0.113.7");
        assert_eq!(h.get("x-real-ip").unwrap(), "203.0.113.7");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn trusted_proxy_xff_appended() {
        let mut h = hm(&[("x-forwarded-for", "1.2.3.4")]);
        let client: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        apply_forwarding_policy(&mut h, client, "https", None, &trusted);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "1.2.3.4, 10.0.0.1");
    }

    #[test]
    fn forwarded_host_set_from_original() {
        let mut h = HeaderMap::new();
        let host = HeaderValue::from_static("example.com");
        let client: IpAddr = "203.0.113.7".parse().unwrap();
        apply_forwarding_policy(&mut h, client, "https", Some(&host), &[]);
        assert_eq!(h.get("x-forwarded-host").unwrap(), "example.com");
    }
}
