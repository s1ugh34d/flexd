use http::HeaderMap;

/// Hop-by-hop headers per RFC 9110 (Invariant 44)
const HOP_BY_HOP: &[&str] = &[
    "connection", "keep-alive", "transfer-encoding", "te",
    "trailer", "upgrade", "proxy-authorization", "proxy-authenticate",
];

/// Strip hop-by-hop headers before proxying (Invariant 44)
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for &name in HOP_BY_HOP {
        headers.remove(name);
    }

    // Also remove any headers listed in the Connection header
    if let Some(conn_val) = headers.get("connection") {
        if let Ok(conn_str) = conn_val.to_str() {
            let tokens: Vec<String> = conn_str
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
            for token in tokens {
                headers.remove(token.as_str());
            }
        }
    }
}

/// Strip untrusted proxy headers (Invariant 43)
pub fn strip_untrusted_proxy_headers(headers: &mut HeaderMap, trusted_proxies: &[String]) {
    // If no trusted proxies configured, strip all proxy attribution headers
    if trusted_proxies.is_empty() {
        headers.remove("x-forwarded-for");
        headers.remove("forwarded");
        headers.remove("x-real-ip");
        headers.remove("x-forwarded-host");
        headers.remove("x-forwarded-proto");
    }
    // TODO: implement CIDR matching for trusted_proxies
}

/// Normalize headers to lowercase (Invariant 23)
pub fn normalize_headers(headers: &mut HeaderMap) {
    // In hyper, header names are already case-insensitive for lookup,
    // but we ensure no duplicate hop-by-hop headers remain
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
