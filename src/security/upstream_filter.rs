//! SSRF filtering of upstream and CONNECT targets (Invariants 41 & 42).
//!
//! A reverse proxy that will connect to any address an upstream config (or a
//! resolved hostname) names is an SSRF primitive. This module decides whether a
//! target IP is reachable: addresses in restricted ranges — loopback, RFC1918
//! private, link-local, CGNAT, multicast, unspecified, IPv4-mapped equivalents,
//! and the IPv6 analogues — are refused unless the operator has explicitly
//! allowlisted them via `upstream_allowed_networks`. Public addresses always
//! pass.
//!
//! IP literals in the config are judged at load time by
//! [`is_upstream_allowed`](crate::security::upstream_filter::is_upstream_allowed);
//! hostnames pass that gate and are re-checked, every resolved answer, at
//! connect time by [`crate::resolver::PinningResolver`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Split an authority into host and optional port.
///
/// Handles every form an upstream address or CONNECT target can take:
/// `1.2.3.4:80`, `1.2.3.4`, `[::1]:80`, `[::1]`, `::1`, `host:80`, `host`.
/// Naive `rsplit_once(':')` mangles IPv6 literals — `[::1]:80` used to come
/// back as host `[::1]` which fails IP parsing and was waved through as a
/// "hostname", bypassing the range filter entirely.
///
/// # Examples
///
/// ```
/// use flexd::security::upstream_filter::split_host_port;
///
/// assert_eq!(split_host_port("1.2.3.4:80"), ("1.2.3.4", Some(80)));
/// assert_eq!(split_host_port("[::1]:80"), ("::1", Some(80)));
/// assert_eq!(split_host_port("host.example"), ("host.example", None));
/// ```
pub fn split_host_port(addr: &str) -> (&str, Option<u16>) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok());
            return (host, port);
        }
        return (addr, None); // malformed bracket form; later IP parse will fail
    }
    // A bare IPv6 literal contains more than one ':' — the whole string is the host.
    if addr.matches(':').count() > 1 {
        return (addr, None);
    }
    match addr.rsplit_once(':') {
        Some((host, port)) => match port.parse() {
            Ok(p) => (host, Some(p)),
            Err(_) => (addr, None),
        },
        None => (addr, None),
    }
}

fn restricted_v4(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_documentation()
        || v4.octets()[0] == 0 // 0.0.0.0/8 "this network"
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
}

fn restricted_v6(v6: Ipv6Addr) -> bool {
    // An IPv4-mapped address like ::ffff:127.0.0.1 reaches the IPv4 loopback
    // but fails Ipv6Addr::is_loopback(); judge it by its embedded IPv4 form.
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return restricted_v4(mapped);
    }
    v6.is_loopback()
        || v6.is_multicast()
        || v6.is_unspecified()
        || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
}

/// Whether `ip` falls in a range that must not be reached implicitly
/// (loopback, RFC1918, link-local, CGNAT, multicast, unspecified, …).
///
/// IPv4-mapped IPv6 addresses are judged by their embedded IPv4 form, so
/// `::ffff:127.0.0.1` counts as loopback.
///
/// # Examples
///
/// ```
/// use flexd::security::upstream_filter::is_restricted;
///
/// assert!(is_restricted("127.0.0.1".parse().unwrap()));   // loopback
/// assert!(is_restricted("192.168.1.1".parse().unwrap())); // RFC1918
/// assert!(!is_restricted("93.184.216.34".parse().unwrap())); // public
/// ```
pub fn is_restricted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => restricted_v4(v4),
        IpAddr::V6(v6) => restricted_v6(v6),
    }
}

/// Invariant 41: a restricted IP is reachable only when covered by the
/// operator's `upstream_allowed_networks` allowlist. Public IPs always pass.
pub fn ip_allowed(ip: IpAddr, allowed_networks: &[ipnetwork::IpNetwork]) -> bool {
    if !is_restricted(ip) {
        return true;
    }
    // Match the canonical form too so "127.0.0.0/8" covers ::ffff:127.0.0.1.
    let canonical = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    allowed_networks
        .iter()
        .any(|net| net.contains(ip) || net.contains(canonical))
}

/// Parse a CIDR allowlist, ignoring entries that fail to parse (config
/// validation rejects malformed entries up front; this is the runtime guard).
pub fn parse_networks(allowed: Option<&[String]>) -> Vec<ipnetwork::IpNetwork> {
    allowed
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| c.parse().ok())
        .collect()
}

/// Validate an upstream address against allowed networks (Invariant 41).
///
/// IP literals are judged here. Hostnames pass this gate — they are filtered
/// again at connect time by the pinning resolver, which checks every DNS
/// answer (Invariant 42), so a name resolving to 127.0.0.1 still cannot be
/// reached.
///
/// # Errors
///
/// Returns an error if `addr` is an IP literal in a restricted range that is
/// not covered by `allowed_networks`.
pub fn is_upstream_allowed(addr: &str, allowed_networks: Option<&[String]>) -> anyhow::Result<()> {
    let (host, _) = split_host_port(addr);

    if let Ok(ip) = host.parse::<IpAddr>() {
        let nets = parse_networks(allowed_networks);
        if !ip_allowed(ip, &nets) {
            anyhow::bail!(
                "Upstream {} is in a restricted range and not in upstream_allowed_networks",
                addr
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_rejected_when_no_allowlist() {
        assert!(is_upstream_allowed("127.0.0.1:9081", None).is_err());
    }

    #[test]
    fn loopback_allowed_when_in_allowlist() {
        let nets = vec!["127.0.0.0/8".to_string()];
        assert!(is_upstream_allowed("127.0.0.1:9081", Some(&nets)).is_ok());
    }

    #[test]
    fn loopback_rejected_when_not_in_allowlist() {
        let nets = vec!["10.0.0.0/8".to_string()];
        assert!(is_upstream_allowed("127.0.0.1:9081", Some(&nets)).is_err());
    }

    #[test]
    fn private_range_rejected_when_no_allowlist() {
        assert!(is_upstream_allowed("192.168.1.10:80", None).is_err());
    }

    #[test]
    fn public_ip_allowed() {
        assert!(is_upstream_allowed("93.184.216.34:80", None).is_ok());
    }

    #[test]
    fn hostname_allowed() {
        // Non-IP authorities pass this gate; the pinning resolver re-checks
        // every resolved address at connect time.
        assert!(is_upstream_allowed("backend.internal:8080", None).is_ok());
    }

    #[test]
    fn ipv4_mapped_loopback_rejected() {
        assert!(is_upstream_allowed("[::ffff:127.0.0.1]:80", None).is_err());
        assert!(is_upstream_allowed("::ffff:127.0.0.1", None).is_err());
    }

    #[test]
    fn ipv4_mapped_loopback_allowed_via_v4_allowlist() {
        let nets = vec!["127.0.0.0/8".to_string()];
        assert!(is_upstream_allowed("[::ffff:127.0.0.1]:80", Some(&nets)).is_ok());
    }

    #[test]
    fn bracketed_v6_loopback_rejected() {
        assert!(is_upstream_allowed("[::1]:80", None).is_err());
        assert!(is_upstream_allowed("::1", None).is_err());
    }

    #[test]
    fn v6_unique_local_and_link_local_rejected() {
        assert!(is_upstream_allowed("[fc00::1]:80", None).is_err());
        assert!(is_upstream_allowed("[fd12:3456::1]:80", None).is_err());
        assert!(is_upstream_allowed("[fe80::1]:80", None).is_err());
    }

    #[test]
    fn cgnat_and_zero_net_rejected() {
        assert!(is_upstream_allowed("100.64.0.1:80", None).is_err());
        assert!(is_upstream_allowed("0.0.0.0:80", None).is_err());
    }

    #[test]
    fn split_host_port_forms() {
        assert_eq!(split_host_port("1.2.3.4:80"), ("1.2.3.4", Some(80)));
        assert_eq!(split_host_port("1.2.3.4"), ("1.2.3.4", None));
        assert_eq!(split_host_port("[::1]:80"), ("::1", Some(80)));
        assert_eq!(split_host_port("[::1]"), ("::1", None));
        assert_eq!(split_host_port("::1"), ("::1", None));
        assert_eq!(split_host_port("host.example:8080"), ("host.example", Some(8080)));
        assert_eq!(split_host_port("host.example"), ("host.example", None));
    }
}

#[cfg(all(test, not(miri)))]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Invariant 41: any IPv4 loopback target is rejected when no allowlist
        // is configured, and accepted when 127.0.0.0/8 is allowed.
        #[test]
        fn loopback_gated_by_allowlist(a in 0u8..=255, b in 0u8..=255, c in 1u8..=254, port in 1u16..=65535) {
            let addr = format!("127.{}.{}.{}:{}", a, b, c, port);
            prop_assert!(is_upstream_allowed(&addr, None).is_err());
            let nets = vec!["127.0.0.0/8".to_string()];
            prop_assert!(is_upstream_allowed(&addr, Some(&nets)).is_ok());
        }

        // The IPv4-mapped form of the same loopback must behave identically.
        #[test]
        fn mapped_loopback_gated_by_allowlist(c in 1u8..=254, port in 1u16..=65535) {
            let addr = format!("[::ffff:127.0.0.{}]:{}", c, port);
            prop_assert!(is_upstream_allowed(&addr, None).is_err());
            let nets = vec!["127.0.0.0/8".to_string()];
            prop_assert!(is_upstream_allowed(&addr, Some(&nets)).is_ok());
        }
    }
}
