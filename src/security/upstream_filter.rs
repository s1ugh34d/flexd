use std::net::IpAddr;

/// Validate upstream address against allowed networks (Invariant 41)
pub fn is_upstream_allowed(addr: &str, allowed_networks: Option<&[String]>) -> anyhow::Result<()> {
    let (host, _) = addr.rsplit_once(':').unwrap_or((addr, ""));

    if let Ok(ip) = host.parse::<IpAddr>() {
        let is_private = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast(),
        };
        if is_private {
            if let Some(networks) = allowed_networks {
                let allowed = networks.iter().any(|cidr| {
                    if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
                        net.contains(ip)
                    } else {
                        false
                    }
                });
                if !allowed {
                    anyhow::bail!(
                        "Upstream {} is in a restricted range and not in allowed networks",
                        addr
                    );
                }
            } else {
                anyhow::bail!(
                    "Upstream {} is in a private/loopback range and no upstream_allowed_networks is configured",
                    addr
                );
            }
        }
    }
    // Non-IP addresses (hostnames) are allowed
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
        // Non-IP authorities are not subject to the range check.
        assert!(is_upstream_allowed("backend.internal:8080", None).is_ok());
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
    }
}
