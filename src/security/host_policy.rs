use crate::config::HttpBlock;

/// Validate Host header per Invariant 22
pub fn validate_host(host: &str, block: &HttpBlock) -> bool {
    if host.is_empty() {
        return false;
    }

    let host_only = host.split(':').next().unwrap_or(host).to_lowercase();

    match block.host_header_policy.as_str() {
        "any" => true,
        "list" => {
            let allowed = block.allowed_hosts.as_ref().unwrap_or(&block.server_name);
            allowed.iter().any(|name| matches_name(&host_only, name))
        }
        _ => {
            // "strict" - match server_name
            block.server_name.iter().any(|name| matches_name(&host_only, name))
        }
    }
}

fn matches_name(host: &str, pattern: &str) -> bool {
    let pattern = pattern.to_lowercase();
    if host == pattern {
        return true;
    }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..];
        if host.ends_with(suffix) || host == &pattern[2..] {
            return true;
        }
    }
    false
}
