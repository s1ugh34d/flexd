use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub global: GlobalSettings,
    pub http: Vec<HttpBlock>,
    #[serde(default)]
    pub stream: Vec<StreamBlock>,
    #[serde(default)]
    pub mail: Option<MailBlock>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GlobalSettings {
    #[serde(default = "default_worker_processes")]
    pub worker_processes: WorkerProcesses,
    #[serde(default = "default_error_log")]
    pub error_log: String,
    #[serde(default)]
    pub pid_file: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub timeouts: Option<TimeoutSettings>,
    #[serde(default = "default_downgrade_policy")]
    pub http_downgrade_policy: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum WorkerProcesses {
    Auto(String),
    Count(usize),
}

impl Default for WorkerProcesses {
    fn default() -> Self {
        WorkerProcesses::Auto("auto".to_string())
    }
}

fn default_worker_processes() -> WorkerProcesses {
    WorkerProcesses::Auto("auto".to_string())
}

fn default_error_log() -> String {
    "./logs/error.log".to_string()
}

fn default_downgrade_policy() -> String {
    "validate".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeoutSettings {
    #[serde(default = "default_idle_timeout")]
    pub idle: u64,
    #[serde(default = "default_request_timeout")]
    pub request: u64,
    #[serde(default = "default_keepalive_timeout")]
    pub keepalive: u64,
    #[serde(default = "default_proxy_read_timeout")]
    pub proxy_read: u64,
}

fn default_idle_timeout() -> u64 { 75 }
fn default_request_timeout() -> u64 { 30 }
fn default_keepalive_timeout() -> u64 { 75 }
fn default_proxy_read_timeout() -> u64 { 60 }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpBlock {
    pub listen: Vec<ListenDirective>,
    #[serde(default)]
    pub server_name: Vec<String>,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub ssl: Option<SslSettings>,
    #[serde(default)]
    pub http2: bool,
    #[serde(default)]
    pub http3: bool,
    #[serde(default)]
    pub locations: Vec<Location>,
    #[serde(default)]
    pub rewrites: Vec<RewriteRule>,
    #[serde(default)]
    pub geoip_db: Option<String>,
    #[serde(default)]
    pub ab_splits: Vec<AbSplit>,
    #[serde(default = "default_access_log")]
    pub access_log: String,
    #[serde(default)]
    pub max_header_size: Option<usize>,
    #[serde(default)]
    pub max_body_size: Option<usize>,
    #[serde(default = "default_true")]
    pub reject_ambiguous_framing: bool,
    #[serde(default = "default_true")]
    pub normalize_headers_before_proxy: bool,
    #[serde(default)]
    pub http2_max_reset_rate: Option<ResetRateLimit>,
    #[serde(default)]
    pub http3_max_dynamic_table_size: Option<usize>,
    #[serde(default = "default_strict")]
    pub host_header_policy: String,
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub trusted_proxy_headers: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub reject_headers_with_control_chars: bool,
    #[serde(default)]
    pub allow_connect: bool,
    #[serde(default)]
    pub connect_upstream: Option<UpstreamRef>,
    #[serde(default)]
    pub connect_allowed_targets: Option<Vec<String>>,
    #[serde(default)]
    pub trusted_proxies: Option<Vec<String>>,
    #[serde(default)]
    pub minimum_read_rate: Option<usize>,
    #[serde(default)]
    pub upstream_allowed_networks: Option<Vec<String>>,
    #[serde(default)]
    pub max_header_count: Option<usize>,
    #[serde(default)]
    pub max_decompression_ratio: Option<usize>,
    #[serde(default)]
    pub max_decompression_size: Option<usize>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamRef>,
}

fn default_true() -> bool { true }
fn default_strict() -> String { "strict".to_string() }
fn default_access_log() -> String { "./logs/access.log".to_string() }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListenDirective {
    pub port: u16,
    #[serde(default = "default_tcp")]
    pub protocol: String,
    #[serde(default)]
    pub default: bool,
}

fn default_tcp() -> String { "tcp".to_string() }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SslSettings {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub certificate_key: Option<String>,
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    #[serde(default = "default_tls_protocols")]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub ciphers: Option<String>,
}

fn default_tls_protocols() -> Vec<String> {
    vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()]
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub email: String,
    #[serde(default = "default_acme_endpoint")]
    pub ca_endpoint: String,
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default = "default_challenge_types")]
    pub challenge_types: Vec<String>,
    #[serde(default)]
    pub dns_webhook: Option<WebhookConfig>,
    #[serde(default)]
    pub eab: Option<EabConfig>,
    #[serde(default = "default_renewal_window")]
    pub renewal_window: u32,
    #[serde(default)]
    pub http_challenge_port: Option<u16>,
    #[serde(default)]
    pub agree_tos: bool,
    /// Optional PEM file of an additional trusted root CA. Used so the daemon can
    /// talk to a testing/enterprise ACME PKI whose chain is not publicly trusted
    /// (mirrors `instant_acme::Account::builder_with_root`). Additive, off by
    /// default — production Let's Encrypt needs no override.
    #[serde(default)]
    pub ca_root: Option<String>,
    /// Directory where issued cert/key are persisted (mode 0600). Default: ./acme.
    #[serde(default = "default_acme_cert_dir")]
    pub cert_dir: String,
    /// How often (seconds) the background task checks the issued cert against
    /// `renewal_window`. Default 3600 (1h); lower values are useful in tests.
    #[serde(default)]
    pub renewal_check_interval_secs: Option<u64>,
}

fn default_acme_cert_dir() -> String { "./acme".to_string() }

fn default_acme_endpoint() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
fn default_challenge_types() -> Vec<String> {
    vec!["http-01".to_string(), "tls-alpn-01".to_string()]
}
fn default_renewal_window() -> u32 { 30 }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default = "default_webhook_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub auth_header: Option<String>,
}

fn default_webhook_timeout() -> u64 { 30 }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EabConfig {
    pub kid: String,
    pub hmac_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Location {
    pub pattern: String,
    #[serde(default = "default_prefix")]
    pub match_type: String,
    pub handler: Handler,
}

fn default_prefix() -> String { "prefix".to_string() }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Handler {
    #[serde(rename = "type")]
    pub handler_type: String,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub upstream: Option<UpstreamRef>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub status: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RewriteRule {
    pub pattern: String,
    pub replacement: String,
    #[serde(default = "default_break")]
    pub flag: String,
}

fn default_break() -> String { "break".to_string() }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpstreamRef {
    pub name: String,
    #[serde(default)]
    pub servers: Vec<UpstreamServer>,
    #[serde(default = "default_round_robin")]
    pub strategy: String,
}

fn default_round_robin() -> String { "round-robin".to_string() }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpstreamServer {
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 { 1 }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AbSplit {
    pub name: String,
    #[serde(default)]
    pub sticky: bool,
    pub groups: Vec<AbGroup>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AbGroup {
    pub name: String,
    pub upstream: String,
    pub weight: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StreamBlock {
    pub listen: ListenDirective,
    pub upstream: UpstreamRef,
    #[serde(default)]
    pub ssl: Option<SslSettings>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MailBlock {
    pub listen: Vec<ListenDirective>,
    pub protocol: String,
    pub upstream: UpstreamRef,
    #[serde(default)]
    pub ssl: Option<SslSettings>,
    #[serde(default)]
    pub auth_required: bool,
    #[serde(default)]
    pub max_line_length: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResetRateLimit {
    pub count: usize,
    pub window_seconds: u64,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let trimmed = content.trim();

        // Detect JSON format
        if trimmed.starts_with('{') {
            let config: Config = serde_json::from_str(trimmed)
                .with_context(|| "Failed to parse JSON config")?;
            config.validate()?;
            return Ok(config);
        }

        // Try TOML first
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config TOML")?;

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Validate A/B split weights sum to 100 (Invariant 4)
        for http_block in self.http.iter() {
            for ab_split in &http_block.ab_splits {
                let total_weight: u32 = ab_split.groups.iter().map(|g| g.weight).sum();
                if total_weight != 100 {
                    anyhow::bail!(
                        "A/B split '{}' weights sum to {}, must be 100",
                        ab_split.name,
                        total_weight
                    );
                }
            }

            // Validate host_header_policy
            match http_block.host_header_policy.as_str() {
                "strict" | "any" | "list" => {}
                other => anyhow::bail!("Invalid host_header_policy: {}", other),
            }

            // Validate list policy requires allowed_hosts or server_name
            if http_block.host_header_policy == "list"
                && http_block.allowed_hosts.as_ref().map_or(true, |h| h.is_empty())
                && http_block.server_name.is_empty()
            {
                anyhow::bail!("host_header_policy 'list' requires allowed_hosts or server_name");
            }

            // Validate upstream_allowed_networks CIDR
            if let Some(networks) = &http_block.upstream_allowed_networks {
                for net in networks {
                    net.parse::<ipnetwork::IpNetwork>()
                        .with_context(|| format!("Invalid CIDR in upstream_allowed_networks: {}", net))?;
                }
            }

            // Validate upstream addresses against allowed networks
            for upstream in &http_block.upstreams {
                for server in &upstream.servers {
                    Self::validate_upstream_address(&server.address, &http_block.upstream_allowed_networks)
                        .with_context(|| format!("Upstream '{}' server '{}'", upstream.name, server.address))?;
                }
            }

            // Validate SSL protocols
            if let Some(ssl) = &http_block.ssl {
                for proto in &ssl.protocols {
                    let p = proto.to_uppercase();
                    match p.as_str() {
                        "TLSV1.2" | "TLSV1.3" => {}
                        "SSLV3" | "TLSV1.0" | "TLSV1.1" => {
                            anyhow::bail!("Prohibited TLS protocol: {} (minimum TLSv1.2)", proto);
                        }
                        _ => anyhow::bail!("Unsupported SSL protocol: {}", proto),
                    }
                }

                // Validate ACME config
                if let Some(acme) = &ssl.acme {
                    if acme.enabled {
                        if acme.email.is_empty() {
                            anyhow::bail!("ACME enabled but email is empty");
                        }
                        if !acme.agree_tos {
                            anyhow::bail!("ACME enabled but agree_tos is false");
                        }
                        // Validate domains match server_name (C55)
                        for domain in &acme.domains {
                            if !http_block.server_name.iter().any(|s| s == domain || Self::matches_wildcard(s, domain)) {
                                anyhow::bail!("ACME domain '{}' not in server_name list", domain);
                            }
                        }
                        // Invariant 70 — staging isolation: staging must never point at
                        // the production Let's Encrypt CA.
                        if acme.staging
                            && acme.ca_endpoint.contains("acme-v02.api.letsencrypt.org")
                            && !acme.ca_endpoint.contains("staging")
                        {
                            anyhow::bail!(
                                "ACME staging=true but production CA endpoint specified (Invariant 70)"
                            );
                        }

                        // Invariant 72 — challenge port binding: a privileged HTTP-01
                        // port (<1024) requires root, else startup must fail.
                        let challenge_port = acme.http_challenge_port.unwrap_or(80);
                        if challenge_port < 1024 && !Self::is_effective_root() {
                            anyhow::bail!(
                                "ACME http_challenge_port {} is privileged (<1024) but the daemon \
                                 is not running as root (Invariant 72)",
                                challenge_port
                            );
                        }

                        // Invariant 73 — DNS webhook auth header must be file-backed,
                        // 0600 or stricter.
                        if let Some(webhook) = &acme.dns_webhook {
                            if let Some(auth_path) = &webhook.auth_header {
                                Self::check_secret_file(auth_path, "dns_webhook.auth_header")?;
                            }
                        }

                        // Invariant 77 — EAB hmac_key must be file-backed, 0600 or stricter.
                        if let Some(eab) = &acme.eab {
                            if eab.kid.is_empty() {
                                anyhow::bail!("ACME eab.kid is empty");
                            }
                            Self::check_secret_file(&eab.hmac_key, "eab.hmac_key")?;
                        }

                        // If a custom CA root is configured, it must exist.
                        if let Some(ca_root) = &acme.ca_root {
                            if !Path::new(ca_root).exists() {
                                anyhow::bail!("ACME ca_root file not found: {}", ca_root);
                            }
                        }

                        // dns-01 requires a configured webhook (contract §4 note).
                        if acme.challenge_types.iter().any(|c| c == "dns-01")
                            && acme.dns_webhook.is_none()
                        {
                            anyhow::bail!(
                                "ACME challenge_types includes 'dns-01' but no dns_webhook configured"
                            );
                        }
                    }
                }

                // Validate cert files exist if specified
                if let Some(cert) = &ssl.certificate {
                    if !Path::new(&cert).exists() {
                        anyhow::bail!("TLS certificate file not found: {}", cert);
                    }
                }
                if let Some(key) = &ssl.certificate_key {
                    if !Path::new(&key).exists() {
                        anyhow::bail!("TLS certificate key file not found: {}", key);
                    }
                }
            }

            // Validate CONNECT config
            if http_block.allow_connect && http_block.connect_upstream.is_none() {
                anyhow::bail!("allow_connect=true but no connect_upstream specified");
            }
        }

        // Validate stream blocks
        for (i, sb) in self.stream.iter().enumerate() {
            if sb.listen.port < 1 {
                anyhow::bail!("stream[{}]: listen port {} out of range", i, sb.listen.port);
            }
            if sb.upstream.name.is_empty() {
                anyhow::bail!("stream[{}]: upstream name is empty", i);
            }
        }

        // Validate mail blocks
        if let Some(mail) = &self.mail {
            for ld in &mail.listen {
                if ld.port < 1 {
                    anyhow::bail!("mail: listen port {} out of range", ld.port);
                }
            }
            if mail.upstream.name.is_empty() {
                anyhow::bail!("mail: upstream name is empty");
            }
        }

        Ok(())
    }

    fn validate_upstream_address(addr: &str, allowed_networks: &Option<Vec<String>>) -> Result<()> {
        let (host, _) = addr.rsplit_once(':').unwrap_or((addr, ""));
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let is_private = match ip {
                std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast(),
                std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast(),
            };
            if is_private {
                if let Some(networks) = &allowed_networks {
                    let allowed = networks.iter().any(|cidr| {
                        if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
                            net.contains(ip)
                        } else {
                            false
                        }
                    });
                    if !allowed {
                        anyhow::bail!(
                            "Address {} is private/loopback and not in allowed networks",
                            addr
                        );
                    }
                } else {
                    anyhow::bail!(
                        "Address {} is in a private/loopback range and no upstream_allowed_networks is configured",
                        addr
                    );
                }
            }
        }
        Ok(())
    }

    fn matches_wildcard(pattern: &str, domain: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..];
            domain.ends_with(suffix) || domain == &pattern[2..]
        } else {
            pattern == domain
        }
    }

    /// True if the process's effective UID is root. Behind a helper so the
    /// challenge-port check (Invariant 72) reads cleanly and is overridable in
    /// tests via the unix `Uid` API.
    fn is_effective_root() -> bool {
        #[cfg(unix)]
        {
            nix::unistd::Uid::effective().is_root()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Invariants 73 & 77 — a file holding secret material (DNS webhook auth
    /// header value, EAB HMAC key) must exist and be readable only by its owner:
    /// no group/other permission bits (`mode & 0o077 == 0`, i.e. 0600/0400).
    /// The secret value itself is never read here and never logged.
    fn check_secret_file(path: &str, what: &str) -> Result<()> {
        let meta = fs::metadata(path)
            .with_context(|| format!("{} secret file not found: {}", what, path))?;
        if !meta.is_file() {
            anyhow::bail!("{} path {} is not a regular file", what, path);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let perms = meta.mode() & 0o777;
            if perms & 0o077 != 0 {
                anyhow::bail!(
                    "{} file {} has insecure permissions {:#o}; must be 0600 or stricter \
                     (no group/other access)",
                    what,
                    path,
                    perms
                );
            }
        }
        Ok(())
    }
}

pub fn resolve_upstream<'a>(hb: &'a HttpBlock, name: &'a str) -> Option<&'a UpstreamRef> {
    hb.upstreams.iter().find(|u| u.name == name)
}
