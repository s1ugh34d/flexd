//! Configuration schema, parsing, and startup validation.
//!
//! This module is the typed mirror of the on-disk configuration file. The
//! format is nginx-shaped but strongly typed: every directive deserializes into
//! a field below, and [`Config::validate`](crate::config::Config::validate)
//! rejects unsafe or contradictory
//! combinations *before* a socket is bound, so misconfiguration fails at
//! `--test` time rather than at request time.
//!
//! The structs are `serde`-derived and accept both TOML (the documented format)
//! and JSON. Field defaults are supplied by the `default_*` helper functions so
//! a minimal config stays short while still validating. See `flexd.conf.example`
//! in the repository for the fully annotated directive surface.
//!
//! # Examples
//!
//! ```no_run
//! use flexd::config::Config;
//! use std::path::Path;
//!
//! // Parses the file (TOML or JSON) and runs full validation.
//! let config = Config::load(Path::new("flexd.conf"))?;
//! println!("{} http block(s) configured", config.http.len());
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Top-level configuration: the whole parsed config file.
///
/// Maps to the document root of `flexd.conf`. A `[global]` table and at least
/// one `[[http]]` block are expected; `[[stream]]` and `[mail]` are optional.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Process-wide settings (`[global]`): workers, logging, privilege drop.
    pub global: GlobalSettings,
    /// One or more virtual-server blocks (`[[http]]`), each with its own
    /// listeners, locations, TLS, and hardening policy.
    pub http: Vec<HttpBlock>,
    /// Raw TCP stream-proxy blocks (`[[stream]]`), optional.
    #[serde(default)]
    pub stream: Vec<StreamBlock>,
    /// Mail (SMTP/IMAP/POP3) proxy block (`[mail]`), optional.
    #[serde(default)]
    pub mail: Option<MailBlock>,
}

/// Process-wide settings from the `[global]` table.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GlobalSettings {
    /// Number of worker threads, or `"auto"` to match the CPU count.
    #[serde(default = "default_worker_processes")]
    pub worker_processes: WorkerProcesses,
    /// Path to the error log. Defaults to `./logs/error.log`.
    #[serde(default = "default_error_log")]
    pub error_log: String,
    /// Optional path to write the process PID to at startup.
    #[serde(default)]
    pub pid_file: Option<String>,
    /// User to drop privileges to after binding (e.g. low ports). When set and
    /// the process starts as root, [`crate::security::privilege::drop_privileges`]
    /// is invoked after listeners are bound. Ignored on non-Unix.
    #[serde(default)]
    pub user: Option<String>,
    /// Optional timeout overrides; see [`TimeoutSettings`].
    #[serde(default)]
    pub timeouts: Option<TimeoutSettings>,
}

/// `worker_processes` value: either the literal `"auto"` or an explicit count.
///
/// Deserialized untagged, so the TOML accepts both `worker_processes = "auto"`
/// and `worker_processes = 4`.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum WorkerProcesses {
    /// The string `"auto"` — size the runtime to the available CPU count.
    Auto(String),
    /// An explicit worker-thread count.
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


/// Per-connection timeout overrides (`[global.timeouts]`), all in seconds.
///
/// These bound how long a slow or idle peer can hold resources, which is part
/// of the slow-loris defense.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeoutSettings {
    /// Idle connection timeout. Default 75s.
    #[serde(default = "default_idle_timeout")]
    pub idle: u64,
    /// Maximum time to receive a complete request. Default 30s.
    #[serde(default = "default_request_timeout")]
    pub request: u64,
    /// Keep-alive timeout between requests on a connection. Default 75s.
    #[serde(default = "default_keepalive_timeout")]
    pub keepalive: u64,
    /// Maximum time to read a response from an upstream. Default 60s.
    #[serde(default = "default_proxy_read_timeout")]
    pub proxy_read: u64,
}

fn default_idle_timeout() -> u64 { 75 }
fn default_request_timeout() -> u64 { 30 }
fn default_keepalive_timeout() -> u64 { 75 }
fn default_proxy_read_timeout() -> u64 { 60 }

impl Default for TimeoutSettings {
    fn default() -> Self {
        Self {
            idle: default_idle_timeout(),
            request: default_request_timeout(),
            keepalive: default_keepalive_timeout(),
            proxy_read: default_proxy_read_timeout(),
        }
    }
}

/// One virtual-server block (`[[http]]`).
///
/// A block owns one or more [listeners](ListenDirective), an optional TLS
/// configuration, a list of [`Location`] routes, and the full set of hardening
/// knobs. Most security-relevant fields default to their safe setting (strict
/// host policy, ambiguous-framing rejection, control-char rejection all on), so
/// a minimal block is already hardened.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpBlock {
    /// Sockets this block listens on (`[[http.listen]]`).
    pub listen: Vec<ListenDirective>,
    /// Virtual-host names this block answers for. Used by the strict/list
    /// [`host_header_policy`](Self::host_header_policy) and to validate ACME
    /// domains. Supports `*.example.com` wildcards.
    #[serde(default)]
    pub server_name: Vec<String>,
    /// Document root for the static handler, when not set per-location.
    #[serde(default)]
    pub root: Option<String>,
    /// TLS settings (`[http.ssl]`). Absent for plaintext listeners.
    #[serde(default)]
    pub ssl: Option<SslSettings>,
    /// Advertise HTTP/2 (`h2`) via ALPN on TLS listeners. Default true.
    #[serde(default = "default_true")]
    pub http2: bool,
    /// Enable HTTP/3 (QUIC) on `protocol = "quic"` listeners. Default false.
    #[serde(default)]
    pub http3: bool,
    /// Route table (`[[http.locations]]`), matched in order.
    #[serde(default)]
    pub locations: Vec<Location>,
    /// Regex rewrite/redirect rules (`[[http.rewrites]]`), applied before routing.
    #[serde(default)]
    pub rewrites: Vec<RewriteRule>,
    /// Path to a MaxMind GeoIP database; enables `x-geoip-*` request headers.
    #[serde(default)]
    pub geoip_db: Option<String>,
    /// A/B split definitions (`[[http.ab_splits]]`) referenced by proxy locations.
    #[serde(default)]
    pub ab_splits: Vec<AbSplit>,
    /// Access-log path. Defaults to `./logs/access.log`.
    #[serde(default = "default_access_log")]
    pub access_log: String,
    /// Maximum size of an individual request header. Unset uses the server default.
    #[serde(default)]
    pub max_header_size: Option<usize>,
    /// Maximum request body size in bytes. Bodies beyond this are rejected.
    #[serde(default)]
    pub max_body_size: Option<usize>,
    /// Reject requests with ambiguous framing (both `Content-Length` and
    /// `Transfer-Encoding`, etc.) — request-smuggling defense. Default true.
    #[serde(default = "default_true")]
    pub reject_ambiguous_framing: bool,
    /// Apply the trusted-proxy attribution policy and strip hop-by-hop headers
    /// before proxying. Default true; set false to pass `X-Forwarded-*` through
    /// untouched (only safe behind a trusted front proxy).
    #[serde(default = "default_true")]
    pub normalize_headers_before_proxy: bool,
    /// Per-connection HTTP/2 reset-flood budget (Rapid Reset defense). Unset
    /// uses a generous built-in default.
    #[serde(default)]
    pub http2_max_reset_rate: Option<ResetRateLimit>,
    /// HTTP/3 QPACK dynamic table size cap, in bytes.
    #[serde(default)]
    pub http3_max_dynamic_table_size: Option<usize>,
    /// `Host` header policy: `"strict"` (must match `server_name`), `"list"`
    /// (match `allowed_hosts` or `server_name`), or `"any"`. Default `"strict"`.
    #[serde(default = "default_strict")]
    pub host_header_policy: String,
    /// Extra accepted hosts for the `"list"` policy.
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Reject requests whose headers contain control characters. Default true.
    #[serde(default = "default_true")]
    pub reject_headers_with_control_chars: bool,
    /// Permit the `CONNECT` method (forward-proxy tunneling). Default false;
    /// requires [`connect_upstream`](Self::connect_upstream).
    #[serde(default)]
    pub allow_connect: bool,
    /// Upstream pool used to validate/route permitted `CONNECT` targets.
    #[serde(default)]
    pub connect_upstream: Option<UpstreamRef>,
    /// Explicit `CONNECT` target allowlist (`"host:port"`, or bare `"host"` for
    /// any port). Without it, only `connect_upstream` server addresses match.
    #[serde(default)]
    pub connect_allowed_targets: Option<Vec<String>>,
    /// CIDRs whose clients are trusted to set `X-Forwarded-*`/`Forwarded`
    /// attribution headers. Requests from outside have those headers rewritten.
    #[serde(default)]
    pub trusted_proxies: Option<Vec<String>>,
    /// CIDRs that override SSRF filtering, allowing upstreams in otherwise
    /// restricted ranges (loopback, RFC1918, …) to be reached.
    #[serde(default)]
    pub upstream_allowed_networks: Option<Vec<String>>,
    /// Maximum number of request headers accepted.
    #[serde(default)]
    pub max_header_count: Option<usize>,
    /// Maximum allowed decompression expansion ratio (decompression-bomb guard).
    #[serde(default)]
    pub max_decompression_ratio: Option<usize>,
    /// Maximum decompressed body size in bytes (decompression-bomb guard).
    #[serde(default)]
    pub max_decompression_size: Option<usize>,
    /// Named upstream pools (`[[http.upstreams]]`) shared across locations.
    #[serde(default)]
    pub upstreams: Vec<UpstreamRef>,
    /// TTL (seconds) for vetted upstream DNS answers (Invariant 42). Default 30.
    #[serde(default)]
    pub dns_cache_ttl_seconds: Option<u64>,
    /// When set on a TLS block, responses carry
    /// `Strict-Transport-Security: max-age=<value>; includeSubDomains`.
    #[serde(default)]
    pub hsts_max_age: Option<u64>,
    /// Cap on a buffered upstream response body. Default 100 MiB.
    #[serde(default)]
    pub max_upstream_response_size: Option<usize>,
}

fn default_true() -> bool { true }
fn default_strict() -> String { "strict".to_string() }
fn default_access_log() -> String { "./logs/access.log".to_string() }

/// A single listener (`[[http.listen]]` / `[[stream]].listen`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListenDirective {
    /// TCP/UDP port to bind.
    pub port: u16,
    /// Transport: `"tcp"` (HTTP/1.1, HTTP/2) or `"quic"` (HTTP/3). Default `"tcp"`.
    #[serde(default = "default_tcp")]
    pub protocol: String,
    /// Bind address. Defaults to 0.0.0.0 (all interfaces); set e.g.
    /// "127.0.0.1" to keep a listener loopback-only.
    #[serde(default)]
    pub address: Option<String>,
}

fn default_tcp() -> String { "tcp".to_string() }

/// TLS configuration (`[http.ssl]`).
///
/// Provide either a static `certificate`/`certificate_key` pair or an
/// [`acme`](Self::acme) block for automatic issuance — not both for the same
/// domain. flexd uses rustls exclusively (no OpenSSL).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SslSettings {
    /// Path to the PEM certificate chain (static certs).
    #[serde(default)]
    pub certificate: Option<String>,
    /// Path to the PEM private key (PKCS#8 or RSA).
    #[serde(default)]
    pub certificate_key: Option<String>,
    /// ACME automatic-issuance settings (`[http.ssl.acme]`).
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// Enabled TLS versions; only `TLSv1.2` and `TLSv1.3` are permitted.
    /// Defaults to both.
    #[serde(default = "default_tls_protocols")]
    pub protocols: Vec<String>,
}

fn default_tls_protocols() -> Vec<String> {
    vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()]
}

/// ACME (RFC 8555) automatic-certificate settings (`[http.ssl.acme]`).
///
/// When `enabled`, flexd obtains and renews certificates from the configured CA
/// (Let's Encrypt by default). Validation enforces several invariants up front:
/// `email` and `agree_tos` are required, every `domains` entry must be covered
/// by `server_name`, staging must not point at the production CA, and secret
/// material (EAB key, webhook auth header) must be 0600 files.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcmeConfig {
    /// Turn ACME on for this block.
    #[serde(default)]
    pub enabled: bool,
    /// Account contact email (required when enabled).
    #[serde(default)]
    pub email: String,
    /// ACME directory URL. Defaults to Let's Encrypt production.
    #[serde(default = "default_acme_endpoint")]
    pub ca_endpoint: String,
    /// Use the staging environment. Must not be combined with the production
    /// `ca_endpoint` (Invariant 70).
    #[serde(default)]
    pub staging: bool,
    /// Domains to request. Defaults to `server_name` when empty.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Challenge types to attempt, in preference order. Defaults to
    /// `["http-01", "tls-alpn-01"]`; `dns-01` requires `dns_webhook`.
    #[serde(default = "default_challenge_types")]
    pub challenge_types: Vec<String>,
    /// Webhook used to publish `dns-01` TXT records.
    #[serde(default)]
    pub dns_webhook: Option<WebhookConfig>,
    /// External Account Binding credentials, if the CA requires them.
    #[serde(default)]
    pub eab: Option<EabConfig>,
    /// Renew this many days before expiry. Default 30.
    #[serde(default = "default_renewal_window")]
    pub renewal_window: u32,
    /// Port to serve `http-01` challenges on. Default 80; a port below 1024
    /// requires the process to be root (Invariant 72).
    #[serde(default)]
    pub http_challenge_port: Option<u16>,
    /// Must be `true` to accept the CA's terms of service (required when enabled).
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

/// `dns-01` webhook used to publish DNS TXT challenge records.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookConfig {
    /// Webhook endpoint URL.
    pub url: String,
    /// Request timeout in seconds. Default 30.
    #[serde(default = "default_webhook_timeout")]
    pub timeout: u64,
    /// Path to a 0600 file whose contents are sent as the auth header value
    /// (Invariant 73). The secret is never logged.
    #[serde(default)]
    pub auth_header: Option<String>,
}

fn default_webhook_timeout() -> u64 { 30 }

/// External Account Binding credentials (`[http.ssl.acme.eab]`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EabConfig {
    /// Key identifier issued by the CA.
    pub kid: String,
    /// Path to a 0600 file holding the base64url HMAC key (Invariant 77).
    pub hmac_key: String,
}

/// One route (`[[http.locations]]`): a pattern plus the handler that serves it.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Location {
    /// The URI pattern to match, interpreted per [`match_type`](Self::match_type).
    pub pattern: String,
    /// How `pattern` is matched: `"prefix"` (default), `"exact"`, or `"regex"`.
    #[serde(default = "default_prefix")]
    pub match_type: String,
    /// What to do with matching requests.
    pub handler: Handler,
}

fn default_prefix() -> String { "prefix".to_string() }

/// The action for a matched [`Location`] (`[http.locations.handler]`).
///
/// `handler_type` selects the behavior and determines which other fields are
/// meaningful: `"static"` uses `root`; `"proxy"`/`"reverse_proxy"` use
/// `upstream` or `ab_split`; `"redirect"` uses `target` and `status`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Handler {
    /// Handler kind: `"static"`, `"proxy"`/`"reverse_proxy"`, or `"redirect"`.
    #[serde(rename = "type")]
    pub handler_type: String,
    /// Document root for the `"static"` handler.
    #[serde(default)]
    pub root: Option<String>,
    /// Inline upstream pool for the `"proxy"` handler.
    #[serde(default)]
    pub upstream: Option<UpstreamRef>,
    /// Redirect target for the `"redirect"` handler.
    #[serde(default)]
    pub target: Option<String>,
    /// Status code for the `"redirect"` handler (e.g. 301, 302).
    #[serde(default)]
    pub status: Option<u16>,
    /// Route this proxy location through the named `[[http.ab_splits]]` entry
    /// instead of a fixed upstream.
    #[serde(default)]
    pub ab_split: Option<String>,
}

/// A regex rewrite/redirect rule (`[[http.rewrites]]`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RewriteRule {
    /// Regular expression matched against the request path.
    pub pattern: String,
    /// Replacement string; `$1`, `$2`, … reference capture groups.
    pub replacement: String,
    /// Rule flag: `"break"`/`"last"` rewrite internally; `"redirect"` (302) and
    /// `"permanent"` (301) emit HTTP redirects. Default `"break"`.
    #[serde(default = "default_break")]
    pub flag: String,
}

fn default_break() -> String { "break".to_string() }

/// A named upstream pool (`[[http.upstreams]]`) and its balancing strategy.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpstreamRef {
    /// Pool name, referenced by handlers and A/B groups.
    pub name: String,
    /// Member servers.
    #[serde(default)]
    pub servers: Vec<UpstreamServer>,
    /// Balancing strategy: `"round-robin"` (default), `"least-conn"`, or
    /// `"ip-hash"`. See [`crate::balance`].
    #[serde(default = "default_round_robin")]
    pub strategy: String,
}

fn default_round_robin() -> String { "round-robin".to_string() }

/// One member of an [`UpstreamRef`].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpstreamServer {
    /// `host:port` or `ip:port`. IP literals in restricted ranges are rejected
    /// unless allowlisted via `upstream_allowed_networks` (SSRF defense).
    pub address: String,
    /// Relative weight for weighted balancing. Must be >= 1; default 1.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 { 1 }

/// An A/B split definition (`[[http.ab_splits]]`).
///
/// Group weights must sum to 100 (checked by
/// [`Config::validate`](crate::config::Config::validate)).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AbSplit {
    /// Split name, referenced by a proxy handler's `ab_split` field.
    pub name: String,
    /// When true, a given session sticks to its first-assigned group.
    #[serde(default)]
    pub sticky: bool,
    /// Weighted target groups.
    pub groups: Vec<AbGroup>,
}

/// One arm of an [`AbSplit`].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AbGroup {
    /// Group name (for stickiness bookkeeping and logging).
    pub name: String,
    /// Name of the [`UpstreamRef`] this group routes to.
    pub upstream: String,
    /// Share of traffic; all groups in a split must sum to 100.
    pub weight: u32,
}

/// A raw TCP stream-proxy block (`[[stream]]`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StreamBlock {
    /// The socket to accept connections on.
    pub listen: ListenDirective,
    /// Backend pool to forward connections to.
    pub upstream: UpstreamRef,
    /// Optional TLS termination for the listener.
    #[serde(default)]
    pub ssl: Option<SslSettings>,
}

/// The mail-proxy block (`[mail]`) for SMTP/IMAP/POP3 front-ending.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MailBlock {
    /// Sockets to listen on.
    pub listen: Vec<ListenDirective>,
    /// Mail protocol: `"smtp"`, `"imap"`, or `"pop3"`.
    pub protocol: String,
    /// Backend mail server pool.
    pub upstream: UpstreamRef,
    /// Optional TLS termination.
    #[serde(default)]
    pub ssl: Option<SslSettings>,
    /// Require authentication before proxying.
    #[serde(default)]
    pub auth_required: bool,
    /// Maximum protocol line length, in bytes.
    #[serde(default)]
    pub max_line_length: Option<usize>,
}

/// HTTP/2 reset-flood budget (`http2_max_reset_rate`): `count` resets per
/// `window_seconds` before the connection is terminated (Rapid Reset defense).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResetRateLimit {
    /// Reset count that trips termination within the window.
    pub count: usize,
    /// Sliding-window length in seconds.
    pub window_seconds: u64,
}

impl Config {
    /// Read and validate a configuration file.
    ///
    /// The format is auto-detected: input beginning with `{` is parsed as JSON,
    /// otherwise as TOML. The parsed config is then run through
    /// [`validate`](Self::validate) before being returned, so a successful load
    /// is also a valid, safe-to-run configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, fails to parse, or fails
    /// validation. The error message names the offending file or directive.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use flexd::config::Config;
    /// use std::path::Path;
    ///
    /// let config = Config::load(Path::new("flexd.conf"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
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

    /// Check the configuration for unsafe or contradictory settings.
    ///
    /// This is the gate that lets `flexd --test` catch problems before the
    /// server runs. Among the things it enforces: A/B split weights sum to 100
    /// and reference defined upstreams; balancing strategies, location match
    /// types, and rewrite flags are known values; listen and CIDR strings parse;
    /// upstream IP literals are not in restricted ranges unless allowlisted; TLS
    /// versions are 1.2/1.3 only; and, when ACME is enabled, that its required
    /// fields, staging isolation, privileged-port, and 0600-secret-file
    /// invariants all hold.
    ///
    /// # Errors
    ///
    /// Returns the first violation found, with a message identifying the
    /// directive at fault. [`load`](Self::load) calls this automatically.
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
                // Every group must point at a defined upstream, otherwise the
                // split silently 502s at runtime.
                for group in &ab_split.groups {
                    if !http_block.upstreams.iter().any(|u| u.name == group.upstream) {
                        anyhow::bail!(
                            "A/B split '{}' group '{}' references unknown upstream '{}'",
                            ab_split.name,
                            group.name,
                            group.upstream
                        );
                    }
                }
            }

            // Validate listen directives
            for listen in &http_block.listen {
                if let Some(addr) = &listen.address {
                    addr.parse::<std::net::IpAddr>()
                        .with_context(|| format!("Invalid listen address: {}", addr))?;
                }
            }

            // Validate every upstream pool (shared, per-location, CONNECT)
            let check_upstream = |upstream: &UpstreamRef| -> Result<()> {
                match upstream.strategy.as_str() {
                    "round-robin" | "least-conn" | "ip-hash" => {}
                    other => anyhow::bail!(
                        "Upstream '{}' has unknown strategy '{}' (round-robin, least-conn, ip-hash)",
                        upstream.name,
                        other
                    ),
                }
                for server in &upstream.servers {
                    if server.weight == 0 {
                        anyhow::bail!(
                            "Upstream '{}' server '{}' has weight 0; weights must be >= 1",
                            upstream.name,
                            server.address
                        );
                    }
                }
                Ok(())
            };
            for upstream in &http_block.upstreams {
                check_upstream(upstream)?;
            }
            for location in &http_block.locations {
                if let Some(upstream) = &location.handler.upstream {
                    check_upstream(upstream)?;
                }
            }
            if let Some(upstream) = &http_block.connect_upstream {
                check_upstream(upstream)?;
            }

            // Validate locations
            for location in &http_block.locations {
                match location.match_type.as_str() {
                    "exact" | "prefix" => {}
                    "regex" => {
                        regex::Regex::new(&location.pattern).with_context(|| {
                            format!("Invalid location regex: {}", location.pattern)
                        })?;
                    }
                    other => anyhow::bail!("Unknown location match_type: {}", other),
                }

                let h = &location.handler;
                if matches!(h.handler_type.as_str(), "proxy" | "reverse_proxy") {
                    if let Some(split_name) = &h.ab_split {
                        if !http_block.ab_splits.iter().any(|s| &s.name == split_name) {
                            anyhow::bail!(
                                "Location '{}' references unknown ab_split '{}'",
                                location.pattern,
                                split_name
                            );
                        }
                    } else {
                        let has_inline =
                            h.upstream.as_ref().is_some_and(|u| !u.servers.is_empty());
                        let has_shared = http_block
                            .upstreams
                            .first()
                            .is_some_and(|u| !u.servers.is_empty());
                        if !has_inline && !has_shared {
                            anyhow::bail!(
                                "Proxy location '{}' has no upstream servers configured",
                                location.pattern
                            );
                        }
                    }
                }
            }

            // Validate rewrite rules
            for rule in &http_block.rewrites {
                regex::Regex::new(&rule.pattern)
                    .with_context(|| format!("Invalid rewrite pattern: {}", rule.pattern))?;
                match rule.flag.as_str() {
                    "break" | "last" | "redirect" | "permanent" => {}
                    other => anyhow::bail!(
                        "Rewrite '{}' has unknown flag '{}' (break, last, redirect, permanent)",
                        rule.pattern,
                        other
                    ),
                }
            }

            // Validate trusted_proxies CIDRs (Invariant 43)
            if let Some(proxies) = &http_block.trusted_proxies {
                for cidr in proxies {
                    cidr.parse::<ipnetwork::IpNetwork>()
                        .with_context(|| format!("Invalid CIDR in trusted_proxies: {}", cidr))?;
                }
            }

            // Validate CONNECT allowlist entries
            if let Some(targets) = &http_block.connect_allowed_targets {
                for target in targets {
                    if target.trim().is_empty() {
                        anyhow::bail!("connect_allowed_targets contains an empty entry");
                    }
                }
            }

            // Validate host_header_policy
            match http_block.host_header_policy.as_str() {
                "strict" | "any" | "list" => {}
                other => anyhow::bail!("Invalid host_header_policy: {}", other),
            }

            // Validate list policy requires allowed_hosts or server_name
            if http_block.host_header_policy == "list"
                && http_block.allowed_hosts.as_ref().is_none_or(|h| h.is_empty())
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
            if sb.upstream.servers.is_empty() {
                anyhow::bail!("stream[{}]: upstream '{}' has no servers", i, sb.upstream.name);
            }
            if let Some(addr) = &sb.listen.address {
                addr.parse::<std::net::IpAddr>()
                    .with_context(|| format!("stream[{}]: invalid listen address {}", i, addr))?;
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

/// Look up a shared upstream pool by name within an [`HttpBlock`].
///
/// Returns `None` if no `[[http.upstreams]]` entry has that name. Note this
/// searches only the block-level shared pools, not per-location inline
/// upstreams.
pub fn resolve_upstream<'a>(hb: &'a HttpBlock, name: &'a str) -> Option<&'a UpstreamRef> {
    hb.upstreams.iter().find(|u| u.name == name)
}
