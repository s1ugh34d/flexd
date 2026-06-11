---
osc: osc://flexible-webserver/local/0.2.3
version: 0.12.0
license: OSC-Open
sha256: 4e01e97c411678dd62d975e4524b922c13950deedaf2a85375993ad530adfce1
---

## § 1 — Intent

### § 1.1 — Purpose

A server operator needs a single daemon that can handle diverse traffic workloads — web requests, mail relay, raw TCP streams, and UDP — without deploying multiple tools. They want modern protocol support (HTTP/2, HTTP/3/QUIC), TLS termination, intelligent request routing, URL rewriting, client geolocation, and traffic splitting for A/B testing experiments, all configurable via a single declarative file. Automatic certificate management via ACME (Let's Encrypt and compatible CAs) eliminates manual certificate rotation.

This software is for developers, system administrators, and platform engineers who need a programmable, high-performance reverse proxy and server that does not require a cloud provider or proprietary runtime.

### § 1.2 — Expected Outcome

A daemon the operator starts with:

    flexd --config ./flexd.conf

The server reads its configuration, binds its listeners, and begins serving traffic. A `--test` flag validates configuration without starting the server. Running `flexd --help` prints usage and exits 0.

---

## § 2 — Behavior Contract

### Inputs

- **Configuration file:** a declarative text file specifying listeners, virtual hosts, upstreams, TLS certificates, routing rules, rewrite rules, geolocation database path, A/B split definitions, and ACME certificate management settings
- **HTTP/1.1 and HTTP/2 requests** on configured TCP ports (default 80, 443)
- **HTTP/3 requests** over QUIC on configured UDP ports (default 443)
- **SMTP/IMAP/POP3 connections** on configured mail ports when a mail block is present in the configuration
- **Raw TCP and UDP streams** on any port defined as a stream listener
- **TLS handshakes** using PEM-encoded certificate and key files specified in the configuration, or ACME-issued certificates when `acme.enabled: true`
- **ACME challenge requests:** HTTP-01 on port 80, TLS-ALPN-01 on configured TLS listeners, DNS-01 via optional webhook endpoint
- **Reload signal (SIGHUP):** reload configuration without dropping in-flight connections; triggers ACME renewal check
- **Graceful shutdown signal (SIGTERM):** drain in-flight connections before exit

### Outputs

- **HTTP responses** conforming to the upstream or static file handler for each matched virtual host and location
- **Proxied TCP/UDP streams** forwarded to upstream addresses defined in stream blocks
- **Mail relay** forwarding messages to configured backend mail servers
- **Access log:** one line per request, configurable format, written to a path defined in configuration (default: `./logs/access.log`)
- **Error log:** warnings and errors, configurable level, written to a path defined in configuration (default: `./logs/error.log`)
- **`--test` output:** "configuration OK" and exit 0 on valid config; descriptive error and exit non-zero on invalid config
- **Rewritten URLs:** requests matching a rewrite rule are redirected or proxied to the rewritten path/host
- **Geolocation header injection:** requests are annotated with `X-GeoIP-Country` and `X-GeoIP-Region` when a GeoIP database is configured
- **A/B split routing:** requests are distributed to upstream groups according to configured percentage weights, with consistent routing per session cookie when sticky mode is enabled
- **ACME certificate lifecycle events:** automatic issuance on startup, background renewal when certificates have fewer than `renewal_window` days validity, challenge responses served on configured ports, ACME errors logged with structured fields (`acme_error`, `domain`, `challenge_type`)

### Invariants

1. **No request may be silently dropped.** Every connection attempt must result in either a response, a proxied connection, or a logged error. Silent discard is not permitted.
2. **TLS certificate files are never transmitted over the network.** Key material remains on disk; the server reads it at startup and on reload only.
3. **Rewrite rules are applied before upstream selection.** A request that matches a rewrite rule must be routed to the rewritten target, not the original.
4. **A/B split weights must sum to 100.** A configuration with split weights that do not sum to 100 is invalid and must be rejected at startup or reload.
5. **SIGHUP reload must not drop established connections.** In-flight requests at the time of reload must complete against the old configuration; new requests use the new configuration.
6. **No network requests are made to external services during startup, reload, or normal operation** except those that are direct results of proxying client traffic, or ACME endpoint/DNS webhook requests when `acme.enabled: true` (see invariant 67).
7. **Geolocation lookups are local-only.** The GeoIP database is read from disk. No external IP lookup service may be consulted.
8. **`copy` mode for file serving.** Static file responses must not modify source files on disk.

9. **Privilege drop after port binding.** If the server starts as root, it binds privileged ports (<1024), then drops root privileges to a non-root user specified in `global.user` (default: `nobody`). Post-binding operations must not execute as root.

10. **Path traversal prevention.** Static file handlers must resolve the requested path against the configured document root. A request where the resolved path escapes the root directory must return 403 Forbidden. Paths containing `..` components that traverse outside root must be rejected regardless of encoding.

11. **Maximum header and URI size enforcement.** The server must enforce configurable maximum sizes for HTTP request headers and URIs (default: 8 KB headers, 4 KB URI). Requests exceeding these limits must be rejected with 431 (Request Header Fields Too Large) or 414 (URI Too Long) respectively.

12. **Minimum TLS protocol version.** The server must reject TLS connections using SSLv3, TLSv1.0, or TLSv1.1 by default. The `ssl.protocols` configuration may further restrict but must not enable protocols below TLSv1.2.

13. **Idle connection timeout.** The server must close connections idle beyond the configured timeout (default: 75 seconds). This applies to HTTP keepalive, TCP streams, and mail protocol connections.

14. **Directory listing disabled.** A request to a directory path without a matching index file must return 403 Forbidden or 404 Not Found. The server must never generate or expose an automatic directory listing.

15. **HTTP/2 concurrent stream limit.** The server must enforce a maximum of 128 concurrent streams per HTTP/2 connection. A client exceeding this limit must have excess streams reset with HTTP/2 `REFUSED_STREAM` error code.

16. **Request body size limit.** The server must reject requests with a body exceeding the configured `max_body_size` (default: 1 MB) with 413 Payload Too Large.

17. **HTTP/1.x framing ambiguity rejection.** Requests containing both `Content-Length` and `Transfer-Encoding` headers, or multiple `Content-Length` headers, must be rejected with 400 Bad Request.

18. **Upgrade header validation.** When an `Upgrade` header is present, the server must not forward subsequent bytes on the connection until receiving a 101 Switching Protocols response from upstream. If upstream returns any other status, subsequent bytes must be parsed as HTTP, not forwarded raw.

19. **HTTP/1.0 + Transfer-Encoding rejection.** Requests using HTTP/1.0 that contain a `Transfer-Encoding` header must be rejected with 400 Bad Request, per RFC 9112.

20. **HTTP/2 stream reset rate limiting.** The server must track RST_STREAM frames per connection. If a client exceeds the configured reset rate, the connection must be terminated.

21. **QPACK dynamic table limits for HTTP/3.** HTTP/3 connections must enforce a maximum dynamic table size (default: 64 KB) and reject SETTINGS frames requesting larger tables.

22. **Host header validation.** The `Host` header must match a configured `server_name` or the request must be rejected with 400 Bad Request. Wildcard matching is permitted only when explicitly configured.

23. **Header normalization before proxying.** Before forwarding requests to upstreams, the server must remove or sanitize `X-Forwarded-*`, `Forwarded`, and `X-Real-IP` headers unless explicitly trusted. Headers containing CR/LF characters must be rejected. Header names must be normalized to lowercase.

24. **CONNECT method handling.** The `CONNECT` method must be rejected by default (405 Method Not Allowed) unless explicitly enabled in configuration with an explicit upstream target.

25. **Strict URI parsing.** URIs containing encoded traversal sequences (`%2e%2e%2f`, `%252e%252e%252f`), null bytes (`%00`), or vertical tabs (`%0b`) must be rejected with 400 Bad Request before path resolution.

26. **HTTP parser canonicalization.** Requests must be parsed by a single canonical framing algorithm before routing or proxying. Any ambiguity in whitespace, duplicate hop-by-hop headers, line termination, transfer coding syntax, or header normalization must result in 400 Bad Request and connection close.

27. **Strict line ending enforcement.** Requests containing bare CR or bare LF characters outside protocol-permitted line endings are invalid and must be rejected with 400 Bad Request.

28. **Transfer-Encoding validation.** If `Transfer-Encoding` is present, its final coding must be exactly `chunked`. Multiple transfer codings, duplicate TE headers, obfuscated tokens (`Transfer-Encoding:\tchunked`, `Transfer-Encoding : chunked`), or unsupported codings must be rejected with 400 Bad Request.

29. **HTTP/2 downgrade normalization.** Requests translated from HTTP/2 or HTTP/3 to HTTP/1.1 upstreams must emit exactly one valid `Content-Length` or `Transfer-Encoding` header, never both.

30. **Maximum HTTP/2 header block fragments.** An HTTP/2 header block exceeding 16 CONTINUATION frames without END_HEADERS must terminate the connection with ENHANCE_YOUR_CALM.

31. **HPACK memory bound.** HPACK decoder memory usage must remain bounded independent of peer-controlled compression state. Total HPACK table size must not exceed the configured limit (default: 4 KB).

32. **SETTINGS flood protection.** Excessive SETTINGS frames (more than 5 within any 10-second window) per HTTP/2 connection must terminate the connection.

33. **PRIORITY frame rate limiting.** HTTP/2 PRIORITY frame floods must be rate-limited (more than 100 per second terminates the connection) or ignored entirely.

34. **QUIC anti-amplification.** Before address validation, the server must not transmit more than 3 times the bytes received from an unvalidated client address.

35. **0-RTT replay safety.** Non-idempotent requests received over 0-RTT must be rejected unless explicitly enabled via configuration.

36. **Maximum concurrent QUIC streams.** Bidirectional and unidirectional stream counts must be bounded per QUIC connection (default: 100 each).

37. **Connection ID exhaustion protection.** Excessive NEW_CONNECTION_ID frames from a QUIC client must terminate the connection.

38. **Regex safety.** Regex evaluation used for routing or rewriting must execute in bounded time. Backtracking-based regex engines (e.g., PCRE without sandboxing) are prohibited for untrusted request input. Go's RE2 or Rust's `regex` crate are required.

39. **Static file canonicalization.** Static files must be opened using the canonical resolved filesystem path after symlink resolution. On Linux, `openat2` with `RESOLVE_BENEATH` or equivalent must be used.

40. **Symlink escape prevention.** If symlink resolution during static file serving escapes the configured document root, access must be denied with 403 Forbidden.

41. **Upstream address restrictions.** Upstream targets resolving to loopback, link-local, multicast, or private address ranges must be rejected unless explicitly permitted via `upstream_allowed_networks`.

42. **DNS resolution pinning.** Upstream DNS results must be cached for the configured TTL and reused consistently during active connections. DNS rebinding during a connection's lifetime must not redirect traffic to a different address.

43. **Trusted proxy boundary.** Client IP attribution headers (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`) may only be honored when the connecting client address matches a CIDR range listed in `trusted_proxies`. Otherwise, these headers must be stripped.

44. **Hop-by-hop header stripping.** Hop-by-hop headers defined by RFC 9110 (Connection, Keep-Alive, Transfer-Encoding, TE, Trailer, Upgrade, Proxy-Authorization, Proxy-Authenticate) must never be forwarded to upstreams.

45. **TLS compression prohibition.** TLS-level compression must remain disabled. Requests negotiating TLS compression must have the connection terminated.

46. **Dynamic compression policy.** Responses containing authentication secrets, cookies, or CSRF tokens must not be dynamically compressed (gzip, brotli) unless explicitly enabled in the handler configuration.

47. **Atomic configuration swap.** Reloaded configuration must be fully validated and initialized before replacing active runtime state. A partially loaded configuration must never serve traffic.

48. **Listener inheritance safety.** During reload, existing listeners must remain active until replacement listeners successfully bind. A reload that fails to bind new listeners must leave the existing listeners running.

49. **Minimum read progress.** Clients failing to transmit request headers or bodies at a minimum configured rate (default: 1 byte per 30 seconds) must have their connections terminated.

50. **Authority consistency.** The effective request authority derived from HTTP/2 `:authority`, HTTP/1.1 `Host`, SNI, and absolute-form request targets must resolve to the same origin. Conflicts must result in 400 Bad Request.

51. **Log injection prevention.** Logged request fields (URI, headers, user-agent) must have control characters stripped or escaped before serialization to log output.

52. **Sensitive header redaction.** `Authorization`, `Cookie`, `Proxy-Authorization`, `Set-Cookie`, and TLS private key material must never be written to logs unless explicitly enabled via configuration.

53. **TLS renegotiation disabled.** TLS renegotiation must remain disabled. Connections attempting renegotiation must be terminated.

54. **Forward secrecy requirement.** Cipher suites without forward secrecy (e.g., static RSA key exchange) must not be enabled.

55. **Session ticket rotation.** TLS session ticket keys must rotate periodically (minimum once per hour) without requiring process restart.

56. **CONNECT destination validation.** When CONNECT tunneling is enabled, destination targets must match the configured `connect_allowed_targets` list and must not resolve to loopback, link-local, multicast, or private networks unless explicitly permitted.

57. **Mail protocol line limits.** SMTP/IMAP/POP3 command lines exceeding the configured `max_line_length` (default: 4096 bytes) must terminate the session.

58. **STARTTLS downgrade protection.** Once STARTTLS is negotiated on a mail connection, plaintext commands must not be accepted. A client sending plaintext after STARTTLS must have the connection terminated.

59. **Upstream response framing validation.** Responses received from upstreams containing ambiguous or invalid framing (multiple Content-Length headers, conflicting Transfer-Encoding, invalid chunk encoding, malformed status line, or prohibited hop-by-hop headers) must be rejected and converted into 502 Bad Gateway for the downstream client.

60. **Maximum header count.** Requests exceeding the configured maximum header count (default: 100) must be rejected with 431 Request Header Fields Too Large.

61. **Compressed request expansion limits.** Decompressed request bodies must not exceed the configured expansion ratio (default: 10x) or absolute decompressed size limit (default: 10 MB), whichever is tighter. Requests exceeding these limits must be rejected with 413 Payload Too Large.

62. **UTF-8 normalization enforcement.** URIs and header values interpreted as UTF-8 must be valid normalized UTF-8. Overlong encodings and invalid surrogate halves must be rejected with 400 Bad Request.

63. **Path separator normalization.** Alternative path separators (backslash on Unix, Unicode slash variants such as U+2044 or U+2215) must not bypass traversal protections. Any path separator outside the platform standard (``/`` on Unix) must be rejected or normalized to a standard separator before traversal checks.

64. **Bounded request queues.** Internal request, stream, and connection processing queues must have fixed upper bounds. Queue exhaustion must fail closed with overload responses (503 Service Unavailable) rather than permitting unbounded memory growth.

65. **Crash containment.** A parser or connection handler failure within a worker must not terminate the entire daemon. Faults must be isolated to the affected worker, connection, or request context.

66. **Memory exhaustion handling.** Under memory pressure, the server must reject new work before entering unrecoverable allocation failure states. When system memory falls below a configured threshold, new connections must be refused with 503 Service Unavailable until pressure subsides.

67. **ACME network exception.** When `acme.enabled: true`, outbound HTTPS requests to `ca_endpoint` and `dns_webhook.url` are permitted. All other outbound network requests remain prohibited per invariant #6. This is the sole exception to the no-external-network rule.

68. **Certificate-key binding.** ACME-issued certificates must be stored with file permissions `0600`. Private key material must never be written to logs, access logs, or error responses.

69. **Domain ownership validation.** A certificate is only installed if ACME validation succeeds for all requested domains. Partial validation failures must abort installation and log the failure.

70. **Staging isolation.** If `acme.staging: true`, the daemon must never request certificates from the production Let's Encrypt CA. Mixing staging and production endpoints in the same config is invalid and must be rejected by `flexd --test`.

71. **Rate limit awareness.** The daemon must respect `Retry-After` headers from the ACME CA and implement exponential backoff for repeated failures. Aggressive retry loops are prohibited.

72. **Challenge port binding.** If `http_challenge_port` is configured to a privileged port (<1024) and the daemon is not running as root, startup must fail with a descriptive error.

73. **DNS webhook authentication.** If `dns_webhook.auth_header` is configured, the webhook request must include the header with a value read from a file path (not inline in config). The file path must have permissions `0600` or stricter.

74. **Certificate transparency.** ACME-issued certificates must not disable Certificate Transparency (CT) logging. The `--ct-log-disable` flag or equivalent must not be set.

75. **Revocation handling.** If a certificate is revoked via OCSP or CRL, the daemon must log a warning and continue serving until renewal succeeds. Forced immediate revocation requires manual intervention.

76. **No fallback to self-signed.** If ACME issuance fails and no static `certificate`/`certificate_key` is provided, the listener must not start. Silent fallback to self-signed certificates is prohibited.

77. **EAB key protection.** The `eab.hmac_key` must be read from a file path (not inline). The file must have permissions `0600` or stricter and must never appear in logs or error messages.

---

## § 3 — Stack Negotiation

**Preferred:** Go (BSD 3-clause / MIT ecosystem) — native HTTP/2 via `net/http`, QUIC/HTTP/3 via `quic-go` (MIT), ACME via `lego` (MIT) or `certmagic` (MIT/Apache 2.0), with a pure-Go SMTP proxy layer. Produces a single statically-linked binary with no runtime dependencies.

**Acceptable:**
- Rust (MIT/Apache 2.0) with `hyper`, `tokio`, `quinn` for HTTP/3, and `acme2-rs` for ACME
- C with libevent or libuv (BSD), producing a compiled binary — acceptable if the agent determines a lower-level stack is better suited to the target device

**Prohibited:**
- Any dependency without an OSI-approved open source license
- Any cloud SDK or managed-service client
- Any dependency requiring an API key or account to use
- Electron or browser-based runtimes
- Any stack that makes outbound network requests during the build

**OSI-approved dependencies the agent may use:**
- Any SMTP proxy library with a compatible license
- ODoh, OpenNIC, OpenDNS third party DNS alts compatability
- ACME client libraries (lego, certmagic, acme2-rs) with MIT/Apache 2.0/BSD licenses

---

## § 4 — Data Shape

```
Config {
  global:    GlobalSettings
  http:      HttpBlock[]
  stream:    StreamBlock[]
  mail:      MailBlock | null
}

GlobalSettings {
  worker_processes:      integer | "auto"
  error_log:             path
  pid_file:              path | null
  user:                  string | null
  timeouts:              TimeoutSettings | null
  http_downgrade_policy: "reject" | "validate" | "allow"  -- default: "validate"
}

TimeoutSettings {
  idle:              integer  -- seconds, idle connection timeout (default 75)
  request:           integer  -- seconds, max request processing time
  keepalive:         integer  -- seconds, keepalive timeout
  proxy_read:        integer  -- seconds, upstream read timeout
}

ResetRateLimit {
  count:            integer  -- max resets per window
  window_seconds:   integer  -- window duration in seconds
}

HttpBlock {
  listen:                        ListenDirective[]
  server_name:                   string[]
  root:                          path | null
  ssl:                           SslSettings | null
  http2:                         boolean
  http3:                         boolean
  locations:                     Location[]
  rewrites:                      RewriteRule[]
  geoip_db:                      path | null
  ab_splits:                     AbSplit[]
  access_log:                    path
  max_header_size:               integer | null   -- bytes, default 8192
  max_body_size:                 integer | null   -- bytes, default 1048576
  reject_ambiguous_framing:      boolean          -- default: true, rejects CL+TE or multiple CL
  normalize_headers_before_proxy: boolean          -- default: true
  http2_max_reset_rate:          ResetRateLimit | null  -- default: {count: 10, window_seconds: 5}
  http3_max_dynamic_table_size:  integer | null   -- bytes, default 65536
  host_header_policy:            "strict" | "any" | "list"  -- default: "strict"
  allowed_hosts:                 string[] | null  -- required if policy="list"
  trusted_proxy_headers:         string[] | null
  reject_headers_with_control_chars: boolean       -- default: true
  allow_connect:                 boolean           -- default: false
  connect_upstream:              UpstreamRef | null  -- required if allow_connect=true
  connect_allowed_targets:       string[] | null     -- host:port patterns for CONNECT
  trusted_proxies:               string[] | null     -- CIDR ranges for trusted proxy headers
  minimum_read_rate:             integer | null      -- bytes/sec, minimum client read progress
  upstream_allowed_networks:     string[] | null     -- CIDR ranges, default ["0.0.0.0/0"]
  max_header_count:              integer | null      -- default 100
  max_decompression_ratio:       integer | null      -- default 10 (10:1 max expansion)
  max_decompression_size:        integer | null      -- bytes, default 10485760 (10 MB)
}

ListenDirective {
  port:      integer
  protocol:  "tcp" | "udp" | "quic"
  default:   boolean
}

SslSettings {
  certificate:      path | null    -- PEM cert file (optional if acme.enabled)
  certificate_key:  path | null    -- PEM key file (optional if acme.enabled)
  acme:             AcmeConfig | null
  protocols:        string[]       -- e.g. ["TLSv1.2", "TLSv1.3"]
  ciphers:          string | null
}

AcmeConfig {
  enabled:             boolean          -- default: false
  email:               string           -- ACME account contact (required if enabled)
  ca_endpoint:         string           -- default: "https://acme-v02.api.letsencrypt.org/directory"
  staging:             boolean          -- default: false; use Let's Encrypt staging CA
  domains:             string[]         -- SANs to request; must match server_name or be rejected
  challenge_types:     string[]         -- default: ["http-01", "tls-alpn-01"]; "dns-01" requires webhook
  dns_webhook:         WebhookConfig | null  -- required if "dns-01" in challenge_types
  eab:                 EabConfig | null      -- External Account Binding for enterprise CAs
  renewal_window:      integer          -- days before expiry to attempt renewal; default: 30
  http_challenge_port: integer | null   -- override port 80 for HTTP-01; default: 80
  agree_tos:           boolean          -- must be true; config invalid if false
}

WebhookConfig {
  url:          string  -- HTTPS endpoint for DNS-01 challenge hooks
  timeout:      integer -- seconds; default: 30
  auth_header:  string | null  -- optional Bearer token header name
}

EabConfig {
  kid:      string  -- Key ID from CA
  hmac_key: string  -- Base64-encoded HMAC key; never logged
}

Location {
  pattern:     string         -- path prefix or regex
  match_type:  "prefix" | "exact" | "regex"
  handler:     Handler
}

Handler {
  type:       "static" | "proxy" | "redirect" | "return"
  root:       path | null          -- static
  upstream:   UpstreamRef | null   -- proxy
  target:     string | null        -- redirect / return
  status:     integer | null       -- return
}

RewriteRule {
  pattern:      string   -- regex applied to request URI
  replacement:  string   -- replacement URI, may include capture groups
  flag:         "last" | "break" | "redirect" | "permanent"
}

UpstreamRef {
  name:         string
  servers:      UpstreamServer[]
  strategy:     "round-robin" | "least-conn" | "ip-hash"
}

UpstreamServer {
  address:  string   -- host:port
  weight:   integer
}

AbSplit {
  name:      string
  sticky:    boolean
  groups:    AbGroup[]   -- weights must sum to 100
}

AbGroup {
  name:      string
  upstream:  string
  weight:    integer   -- 0–100
}

StreamBlock {
  listen:    ListenDirective
  upstream:  UpstreamRef
  ssl:       SslSettings | null
}

MailBlock {
  listen:            ListenDirective[]
  protocol:          "smtp" | "imap" | "pop3"
  upstream:          UpstreamRef
  ssl:               SslSettings | null
  auth_required:     boolean
  max_line_length:   integer | null  -- bytes, default 4096
}

AccessLogEntry {
  timestamp:    ISO8601
  remote_addr:  string
  method:       string
  uri:          string
  status:       integer
  bytes_sent:   integer
  user_agent:   string
  geoip_country: string | null
  ab_group:     string | null
}
```

---

## § 5 — Amendments

### Amendment A

**Author:** opencode  
**Date:** 2026-05-15  
**Change:** Add first-class ACME/Let's Encrypt certificate management. Extends §2 Inputs with ACME challenge requests, §2 Outputs with certificate lifecycle events, §2 Invariants with 67-77 (ACME network exception, certificate-key binding, domain validation, staging isolation, rate limit awareness, challenge port binding, DNS webhook auth, certificate transparency, revocation handling, no self-signed fallback, EAB key protection). Extends §4 Data Shape with `AcmeConfig`, `WebhookConfig`, `EabConfig` types and updates `SslSettings` to include optional `acme` field. Extends §7 Verification Criteria with 50-58 (ACME staging issuance, HTTP-01 challenge, TLS-ALPN-01 challenge, automatic renewal, rate limit backoff, domain mismatch rejection, EAB integration, DNS webhook invocation, no self-signed fallback). Updates §3 Stack Negotiation to add ACME client libraries as acceptable dependencies.  
**Reason:** Operators need automatic TLS certificate management without external tooling (certbot, cron jobs). Native ACME support reduces operational complexity and eliminates certificate expiry incidents.  
**Supersedes:** Additive. Version advances to 0.2.3.

---

## § 6 — License Terms

OSC-Open v1.0

---

## § 7 — Verification Criteria

0. The entry point `flexd --help` exists and exits 0.

1. **HTTP/1.1 static serving.** Given a config with a static file root and a test HTML file, an HTTP GET request returns 200 with the file's contents.

2. **HTTP/2 negotiation.** A TLS listener with `http2: true` upgrades a client connection to HTTP/2 via ALPN. Confirmed by a client that reports the negotiated protocol.

3. **HTTP/3 / QUIC.** A listener with `http3: true` on a UDP port accepts and responds to an HTTP/3 request. Confirmed by a client supporting QUIC.

4. **TLS termination.** A request to a TLS listener with a valid self-signed certificate completes the TLS handshake and returns a 200. The certificate file is not modified on disk.

5. **Rewrite rule applied before upstream.** A request matching a rewrite rule with flag `redirect` receives a 301/302 response to the rewritten URL; the original upstream is not contacted.

6. **A/B split routing.** Given two upstream groups weighted 70/30, 1000 synthetic requests are distributed such that each group receives between 60% and 80% / 20% and 40% of traffic respectively. Sticky mode routes the same cookie value to the same group across 100 consecutive requests.

7. **Geolocation header injection.** Given a MaxMind-format GeoIP2 database and an inbound request, the response from the upstream includes `X-GeoIP-Country` set to the correct ISO country code for the client IP.

8. **SIGHUP reload.** Sending SIGHUP while a long-poll request is in flight: the in-flight request completes normally; the server applies an updated configuration for new requests without restarting.

9. **Configuration validation.** `flexd --test` on a config with A/B weights summing to 110 exits non-zero with a descriptive error. `flexd --test` on a valid config exits 0 with "configuration OK".

10. **Access log written.** After serving five requests, `logs/access.log` contains five lines each including timestamp, method, URI, and status code.

11. **No network calls during startup.** Starting the server with all external network interfaces blocked (loopback only) produces no network errors and begins serving on loopback successfully.

12. **TCP stream proxy.** A raw TCP connection to a stream listener is forwarded to the configured upstream address; data written by the client is received by the upstream verbatim.

13. **Graceful shutdown.** SIGTERM during an active request: the request completes before the process exits. The exit code is 0.

14. **Path traversal rejected.** A static file handler with root `/var/www` receives a request for `/../../../etc/passwd`. The server returns 403 and does not serve the file.

15. **Oversized header rejected.** A request with a header line exceeding the configured `max_header_size` (or the default 8 KB) is rejected with 431 Request Header Fields Too Large.

16. **TLS version enforcement.** A client attempting TLSv1.0 or TLSv1.1 handshake to a TLS listener is rejected. A TLSv1.2 handshake succeeds.

17. **Idle timeout enforced.** After establishing an HTTP keepalive connection and sending no data for 90 seconds, the server closes the connection. Confirmed by a read returning EOF on the client side.

18. **Directory listing disabled.** A request to `/css/` where `/css/` is a directory without an index file returns 403 and no HTML directory listing.

19. **HTTP/2 stream limit enforced.** An HTTP/2 client opens 129 concurrent streams. The server resets the 129th stream with `REFUSED_STREAM`.

20. **Request body too large.** A POST request with a 2 MB body and `max_body_size` set to 1 MB is rejected with 413 Payload Too Large.

21. **Ambiguous framing rejected.** A request with both `Content-Length: 10` and `Transfer-Encoding: chunked` headers receives 400 Bad Request.

22. **Upgrade passthrough blocked.** A request with `Upgrade: websocket` followed by pipelined HTTP bytes: only the first request is processed; subsequent bytes are not forwarded until a 101 response is received from upstream.

23. **HTTP/1.0 + TE rejected.** An HTTP/1.0 request with `Transfer-Encoding: chunked` receives 400 Bad Request.

24. **Rapid Reset mitigation.** A client sending 15 RST_STREAM frames within 3 seconds has its connection terminated. Legitimate clients sending 5 or fewer resets are unaffected.

25. **Host header enforcement.** A request with `Host: evil.com` to a server configured for `example.com` receives 400 Bad Request when `host_header_policy: "strict"`.

26. **Header injection blocked.** A request with a header containing embedded CR/LF characters receives 400 Bad Request.

27. **CONNECT method blocked by default.** A `CONNECT example.com:443 HTTP/1.1` request receives 405 Method Not Allowed unless `allow_connect: true` is configured.

28. **Encoded traversal rejected.** A request for `/%2e%2e%2f%2e%2e%2fetc/passwd` receives 400 Bad Request before path resolution.

29. **Parser canonicalization ambiguity.** A request with `Content-Length : 10` (whitespace before colon) receives 400 Bad Request.

30. **Bare line ending rejection.** A request using bare CR or bare LF in place of CRLF line endings receives 400 Bad Request.

31. **Transfer-Encoding obfuscation rejected.** A request with `Transfer-Encoding : chunked` (space before colon) or `Transfer-Encoding:\tchunked` receives 400 Bad Request.

32. **CONTINUATION flood protection.** An HTTP/2 connection sending 20 CONTINUATION frames without END_HEADERS is terminated with ENHANCE_YOUR_CALM error code.

33. **QUIC anti-amplification.** Before address validation, the server transmits at most 3x the bytes received from an unvalidated client. Measured with a packet capture.

34. **Regex ReDoS protection.** A rewrite rule with a vulnerable pattern (e.g., `(a+)+b`) and a crafted URI (`aaaaaaaaaaaaaaaaaaaaaaaaaaaaac`) completes within 1 second without CPU exhaustion.

35. **Symlink escape rejected.** A static file root `/var/www` containing a symlink `www/leak -> /etc` returns 403 Forbidden when accessing `/leak/passwd`.

36. **Private upstream rejected.** An upstream target `127.0.0.1:8080` is rejected at validation when `upstream_allowed_networks` excludes loopback. `flexd --test` exits non-zero.

37. **Hop-by-hop headers stripped.** A request with `Connection: close` and `Transfer-Encoding: chunked` forwarded to upstream does not include `Transfer-Encoding` in the proxied request. Confirmed by upstream access log.

38. **Sensitive header redacted from logs.** A request with `Authorization: Bearer secret123` produces an access log entry where the Authorization value is omitted or replaced with `[REDACTED]`.

39. **TLS renegotiation rejected.** A client initiating TLS renegotiation on an established connection has the connection terminated. Confirmed by `openssl s_client -reconnect`.

40. **CONNECT to private network blocked.** A CONNECT request to `127.0.0.1:22` is rejected with 403 Forbidden when `connect_allowed_targets` does not include `127.0.0.1:22`.

41. **Authority mismatch rejection.** An HTTP/2 request with `:authority: evil.com` and pseudo-header-derived `Host: example.com` conflicting authorities receives 400 Bad Request.

42. **Log injection prevented.** A request with URI containing embedded `\n` control characters results in a log entry with no injected line breaks.

43. **Mail line length enforced.** An SMTP command line exceeding the configured `max_line_length` (default: 4096 bytes) terminates the session with an error response.

44. **Upstream response smuggling rejected.** An upstream returning both `Content-Length: 10` and `Transfer-Encoding: chunked` in its response is rejected by flexd. The downstream client receives 502 Bad Gateway instead of the smuggled payload.

45. **Header count limit enforced.** A request with 150 headers is rejected with 431 Request Header Fields Too Large when `max_header_count: 100`.

46. **Decompression bomb rejected.** A tiny gzip payload (100 bytes) that decompresses to 100 MB is rejected with 413 Payload Too Large when `max_decompression_ratio: 10`.

47. **Overlong UTF-8 rejected.** A request URI containing an overlong UTF-8 encoding (e.g., `%C0%AE` for `.`) receives 400 Bad Request.

48. **Alternative path separator blocked.** A request containing a backslash path separator (`` \..\etc\passwd ``) receives 400 Bad Request or is normalized before traversal checks, never serving the file.

49. **Worker crash isolation.** Sending a malformed request that triggers a parser fault in one worker does not affect connections handled by other workers. Confirmed by serving a valid request on a separate listener during the fault.

50. **ACME staging issuance.** With `acme.staging: true` and a test domain, `flexd --test` validates config; starting the daemon successfully obtains a staging certificate. Confirmed via `openssl x509 -in <cert> -noout -issuer`.

51. **HTTP-01 challenge served.** A request to `http://<domain>/.well-known/acme-challenge/<token>` returns the correct key authorization with `Content-Type: application/octet-stream`.

52. **TLS-ALPN-01 challenge served.** A TLS client negotiating ALPN `acme-tls/1` to the configured port receives the challenge certificate. Confirmed via `openssl s_client -alpn acme-tls/1`.

53. **Automatic renewal.** A certificate with 29 days validity triggers background renewal; the new certificate is loaded without dropping active connections. Confirmed via `inotify` on cert file + connection monitoring.

54. **Rate limit backoff.** Simulating ACME `429 Too Many Requests` with `Retry-After: 60` causes the daemon to wait ≥60 seconds before retrying. Confirmed via log timestamps.

55. **Domain mismatch rejection.** A config with `server_name: example.com` but `acme.domains: ["evil.com"]` fails validation with `flexd --test` and exits non-zero.

56. **EAB integration.** With valid `eab.kid` and `eab.hmac_key` (file-backed), the daemon successfully registers an ACME account with an enterprise CA supporting EAB.

57. **DNS webhook invocation.** When `challenge_types: ["dns-01"]`, the daemon POSTs to `dns_webhook.url` with a JSON body containing `domain`, `token`, and `action: "create"`. Confirmed via webhook server logs.

58. **No self-signed fallback.** Removing network access during ACME issuance causes startup to fail with a descriptive error; the listener does not bind.

---

## § 8 — Security Posture

### § 8.1 — Default-Deny Principle

Any request, header, or protocol feature not explicitly permitted by configuration must be rejected. Leniency is a security vulnerability.

### § 8.2 — Fail-Close on Ambiguity

When parsing ambiguity exists (conflicting framing headers, malformed URIs, protocol downgrades), the server must reject the request and close the connection. Silent normalization is prohibited.

### § 8.3 — Auditability

All security rejections (4xx responses due to policy, not application logic) must be logged with:
- Rejection reason code (e.g., `AMBIGUOUS_FRAMING`, `INVALID_HOST`)
- Client IP and TLS fingerprint (if applicable)
- Raw request line (truncated to 1 KB) for forensic analysis
- explicit trust boundaries
- parser isolation
- canonicalization layers
- runtime ownership separation
- resource accounting
- avoiding cyclic dependencies
- separating parsing from policy
- keeping canonicalization centralized
- avoiding protocol-specific business logic
