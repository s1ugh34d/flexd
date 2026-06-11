# flexd

A hardened web server and reverse proxy, written in Rust.

flexd owns the external port and does strict parsing, connection limiting, and
static file serving in front of your application backend. Configuration is a
single TOML file, nginx-shaped but typed and validated at startup.

## Features

- **HTTP/1.1, HTTP/2, HTTP/3** — h2 via hyper, h3 via quinn/QUIC
- **TLS** — rustls only (no OpenSSL); TLS 1.2/1.3, static certs or ACME
- **ACME** — automatic issuance and renewal (Let's Encrypt or any RFC 8555 CA),
  `http-01` and `tls-alpn-01` challenges, EAB support, custom CA roots for
  private PKI, certs persisted with mode 0600
- **Reverse proxy** — weighted round-robin upstreams, header normalization
  before proxying, configurable trusted-proxy headers
- **Static file serving** — with path traversal protection
- **Rewrites and redirects** — regex rewrite rules, exact/prefix location matching
- **A/B traffic splitting** — weighted groups, optional sticky assignment
- **TCP stream proxying** — raw TCP forwarding with optional TLS termination
- **GeoIP** — MaxMind database lookups
- **Hardening built in:**
  - strict host-header policy (reject unknown `Host:` by default)
  - ambiguous request framing rejected (request smuggling defense)
  - control characters in headers rejected
  - header count/size and body size limits
  - HTTP/2 reset-flood rate limiting
  - decompression ratio/size bombs capped
  - slow-loris defense via minimum read rate and idle timeouts
  - upstream targets resolving to loopback/private ranges require explicit
    allowlisting (SSRF defense)
  - privilege drop (`user = "..."`) after binding low ports

## Install

```sh
cargo install flexd
```

## Quick start

```sh
# Write a config (see flexd.conf.example in this repository)
flexd --config flexd.conf --test   # validate config and exit
flexd --config flexd.conf          # run
```

A minimal static-site config:

```toml
[global]
worker_processes = "auto"
error_log = "./logs/error.log"

[[http]]
server_name = ["localhost"]
root = "./public"
host_header_policy = "any"

[[http.listen]]
port = 8080
protocol = "tcp"

[[http.locations]]
pattern = "/"
match_type = "prefix"

[http.locations.handler]
type = "static"
root = "./public"
```

Add a reverse-proxied backend:

```toml
[[http.locations]]
pattern = "/api/"
match_type = "prefix"

[http.locations.handler]
type = "proxy"

[http.locations.handler.upstream]
name = "backend"

[[http.locations.handler.upstream.servers]]
address = "127.0.0.1:3000"
```

HTTPS with automatic certificates:

```toml
[http.ssl.acme]
enabled = true
email = "admin@example.com"
domains = ["example.com"]
agree_tos = true
```

See `flexd.conf.example` for the full annotated configuration surface,
including HTTP/3, stream proxying, A/B splits, and ACME EAB/private-CA options.

## Logging

flexd uses `tracing`; set `RUST_LOG` to control verbosity:

```sh
RUST_LOG=debug flexd --config flexd.conf
```

Access and error logs are written to the paths configured per-server
(`access_log`, `error_log`).

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
