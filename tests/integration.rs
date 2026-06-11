//! End-to-end coverage for the audit fixes: load balancing, failover,
//! trusted-proxy boundary, Host preservation, hop-by-hop stripping (both
//! directions), framing rejects, body limits, CONNECT tunneling, rewrites,
//! HSTS, and host policy.

use bytes::Bytes;
use flexd::config::{Config, HttpBlock, TimeoutSettings};
use flexd::handler::HandlerService;
use flexd::logging::AccessLogger;
use flexd::server::Server;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CLIENT: &str = "198.51.100.7:4321";

#[derive(Clone)]
enum Mock {
    /// 200 response whose body is `<marker>\n<received request head>`.
    EchoHeaders(String),
    /// Bytes written verbatim after the request head (and body) is consumed.
    Raw(String),
}

/// Minimal raw-TCP HTTP/1.1 upstream; one response per connection.
async fn mock_upstream(mode: Mock) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            let mode = mode.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let header_end = loop {
                    let Ok(n) = sock.read(&mut tmp).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                let mut body_read = buf.len() - header_end;
                while body_read < content_length {
                    let Ok(n) = sock.read(&mut tmp).await else { return };
                    if n == 0 {
                        break;
                    }
                    body_read += n;
                }

                let response = match mode {
                    Mock::EchoHeaders(marker) => {
                        let body = format!("{}\n{}", marker, head);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                    Mock::Raw(raw) => raw,
                };
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn make_handler(block_toml: &str, is_tls: bool) -> HandlerService {
    let block: HttpBlock = toml::from_str(block_toml).expect("block toml");
    let log_path = std::env::temp_dir().join(format!(
        "flexd-it-{}-{}.log",
        std::process::id(),
        rand_suffix()
    ));
    let logger = Arc::new(AccessLogger::new(log_path.to_str().unwrap()).unwrap());
    HandlerService::new(
        Arc::new(block),
        logger,
        None,
        is_tls,
        &TimeoutSettings::default(),
    )
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request<Bytes> {
    let mut builder = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder.body(Bytes::copy_from_slice(body)).unwrap()
}

async fn body_string(resp: Response<Full<Bytes>>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

fn proxy_block(servers: &[SocketAddr], strategy: &str, extra: &str) -> String {
    let server_list = servers
        .iter()
        .map(|a| format!("{{ address = \"{}\" }}", a))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
listen = [{{ port = 0 }}]
server_name = ["test.local"]
host_header_policy = "any"
upstream_allowed_networks = ["127.0.0.0/8"]
{extra}

[[locations]]
pattern = "/"
match_type = "prefix"

[locations.handler]
type = "proxy"

[locations.handler.upstream]
name = "pool"
strategy = "{strategy}"
servers = [{server_list}]
"#
    )
}

// ---------------------------------------------------------------------------
// Load balancing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn round_robin_rotates_across_upstreams() {
    let a = mock_upstream(Mock::EchoHeaders("upstream-a".into())).await;
    let b = mock_upstream(Mock::EchoHeaders("upstream-b".into())).await;
    let handler = make_handler(&proxy_block(&[a, b], "round-robin", ""), false);
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let mut seen = Vec::new();
    for _ in 0..4 {
        let resp = handler
            .handle_collected(request("GET", "/", &[("host", "test.local")], b""), remote)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        seen.push(body.lines().next().unwrap_or("").to_string());
    }
    assert_eq!(seen[0], seen[2]);
    assert_eq!(seen[1], seen[3]);
    assert_ne!(seen[0], seen[1], "round-robin must alternate: {:?}", seen);
}

#[tokio::test]
async fn failover_skips_dead_upstream() {
    // Reserve a port and immediately release it: connection refused.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let live = mock_upstream(Mock::EchoHeaders("live".into())).await;
    let handler = make_handler(&proxy_block(&[dead, live], "round-robin", ""), false);
    let remote: SocketAddr = CLIENT.parse().unwrap();

    for _ in 0..3 {
        let resp = handler
            .handle_collected(request("GET", "/", &[("host", "test.local")], b""), remote)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.starts_with("live"));
    }
}

#[tokio::test]
async fn all_upstreams_down_yields_502() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let handler = make_handler(&proxy_block(&[dead], "round-robin", ""), false);
    let remote: SocketAddr = CLIENT.parse().unwrap();
    let resp = handler
        .handle_collected(request("GET", "/", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

// ---------------------------------------------------------------------------
// Forwarded request headers: Host, trusted-proxy boundary, hop-by-hop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn host_preserved_and_attribution_stamped() {
    let upstream = mock_upstream(Mock::EchoHeaders("echo".into())).await;
    let handler = make_handler(&proxy_block(&[upstream], "round-robin", ""), false);
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let resp = handler
        .handle_collected(
            request(
                "GET",
                "/",
                &[
                    ("host", "test.local"),
                    // Spoofed attribution from an untrusted client:
                    ("x-forwarded-for", "1.2.3.4"),
                    ("x-real-ip", "1.2.3.4"),
                    ("x-geoip-country", "XX"),
                    // Connection-nominated header must not reach upstream:
                    ("connection", "x-secret"),
                    ("x-secret", "leak"),
                ],
                b"",
            ),
            remote,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let head = body_string(resp).await.to_ascii_lowercase();

    assert!(head.contains("host: test.local"), "original Host must be preserved: {head}");
    assert!(head.contains("x-forwarded-for: 198.51.100.7"), "XFF must be the real client: {head}");
    assert!(!head.contains("1.2.3.4"), "spoofed attribution must be stripped: {head}");
    assert!(head.contains("x-real-ip: 198.51.100.7"), "{head}");
    assert!(head.contains("x-forwarded-proto: http"), "{head}");
    assert!(!head.contains("x-secret"), "Connection-nominated header leaked: {head}");
    assert!(!head.contains("x-geoip-country"), "client GeoIP spoof must be stripped: {head}");
}

#[tokio::test]
async fn trusted_proxy_xff_is_appended_not_replaced() {
    let upstream = mock_upstream(Mock::EchoHeaders("echo".into())).await;
    let handler = make_handler(
        &proxy_block(
            &[upstream],
            "round-robin",
            r#"trusted_proxies = ["198.51.100.0/24"]"#,
        ),
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let resp = handler
        .handle_collected(
            request(
                "GET",
                "/",
                &[("host", "test.local"), ("x-forwarded-for", "1.2.3.4")],
                b"",
            ),
            remote,
        )
        .await;
    let head = body_string(resp).await.to_ascii_lowercase();
    assert!(
        head.contains("x-forwarded-for: 1.2.3.4, 198.51.100.7"),
        "trusted chain must be appended: {head}"
    );
}

// ---------------------------------------------------------------------------
// Upstream response handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn response_hop_by_hop_and_nominated_stripped() {
    let raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: x-hop\r\nX-Hop: leak\r\nKeep-Alive: timeout=5\r\nX-Kept: yes\r\n\r\nok";
    let upstream = mock_upstream(Mock::Raw(raw.into())).await;
    let handler = make_handler(&proxy_block(&[upstream], "round-robin", ""), false);
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let resp = handler
        .handle_collected(request("GET", "/", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("connection").is_none());
    assert!(resp.headers().get("keep-alive").is_none());
    assert!(resp.headers().get("x-hop").is_none(), "nominated header leaked downstream");
    assert_eq!(resp.headers().get("x-kept").unwrap(), "yes");
}

#[tokio::test]
async fn multiple_set_cookie_headers_survive() {
    let raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nok";
    let upstream = mock_upstream(Mock::Raw(raw.into())).await;
    let handler = make_handler(&proxy_block(&[upstream], "round-robin", ""), false);
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let resp = handler
        .handle_collected(request("GET", "/", &[("host", "test.local")], b""), remote)
        .await;
    let cookies: Vec<_> = resp
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .collect();
    assert_eq!(cookies.len(), 2, "both Set-Cookie headers must be forwarded");
}

#[tokio::test]
async fn upstream_cl_te_response_rejected() {
    let raw =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
    let upstream = mock_upstream(Mock::Raw(raw.into())).await;
    let handler = make_handler(&proxy_block(&[upstream], "round-robin", ""), false);
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let resp = handler
        .handle_collected(request("GET", "/", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

// ---------------------------------------------------------------------------
// Request limits & framing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oversized_body_rejected() {
    let handler = make_handler(
        r#"
listen = [{ port = 0 }]
server_name = ["test.local"]
host_header_policy = "any"
max_body_size = 1024
"#,
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();
    let resp = handler
        .handle_collected(
            request("POST", "/", &[("host", "test.local")], &[0u8; 4096]),
            remote,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn request_cl_te_rejected() {
    let handler = make_handler(
        r#"
listen = [{ port = 0 }]
server_name = ["test.local"]
host_header_policy = "any"
"#,
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();
    let resp = handler
        .handle_collected(
            request(
                "POST",
                "/",
                &[
                    ("host", "test.local"),
                    ("content-length", "5"),
                    ("transfer-encoding", "chunked"),
                ],
                b"hello",
            ),
            remote,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gzip_bomb_rejected() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&vec![0u8; 1024 * 1024]).unwrap(); // 1 MiB of zeros
    let bomb = enc.finish().unwrap(); // ~1 KB compressed → ratio ≫ 10

    let handler = make_handler(
        r#"
listen = [{ port = 0 }]
server_name = ["test.local"]
host_header_policy = "any"
"#,
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();
    let resp = handler
        .handle_collected(
            request(
                "POST",
                "/",
                &[("host", "test.local"), ("content-encoding", "gzip")],
                &bomb,
            ),
            remote,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn encoded_traversal_rejected() {
    let handler = make_handler(
        r#"
listen = [{ port = 0 }]
server_name = ["test.local"]
host_header_policy = "any"
"#,
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();
    let resp = handler
        .handle_collected(
            request("GET", "/%2e%2e%2fetc/passwd", &[("host", "test.local")], b""),
            remote,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn disallowed_method_rejected() {
    let handler = make_handler(
        r#"
listen = [{ port = 0 }]
server_name = ["test.local"]
host_header_policy = "any"
"#,
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();
    let resp = handler
        .handle_collected(request("TRACE", "/", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ---------------------------------------------------------------------------
// Host policy, locations, rewrites, HSTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn strict_host_policy_enforced() {
    let handler = make_handler(
        r#"
listen = [{ port = 0 }]
server_name = ["test.local"]
host_header_policy = "strict"

[[locations]]
pattern = "/"
match_type = "prefix"

[locations.handler]
type = "return"
status = 200
target = "ok"
"#,
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let ok = handler
        .handle_collected(request("GET", "/", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(ok.status(), StatusCode::OK);

    let bad = handler
        .handle_collected(request("GET", "/", &[("host", "evil.example")], b""), remote)
        .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let missing = handler
        .handle_collected(request("GET", "/", &[], b""), remote)
        .await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deny_location_and_return_location() {
    let handler = make_handler(
        r#"
listen = [{ port = 0 }]
server_name = ["test.local"]
host_header_policy = "any"

[[locations]]
pattern = "/admin"
match_type = "prefix"

[locations.handler]
type = "deny"

[[locations]]
pattern = "/teapot"
match_type = "exact"

[locations.handler]
type = "return"
status = 418
target = "short and stout"
"#,
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let denied = handler
        .handle_collected(request("GET", "/admin/panel", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let teapot = handler
        .handle_collected(request("GET", "/teapot", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(teapot.status(), StatusCode::IM_A_TEAPOT);
}

#[tokio::test]
async fn rewrite_redirect_and_internal() {
    let root = std::env::temp_dir().join(format!("flexd-it-root-{}", rand_suffix()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("new.html"), b"<p>fresh</p>").unwrap();

    let handler = make_handler(
        &format!(
            r#"
listen = [{{ port = 0 }}]
server_name = ["test.local"]
host_header_policy = "any"
root = "{}"

[[rewrites]]
pattern = "^/moved$"
replacement = "/elsewhere"
flag = "permanent"

[[rewrites]]
pattern = "^/old.html$"
replacement = "/new.html"
flag = "break"
"#,
            root.display()
        ),
        false,
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();

    let redirect = handler
        .handle_collected(request("GET", "/moved", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(redirect.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(redirect.headers().get("location").unwrap(), "/elsewhere");

    let internal = handler
        .handle_collected(request("GET", "/old.html", &[("host", "test.local")], b""), remote)
        .await;
    assert_eq!(internal.status(), StatusCode::OK);
    assert!(body_string(internal).await.contains("fresh"));
}

#[tokio::test]
async fn hsts_present_on_tls_block() {
    let handler = make_handler(
        r#"
listen = [{ port = 0 }]
server_name = ["test.local"]
host_header_policy = "any"
hsts_max_age = 63072000
"#,
        true, // TLS listener
    );
    let remote: SocketAddr = CLIENT.parse().unwrap();
    let resp = handler
        .handle_collected(request("GET", "/nope", &[("host", "test.local")], b""), remote)
        .await;
    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .expect("HSTS header missing");
    assert_eq!(hsts, "max-age=63072000; includeSubDomains");
}

// ---------------------------------------------------------------------------
// CONNECT tunneling (full server, real sockets)
// ---------------------------------------------------------------------------

async fn echo_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn spawn_server(config_toml: &str) -> (Arc<Server>, SocketAddr) {
    let config: Config = toml::from_str(config_toml).expect("config toml");
    config.validate().expect("config validate");
    let server = Arc::new(Server::new(config));
    let runner = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = runner.run().await;
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let addr = loop {
        let addrs = server.bound_addrs();
        if let Some(a) = addrs.first() {
            break *a;
        }
        assert!(std::time::Instant::now() < deadline, "server did not bind");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    (server, addr)
}

async fn read_response_head(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read");
        assert!(n > 0, "connection closed before response head");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn connect_config(echo: SocketAddr, allow_connect: bool, log: &str) -> String {
    format!(
        r#"
[global]

[[http]]
server_name = ["tunnel.local"]
host_header_policy = "any"
allow_connect = {allow}
upstream_allowed_networks = ["127.0.0.0/8"]
connect_allowed_targets = ["127.0.0.1:{port}"]
access_log = "{log}"

[[http.listen]]
port = 0
address = "127.0.0.1"
protocol = "tcp"

[http.connect_upstream]
name = "tunnel"
servers = [{{ address = "127.0.0.1:{port}" }}]
"#,
        allow = allow_connect,
        port = echo.port(),
        log = log,
    )
}

#[tokio::test]
async fn connect_tunnel_end_to_end() {
    let echo = echo_tcp_server().await;
    let log = std::env::temp_dir().join(format!("flexd-it-connect-{}.log", rand_suffix()));
    let (server, addr) = spawn_server(&connect_config(echo, true, log.to_str().unwrap())).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{p} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n",
                p = echo.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let head = read_response_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 200"), "expected 200, got: {head}");

    // Tunnel established: bytes must round-trip through the echo upstream.
    client.write_all(b"ping-through-tunnel").await.unwrap();
    let mut echoed = [0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
        .await
        .expect("tunnel read timeout")
        .expect("tunnel read");
    assert_eq!(&echoed, b"ping-through-tunnel");

    let _ = server.shutdown_tx().send(());
}

#[tokio::test]
async fn connect_disallowed_target_403() {
    let echo = echo_tcp_server().await;
    let log = std::env::temp_dir().join(format!("flexd-it-connect403-{}.log", rand_suffix()));
    let (server, addr) = spawn_server(&connect_config(echo, true, log.to_str().unwrap())).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    // Port not on the allowlist:
    client
        .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
        .await
        .unwrap();
    let head = read_response_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 403"), "expected 403, got: {head}");

    let _ = server.shutdown_tx().send(());
}

#[tokio::test]
async fn connect_denied_405_when_disabled() {
    let echo = echo_tcp_server().await;
    let log = std::env::temp_dir().join(format!("flexd-it-connect405-{}.log", rand_suffix()));
    // allow_connect=false (connect_upstream present but unused — valid config).
    let (server, addr) = spawn_server(&connect_config(echo, false, log.to_str().unwrap())).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{p} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n",
                p = echo.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_response_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 405"), "expected 405, got: {head}");

    let _ = server.shutdown_tx().send(());
}

// ---------------------------------------------------------------------------
// Bare-LF rejection over a real listener (C30)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bare_lf_request_rejected() {
    let echo = echo_tcp_server().await;
    let log = std::env::temp_dir().join(format!("flexd-it-barelf-{}.log", rand_suffix()));
    let (server, addr) = spawn_server(&connect_config(echo, false, log.to_str().unwrap())).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\nHost: tunnel.local\n\n")
        .await
        .unwrap();
    let head = read_response_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 400"), "expected 400, got: {head}");

    let _ = server.shutdown_tx().send(());
}
