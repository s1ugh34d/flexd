//! The pooled upstream HTTP client used by the reverse proxy.
//!
//! [`ProxyClient`](crate::proxy::ProxyClient) wraps a single `hyper` client
//! (one per `[[http]]` block, not per request) configured with the
//! [`PinningResolver`](crate::resolver::PinningResolver) for connection
//! pooling, DNS caching, rebinding defense, and SSRF filtering.
//! [`ProxyClient::forward`](crate::proxy::ProxyClient::forward) sends one
//! fully-buffered request and returns the buffered response, applying
//! hop-by-hop stripping (Invariant 44), the trusted-proxy attribution policy
//! (Invariants 23 & 43), response-size limits, and ambiguous-framing rejection
//! (Invariant 59) along the way.
//!
//! Because the request body is a cheap-to-clone `Bytes` and the request parts
//! are borrowed, a [`ProxyError::Connect`](crate::proxy::ProxyError::Connect)
//! result is safe for the caller to retry verbatim against the next balancer
//! candidate.

use crate::resolver::PinningResolver;
use crate::security::headers::{apply_forwarding_policy, strip_hop_by_hop};
use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use std::net::IpAddr;
use std::time::Duration;

/// Why a forward attempt failed — drives load-balancer failover.
#[derive(Debug)]
pub enum ProxyError {
    /// TCP/DNS-level failure before the request was sent; safe to retry the
    /// identical request on the next candidate server.
    Connect,
    /// Definitive failure, mapped straight to a downstream status.
    Status(StatusCode),
}

impl From<StatusCode> for ProxyError {
    fn from(status: StatusCode) -> Self {
        ProxyError::Status(status)
    }
}

/// Shared upstream HTTP client — one per http block, not per request.
///
/// Connection pooling plus the [`PinningResolver`] give DNS caching with TTL,
/// rebinding defense (Invariant 42), and SSRF filtering of every resolved
/// address (Invariant 41). The previous design built a fresh client (and did
/// a fresh, unchecked DNS resolution) on every request.
pub struct ProxyClient {
    client: Client<HttpConnector<PinningResolver>, Full<Bytes>>,
    resolver: PinningResolver,
    request_timeout: Duration,
    max_response_size: usize,
    trusted_proxies: Vec<ipnetwork::IpNetwork>,
    /// `normalize_headers_before_proxy` — when false the operator has opted
    /// out of attribution rewriting (Invariant 23/43) and incoming
    /// X-Forwarded-* headers pass through untouched.
    apply_attribution_policy: bool,
}

impl ProxyClient {
    /// Build a shared client for one http block.
    ///
    /// `allowed_networks` is the SSRF allowlist handed to the resolver,
    /// `dns_ttl` how long vetted answers are cached, `request_timeout` the
    /// upstream response deadline, `max_response_size` the buffered-body cap,
    /// `trusted_proxies` the CIDRs whose attribution headers are honored, and
    /// `apply_attribution_policy` whether the trusted-proxy rewrite runs at all
    /// (the `normalize_headers_before_proxy` opt-out).
    pub fn new(
        allowed_networks: Vec<ipnetwork::IpNetwork>,
        dns_ttl: Duration,
        request_timeout: Duration,
        max_response_size: usize,
        trusted_proxies: Vec<ipnetwork::IpNetwork>,
        apply_attribution_policy: bool,
    ) -> Self {
        let resolver = PinningResolver::new(allowed_networks, dns_ttl);
        let mut connector = HttpConnector::new_with_resolver(resolver.clone());
        connector.set_connect_timeout(Some(Duration::from_secs(10)));
        connector.set_nodelay(true);
        let client = Client::builder(hyper_util::rt::TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(connector);
        Self {
            client,
            resolver,
            request_timeout,
            max_response_size,
            trusted_proxies,
            apply_attribution_policy,
        }
    }

    /// The pinning resolver, shared with the CONNECT handler so tunnel
    /// targets get the same vetting as proxied requests.
    pub fn resolver(&self) -> &PinningResolver {
        &self.resolver
    }

    /// Forward a fully-buffered request to `upstream_addr`.
    ///
    /// `parts` is borrowed and `body` is a cheap-to-clone `Bytes`, so the
    /// caller can retry the identical request on another server when this
    /// returns [`ProxyError::Connect`].
    ///
    /// # Errors
    ///
    /// - [`ProxyError::Connect`] — TCP/DNS failure before the request was sent;
    ///   safe to retry the identical request on another candidate.
    /// - [`ProxyError::Status`] with `GATEWAY_TIMEOUT` on timeout,
    ///   `BAD_GATEWAY` on a transport error, ambiguous upstream response
    ///   framing, or an over-limit response body.
    pub async fn forward(
        &self,
        upstream_addr: &str,
        parts: &http::request::Parts,
        body: Bytes,
        client_ip: IpAddr,
        scheme: &'static str,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let upstream_uri: http::Uri = format!(
            "http://{}{}",
            upstream_addr,
            parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
        )
        .parse()
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

        let mut headers = parts.headers.clone();
        let original_host = headers.get(http::header::HOST).cloned();

        // Invariant 44 — hop-by-hop headers, including Connection-nominated names.
        strip_hop_by_hop(&mut headers);

        // The buffered body is authoritative: drop any client-declared
        // Content-Length (it may be stale after decompression) and let hyper
        // frame from the actual body size.
        headers.remove(http::header::CONTENT_LENGTH);

        // Invariants 23 & 43 — trusted-proxy boundary for attribution headers.
        if self.apply_attribution_policy {
            apply_forwarding_policy(
                &mut headers,
                client_ip,
                scheme,
                original_host.as_ref(),
                &self.trusted_proxies,
            );
        }

        let mut upstream_req = Request::new(Full::new(body));
        *upstream_req.method_mut() = parts.method.clone();
        *upstream_req.uri_mut() = upstream_uri;
        *upstream_req.version_mut() = http::Version::HTTP_11;
        // Wholesale assignment preserves multi-valued headers; per-entry
        // `insert` collapses repeats (e.g. several Cookie lines) to the last.
        *upstream_req.headers_mut() = headers;

        // Preserve the client-supplied Host for virtual-hosted upstreams;
        // fall back to the upstream authority when the client sent none.
        let host_value = match original_host {
            Some(h) => h,
            None => HeaderValue::from_str(upstream_addr).map_err(|_| StatusCode::BAD_GATEWAY)?,
        };
        upstream_req
            .headers_mut()
            .insert(http::header::HOST, host_value);

        let resp = match tokio::time::timeout(
            self.request_timeout,
            self.client.request(upstream_req),
        )
        .await
        {
            Err(_elapsed) => return Err(ProxyError::Status(StatusCode::GATEWAY_TIMEOUT)),
            Ok(Err(e)) if e.is_connect() => return Err(ProxyError::Connect),
            Ok(Err(_)) => return Err(ProxyError::Status(StatusCode::BAD_GATEWAY)),
            Ok(Ok(resp)) => resp,
        };

        let (resp_parts, resp_body) = resp.into_parts();

        // C44 / Invariant 59: ambiguous upstream response framing → 502.
        let upstream_has_cl = resp_parts.headers.contains_key(http::header::CONTENT_LENGTH);
        let upstream_has_te = resp_parts
            .headers
            .contains_key(http::header::TRANSFER_ENCODING);
        if upstream_has_cl && upstream_has_te {
            return Err(ProxyError::Status(StatusCode::BAD_GATEWAY));
        }

        // Responses are buffered (no streaming path yet); bound the buffer so
        // a misbehaving upstream cannot exhaust memory.
        let resp_body_bytes = Limited::new(resp_body, self.max_response_size)
            .collect()
            .await
            .map_err(|_| ProxyError::Status(StatusCode::BAD_GATEWAY))?
            .to_bytes();

        // Invariant 44 applies on the way out too: upstream hop-by-hop
        // headers (Transfer-Encoding, Connection, …) must not leak downstream.
        let mut resp_headers = resp_parts.headers;
        strip_hop_by_hop(&mut resp_headers);

        let mut out = Response::new(Full::new(resp_body_bytes));
        *out.status_mut() = resp_parts.status;
        *out.headers_mut() = resp_headers;
        Ok(out)
    }
}
