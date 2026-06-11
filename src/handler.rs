use crate::absplit::AbSplitRouter;
use crate::balance::Balancer;
use crate::config::{self, Handler as HandlerType, HttpBlock, TimeoutSettings, UpstreamRef};
use crate::geoip::GeoIpService;
use crate::logging::AccessLogger;
use crate::proxy::{ProxyClient, ProxyError};
use crate::rewrite::{RewriteAction, RewriteEngine};
use crate::security::{host_policy, upstream_filter, uri_validate};
use crate::static_file;
use bytes::Bytes;
use flate2::read::GzDecoder;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Body;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// A location with its regex pattern compiled once at construction instead of
/// per request.
struct CompiledLocation {
    location: config::Location,
    regex: Option<regex::Regex>,
}

pub struct HandlerService {
    http_block: Arc<HttpBlock>,
    access_logger: Arc<AccessLogger>,
    /// Present when this listener belongs to an `acme.enabled` block; used to
    /// answer HTTP-01 challenges (C51) from the shared challenge store.
    acme_store: Option<crate::acme::ChallengeStore>,
    /// Shared upstream client: DNS pinning + pooling (Invariants 41/42).
    proxy: ProxyClient,
    balancer: Balancer,
    geoip: Option<GeoIpService>,
    rewriter: RewriteEngine,
    ab_router: Option<AbSplitRouter>,
    locations: Vec<CompiledLocation>,
    /// "https" when this handler serves a TLS or QUIC listener.
    scheme: &'static str,
    /// Precomputed Strict-Transport-Security value (TLS listeners only).
    hsts: Option<HeaderValue>,
    max_body: usize,
}

impl HandlerService {
    pub fn new(
        http_block: Arc<HttpBlock>,
        access_logger: Arc<AccessLogger>,
        acme_store: Option<crate::acme::ChallengeStore>,
        is_tls: bool,
        timeouts: &TimeoutSettings,
    ) -> Self {
        let allowed_networks =
            upstream_filter::parse_networks(http_block.upstream_allowed_networks.as_deref());
        let trusted_proxies =
            upstream_filter::parse_networks(http_block.trusted_proxies.as_deref());

        let proxy = ProxyClient::new(
            allowed_networks,
            Duration::from_secs(http_block.dns_cache_ttl_seconds.unwrap_or(30)),
            Duration::from_secs(timeouts.proxy_read),
            http_block
                .max_upstream_response_size
                .unwrap_or(100 * 1024 * 1024),
            trusted_proxies,
            http_block.normalize_headers_before_proxy,
        );

        let balancer = Balancer::new(&http_block);

        let geoip = http_block.geoip_db.as_deref().and_then(|path| {
            match GeoIpService::new(path) {
                Ok(svc) => Some(svc),
                Err(e) => {
                    warn!("GeoIP database unavailable ({:#}); lookups disabled", e);
                    None
                }
            }
        });

        let rewriter = RewriteEngine::new(&http_block.rewrites);
        let ab_router =
            (!http_block.ab_splits.is_empty()).then(|| AbSplitRouter::new(&http_block.ab_splits));

        let locations = http_block
            .locations
            .iter()
            .map(|l| CompiledLocation {
                regex: (l.match_type == "regex")
                    .then(|| regex::Regex::new(&l.pattern).ok())
                    .flatten(),
                location: l.clone(),
            })
            .collect();

        let scheme = if is_tls { "https" } else { "http" };
        let hsts = is_tls
            .then_some(http_block.hsts_max_age)
            .flatten()
            .and_then(|secs| {
                HeaderValue::from_str(&format!("max-age={}; includeSubDomains", secs)).ok()
            });
        let max_body = http_block.max_body_size.unwrap_or(10 * 1024 * 1024);

        Self {
            http_block,
            access_logger,
            acme_store,
            proxy,
            balancer,
            geoip,
            rewriter,
            ab_router,
            locations,
            scheme,
            hsts,
            max_body,
        }
    }

    /// C51 / invariant 67: serve the HTTP-01 key authorization for a known
    /// token as `application/octet-stream`, else 404. Returns `None` when the
    /// path is not an ACME challenge so normal routing proceeds.
    fn acme_challenge_response(&self, uri_path: &str) -> Option<Response<Full<Bytes>>> {
        const PREFIX: &str = "/.well-known/acme-challenge/";
        let store = self.acme_store.as_ref()?;
        let token = uri_path.strip_prefix(PREFIX)?;
        // A token is a single path segment; reject anything with further slashes.
        if token.is_empty() || token.contains('/') {
            return Some(self.error_response(StatusCode::NOT_FOUND));
        }
        match store.get_http01(token) {
            Some(key_auth) => {
                let mut resp = Response::new(Full::new(Bytes::from(key_auth)));
                resp.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
                Some(resp)
            }
            None => Some(self.error_response(StatusCode::NOT_FOUND)),
        }
    }

    fn log(
        &self,
        remote_addr: SocketAddr,
        method: &Method,
        target: &str,
        resp: &Response<Full<Bytes>>,
        user_agent: &str,
    ) {
        self.access_logger.log(
            &remote_addr.ip().to_string(),
            method.as_str(),
            target,
            resp.status().as_u16(),
            resp.body().size_hint().lower() as usize,
            user_agent,
        );
    }

    /// HTTP/1.x and HTTP/2 entry point (streaming hyper body).
    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
        remote_addr: SocketAddr,
    ) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let uri_path = uri.path().to_string();
        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();

        // C51: HTTP-01 ACME challenge — answered before any other routing or
        // host checks so the CA can always reach it over plain HTTP.
        if let Some(resp) = self.acme_challenge_response(&uri_path) {
            self.log(remote_addr, &method, &uri_path, &resp, &user_agent);
            return resp;
        }

        // Invariant 24: CONNECT tunneling — authority-form URI, handled
        // before URI validation (which expects path-form).
        if method == Method::CONNECT {
            let target = uri.to_string();
            let resp = self.handle_connect(req, remote_addr).await;
            self.log(remote_addr, &method, &target, &resp, &user_agent);
            return resp;
        }

        // Header/framing checks before touching the body so malformed
        // requests are rejected without reading their payload.
        if let Err(status) = self.security_checks(&req) {
            let resp = self.finalize(self.error_response(status));
            self.log(remote_addr, &method, &uri_path, &resp, &user_agent);
            return resp;
        }

        // Invariant 16: collect the body under a hard cap. The Content-Length
        // check in security_checks cannot bound chunked bodies — `Limited`
        // enforces the cap regardless of framing.
        let (parts, body) = req.into_parts();
        let body_bytes = match Limited::new(body, self.max_body).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                let status = if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                };
                let resp = self.finalize(self.error_response(status));
                self.log(remote_addr, &method, &uri_path, &resp, &user_agent);
                return resp;
            }
        };

        let req = Request::from_parts(parts, body_bytes);
        let resp = self.handle_collected(req, remote_addr).await;
        self.log(remote_addr, &method, &uri_path, &resp, &user_agent);
        resp
    }

    /// HTTP/3 entry point. The h3 layer hands us a `Request<()>` (pseudo-headers
    /// already lifted into the URI) plus the body collected separately. We
    /// derive a `Host` header from the `:authority` (invariant 50 — authority
    /// consistency) when one is absent, then run the shared pipeline.
    pub async fn handle_h3(
        &self,
        req: Request<()>,
        body: Bytes,
        remote_addr: SocketAddr,
    ) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let uri_path = req.uri().path().to_string();
        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();

        let (mut parts, _) = req.into_parts();

        // Invariant 50: the effective authority comes from :authority for HTTP/3.
        // If the request carried an explicit Host that disagrees with :authority,
        // the authorities conflict -> 400. Otherwise synthesise Host from authority.
        if let Some(authority) = parts.uri.authority().map(|a| a.as_str().to_string()) {
            match parts.headers.get(http::header::HOST) {
                Some(h) => {
                    let host_str = h.to_str().unwrap_or("");
                    if !host_str.is_empty() && host_str != authority {
                        let resp = self.finalize(self.error_response(StatusCode::BAD_REQUEST));
                        self.log(remote_addr, &method, &uri_path, &resp, &user_agent);
                        return resp;
                    }
                }
                None => {
                    if let Ok(hv) = HeaderValue::from_str(&authority) {
                        parts.headers.insert(http::header::HOST, hv);
                    }
                }
            }
        }

        let req = Request::from_parts(parts, body);
        let resp = self.handle_collected(req, remote_addr).await;
        self.log(remote_addr, &method, &uri_path, &resp, &user_agent);
        resp
    }

    /// Shared pipeline for a fully-buffered request: security checks,
    /// decompression guard, host policy, rewrites, GeoIP stamping, routing.
    /// Public so integration tests can exercise policy without a listener.
    pub async fn handle_collected(
        &self,
        req: Request<Bytes>,
        remote_addr: SocketAddr,
    ) -> Response<Full<Bytes>> {
        match self.process(req, remote_addr).await {
            Ok(resp) => self.finalize(resp),
            Err(status) => self.finalize(self.error_response(status)),
        }
    }

    async fn process(
        &self,
        req: Request<Bytes>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, StatusCode> {
        self.security_checks(&req)?;

        // Uniform body cap for entry points that collect outside `handle`
        // (HTTP/3, tests).
        if req.body().len() > self.max_body {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let method = req.method().clone();

        // C46: decompression bomb guard.
        let mut req = self.maybe_decompress(req)?;

        // Invariant 22: host policy.
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok());
        if !host_policy::validate_host(host, &self.http_block) {
            return Err(StatusCode::BAD_REQUEST);
        }

        if !Self::check_method_allowed(&method) {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }

        // Rewrites (first matching rule wins).
        let mut uri_path = req.uri().path().to_string();
        match self.rewriter.apply(&uri_path) {
            Some(RewriteAction::Redirect { target, status }) => {
                return Self::redirect_response(&target, status);
            }
            Some(RewriteAction::Internal(new_path)) => {
                // The rewritten path is operator + capture-group derived;
                // re-validate before it reaches routing or upstreams.
                if uri_validate::validate_uri(&new_path).is_err() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                Self::set_path(&mut req, &new_path)?;
                uri_path = new_path;
            }
            None => {}
        }

        // GeoIP enrichment — never trusts client-supplied x-geoip-* headers.
        self.stamp_geoip(req.headers_mut(), remote_addr.ip());

        match self.find_location(&uri_path) {
            Some(loc) => self.dispatch(loc, &uri_path, req, remote_addr).await,
            None => {
                if let Some(root) = self.http_block.root.as_deref() {
                    static_file::serve_file(root, &uri_path).await
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
    }

    /// Invariants 11, 16, 17, 19, 25, 26, 60 — header/framing checks shared by
    /// every protocol entry point. Body-generic: inspects only headers,
    /// version and URI.
    fn security_checks<B>(&self, req: &Request<B>) -> Result<(), StatusCode> {
        // Invariant 60: max header count
        let max_headers = self.http_block.max_header_count.unwrap_or(100);
        if req.headers().len() > max_headers {
            return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }

        // Invariant 11: max header size
        let max_header_size = self.http_block.max_header_size.unwrap_or(8192);
        let header_size: usize = req
            .headers()
            .iter()
            .map(|(n, v)| n.as_str().len() + v.as_bytes().len() + 2)
            .sum();
        if header_size > max_header_size {
            return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }

        // Invariant 16: reject oversized declared bodies before reading.
        let max_body = self.max_body;
        if let Some(cl) = req.headers().get(http::header::CONTENT_LENGTH) {
            if let Ok(cl_val) = cl.to_str() {
                if let Ok(cl_num) = cl_val.parse::<usize>() {
                    if cl_num > max_body {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                }
            }
        }

        // Invariant 19: HTTP/1.0 + Transfer-Encoding is invalid per RFC 9112 (C23)
        if req.version() == http::Version::HTTP_10
            && req
                .headers()
                .get(http::header::TRANSFER_ENCODING)
                .is_some()
        {
            return Err(StatusCode::BAD_REQUEST);
        }

        // Invariant 17: HTTP/1.x framing ambiguity — reject CL + TE
        if self.http_block.reject_ambiguous_framing {
            let has_cl = req.headers().get(http::header::CONTENT_LENGTH).is_some();
            let has_te = req
                .headers()
                .get(http::header::TRANSFER_ENCODING)
                .is_some();
            if has_cl && has_te {
                return Err(StatusCode::BAD_REQUEST);
            }
            let cl_count = req
                .headers()
                .get_all(http::header::CONTENT_LENGTH)
                .iter()
                .count();
            if cl_count > 1 {
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        // Invariant 26: reject header values containing CR/LF, including
        // values that are not valid UTF-8 (checked at the byte level).
        if self.http_block.reject_headers_with_control_chars {
            for (_, value) in req.headers().iter() {
                if value.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }

        // Invariant 25: strict URI parsing
        if let Err((status, _)) = uri_validate::validate_uri(req.uri().path()) {
            return Err(status);
        }

        Ok(())
    }

    /// C46: decompress a gzip request body with the expansion capped *during*
    /// decompression — the previous implementation inflated the entire body
    /// into memory before checking the ratio, defeating the bomb guard.
    fn maybe_decompress(&self, req: Request<Bytes>) -> Result<Request<Bytes>, StatusCode> {
        let is_gzip = req
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("gzip"))
            .unwrap_or(false);
        if !is_gzip {
            return Ok(req);
        }

        let max_ratio = self.http_block.max_decompression_ratio.unwrap_or(10);
        let max_size = self
            .http_block
            .max_decompression_size
            .unwrap_or(10 * 1024 * 1024);

        let (mut parts, body) = req.into_parts();
        if body.is_empty() {
            return Ok(Request::from_parts(parts, body));
        }

        let compressed_len = body.len();
        let mut decoder = GzDecoder::new(&body[..]).take(max_size as u64 + 1);
        let mut decompressed = Vec::new();
        if decoder.read_to_end(&mut decompressed).is_err() {
            // Not valid gzip — pass the original bytes through unchanged.
            return Ok(Request::from_parts(parts, body));
        }

        if decompressed.len() > max_size {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let ratio = decompressed.len().saturating_div(compressed_len.max(1));
        if ratio > max_ratio {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        // The body is no longer gzip; drop the stale encoding header so
        // upstreams don't try to decompress plain bytes.
        parts.headers.remove(http::header::CONTENT_ENCODING);
        Ok(Request::from_parts(parts, Bytes::from(decompressed)))
    }

    /// Replace the request path, preserving the query string.
    fn set_path(req: &mut Request<Bytes>, new_path: &str) -> Result<(), StatusCode> {
        let mut parts = req.uri().clone().into_parts();
        let pq = match req.uri().query() {
            Some(q) => format!("{}?{}", new_path, q),
            None => new_path.to_string(),
        };
        parts.path_and_query = Some(pq.parse().map_err(|_| StatusCode::BAD_REQUEST)?);
        *req.uri_mut() =
            http::Uri::from_parts(parts).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(())
    }

    /// Inject GeoIP headers derived from the connecting address. Any
    /// client-supplied x-geoip-* headers are stripped first so upstreams can
    /// trust the values.
    fn stamp_geoip(&self, headers: &mut HeaderMap, ip: IpAddr) {
        const GEO_HEADERS: &[&str] = &["x-geoip-country", "x-geoip-city", "x-geoip-continent"];
        for h in GEO_HEADERS {
            headers.remove(*h);
        }
        let Some(geoip) = &self.geoip else { return };
        let Some(info) = geoip.lookup(ip) else { return };
        let mut put = |name: &'static str, value: Option<String>| {
            if let Some(v) = value {
                if let Ok(hv) = HeaderValue::from_str(&v) {
                    headers.insert(name, hv);
                }
            }
        };
        put("x-geoip-country", info.iso_code);
        put("x-geoip-city", info.city);
        put("x-geoip-continent", info.continent);
    }

    fn check_method_allowed(method: &Method) -> bool {
        matches!(
            method,
            &Method::GET
                | &Method::HEAD
                | &Method::POST
                | &Method::PUT
                | &Method::DELETE
                | &Method::PATCH
                | &Method::OPTIONS
        )
    }

    fn find_location(&self, uri_path: &str) -> Option<&CompiledLocation> {
        let mut best_match: Option<&CompiledLocation> = None;
        let mut best_prefix_len = 0usize;

        for compiled in &self.locations {
            match compiled.location.match_type.as_str() {
                "exact" => {
                    if compiled.location.pattern == uri_path {
                        return Some(compiled);
                    }
                }
                "prefix" => {
                    if uri_path.starts_with(&compiled.location.pattern)
                        && compiled.location.pattern.len() > best_prefix_len
                    {
                        best_prefix_len = compiled.location.pattern.len();
                        best_match = Some(compiled);
                    }
                }
                "regex" => {
                    if let Some(re) = &compiled.regex {
                        if re.is_match(uri_path) {
                            return Some(compiled);
                        }
                    }
                }
                _ => {}
            }
        }

        best_match
    }

    async fn dispatch(
        &self,
        compiled: &CompiledLocation,
        uri_path: &str,
        req: Request<Bytes>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, StatusCode> {
        let handler = &compiled.location.handler;
        match handler.handler_type.as_str() {
            "static" => {
                let root = handler
                    .root
                    .as_deref()
                    .or(self.http_block.root.as_deref())
                    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                static_file::serve_file(root, uri_path).await
            }
            "proxy" | "reverse_proxy" => self.dispatch_proxy(handler, req, remote_addr).await,
            "return" => {
                let status = handler.status.unwrap_or(200);
                let body = handler.target.as_deref().unwrap_or("");
                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
                let mut resp = Response::new(Full::new(Bytes::from(body.to_string())));
                *resp.status_mut() = status_code;
                resp.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                Ok(resp)
            }
            "redirect" => {
                let target = handler
                    .target
                    .as_deref()
                    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                Self::redirect_response(target, handler.status.unwrap_or(301))
            }
            "deny" => Err(StatusCode::FORBIDDEN),
            _ => Err(StatusCode::NOT_IMPLEMENTED),
        }
    }

    fn redirect_response(
        target: &str,
        status: u16,
    ) -> Result<Response<Full<Bytes>>, StatusCode> {
        let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::MOVED_PERMANENTLY);
        let location =
            HeaderValue::from_str(target).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = status_code;
        resp.headers_mut().insert(http::header::LOCATION, location);
        Ok(resp)
    }

    /// Pick the upstream pool for a proxy location: A/B split group when
    /// configured, else the location's inline upstream, else the block's
    /// first shared upstream.
    fn select_upstream<'a>(
        &'a self,
        handler: &'a HandlerType,
        client: IpAddr,
    ) -> Result<&'a UpstreamRef, StatusCode> {
        if let Some(split_name) = handler.ab_split.as_deref() {
            if let Some(router) = &self.ab_router {
                if let Some(group_name) = router.resolve(split_name, &client.to_string()) {
                    if let Some(split) = self
                        .http_block
                        .ab_splits
                        .iter()
                        .find(|s| s.name == split_name)
                    {
                        if let Some(group) = split.groups.iter().find(|g| g.name == group_name) {
                            if let Some(upstream) =
                                config::resolve_upstream(&self.http_block, &group.upstream)
                            {
                                return Ok(upstream);
                            }
                        }
                    }
                }
            }
            warn!(
                "ab_split '{}' did not resolve to a configured upstream",
                split_name
            );
            return Err(StatusCode::BAD_GATEWAY);
        }

        handler
            .upstream
            .as_ref()
            .or_else(|| self.http_block.upstreams.first())
            .ok_or(StatusCode::BAD_GATEWAY)
    }

    /// Proxy with load balancing and connect-failure failover: candidates are
    /// tried in balancer order; a server that refuses the TCP connection is
    /// skipped, any HTTP-level outcome is final.
    async fn dispatch_proxy(
        &self,
        handler: &HandlerType,
        req: Request<Bytes>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, StatusCode> {
        let upstream = self.select_upstream(handler, remote_addr.ip())?;
        let (parts, body) = req.into_parts();
        let mut last_status = StatusCode::BAD_GATEWAY;

        for idx in self.balancer.candidates(upstream, remote_addr.ip()) {
            let Some(server) = upstream.servers.get(idx) else {
                continue;
            };

            // Invariant 41: enforced at request time, not only at config load.
            if upstream_filter::is_upstream_allowed(
                &server.address,
                self.http_block.upstream_allowed_networks.as_deref(),
            )
            .is_err()
            {
                last_status = StatusCode::FORBIDDEN;
                continue;
            }

            let _inflight = self.balancer.track(upstream, idx);
            match self
                .proxy
                .forward(
                    &server.address,
                    &parts,
                    body.clone(),
                    remote_addr.ip(),
                    self.scheme,
                )
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(ProxyError::Connect) => {
                    warn!(
                        "upstream {} unreachable; trying next candidate",
                        server.address
                    );
                    last_status = StatusCode::BAD_GATEWAY;
                }
                Err(ProxyError::Status(status)) => return Err(status),
            }
        }

        Err(last_status)
    }

    /// Invariant 24: CONNECT is denied (405) unless `allow_connect` is set,
    /// and then only for targets on the explicit allowlist. Permitted targets
    /// are resolved through the pinning resolver (Invariants 41/42), the
    /// tunnel is established first, and the 200 response hands the connection
    /// over to a bidirectional copy via hyper's upgrade mechanism.
    async fn handle_connect(
        &self,
        req: Request<hyper::body::Incoming>,
        _remote_addr: SocketAddr,
    ) -> Response<Full<Bytes>> {
        if !self.http_block.allow_connect {
            return self.simple_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "405 Method Not Allowed\n",
            );
        }

        let Some(authority) = req.uri().authority().map(|a| a.as_str().to_string()) else {
            return self.simple_response(
                StatusCode::BAD_REQUEST,
                "CONNECT requires an authority-form target\n",
            );
        };

        let (host, port) = upstream_filter::split_host_port(&authority);
        let Some(port) = port else {
            return self.simple_response(
                StatusCode::BAD_REQUEST,
                "CONNECT target must include an explicit port\n",
            );
        };
        let host = host.to_string();

        if !self.connect_target_permitted(&host, port, &authority) {
            return self.simple_response(StatusCode::FORBIDDEN, "CONNECT target not permitted\n");
        }

        // Resolve and vet the target (Invariant 41 applies to tunnels too);
        // connections go to the vetted addresses, never a re-resolution.
        let vetted: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            let allowed = upstream_filter::parse_networks(
                self.http_block.upstream_allowed_networks.as_deref(),
            );
            if !upstream_filter::ip_allowed(ip, &allowed) {
                return self
                    .simple_response(StatusCode::FORBIDDEN, "CONNECT target not permitted\n");
            }
            vec![SocketAddr::new(ip, port)]
        } else {
            match self.proxy.resolver().resolve_checked(&host).await {
                Ok(addrs) => addrs
                    .into_iter()
                    .map(|sa| SocketAddr::new(sa.ip(), port))
                    .collect(),
                Err(e) => {
                    warn!("CONNECT target '{}' rejected: {}", host, e);
                    return self
                        .simple_response(StatusCode::FORBIDDEN, "CONNECT target not permitted\n");
                }
            }
        };

        let mut upstream = None;
        for addr in vetted {
            match tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    upstream = Some(stream);
                    break;
                }
                _ => continue,
            }
        }
        let Some(mut upstream) = upstream else {
            return self.simple_response(StatusCode::BAD_GATEWAY, "502 Bad Gateway\n");
        };

        // The upgrade resolves after the 200 below is flushed; from then on
        // bytes are copied verbatim in both directions until either side
        // closes.
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let mut client_io = hyper_util::rt::TokioIo::new(upgraded);
                    let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream).await;
                }
                Err(e) => warn!("CONNECT upgrade failed: {}", e),
            }
        });

        self.simple_response(StatusCode::OK, "")
    }

    /// A CONNECT target is permitted when it matches `connect_allowed_targets`
    /// ("host:port" exact, or bare "host" for any port) or, absent that list,
    /// when it exactly matches a `connect_upstream` server address.
    fn connect_target_permitted(&self, host: &str, port: u16, full_authority: &str) -> bool {
        if let Some(targets) = &self.http_block.connect_allowed_targets {
            return targets.iter().any(|t| {
                let (t_host, t_port) = upstream_filter::split_host_port(t);
                t_host.eq_ignore_ascii_case(host) && t_port.is_none_or(|p| p == port)
            });
        }
        if let Some(up) = &self.http_block.connect_upstream {
            return up.servers.iter().any(|s| {
                if s.address.eq_ignore_ascii_case(full_authority) {
                    return true;
                }
                let (s_host, s_port) = upstream_filter::split_host_port(&s.address);
                s_host.eq_ignore_ascii_case(host) && s_port == Some(port)
            });
        }
        false
    }

    /// Stamp response-wide headers (currently HSTS for TLS listeners).
    fn finalize(&self, mut resp: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
        if let Some(hsts) = &self.hsts {
            resp.headers_mut()
                .entry(http::header::STRICT_TRANSPORT_SECURITY)
                .or_insert_with(|| hsts.clone());
        }
        resp
    }

    fn simple_response(&self, status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
        let mut resp = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
        *resp.status_mut() = status;
        if !body.is_empty() {
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
        self.finalize(resp)
    }

    fn error_response(&self, status: StatusCode) -> Response<Full<Bytes>> {
        let phrase = status.canonical_reason().unwrap_or("Error");
        let body = format!("{} {}\n", status.as_u16(), phrase);
        let mut resp = Response::new(Full::new(Bytes::from(body)));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        resp
    }
}
