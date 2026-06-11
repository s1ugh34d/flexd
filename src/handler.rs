use crate::config::{Config, Handler as HandlerType, HttpBlock, Location};
use crate::logging::AccessLogger;
use crate::proxy;
use crate::security::upstream_filter;
use crate::security::uri_validate;
use crate::static_file;
use bytes::Bytes;
use flate2::read::GzDecoder;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use std::io::Read;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct HandlerService {
    #[allow(dead_code)]
    config: Arc<RwLock<Config>>,
    http_block: Arc<HttpBlock>,
    access_logger: Arc<AccessLogger>,
    /// Present when this listener belongs to an `acme.enabled` block; used to
    /// answer HTTP-01 challenges (C51) from the shared challenge store.
    acme_store: Option<crate::acme::ChallengeStore>,
}

impl HandlerService {
    pub fn new(
        config: Arc<RwLock<Config>>,
        http_block: Arc<HttpBlock>,
        access_logger: Arc<AccessLogger>,
    ) -> Self {
        Self {
            config,
            http_block,
            access_logger,
            acme_store: None,
        }
    }

    /// Like [`HandlerService::new`] but wired to an ACME challenge store so the
    /// listener serves `/.well-known/acme-challenge/<token>` (HTTP-01).
    pub fn with_acme(
        config: Arc<RwLock<Config>>,
        http_block: Arc<HttpBlock>,
        access_logger: Arc<AccessLogger>,
        acme_store: Option<crate::acme::ChallengeStore>,
    ) -> Self {
        Self {
            config,
            http_block,
            access_logger,
            acme_store,
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
            Some(key_auth) => Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .body(Full::new(Bytes::from(key_auth)))
                    .unwrap_or_else(|_| self.error_response(StatusCode::INTERNAL_SERVER_ERROR)),
            ),
            None => Some(self.error_response(StatusCode::NOT_FOUND)),
        }
    }

    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
        remote_addr: std::net::SocketAddr,
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
            self.access_logger.log(
                &remote_addr.ip().to_string(),
                method.as_str(),
                &uri_path,
                resp.status().as_u16(),
                resp.body().size_hint().lower() as usize,
                &user_agent,
            );
            return resp;
        }

        // Invariant 24: CONNECT handling — check before URI validation
        // CONNECT uses authority-form URI (host:port), not path
        if method == Method::CONNECT {
            let resp = if self.http_block.allow_connect {
                Response::builder()
                    .status(StatusCode::NOT_IMPLEMENTED)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from("CONNECT not implemented\n")))
                    .unwrap_or_else(|_| self.error_response(StatusCode::INTERNAL_SERVER_ERROR))
            } else {
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from("405 Method Not Allowed\n")))
                    .unwrap_or_else(|_| self.error_response(StatusCode::INTERNAL_SERVER_ERROR))
            };
            self.access_logger.log(
                &remote_addr.ip().to_string(),
                "CONNECT",
                uri.to_string().as_str(),
                resp.status().as_u16(),
                resp.body().size_hint().lower() as usize,
                &user_agent,
            );
            return resp;
        }

        let response = match self.security_checks(&req).await {
            Err(status) => self.error_response(status),
            Ok(()) => {
                // C46: decompression bomb — decompress gzip-encoded request bodies and check ratio
                let is_gzip = req
                    .headers()
                    .get("content-encoding")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_lowercase().contains("gzip"))
                    .unwrap_or(false);

                if is_gzip {
                    match self.handle_gzip_body(req).await {
                        Err(status) => self.error_response(status),
                        Ok(req_full) => match self.route_full(&method, &uri_path, req_full).await {
                            Ok(resp) => resp,
                            Err(status) => self.error_response(status),
                        },
                    }
                } else {
                    match self.route(&method, &uri_path, req).await {
                        Ok(resp) => resp,
                        Err(status) => self.error_response(status),
                    }
                }
            }
        };

        let status = response.status().as_u16();
        let body_len = response.body().size_hint().lower() as usize;

        self.access_logger.log(
            &remote_addr.ip().to_string(),
            method.as_str(),
            &uri_path,
            status,
            body_len,
            &user_agent,
        );

        response
    }

    /// HTTP/3 entry point. The h3 layer hands us a `Request<()>` (pseudo-headers
    /// already lifted into the URI) plus the body collected separately. We
    /// reconstruct a `Request<Full<Bytes>>`, derive a `Host` header from the
    /// `:authority` (invariant 50 — authority consistency) when one is absent,
    /// then run the same security checks and routing as the TCP paths.
    pub async fn handle_h3(
        &self,
        req: Request<()>,
        body: Bytes,
        remote_addr: std::net::SocketAddr,
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

        let (mut parts, _) = req.into_parts();

        // Invariant 50: the effective authority comes from :authority for HTTP/3.
        // If the request carried an explicit Host that disagrees with :authority,
        // the authorities conflict -> 400. Otherwise synthesise Host from authority.
        if let Some(authority) = parts.uri.authority().map(|a| a.as_str().to_string()) {
            match parts.headers.get(http::header::HOST) {
                Some(h) => {
                    let host_str = h.to_str().unwrap_or("");
                    if !host_str.is_empty() && host_str != authority {
                        self.access_logger.log(
                            &remote_addr.ip().to_string(),
                            method.as_str(),
                            &uri_path,
                            400,
                            0,
                            &user_agent,
                        );
                        return self.error_response(StatusCode::BAD_REQUEST);
                    }
                }
                None => {
                    if let Ok(hv) = HeaderValue::from_str(&authority) {
                        parts.headers.insert(http::header::HOST, hv);
                    }
                }
            }
        }

        let full_req = Request::from_parts(parts, Full::new(body));

        let response = match self.security_checks(&full_req).await {
            Err(status) => self.error_response(status),
            Ok(()) => match self.route_full(&method, &uri_path, full_req).await {
                Ok(resp) => resp,
                Err(status) => self.error_response(status),
            },
        };

        let status = response.status().as_u16();
        let body_len = response.body().size_hint().lower() as usize;
        self.access_logger.log(
            &remote_addr.ip().to_string(),
            method.as_str(),
            &uri_path,
            status,
            body_len,
            &user_agent,
        );

        response
    }

    /// Invariants 11, 16, 17, 25, 26, 28, 60 — security checks before routing.
    /// Body-generic: inspects only headers/version/URI, so it serves the
    /// HTTP/1.x, HTTP/2 (hyper `Incoming`) and HTTP/3 (`Full<Bytes>`) paths alike.
    async fn security_checks<B>(&self, req: &Request<B>) -> Result<(), StatusCode> {
        // Invariant 60: max header count
        let max_headers = self.http_block.max_header_count.unwrap_or(100);
        if req.headers().len() > max_headers {
            return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }

        // Invariant 11: max header size
        let max_header_size = self.http_block.max_header_size.unwrap_or(8192);
        let header_size: usize = req.headers().iter()
            .map(|(n, v)| n.as_str().len() + v.as_bytes().len() + 2)
            .sum();
        if header_size > max_header_size {
            return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }

        // Invariant 16: request body size limit — check Content-Length before reading body
        let max_body = self.http_block.max_body_size.unwrap_or(10 * 1024 * 1024);
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
        if req.version() == http::Version::HTTP_10 {
            if req.headers().get(http::header::TRANSFER_ENCODING).is_some() {
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        // Invariant 17: HTTP/1.x framing ambiguity — reject CL + TE
        if self.http_block.reject_ambiguous_framing {
            let has_cl = req.headers().get(http::header::CONTENT_LENGTH).is_some();
            let has_te = req.headers().get(http::header::TRANSFER_ENCODING).is_some();
            if has_cl && has_te {
                return Err(StatusCode::BAD_REQUEST);
            }
            let cl_count = req.headers().get_all(http::header::CONTENT_LENGTH).iter().count();
            if cl_count > 1 {
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        // Invariant 26: reject headers with CR/LF
        if self.http_block.reject_headers_with_control_chars {
            for (_, value) in req.headers().iter() {
                if let Ok(s) = value.to_str() {
                    if s.contains('\r') || s.contains('\n') {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                }
            }
        }

        // Invariant 25: strict URI parsing
        if let Err((status, _)) = uri_validate::validate_uri(req.uri().path()) {
            return Err(status);
        }

        Ok(())
    }

    /// C46: Collect a gzip-encoded request body, check expansion ratio, return decompressed request.
    async fn handle_gzip_body(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Request<Full<Bytes>>, StatusCode> {
        let max_ratio = self.http_block.max_decompression_ratio.unwrap_or(10);
        let max_size = self.http_block.max_decompression_size.unwrap_or(10 * 1024 * 1024);

        let (parts, body) = req.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .to_bytes();

        let compressed_len = body_bytes.len();
        if compressed_len == 0 {
            let new_req = Request::from_parts(parts, Full::new(Bytes::new()));
            return Ok(new_req);
        }

        let mut decoder = GzDecoder::new(&body_bytes[..]);
        let mut decompressed = Vec::new();
        if decoder.read_to_end(&mut decompressed).is_err() {
            // Not valid gzip — pass through the original bytes compressed
            let new_req = Request::from_parts(parts, Full::new(body_bytes));
            return Ok(new_req);
        }

        let ratio = decompressed.len().saturating_div(compressed_len.max(1));
        if ratio > max_ratio || decompressed.len() > max_size {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let new_req = Request::from_parts(parts, Full::new(Bytes::from(decompressed)));
        Ok(new_req)
    }

    /// Route a request whose body has already been collected as Full<Bytes> (e.g. after decompression).
    async fn route_full(
        &self,
        method: &Method,
        uri_path: &str,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>, StatusCode> {
        // Reuse host/method checks
        if !self.check_host_header_full(&req) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if !self.check_method_allowed(method) {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }

        let matched_location = self.find_location(uri_path);
        match matched_location {
            Some(location) => self.dispatch_location_full(&location.handler, uri_path, req).await,
            None => {
                if let Some(ref root) = self.http_block.root {
                    static_file::serve_file(root, uri_path).await
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
    }

    fn check_host_header_full<B>(&self, req: &Request<B>) -> bool {
        match self.http_block.host_header_policy.as_str() {
            "any" => true,
            "strict" => {
                if let Some(host) = req.headers().get(http::header::HOST) {
                    if let Ok(host_str) = host.to_str() {
                        let host_name = host_str.split(':').next().unwrap_or(host_str).to_lowercase();
                        return self.http_block.server_name.iter().any(|s| {
                            let s_lower = s.to_lowercase();
                            host_name == s_lower || Self::matches_wildcard(&s_lower, &host_name)
                        });
                    }
                }
                false
            }
            "list" => {
                if let Some(host) = req.headers().get(http::header::HOST) {
                    if let Ok(host_str) = host.to_str() {
                        let host_name = host_str.split(':').next().unwrap_or(host_str);
                        let allowed = self
                            .http_block
                            .allowed_hosts
                            .as_ref()
                            .map(|hosts| hosts.iter().any(|h| h == host_name))
                            .unwrap_or(false);
                        let server_names = self
                            .http_block
                            .server_name
                            .iter()
                            .any(|s| s == host_name || Self::matches_wildcard(s, host_name));
                        return allowed || server_names;
                    }
                }
                false
            }
            _ => true,
        }
    }

    /// Invariant 41: reject upstream targets resolving to loopback/link-local/
    /// multicast/private ranges unless explicitly permitted via
    /// `upstream_allowed_networks`. Enforced at request time before forwarding,
    /// not only at config-load time.
    fn check_upstream_allowed(&self, addr: &str) -> Result<(), StatusCode> {
        upstream_filter::is_upstream_allowed(
            addr,
            self.http_block.upstream_allowed_networks.as_deref(),
        )
        .map_err(|_| StatusCode::FORBIDDEN)
    }

    async fn dispatch_location_full(
        &self,
        handler: &HandlerType,
        uri_path: &str,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>, StatusCode> {
        match handler.handler_type.as_str() {
            "static" => {
                let root = handler
                    .root
                    .as_deref()
                    .or(self.http_block.root.as_deref())
                    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                static_file::serve_file(root, uri_path).await
            }
            "proxy" | "reverse_proxy" => {
                let upstream = handler
                    .upstream
                    .as_ref()
                    .or_else(|| self.http_block.upstreams.first())
                    .ok_or(StatusCode::BAD_GATEWAY)?;
                let server = upstream.servers.first().ok_or(StatusCode::BAD_GATEWAY)?;
                self.check_upstream_allowed(&server.address)?;
                proxy::proxy_request_bytes(&server.address, req).await
            }
            "return" => {
                let status = handler.status.unwrap_or(200);
                let body = handler.target.as_deref().unwrap_or("");
                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
                Ok(Response::builder()
                    .status(status_code)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from(body.to_string())))
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?)
            }
            "redirect" => {
                let target = handler.target.as_deref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                let status = handler.status.unwrap_or(301);
                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::MOVED_PERMANENTLY);
                let location = HeaderValue::from_str(target)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok(Response::builder()
                    .status(status_code)
                    .header(http::header::LOCATION, location)
                    .body(Full::new(Bytes::new()))
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?)
            }
            "deny" => Err(StatusCode::FORBIDDEN),
            _ => Err(StatusCode::NOT_IMPLEMENTED),
        }
    }

    async fn route(
        &self,
        method: &Method,
        uri_path: &str,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, StatusCode> {
        if !self.check_host_header(&req) {
            return Err(StatusCode::BAD_REQUEST);
        }

        if !self.check_method_allowed(method) {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }

        let matched_location = self.find_location(uri_path);

        match matched_location {
            Some(location) => self.dispatch_location(&location.handler, uri_path, req).await,
            None => {
                if let Some(ref root) = self.http_block.root {
                    static_file::serve_file(root, uri_path).await
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
    }

    fn check_host_header(&self, req: &Request<hyper::body::Incoming>) -> bool {
        match self.http_block.host_header_policy.as_str() {
            "any" => true,
            "strict" => {
                // Invariant 22: Host must match server_name
                if let Some(host) = req.headers().get(http::header::HOST) {
                    if let Ok(host_str) = host.to_str() {
                        let host_name = host_str.split(':').next().unwrap_or(host_str).to_lowercase();
                        return self.http_block.server_name.iter().any(|s| {
                            let s_lower = s.to_lowercase();
                            host_name == s_lower || Self::matches_wildcard(&s_lower, &host_name)
                        });
                    }
                }
                false
            }
            "list" => {
                if let Some(host) = req.headers().get(http::header::HOST) {
                    if let Ok(host_str) = host.to_str() {
                        let host_name = host_str.split(':').next().unwrap_or(host_str);
                        let allowed = self
                            .http_block
                            .allowed_hosts
                            .as_ref()
                            .map(|hosts| hosts.iter().any(|h| h == host_name))
                            .unwrap_or(false);
                        let server_names = self
                            .http_block
                            .server_name
                            .iter()
                            .any(|s| s == host_name || Self::matches_wildcard(s, host_name));
                        return allowed || server_names;
                    }
                }
                false
            }
            _ => true,
        }
    }

    fn matches_wildcard(pattern: &str, domain: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..];
            domain.ends_with(suffix) || domain == &pattern[2..]
        } else {
            pattern == domain
        }
    }

    fn check_method_allowed(&self, method: &Method) -> bool {
        // CONNECT is handled separately in handle()
        if method == Method::CONNECT {
            return true;
        }
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

    fn find_location(&self, uri_path: &str) -> Option<Location> {
        let mut best_match: Option<&Location> = None;
        let mut best_prefix_len = 0usize;

        for location in &self.http_block.locations {
            match location.match_type.as_str() {
                "exact" => {
                    if location.pattern == uri_path {
                        return Some(location.clone());
                    }
                }
                "prefix" => {
                    if uri_path.starts_with(&location.pattern)
                        && location.pattern.len() > best_prefix_len
                    {
                        best_prefix_len = location.pattern.len();
                        best_match = Some(location);
                    }
                }
                "regex" => {
                    if let Ok(re) = regex::Regex::new(&location.pattern) {
                        if re.is_match(uri_path) {
                            return Some(location.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        best_match.cloned()
    }

    async fn dispatch_location(
        &self,
        handler: &HandlerType,
        uri_path: &str,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, StatusCode> {
        match handler.handler_type.as_str() {
            "static" => {
                let root = handler
                    .root
                    .as_deref()
                    .or(self.http_block.root.as_deref())
                    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                static_file::serve_file(root, uri_path).await
            }
            "proxy" | "reverse_proxy" => {
                let upstream = handler
                    .upstream
                    .as_ref()
                    .or_else(|| {
                        self.http_block
                            .upstreams
                            .first()
                    })
                    .ok_or(StatusCode::BAD_GATEWAY)?;

                let server = upstream
                    .servers
                    .first()
                    .ok_or(StatusCode::BAD_GATEWAY)?;

                self.check_upstream_allowed(&server.address)?;
                proxy::proxy_request(&server.address, req).await
            }
            "return" => {
                let status = handler.status.unwrap_or(200);
                let body = handler.target.as_deref().unwrap_or("");
                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
                let resp = Response::builder()
                    .status(status_code)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from(body.to_string())))
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok(resp)
            }
            "redirect" => {
                let target = handler.target.as_deref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                let status = handler.status.unwrap_or(301);
                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::MOVED_PERMANENTLY);
                let location = HeaderValue::from_str(target)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                let resp = Response::builder()
                    .status(status_code)
                    .header(http::header::LOCATION, location)
                    .body(Full::new(Bytes::new()))
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok(resp)
            }
            "deny" => Err(StatusCode::FORBIDDEN),
            _ => Err(StatusCode::NOT_IMPLEMENTED),
        }
    }

    fn error_response(&self, status: StatusCode) -> Response<Full<Bytes>> {
        let phrase = status.canonical_reason().unwrap_or("Error");
        let body = format!("{} {}\n", status.as_u16(), phrase);
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("500 Internal Server Error\n")))
                    .unwrap()
            })
    }
}
