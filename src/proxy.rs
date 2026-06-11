use crate::security::headers::strip_hop_by_hop;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

/// Proxy a streaming Incoming request to an upstream (C37, C44).
pub async fn proxy_request(
    upstream_addr: &str,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, StatusCode> {
    let (parts, body) = req.into_parts();

    let body_bytes = body
        .collect()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_bytes();

    forward_to_upstream(upstream_addr, parts, body_bytes).await
}

/// Proxy a pre-collected Full<Bytes> request to an upstream (used after decompression, C46).
pub async fn proxy_request_bytes(
    upstream_addr: &str,
    req: Request<Full<Bytes>>,
) -> Result<Response<Full<Bytes>>, StatusCode> {
    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_bytes();

    forward_to_upstream(upstream_addr, parts, body_bytes).await
}

async fn forward_to_upstream(
    upstream_addr: &str,
    mut parts: http::request::Parts,
    body_bytes: Bytes,
) -> Result<Response<Full<Bytes>>, StatusCode> {
    let upstream_uri = format!(
        "http://{}{}",
        upstream_addr,
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );
    let upstream_uri: http::Uri = upstream_uri
        .parse()
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    // C37: strip hop-by-hop headers before forwarding (Invariant 44)
    strip_hop_by_hop(&mut parts.headers);

    // Remove Host — will be set by hyper for the upstream
    parts.headers.remove(http::header::HOST);

    let mut builder = Request::builder()
        .method(parts.method)
        .uri(upstream_uri)
        .version(http::Version::HTTP_11);

    let headers = builder.headers_mut().unwrap();
    for (name, value) in &parts.headers {
        headers.insert(name, value.clone());
    }

    let upstream_req = builder
        .body(Full::new(body_bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let resp = client
        .request(upstream_req)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let (resp_parts, resp_body) = resp.into_parts();

    // C44: validate upstream response framing — reject ambiguous CL+TE (Invariant 59)
    let upstream_has_cl = resp_parts.headers.get(http::header::CONTENT_LENGTH).is_some();
    let upstream_has_te = resp_parts.headers.get(http::header::TRANSFER_ENCODING).is_some();
    if upstream_has_cl && upstream_has_te {
        // Smuggling attempt — return 502 Bad Gateway to downstream
        return Err(StatusCode::BAD_GATEWAY);
    }

    let resp_body_bytes = resp_body
        .collect()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .to_bytes();

    let mut resp_builder = Response::builder().status(resp_parts.status);
    let resp_headers = resp_builder.headers_mut().unwrap();
    for (name, value) in resp_parts.headers {
        if let Some(name) = name {
            resp_headers.insert(name, value);
        }
    }

    resp_builder
        .body(Full::new(resp_body_bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
