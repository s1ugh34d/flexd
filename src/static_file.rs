use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use std::path::{Path, PathBuf};

pub async fn serve_file(
    root: &str,
    uri_path: &str,
) -> Result<Response<Full<Bytes>>, StatusCode> {
    let decoded = url_decode(uri_path);
    let sanitized = sanitize_path(&decoded);

    if sanitized.contains("..") || sanitized.starts_with('/') {
        return Err(StatusCode::FORBIDDEN);
    }

    let file_path = PathBuf::from(root).join(&sanitized);
    let canonical = file_path
        .canonicalize()
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let root_canonical = PathBuf::from(root)
        .canonicalize()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !canonical.starts_with(&root_canonical) {
        return Err(StatusCode::FORBIDDEN);
    }

    if !canonical.is_file() {
        return Err(StatusCode::NOT_FOUND);
    }

    let content = tokio::fs::read(&canonical)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mime_type = guess_mime(&canonical);

    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, mime_type)
        .header(http::header::CONTENT_LENGTH, content.len())
        .body(Full::new(Bytes::from(content)))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h = chars.next();
            let l = chars.next();
            if let (Some(h), Some(l)) = (h, l) {
                if let Ok(byte) = u8::from_str_radix(
                    &String::from_utf8_lossy(&[h, l]),
                    16,
                ) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn sanitize_path(path: &str) -> String {
    path.replace('\\', "/")
        .replace('\u{2044}', "/")
        .replace('\u{2215}', "/")
        .trim_start_matches('/')
        .to_string()
}

fn guess_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("pdf") => "application/pdf",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}
