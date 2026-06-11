//! Path-traversal-safe static file serving.
//!
//! [`serve_file`](crate::static_file::serve_file) maps a request path to a file
//! strictly beneath a document
//! root and returns it with a guessed MIME type. Containment is the whole point
//! of this module: on Linux the open goes through `openat2(2)` with
//! `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, so the kernel atomically refuses
//! any path — including a symlink swapped in between check and open — that would
//! escape the root. There is no check-then-use (TOCTOU) window. Platforms
//! without `openat2` fall back to a canonicalize-and-prefix-check.
//!
//! String-level guards (rejecting `..` and NUL after percent-decoding) run
//! first as defense in depth, but the kernel is the authority.

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use std::io::Read;
use std::path::Path;

/// Serve the file at `uri_path` from beneath `root`.
///
/// The path is percent-decoded (rejecting invalid UTF-8), separator-normalized,
/// pre-filtered for traversal sequences, then opened strictly beneath `root`.
/// The file is read on the blocking thread pool and returned with a
/// `Content-Type` guessed from its extension.
///
/// # Errors
///
/// Returns an HTTP [`StatusCode`] describing the failure rather than an opaque
/// error:
/// - `BAD_REQUEST` — undecodable percent-encoding.
/// - `FORBIDDEN` — a traversal or symlink escape attempt.
/// - `NOT_FOUND` — missing file, or a path that resolves to a non-file.
/// - `INTERNAL_SERVER_ERROR` — an unexpected I/O or response-build failure.
pub async fn serve_file(
    root: &str,
    uri_path: &str,
) -> Result<Response<Full<Bytes>>, StatusCode> {
    let decoded = url_decode(uri_path).ok_or(StatusCode::BAD_REQUEST)?;
    let sanitized = sanitize_path(&decoded);

    // String-level pre-filters (defense in depth — containment is enforced by
    // the kernel below).
    if sanitized.contains("..") || sanitized.contains('\0') {
        return Err(StatusCode::FORBIDDEN);
    }
    if sanitized.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let root = root.to_string();
    let mime_type = guess_mime(Path::new(&sanitized));

    // Open + read on the blocking pool: openat2 and read_to_end are sync.
    let content = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, StatusCode> {
        let file = open_beneath(Path::new(&root), Path::new(&sanitized))?;
        let meta = file
            .metadata()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !meta.is_file() {
            return Err(StatusCode::NOT_FOUND);
        }
        let mut content = Vec::with_capacity(meta.len().min(64 * 1024 * 1024) as usize);
        (&file)
            .read_to_end(&mut content)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(content)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, mime_type)
        .header(http::header::CONTENT_LENGTH, content.len())
        .body(Full::new(Bytes::from(content)))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Open `rel` strictly beneath `root` without a check-then-use window.
///
/// On Linux this is `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`:
/// the kernel resolves the entire path atomically and refuses any traversal
/// (including symlink swaps between check and open) that would escape `root`.
/// The previous `canonicalize()`-then-`read()` sequence was racy (TOCTOU).
#[cfg(target_os = "linux")]
fn open_beneath(root: &Path, rel: &Path) -> Result<std::fs::File, StatusCode> {
    use nix::errno::Errno;
    use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
    use nix::sys::stat::Mode;
    use std::os::fd::{FromRawFd, OwnedFd};

    let root_fd = open(
        root,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOCTTY)
        .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_MAGICLINKS);

    use std::os::fd::AsRawFd;
    match openat2(root_fd.as_raw_fd(), rel, how) {
        Ok(fd) => Ok(unsafe { std::fs::File::from_raw_fd(fd) }),
        // Kernels older than 5.6: fall back to the best-effort userspace check.
        Err(Errno::ENOSYS) => open_beneath_fallback(root, rel),
        // EXDEV/ELOOP are how the kernel reports an escape attempt.
        Err(Errno::EXDEV) | Err(Errno::ELOOP) => Err(StatusCode::FORBIDDEN),
        Err(Errno::ENOENT) | Err(Errno::ENOTDIR) => Err(StatusCode::NOT_FOUND),
        Err(Errno::EACCES) => Err(StatusCode::FORBIDDEN),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

#[cfg(not(target_os = "linux"))]
fn open_beneath(root: &Path, rel: &Path) -> Result<std::fs::File, StatusCode> {
    open_beneath_fallback(root, rel)
}

/// Best-effort containment for platforms without `openat2`: canonicalize and
/// prefix-check. Subject to a narrow TOCTOU window, hence Linux uses the
/// kernel-enforced path above.
fn open_beneath_fallback(root: &Path, rel: &Path) -> Result<std::fs::File, StatusCode> {
    let file_path = root.join(rel);
    let canonical = file_path.canonicalize().map_err(|_| StatusCode::NOT_FOUND)?;
    let root_canonical = root
        .canonicalize()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !canonical.starts_with(&root_canonical) {
        return Err(StatusCode::FORBIDDEN);
    }
    std::fs::File::open(&canonical).map_err(|_| StatusCode::NOT_FOUND)
}

/// Percent-decode into raw bytes, then require valid UTF-8.
///
/// The previous decoder pushed each decoded byte as a `char`, mangling
/// multi-byte UTF-8 filenames (Latin-1 mojibake) before path lookup.
fn url_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
                let byte = u8::from_str_radix(hex, 16).ok()?;
                out.push(byte);
                i += 3;
            }
            b'%' => return None,
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn sanitize_path(path: &str) -> String {
    path.replace(['\\', '\u{2044}', '\u{2215}'], "/")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("flexd-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn serves_regular_file() {
        let root = temp_root("serve");
        std::fs::write(root.join("index.html"), b"<h1>hi</h1>").unwrap();
        let resp = serve_file(root.to_str().unwrap(), "/index.html").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_dotdot_traversal() {
        let root = temp_root("dotdot");
        assert_eq!(
            serve_file(root.to_str().unwrap(), "/../etc/passwd").await.unwrap_err(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            serve_file(root.to_str().unwrap(), "/%2e%2e/etc/passwd").await.unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn symlink_escape_blocked() {
        let root = temp_root("symlink");
        let outside = std::env::temp_dir().join(format!("flexd-outside-{}.txt", std::process::id()));
        {
            let mut f = std::fs::File::create(&outside).unwrap();
            f.write_all(b"secret").unwrap();
        }
        std::os::unix::fs::symlink(&outside, root.join("leak.txt")).unwrap();
        // Absolute symlink target outside the root → kernel refuses (EXDEV → 403).
        assert_eq!(
            serve_file(root.to_str().unwrap(), "/leak.txt").await.unwrap_err(),
            StatusCode::FORBIDDEN
        );
        let _ = std::fs::remove_file(&outside);
    }

    #[tokio::test]
    async fn missing_file_is_404() {
        let root = temp_root("missing");
        assert_eq!(
            serve_file(root.to_str().unwrap(), "/nope.txt").await.unwrap_err(),
            StatusCode::NOT_FOUND
        );
    }
}
