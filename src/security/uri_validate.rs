use http::StatusCode;

/// Validate URI per Invariants 25, 62, 63
pub fn validate_uri(uri: &str) -> Result<(), (StatusCode, &'static str)> {
    let lower = uri.to_lowercase();

    // Invariant 25: Encoded traversal sequences
    if lower.contains("%00") {
        return Err((StatusCode::BAD_REQUEST, "null byte in URI"));
    }
    if lower.contains("%2e%2e%2f") || lower.contains("%2e%2e\\") {
        return Err((StatusCode::BAD_REQUEST, "encoded traversal in URI"));
    }
    if lower.contains("%252e%252e%252f") {
        return Err((StatusCode::BAD_REQUEST, "double-encoded traversal in URI"));
    }
    if lower.contains("%0b") {
        return Err((StatusCode::BAD_REQUEST, "vertical tab in URI"));
    }

    // Invariant 63: Alternative path separators
    if uri.contains('\\') {
        return Err((StatusCode::BAD_REQUEST, "backslash in URI"));
    }
    if uri.contains('\u{2044}') || uri.contains('\u{2215}') {
        return Err((StatusCode::BAD_REQUEST, "unicode slash variant in URI"));
    }

    // Invariant 62: Overlong UTF-8
    if lower.contains("%c0%ae") || lower.contains("%e0%40%ae") {
        return Err((StatusCode::BAD_REQUEST, "overlong UTF-8 in URI"));
    }

    // Check for overlong UTF-8 encoding sequences
    let bytes = uri.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let seq = &uri[i..i + 3].to_lowercase();
            if seq == "%c0" || seq == "%c1" || seq == "%e0" {
                return Err((StatusCode::BAD_REQUEST, "overlong UTF-8 encoding in URI"));
            }
            // Invalid surrogate halves
            if seq == "%ed" && i + 6 < bytes.len() {
                let next = &uri[i + 3..i + 6].to_lowercase();
                if next.starts_with('%') {
                    let byte_val = u8::from_str_radix(&next[1..], 16).unwrap_or(0);
                    if (0xa0..=0xbf).contains(&byte_val) {
                        return Err((StatusCode::BAD_REQUEST, "invalid surrogate half in URI"));
                    }
                }
            }
        }
    }

    // Validate percent-encoding is valid
    let decoded = url_decode(uri);
    if decoded.is_none() {
        return Err((StatusCode::BAD_REQUEST, "invalid percent encoding"));
    }

    Ok(())
}

fn url_decode(s: &str) -> Option<String> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                &String::from_utf8_lossy(&bytes[i + 1..i + 3]),
                16,
            ) {
                result.push(byte);
                i += 3;
            } else {
                return None;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result).ok()
}

/// Check for control characters in header values (Invariant 26, 51)
pub fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| {
        (c as u32) < 0x20 && c != '\t' || c == '\x7f'
    })
}

/// Strip control characters for log safety (Invariant 51)
pub fn strip_control_chars(s: &str) -> String {
    s.chars()
        .filter(|c| !(((*c as u32) < 0x20 && *c != '\t') || *c == '\x7f' || *c == '\n' || *c == '\r'))
        .collect()
}
