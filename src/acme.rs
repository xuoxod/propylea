//! # ACME HTTP-01 Challenge Responder
//!
//! Autonomous, zero-downtime serving of Let's Encrypt / ACME validation tokens
//! directly from the webroot challenge directory without upstream interference.
//!
//! ### RFC 8555 Invariants & Security Guardrails:
//! 1. **RFC 8555 Token Specification**: Tokens must contain solely base64url characters
//!    `[a-zA-Z0-9_-]` and be strictly bounded between 1 and 128 characters.
//! 2. **Path Traversal Immunity**: Any token containing slashes (`/`), backslashes (`\`),
//!    directory traversal dots (`..`), null bytes (`\0`), or invalid characters is
//!    instantly rejected with HTTP 400 Bad Request prior to any filesystem call.
//! 3. **Memory Bounded Reading**: Challenge token files are capped at 4,096 bytes
//!    to eliminate memory exhaustion / allocation bomb vectors.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use std::path::Path;

pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Attempts to serve an ACME HTTP-01 challenge token from the webroot directory.
///
/// Returns `Some(response)` if the request path matches `/.well-known/acme-challenge/*`,
/// or `None` if the request is unrelated to ACME challenges (allowing standard redirect or routing).
pub async fn try_serve_acme_challenge(
    raw_path: &str,
    webroot: Option<&Path>,
) -> Option<Response<Full<Bytes>>> {
    if !raw_path.starts_with(ACME_CHALLENGE_PREFIX) {
        return None;
    }

    let token = &raw_path[ACME_CHALLENGE_PREFIX.len()..];

    // Security Invariant: Strict token validation to prevent path traversal or abuse.
    // RFC 8555 Section 8.3 defines tokens as URL-safe base64 characters.
    if token.is_empty()
        || token.len() > 128
        || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        let mut res = Response::new(Full::new(Bytes::from_static(b"Invalid ACME challenge token\n")));
        *res.status_mut() = StatusCode::BAD_REQUEST;
        return Some(res);
    }

    let Some(root) = webroot else {
        let mut res = Response::new(Full::new(Bytes::from_static(b"ACME challenge directory not configured\n")));
        *res.status_mut() = StatusCode::NOT_FOUND;
        return Some(res);
    };

    // Support both root-level webroot (e.g., /var/www/letsencrypt)
    // where certbot creates .well-known/acme-challenge/<token>,
    // and direct challenge directory configuration.
    let candidate_nested = root.join(".well-known").join("acme-challenge").join(token);
    let candidate_flat = root.join(token);

    let path_to_read = if candidate_nested.is_file() {
        candidate_nested
    } else if candidate_flat.is_file() {
        candidate_flat
    } else {
        let mut res = Response::new(Full::new(Bytes::from_static(b"ACME challenge token not found\n")));
        *res.status_mut() = StatusCode::NOT_FOUND;
        return Some(res);
    };

    // Bounded read: ACME key authorizations are ~80-120 bytes.
    // Enforce 4KB max file length to prevent allocation attacks.
    match tokio::fs::metadata(&path_to_read).await {
        Ok(meta) if meta.is_file() && meta.len() <= 4096 => {
            match tokio::fs::read(&path_to_read).await {
                Ok(content) => {
                    let mut res = Response::new(Full::new(Bytes::from(content)));
                    *res.status_mut() = StatusCode::OK;
                    res.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                    );
                    Some(res)
                }
                Err(_) => {
                    let mut res = Response::new(Full::new(Bytes::from_static(b"Failed to read challenge token\n")));
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    Some(res)
                }
            }
        }
        _ => {
            let mut res = Response::new(Full::new(Bytes::from_static(b"ACME challenge token not found\n")));
            *res.status_mut() = StatusCode::NOT_FOUND;
            Some(res)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_acme_serving_nested_directory() {
        let dir = tempdir().unwrap();
        let challenge_dir = dir.path().join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&challenge_dir).unwrap();

        let token = "test-token-abc-123_XYZ";
        let token_path = challenge_dir.join(token);
        let mut file = std::fs::File::create(&token_path).unwrap();
        write!(file, "test-token-abc-123_XYZ.dummy_thumbprint").unwrap();

        let path = format!("{}{}", ACME_CHALLENGE_PREFIX, token);
        let res = try_serve_acme_challenge(&path, Some(dir.path())).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn test_acme_token_rejection_traversal() {
        let dir = tempdir().unwrap();

        // 1. Directory traversal attempt
        let res = try_serve_acme_challenge(
            "/.well-known/acme-challenge/../../etc/passwd",
            Some(dir.path()),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // 2. Slashes in token
        let res = try_serve_acme_challenge(
            "/.well-known/acme-challenge/sub/token",
            Some(dir.path()),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // 3. Empty token
        let res = try_serve_acme_challenge(
            "/.well-known/acme-challenge/",
            Some(dir.path()),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // 4. Token exceeding length limit
        let huge_token = "a".repeat(129);
        let res = try_serve_acme_challenge(
            &format!("/.well-known/acme-challenge/{}", huge_token),
            Some(dir.path()),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_acme_unrelated_path_ignored() {
        let dir = tempdir().unwrap();
        let res = try_serve_acme_challenge("/index.html", Some(dir.path())).await;
        assert!(res.is_none());

        let res2 = try_serve_acme_challenge("/api/v1/checkout", Some(dir.path())).await;
        assert!(res2.is_none());
    }
}
