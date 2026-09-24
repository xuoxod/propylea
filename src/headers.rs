//! # Proxy Header Manipulation & Security Hardening
//! Injects RFC 7239 / standardized upstream proxy headers and downstream hardening.

use crate::config::SecurityConfig;
use hyper::header::{
    HeaderMap, HeaderValue, SERVER, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use hyper::{Request, Response};
use std::net::IpAddr;

/// Injects standard proxy identification headers before forwarding upstream
pub fn prepare_upstream_headers<B>(req: &mut Request<B>, client_ip: IpAddr) {
    let headers = req.headers_mut();
    let ip_str = client_ip.to_string();

    // 1. X-Forwarded-For
    if let Some(existing) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let combined = format!("{}, {}", existing, ip_str);
        if let Ok(hv) = HeaderValue::from_str(&combined) {
            headers.insert("x-forwarded-for", hv);
        }
    } else if let Ok(hv) = HeaderValue::from_str(&ip_str) {
        headers.insert("x-forwarded-for", hv);
    }

    // 2. X-Real-IP
    if let Ok(hv) = HeaderValue::from_str(&ip_str) {
        headers.insert("x-real-ip", hv);
    }

    // 3. X-Forwarded-Proto
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

    // 4. Via Header
    headers.insert("via", HeaderValue::from_static("1.1 Propylea-Boundary"));
}

/// Hardens downstream client responses with security headers and server banner
pub fn inject_downstream_security_headers(headers: &mut HeaderMap, security: &SecurityConfig) {
    // 1. Obfuscated Server Header
    if let Ok(hv) = HeaderValue::from_str(&security.server_banner) {
        headers.insert(SERVER, hv);
    }

    // 2. HSTS (Strict-Transport-Security)
    if security.hsts {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }

    // 3. MIME Sniffing Defense
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));

    // 4. Clickjacking Frame Options
    if let Ok(hv) = HeaderValue::from_str(&security.frame_options) {
        headers.insert(X_FRAME_OPTIONS, hv);
    }

    // 5. Referrer Policy
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
}

/// Helper to harden a complete hyper Response
pub fn inject_response_security_headers<B>(res: &mut Response<B>, security: &SecurityConfig) {
    inject_downstream_security_headers(res.headers_mut(), security);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;
    use std::net::Ipv4Addr;

    #[test]
    fn test_upstream_headers_preparation() {
        let mut req = Request::builder()
            .uri("https://example.com/api/test")
            .body(())
            .unwrap();

        let client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
        prepare_upstream_headers(&mut req, client_ip);

        assert_eq!(
            req.headers().get("x-forwarded-for").unwrap(),
            "198.51.100.42"
        );
        assert_eq!(req.headers().get("x-real-ip").unwrap(), "198.51.100.42");
        assert_eq!(req.headers().get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(req.headers().get("via").unwrap(), "1.1 Propylea-Boundary");
    }

    #[test]
    fn test_downstream_security_hardening() {
        let mut res = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();

        let security = SecurityConfig {
            server_banner: "Custom-Banner/1.0".to_string(),
            hsts: true,
            frame_options: "DENY".to_string(),
            ..Default::default()
        };

        inject_response_security_headers(&mut res, &security);

        assert_eq!(res.headers().get(SERVER).unwrap(), "Custom-Banner/1.0");
        assert!(res.headers().contains_key(STRICT_TRANSPORT_SECURITY));
        assert_eq!(res.headers().get(X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(res.headers().get(X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
    }
}
