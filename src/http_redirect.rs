//! # Port 80 HTTP-to-HTTPS Instant Redirector
//! Fast 301 Moved Permanently redirector preserving URI paths and query strings.

use crate::acme::try_serve_acme_challenge;
use crate::config::SecurityConfig;
use crate::headers::inject_response_security_headers;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::LOCATION;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info};

pub async fn run_http_redirect_server(
    bind_addr: SocketAddr,
    security: SecurityConfig,
    acme_webroot: Option<PathBuf>,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!(
        addr = %bind_addr,
        "🔒 [PROPYLEA] HTTP-to-HTTPS redirector active on {}", bind_addr
    );
    run_http_redirect_listener(listener, security, acme_webroot).await
}

pub async fn run_http_redirect_listener(
    listener: TcpListener,
    security: SecurityConfig,
    acme_webroot: Option<PathBuf>,
) -> Result<(), std::io::Error> {
    let security = Arc::new(security);
    let acme_webroot = acme_webroot.map(Arc::new);

    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                debug!("Failed to accept HTTP connection: {}", e);
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let sec = security.clone();
        let webroot = acme_webroot.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let sec = sec.clone();
                let webroot = webroot.clone();
                async move {
                    let raw_path = req.uri().path();

                    // 1. Intercept ACME HTTP-01 challenges directly
                    if let Some(mut acme_res) = try_serve_acme_challenge(raw_path, webroot.as_deref().map(|p| p.as_path())).await {
                        inject_response_security_headers(&mut acme_res, &sec);
                        return Ok::<_, hyper::Error>(acme_res);
                    }

                    // 2. Standard 301 Moved Permanently redirect to HTTPS
                    let host = req
                        .uri()
                        .host()
                        .or_else(|| req.headers().get("host").and_then(|h| h.to_str().ok()))
                        .unwrap_or("localhost");

                    // Strip optional port if passed in host header
                    let host_clean = host.split(':').next().unwrap_or(host);

                    let path_and_query = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/");

                    let target_url = format!("https://{}{}", host_clean, path_and_query);

                    let mut res = Response::new(Full::new(Bytes::new()));
                    *res.status_mut() = StatusCode::MOVED_PERMANENTLY;
                    if let Ok(loc) = hyper::header::HeaderValue::from_str(&target_url) {
                        res.headers_mut().insert(LOCATION, loc);
                    }
                    inject_response_security_headers(&mut res, &sec);

                    Ok::<_, hyper::Error>(res)
                }
            });

            if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                debug!(ip = %remote_addr, "Error serving HTTP redirect connection: {}", err);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_redirect_generation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = run_http_redirect_listener(listener, SecurityConfig::default(), None).await;
        });

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let res = client
            .get(format!("http://{}/dashboard?tab=logs", addr))
            .header("Host", "mytest.example.com")
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
        let loc = res.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://mytest.example.com/dashboard?tab=logs");
    }

    #[tokio::test]
    async fn test_port_80_acme_challenge_passthrough() {
        let dir = tempdir().unwrap();
        let challenge_dir = dir.path().join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&challenge_dir).unwrap();

        let token_name = "integration-test-token-7788";
        let token_file = challenge_dir.join(token_name);
        let mut f = std::fs::File::create(&token_file).unwrap();
        write!(f, "integration-test-token-7788.thumbprint12345").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let webroot = dir.path().to_path_buf();
        tokio::spawn(async move {
            let _ = run_http_redirect_listener(listener, SecurityConfig::default(), Some(webroot)).await;
        });

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        // 1. Verify ACME challenge returns 200 OK directly on port 80 without redirecting
        let res = client
            .get(format!("http://{}/.well-known/acme-challenge/{}", addr, token_name))
            .header("Host", "rmediatech.com")
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let body = res.text().await.unwrap();
        assert_eq!(body, "integration-test-token-7788.thumbprint12345");

        // 2. Verify non-ACME path still redirects to HTTPS
        let res_redir = client
            .get(format!("http://{}/about", addr))
            .header("Host", "rmediatech.com")
            .send()
            .await
            .unwrap();

        assert_eq!(res_redir.status(), StatusCode::MOVED_PERMANENTLY);
        let loc = res_redir.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://rmediatech.com/about");
    }
}
