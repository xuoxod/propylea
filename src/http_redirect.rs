//! # Port 80 HTTP-to-HTTPS Instant Redirector
//! Fast 301 Moved Permanently redirector preserving URI paths and query strings.

use crate::config::SecurityConfig;
use crate::headers::inject_response_security_headers;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::LOCATION;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info};

pub async fn run_http_redirect_server(
    bind_addr: SocketAddr,
    security: SecurityConfig,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!(
        addr = %bind_addr,
        "🔒 [PROPYLEA] HTTP-to-HTTPS redirector active on 0.0.0.0:80"
    );
    run_http_redirect_listener(listener, security).await
}

pub async fn run_http_redirect_listener(
    listener: TcpListener,
    security: SecurityConfig,
) -> Result<(), std::io::Error> {
    let security = Arc::new(security);

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

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let sec = sec.clone();
                async move {
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

    #[tokio::test]
    async fn test_redirect_generation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = run_http_redirect_listener(listener, SecurityConfig::default()).await;
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
}
