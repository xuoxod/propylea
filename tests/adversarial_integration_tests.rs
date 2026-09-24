//! # Adversarial & Fault-Tolerance Integration Tests for Propylea
//! Rigorous stress testing against active attackers, vulnerability sprayers,
//! abrupt socket termination, upstream outages, and parameter credential leaks.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use propylea::config::{MaintenanceSettings, PropyleaConfig, RouteConfig, SecurityConfig, ServerConfig};
use propylea::maintenance::{MaintenanceConfig, ResourceGovernor};
use propylea::telemetry::{TelemetryFilter, TelemetryRingBuffer};
use propylea::tls::build_sni_tls_acceptor;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

fn generate_tls_files(domain: &str) -> (NamedTempFile, NamedTempFile) {
    let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();

    (cert_file, key_file)
}

#[tokio::test]
async fn test_adversarial_vulnerability_scanner_battery() {
    let upstream_requests_received = Arc::new(AtomicUsize::new(0));
    let upstream_counter = upstream_requests_received.clone();

    // 1. Mock Upstream HTTP Server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match upstream_listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let counter = upstream_counter.clone();
            let io = TokioIo::new(stream);
            let service = service_fn(move |_: Request<hyper::body::Incoming>| {
                counter.fetch_add(1, Ordering::SeqCst);
                async move {
                    let mut res = Response::new(Full::new(Bytes::from("Upstream OK")));
                    *res.status_mut() = StatusCode::OK;
                    Ok::<_, hyper::Error>(res)
                }
            });

            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // 2. Setup Propylea Gateway
    let (cert_file, key_file) = generate_tls_files("secure.example.com");
    let route = RouteConfig {
        domains: vec!["secure.example.com".into()],
        upstream: upstream_addr,
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
        },
        security: SecurityConfig {
            enable_defense: true,
            abuseipdb_api_key: None,
            webhook_url: None,
            server_banner: "Aegis-Boundary/3.0".into(),
            hsts: true,
            frame_options: "DENY".into(),
        },
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(500);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_cfg = config.clone();
    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            proxy_cfg,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 3. Attack Wave: Hostile scanner paths
    let hostile_probes = [
        "/.env",
        "/.git/config",
        "/.aws/credentials",
        "/wp-login.php",
        "/xmlrpc.php",
        "/phpmyadmin/index.php",
    ];

    for probe_path in &hostile_probes {
        let res = client
            .get(format!("https://{}{}", proxy_addr, probe_path))
            .header("Host", "secure.example.com")
            .header("User-Agent", "Mozilla/5.0 (compatible; Nmap Scripting Engine)")
            .send()
            .await
            .unwrap();

        // Must drop with stealth 404
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "Failed on probe {}", probe_path);
        assert_eq!(
            res.headers().get("server").unwrap().to_str().unwrap(),
            "Aegis-Boundary/3.0"
        );
    }

    // Invariant: ZERO hostile probes reached the upstream server
    assert_eq!(
        upstream_requests_received.load(Ordering::SeqCst),
        0,
        "Upstream server received malicious traffic!"
    );

    // Invariant: Governor recorded every trapped threat
    assert_eq!(
        governor.metrics().total_trapped_threats.load(Ordering::Relaxed) as usize,
        hostile_probes.len()
    );

    // Invariant: Telemetry ring buffer holds all threats with threat_trapped = true
    let trapped = telemetry.query(&TelemetryFilter { threats_only: true, limit: 50, ..Default::default() });
    assert_eq!(trapped.len(), hostile_probes.len());
}

#[tokio::test]
async fn test_upstream_crash_and_resilience() {
    // 1. Point route to a non-existent port (dead upstream)
    let dead_upstream_port = 29999;
    let (cert_file, key_file) = generate_tls_files("resilience.example.com");

    let route = RouteConfig {
        domains: vec!["resilience.example.com".into()],
        upstream: format!("127.0.0.1:{}", dead_upstream_port).parse().unwrap(),
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
        },
        security: SecurityConfig {
            enable_defense: true,
            server_banner: "Aegis-Boundary/3.0".into(),
            ..Default::default()
        },
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(50);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            config,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 2. Send request when backend is completely offline
    let res = client
        .get(format!("https://{}/api/data", proxy_addr))
        .header("Host", "resilience.example.com")
        .send()
        .await
        .unwrap();

    // Invariant: Returns clean 502 Bad Gateway without panicking or hanging
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        res.headers().get("server").unwrap().to_str().unwrap(),
        "Aegis-Boundary/3.0"
    );

    // Invariant: Telemetry recorded 502 status
    let records = telemetry.query(&TelemetryFilter { limit: 10, ..Default::default() });
    assert_eq!(records[0].status, 502);

    // Invariant: Active connection count decremented back to 0 once client closes keep-alive
    drop(client);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(governor.metrics().current_active_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_abrupt_client_disconnect_connection_drain() {
    let (cert_file, key_file) = generate_tls_files("drain.example.com");

    let route = RouteConfig {
        domains: vec!["drain.example.com".into()],
        upstream: "127.0.0.1:8080".parse().unwrap(),
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
        },
        security: SecurityConfig::default(),
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(50);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            config,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    // 1. Open raw TCP connection and abruptly drop it (simulating network cut / attack)
    {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        // Send a few garbage bytes and immediately close socket
        let _ = stream.write_all(b"GARBAGE_PAYLOAD\r\n").await;
        stream.shutdown().await.unwrap();
        drop(stream);
    }

    // 2. Allow brief moment for Tokio task to conclude
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Invariant: Governor active connection count MUST be 0 (no connection leak!)
    assert_eq!(
        governor.metrics().current_active_connections.load(Ordering::Relaxed),
        0,
        "Connection count leaked after abrupt client disconnect!"
    );
}

#[tokio::test]
async fn test_adversarial_query_parameter_credential_scrubbing() {
    let (cert_file, key_file) = generate_tls_files("leak.example.com");

    // Spawn mock upstream
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match upstream_listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let service = service_fn(|_: Request<hyper::body::Incoming>| async move {
                let mut res = Response::new(Full::new(Bytes::from("OK")));
                *res.status_mut() = StatusCode::OK;
                Ok::<_, hyper::Error>(res)
            });
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    let route = RouteConfig {
        domains: vec!["leak.example.com".into()],
        upstream: upstream_addr,
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
        },
        security: SecurityConfig::default(),
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(50);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            config,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // Adversarial query with high-value secrets
    let hostile_query_url = format!(
        "https://{}/auth/callback?user=alice&token=SUPER_SECRET_TOKEN&api_key=sk_live_998877&client_secret=TOP_SECRET&code=AUTH_CODE_XYZ",
        proxy_addr
    );

    let res = client
        .get(&hostile_query_url)
        .header("Host", "leak.example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Invariant: Verify telemetry ring buffer did NOT record any raw secret
    let records = telemetry.query(&TelemetryFilter { limit: 10, ..Default::default() });
    assert!(!records.is_empty());
    let recorded_path = &records[0].path;

    assert!(!recorded_path.contains("SUPER_SECRET_TOKEN"));
    assert!(!recorded_path.contains("sk_live_998877"));
    assert!(!recorded_path.contains("TOP_SECRET"));
    assert!(!recorded_path.contains("AUTH_CODE_XYZ"));

    // Invariant: Non-sensitive parameter 'user=alice' remains preserved
    assert!(recorded_path.contains("user=alice"));
    assert!(recorded_path.contains("token=[REDACTED]"));
    assert!(recorded_path.contains("api_key=[REDACTED]"));
    assert!(recorded_path.contains("client_secret=[REDACTED]"));
    assert!(recorded_path.contains("code=[REDACTED]"));
}
