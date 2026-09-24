//! # Sovereign Perimeter Defense & Honeyroute Trap Engine
//! Direct integration of `phylax` Shield Pipeline at the outer L7 reverse proxy boundary.
//! Drops hostile reconnaissance probes in sub-microsecond time and dispatches
//! asynchronous incident dossiers to threat intelligence (AbuseIPDB, Webhooks).

use crate::config::SecurityConfig;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Response, StatusCode};
use phylax::abuse_reporting::InformantConfig;
use phylax::{ShieldPipeline, ShieldRequest, ShieldVerdict};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct EdgeDefense {
    pipeline: Arc<ShieldPipeline>,
}

impl Default for EdgeDefense {
    fn default() -> Self {
        Self::new(&SecurityConfig::default())
    }
}

impl EdgeDefense {
    pub fn new(config: &SecurityConfig) -> Self {
        let mut builder = ShieldPipeline::builder()
            .enable_pow(false)
            .enable_timing(false);

        if config.enable_defense {
            if config.abuseipdb_api_key.is_some() || config.webhook_url.is_some() {
                let informant_config = InformantConfig {
                    enabled: true,
                    dry_run: false,
                    api_key: config.abuseipdb_api_key.clone(),
                    webhook_url: config.webhook_url.clone(),
                    webhook_auth: None,
                    cooldown: Default::default(),
                };
                builder = builder.with_abuse_reporting(informant_config);
            } else {
                builder = builder.with_default_abuse_reporting();
            }
        }

        Self {
            pipeline: Arc::new(builder.build()),
        }
    }

    pub fn with_pipeline(pipeline: Arc<ShieldPipeline>) -> Self {
        Self { pipeline }
    }

    pub fn pipeline(&self) -> &ShieldPipeline {
        &self.pipeline
    }

    /// Record an anomalous unmapped URI probe into the underlying Threat Harvester (Layer 13).
    /// Autonomously correlates multi-subnet zero-day campaigns into live decoy traps.
    pub fn record_anomalous_uri(
        &self,
        path: &str,
        client_ip: IpAddr,
    ) -> Option<phylax::threat_harvester::PromotionVerdict> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.pipeline.record_anomalous_uri(path, client_ip, now_ms)
    }

    /// Evaluates incoming request. If hostile, returns stealth 404 response
    /// and asynchronously dispatches an incident report.
    pub fn evaluate_request(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        user_agent: Option<&str>,
    ) -> Option<Response<Full<Bytes>>> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let ip_str = client_ip.to_string();
        let empty_fields: [(String, String); 0] = [];

        let shield_req = ShieldRequest {
            client_ip: &ip_str,
            submitted_fields: &empty_fields,
            target_uri: Some(path),
            http_method: Some(method),
            user_agent,
            now_ms,
            ..Default::default()
        };

        match self.pipeline.evaluate_perimeter(&shield_req) {
            ShieldVerdict::Allow { .. } => None,
            ShieldVerdict::Deny(reason) => {
                tracing::warn!(
                    ip = %client_ip,
                    path = %path,
                    method = %method,
                    reason = %reason.public_message(),
                    "🚨 [PROPYLEA-EDGE] Hostile reconnaissance scan trapped at ingress (stealth 404 returned + incident reported)."
                );

                let body = Bytes::from_static(b"404 Not Found\n");
                let mut res = Response::new(Full::new(body));
                *res.status_mut() = StatusCode::NOT_FOUND;
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                res.headers_mut().insert(
                    CONTENT_LENGTH,
                    hyper::header::HeaderValue::from_static("14"),
                );

                Some(res)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_benign_request_passes() {
        let defense = EdgeDefense::default();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(defense.evaluate_request(ip, "GET", "/", None).is_none());
        assert!(defense.evaluate_request(ip, "POST", "/api/v1/data", None).is_none());
        assert!(defense.evaluate_request(ip, "GET", "/assets/main.css", None).is_none());
    }

    #[tokio::test]
    async fn test_hostile_probe_trapped() {
        let defense = EdgeDefense::default();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        let res = defense.evaluate_request(ip, "GET", "/.env", None);
        assert!(res.is_some());
        let res = res.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(res.headers().get("content-length").unwrap(), "14");

        let res2 = defense.evaluate_request(ip, "GET", "/wp-login.php", Some("Mozilla/5.0"));
        assert!(res2.is_some());
        assert_eq!(res2.unwrap().status(), StatusCode::NOT_FOUND);
    }
}
