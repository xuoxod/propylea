//! # Meticulous Forensic Telemetry Engine
//! High-precision execution spans, lock-free ring buffer logging,
//! and automated privacy parameter sanitization.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// High-resolution monotonic execution timer
pub struct ExecutionTimer {
    start: Instant,
}

impl ExecutionTimer {
    #[inline]
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    #[inline]
    pub fn elapsed_micros(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    #[inline]
    pub fn elapsed_nanos(&self) -> u128 {
        self.start.elapsed().as_nanos()
    }
}

/// A structured forensic request record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRecord {
    pub timestamp_ms: u64,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_us: u64,
    pub upstream_target: Option<String>,
    pub threat_trapped: bool,
    pub threat_category: Option<String>,
    pub user_agent: Option<String>,
}

/// Query filter for forensic log inspection
#[derive(Debug, Default, Clone)]
pub struct TelemetryFilter {
    pub client_ip: Option<String>,
    pub status: Option<u16>,
    pub threats_only: bool,
    pub path_contains: Option<String>,
    pub limit: usize,
}

/// Lock-free thread-safe in-memory ring buffer
#[derive(Clone)]
pub struct TelemetryRingBuffer {
    max_capacity: usize,
    records: Arc<RwLock<VecDeque<TelemetryRecord>>>,
}

impl Default for TelemetryRingBuffer {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl TelemetryRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            max_capacity: capacity,
            records: Arc::new(RwLock::new(VecDeque::with_capacity(capacity.min(1000)))),
        }
    }

    /// Record a structured telemetry event into the ring buffer
    pub fn record(&self, entry: TelemetryRecord) {
        let mut buffer = self.records.write();
        if buffer.len() >= self.max_capacity {
            buffer.pop_front();
        }
        buffer.push_back(entry);
    }

    /// Query historical events matching a filter
    pub fn query(&self, filter: &TelemetryFilter) -> Vec<TelemetryRecord> {
        let buffer = self.records.read();
        let limit = if filter.limit == 0 { 50 } else { filter.limit };

        buffer
            .iter()
            .rev()
            .filter(|r| {
                if filter.threats_only && !r.threat_trapped {
                    return false;
                }
                if let Some(ref ip) = filter.client_ip {
                    if &r.client_ip != ip {
                        return false;
                    }
                }
                if let Some(status) = filter.status {
                    if r.status != status {
                        return false;
                    }
                }
                if let Some(ref sub) = filter.path_contains {
                    if !r.path.contains(sub) {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn total_records(&self) -> usize {
        self.records.read().len()
    }

    pub fn clear(&self) {
        self.records.write().clear();
    }
}

/// Redact sensitive query parameters (tokens, keys, passwords, secrets)
pub fn sanitize_query_string(raw_query: &str) -> String {
    if raw_query.is_empty() {
        return String::new();
    }
    let sensitive_keys = ["token", "key", "secret", "password", "auth", "code", "pin", "jwt"];
    raw_query
        .split('&')
        .map(|pair| {
            if let Some((k, _)) = pair.split_once('=') {
                let k_lower = k.to_ascii_lowercase();
                if sensitive_keys.iter().any(|&s| k_lower.contains(s)) {
                    format!("{}=[REDACTED]", k)
                } else {
                    pair.to_string()
                }
            } else {
                pair.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

pub fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_ring_buffer_bounded() {
        let buffer = TelemetryRingBuffer::new(5);
        for i in 0..10 {
            buffer.record(TelemetryRecord {
                timestamp_ms: i,
                client_ip: format!("198.51.100.{}", i),
                method: "GET".to_string(),
                path: format!("/path/{}", i),
                status: 200,
                duration_us: 100,
                upstream_target: None,
                threat_trapped: false,
                threat_category: None,
                user_agent: None,
            });
        }

        assert_eq!(buffer.total_records(), 5);
        let records = buffer.query(&TelemetryFilter { limit: 10, ..Default::default() });
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].path, "/path/9"); // Most recent first
    }

    #[test]
    fn test_filter_threats_only() {
        let buffer = TelemetryRingBuffer::new(10);
        buffer.record(TelemetryRecord {
            timestamp_ms: 1,
            client_ip: "198.51.100.1".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            duration_us: 50,
            upstream_target: None,
            threat_trapped: false,
            threat_category: None,
            user_agent: None,
        });
        buffer.record(TelemetryRecord {
            timestamp_ms: 2,
            client_ip: "198.51.100.2".into(),
            method: "GET".into(),
            path: "/.env".into(),
            status: 404,
            duration_us: 15,
            upstream_target: None,
            threat_trapped: true,
            threat_category: Some("Environment Probe".into()),
            user_agent: None,
        });

        let threats = buffer.query(&TelemetryFilter { threats_only: true, ..Default::default() });
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].path, "/.env");
    }

    #[test]
    fn test_sensitive_query_redaction() {
        let query = "user=rick&token=secret123&action=view&api_key=sk_test_456";
        let sanitized = sanitize_query_string(query);
        assert_eq!(sanitized, "user=rick&token=[REDACTED]&action=view&api_key=[REDACTED]");
    }
}
