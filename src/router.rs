//! # Sovereign Domain & Upstream Router
//! Fast O(1) lookup mapping HTTP `Host` headers and TLS SNI names to backend upstreams.

use crate::config::RouteConfig;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    pub addr: SocketAddr,
    pub websocket_allowed: bool,
    pub primary_host: String,
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamRouter {
    routes: HashMap<String, UpstreamTarget>,
    default_target: Option<UpstreamTarget>,
}

impl UpstreamRouter {
    /// Construct a router from configured routes
    pub fn new(routes: &[RouteConfig]) -> Self {
        let mut map = HashMap::new();
        let mut default_target = None;

        for route in routes {
            let primary_host = route.domains.first().cloned().unwrap_or_default();
            let target = UpstreamTarget {
                addr: route.upstream,
                websocket_allowed: route.websocket,
                primary_host,
            };

            if default_target.is_none() {
                default_target = Some(target.clone());
            }

            for host in &route.domains {
                let clean = host.trim().to_ascii_lowercase();
                map.insert(clean, target.clone());
            }
        }

        Self {
            routes: map,
            default_target,
        }
    }

    /// Resolve an incoming Host header (e.g. "example.com:443" -> "example.com")
    pub fn resolve(&self, raw_host: &str) -> Option<&UpstreamTarget> {
        let clean = Self::clean_host(raw_host);
        self.routes.get(&clean).or(self.default_target.as_ref())
    }

    /// Clean hostname by converting to lowercase and stripping port if present
    pub fn clean_host(raw: &str) -> String {
        let trimmed = raw.trim();
        let host_only = if let Some(idx) = trimmed.find(':') {
            &trimmed[..idx]
        } else {
            trimmed
        };
        host_only.to_ascii_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_router_resolution() {
        let routes = vec![
            RouteConfig {
                domains: vec!["example.com".into(), "www.example.com".into()],
                cert: PathBuf::new(),
                key: PathBuf::new(),
                upstream: "127.0.0.1:8081".parse().unwrap(),
                websocket: true,
            },
            RouteConfig {
                domains: vec!["api.example.com".into()],
                cert: PathBuf::new(),
                key: PathBuf::new(),
                upstream: "127.0.0.1:8082".parse().unwrap(),
                websocket: false,
            },
        ];

        let router = UpstreamRouter::new(&routes);

        let target = router.resolve("api.example.com:443").unwrap();
        assert_eq!(target.addr.port(), 8082);
        assert!(!target.websocket_allowed);

        let target2 = router.resolve("www.example.com").unwrap();
        assert_eq!(target2.addr.port(), 8081);
        assert!(target2.websocket_allowed);

        let target3 = router.resolve("EXAMPLE.COM").unwrap();
        assert_eq!(target3.addr.port(), 8081);

        // Unknown host falls back to default route (first route)
        let target_default = router.resolve("unknown.org").unwrap();
        assert_eq!(target_default.addr.port(), 8081);
    }
}
