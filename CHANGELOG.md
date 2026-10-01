# 📋 Propylea Changelog & Architectural Ledger

All notable changes, architectural milestones, and security invariants for **Propylea** (`propylea`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] - 2026-10-01 (Sovereign Defense Topology & Diagnostic Runbook)

### 🌟 Added
* **Sovereign Defense Topology Blueprint (`docs/DEFENSE_TOPOLOGY.md`)**:
  - Authored comprehensive Layman-to-Architect mental model detailing the 5 concentric security rings (`Bastion` $\to$ `Propylea` $\to$ `Phylax` $\to$ `Slow-Shield` $\to$ Applications $\to$ `Sovereign-Ledger`).
  - Added Definitive Disambiguation Matrix clarifying strict One-Job-Principle (OJP) boundaries across all sovereign crates.
  - Documented fleet node ingress topology across Node 1 (`lin` - Storefront & Matrix) and Node 2 (`sfu` - LiveKit WebRTC).
* **Operator Troubleshooting & Diagnostic Runbook (`docs/TROUBLESHOOTING.md`)**:
  - Published 30-second triage checklist for operators and engineers.
  - Added resolution workflows for `502 Bad Gateway`, port `80`/`443` address collisions (`os error 98`), low-port permissions (`cap_net_bind_service`), TLS certificate mismatch, and WebSocket 1006 drops.
  - Added live diagnostic commands for verifying HTTP-to-HTTPS 301 redirects, decoy trap responses, and RSS memory footprints.
* **Architecture Mental Model in README**:
  - Integrated the Fortress Mental Model directly into the primary `README.md` to eliminate confusion for external developers and operators.

---

## [0.2.0] - 2026-09-24 (Autonomous Closed-Loop Threat Harvester & Memory Vacuum)

### 🌟 Added
* **Layer 13 Closed-Loop Threat Harvester Integration**:
  - Intercepts upstream `404 Not Found` responses from backend services and feeds anomalous paths into `phylax::ThreatHarvesterEngine`.
  - Probes correlated across $\ge 3$ distinct `/24` subnets are autonomously elevated into the active in-memory decoy trie without requiring manual ruleset intervention.
* **Autonomous Linux Heap Vacuum (`maintenance.rs`)**:
  - Integrated `libc::malloc_trim(0)` kernel page recovery executing every 300 seconds.
  - Guarantees constant `< 15 MB` RSS memory footprint under 24/7 continuous production load.
* **Bounded In-Memory Telemetry Ring Buffer (`telemetry.rs`)**:
  - Retains 10,000 structured forensic records in an $O(1)$ circular ring buffer.
  - Automatic query-parameter PII and credential scrubbing (`token=[REDACTED]`, `password=[REDACTED]`).
* **Zero-Allocation HTTP-to-HTTPS 301 Redirect Engine (`http_redirect.rs`)**:
  - Standalone Port 80 redirect listener preserving full target URI paths and query strings.
* **Adversarial Test Suite Battery (`tests/adversarial_integration_tests.rs`)**:
  - Added automated red-team test suite asserting resilience against credential query scrubbing, mass scanner bursts, upstream service crashes, and abrupt client socket termination (20/20 passed in `< 0.15s`).

---

## [0.1.0] - 2026-09-24 (Initial Sovereign Ingress Release)

### 🌟 Added
* **Pure Rust L7 Reverse Proxy Engine**:
  - Built on `Hyper 1.4`, `Tokio 1.38`, and `Rustls 0.23` with zero C dependencies and zero garbage collection pauses.
  - Full HTTP/1.1 and HTTP/2 multiplexing.
* **Multi-Domain SNI TLS Multiplexer (`tls.rs`)**:
  - Dynamic SNI host certificate resolution loading distinct fullchain PEMs and private keys per domain block.
* **Full-Duplex Bi-Directional WebSocket Tunneling (`proxy.rs`)**:
  - Native `101 Switching Protocols` support enabling persistent, low-overhead WebSocket tunnels for WebRTC signaling and real-time messaging.
* **Embedded Phylax Perimeter Defense**:
  - Microsecond decoy path trie dropping automated scans (`/.env`, `/wp-login.php`, `/.git/config`) with stealth `404 Not Found` responses before hitting upstream servers.
  - Asynchronous, rate-limited reporting to **AbuseIPDB** v2 API.
* **Strict TOML Configuration Engine (`config.rs`)**:
  - Verified pre-flight syntax, certificate existence, and port binding validation via `propylea check --config <FILE>`.
