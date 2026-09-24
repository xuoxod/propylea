# 🚀 Propylea Installation & Deployment Guide

Propylea is designed with strict **One-Job-Principle (OJP)** architecture: zero runtime dependencies, static Musl/GNU binaries, and an ultra-lean memory footprint (< 15MB RSS). Whether you are a student deploying your first home server or a senior DevOps architect managing fleet edge gateways, you can have Propylea running in under 60 seconds.

---

## 📋 Requirements

* **Operating System**: Linux (x86_64, aarch64, armv7)
* **Ports**: Standard HTTP (80) and HTTPS (443)
* **RAM**: ~15 MB RSS
* **Rust Toolchain** (if compiling from source): Rust 1.80+ (`stable`)

---

## ⚡ Method 1: Building from Source (Recommended)

### 1. Clone & Build
```bash
git clone https://github.com/xuoxod/propylea.git
cd propylea

# Build optimized release binary
cargo build --release
```

The resulting binary will be located at `target/release/propylea`.

### 2. Install Binary & Create System Directories
```bash
# Install binary into /usr/local/bin
sudo install -m 755 target/release/propylea /usr/local/bin/propylea

# Create configuration directory
sudo mkdir -p /etc/propylea

# Copy example configuration
sudo cp propylea.example.toml /etc/propylea/propylea.toml
```

### 3. Grant Port Binding Permissions (Non-Root Operation)
Propylea does **not** need to run as `root`. Grant it the Linux network capability to bind to privileged ports 80 and 443:
```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/propylea
```

---

## 🛠️ Method 2: Systemd Daemon Service Setup

For production deployments on Ubuntu, Debian, Rocky Linux, or Fedora, manage Propylea via `systemd`.

### 1. Create Dedicated Service User
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin propylea
```

### 2. Create the Systemd Unit File
Create `/etc/systemd/system/propylea.service`:

```ini
[Unit]
Description=Propylea Sovereign L7 Reverse Proxy & Perimeter Defense
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=propylea
Group=propylea
ExecStartPre=/usr/local/bin/propylea check --config /etc/propylea/propylea.toml
ExecStart=/usr/local/bin/propylea serve --config /etc/propylea/propylea.toml
Restart=always
RestartSec=3s

# Security Hardening & Isolation
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/propylea
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

# Resource Limits
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 3. Enable & Start Propylea
```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service at boot
sudo systemctl enable propylea

# Start Propylea
sudo systemctl start propylea

# Check status
sudo systemctl status propylea
```

---

## 🔍 Verifying Installation

Validate your configuration at any time without restarting the live proxy:

```bash
propylea check --config /etc/propylea/propylea.toml
```

Output:
```text
   ____                               __              
  / __ \_________  ____  __  ______  / /__  ____ _    
 / /_/ / ___/ __ \/ __ \/ / / / / _ \/ / _ \/ __ `/    
/ ____/ /  / /_/ / /_/ / /_/ / /  __/ /  __/ /_/ /     
\/    \/   \____/ .___/\__, /_/\___/_/\___/\__,_/      
               /_/    /____/                           
  Sovereign L7 Reverse Proxy & Perimeter Defense Gate

INFO  Validating Propylea configuration at '/etc/propylea/propylea.toml'...
INFO    • HTTP Redirect Bind:  0.0.0.0:80
INFO    • HTTPS Proxy Bind:    0.0.0.0:443
INFO    • Active Defense:      Enabled
INFO    • Memory Vacuum:       Active (malloc_trim)
INFO    • Hygiene Interval:    300s
INFO    • Verifying 2 configured route(s)...
INFO      [0] Domains: ["example.com", "www.example.com"] -> 127.0.0.1:8080 (TLS certs verified: 2 certificates loaded)
INFO      [1] Domains: ["api.example.com"] -> 127.0.0.1:8081 (TLS certs verified: 2 certificates loaded)

✅ [PROPYLEA] Configuration is strictly valid and verified.
```
