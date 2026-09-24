#!/usr/bin/env bash
# Propylea Automated Production Setup Script
# Installs binary, configures non-root capabilities, and registers systemd daemon.

set -euo pipefail

echo "🏛️ Setting up Propylea Sovereign Reverse Proxy..."

# 1. Build release binary if not present
if [ ! -f "target/release/propylea" ]; then
    echo "🔨 Building release binary with cargo..."
    cargo build --release
fi

# 2. Install binary
echo "📦 Installing binary to /usr/local/bin/propylea..."
sudo install -m 755 target/release/propylea /usr/local/bin/propylea

# 3. Grant port 80/443 binding capabilities
echo "🔒 Granting cap_net_bind_service capability..."
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/propylea

# 4. Create configuration directory
echo "📁 Setting up /etc/propylea configuration directory..."
sudo mkdir -p /etc/propylea
if [ ! -f "/etc/propylea/propylea.toml" ]; then
    sudo cp propylea.example.toml /etc/propylea/propylea.toml
    echo "📄 Created /etc/propylea/propylea.toml from example template."
fi

# 5. Create service user if not exists
if ! id -u propylea >/dev/null 2>&1; then
    echo "👤 Creating dedicated system user 'propylea'..."
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin propylea || true
fi

echo "✅ Propylea setup complete!"
echo "👉 Next steps:"
echo "   1. Edit /etc/propylea/propylea.toml with your domains and upstream ports."
echo "   2. Run 'propylea check --config /etc/propylea/propylea.toml' to verify."
echo "   3. Start with 'sudo systemctl start propylea' or 'propylea serve --config /etc/propylea/propylea.toml'."
