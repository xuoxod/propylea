# ==============================================================================
# 🏛️ Propylea — Sovereign Reverse Proxy & Perimeter Defense Makefile
# Standard: AGY-RULE-SOVEREIGN-FLAGSHIP-01
# ==============================================================================

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
CONFDIR ?= /etc/propylea
SYSTEMDDIR ?= /etc/systemd/system
ACMEDIR ?= /var/www/letsencrypt/.well-known/acme-challenge

.PHONY: all build release test check install service uninstall clean help

all: build

help:
	@echo "Propylea Build & Management Targets:"
	@echo "  make build       - Build debug binary"
	@echo "  make release     - Build optimized release binary"
	@echo "  make test        - Run complete unit, proxy, and adversarial test suites"
	@echo "  make check       - Validate configuration syntax using example template"
	@echo "  make install     - Install binary to $(BINDIR), set capabilities, and stage configs (requires sudo)"
	@echo "  make service     - Install and register systemd daemon (requires sudo)"
	@echo "  make uninstall   - Stop service, remove binaries, and clean systemd units (requires sudo)"
	@echo "  make clean       - Remove target/ build artifacts"

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

check:
	cargo run -- check --syntax-only --config propylea.example.toml

check-prod:
	cargo run -- check --config /etc/propylea/propylea.toml

install:
	@echo "📦 Installing Propylea binary to $(BINDIR)/propylea..."
	@mkdir -p $(BINDIR)
	@if [ -f target/release/propylea ]; then \
		install -m 755 target/release/propylea $(BINDIR)/propylea; \
	elif [ -f target/debug/propylea ]; then \
		install -m 755 target/debug/propylea $(BINDIR)/propylea; \
	else \
		cargo build --release && install -m 755 target/release/propylea $(BINDIR)/propylea; \
	fi
	@echo "🔒 Setting cap_net_bind_service capability for low-port (80/443) binding..."
	@setcap 'cap_net_bind_service=+ep' $(BINDIR)/propylea || true
	@echo "📁 Setting up configuration directory at $(CONFDIR)..."
	@mkdir -p $(CONFDIR)
	@if [ ! -f $(CONFDIR)/propylea.toml ]; then \
		cp propylea.example.toml $(CONFDIR)/propylea.toml; \
		echo "📄 Staged initial configuration template at $(CONFDIR)/propylea.toml"; \
	fi
	@echo "🌐 Ensuring ACME challenge directory exists at $(ACMEDIR)..."
	@mkdir -p $(ACMEDIR)
	@chmod -R 755 /var/www/letsencrypt || true
	@echo "✅ Propylea installation complete."

service: install
	@echo "⚙️  Registering Propylea systemd service..."
	@mkdir -p $(SYSTEMDDIR)
	@printf '%s\n' \
		"[Unit]" \
		"Description=Propylea Sovereign L7 Reverse Proxy & Perimeter Defense" \
		"After=network.target network-online.target" \
		"Wants=network-online.target" \
		"" \
		"[Service]" \
		"Type=simple" \
		"User=root" \
		"ExecStart=$(BINDIR)/propylea serve --config $(CONFDIR)/propylea.toml" \
		"ExecReload=/bin/kill -HUP \$$MAINPID" \
		"Restart=always" \
		"RestartSec=3" \
		"LimitNOFILE=65536" \
		"StandardOutput=journal" \
		"StandardError=journal" \
		"" \
		"[Install]" \
		"WantedBy=multi-user.target" > $(SYSTEMDDIR)/propylea.service
	@systemctl daemon-reload
	@echo "✅ Systemd service installed. Start with: sudo systemctl enable --now propylea"

uninstall:
	@echo "🛑 Stopping and disabling Propylea service..."
	@systemctl stop propylea 2>/dev/null || true
	@systemctl disable propylea 2>/dev/null || true
	@rm -f $(SYSTEMDDIR)/propylea.service
	@systemctl daemon-reload 2>/dev/null || true
	@echo "🗑️  Removing installed binary..."
	@rm -f $(BINDIR)/propylea
	@echo "✅ Propylea service and binary uninstalled. (Configuration in $(CONFDIR) preserved)."

clean:
	cargo clean
