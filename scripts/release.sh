#!/usr/bin/env bash
# ==============================================================================
# Propylea Sovereign Release & Cryptographic Packaging Pipeline
# Standard: AGY-RULE-SOVEREIGN-FLAGSHIP-01 & SOVEREIGN-SIGN-01
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="${SCRIPT_DIR}/.."
DIST_DIR="${WORKSPACE_ROOT}/dist"
KEY_ID="6BC8DA5E7F1B8B49BE5CD70A4E428019A109578B"

mkdir -p "${DIST_DIR}"

echo "================================================================================"
echo "  🏛️  PROPYLEA SOVEREIGN RELEASE & CRYPTOGRAPHIC PACKAGING PIPELINE"
echo "================================================================================"

cd "${WORKSPACE_ROOT}"

# 1. Run full test suite & adversarial TDD
echo "🧪 Running workspace test assertions & red-team attack suite..."
cargo test --quiet

# 2. Build Release Target
echo "🔨 Compiling optimized release binary..."
cargo build --release

BIN_SOURCE="${WORKSPACE_ROOT}/target/release/propylea"
VERSION="$(grep -m1 'version = ' "${WORKSPACE_ROOT}/Cargo.toml" | cut -d'"' -f2)"
TARGET_ARCH="x86_64-unknown-linux-gnu"
RELEASE_NAME="propylea-v${VERSION}-${TARGET_ARCH}"
ARCHIVE_NAME="${RELEASE_NAME}.tar.gz"

# 3. Package archive
echo "📦 Packaging distribution archive..."
cd "${WORKSPACE_ROOT}/target/release"
tar -czvf "${DIST_DIR}/${ARCHIVE_NAME}" propylea
cd "${DIST_DIR}"

# 4. Generate SHA-256 Checksums
echo "🔐 Computing cryptographic SHA-256 checksums..."
sha256sum "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.sha256"
sha256sum "${ARCHIVE_NAME}" > "SHA256SUMS"

# 5. GPG Detached Signatures (SOVEREIGN-SIGN-01)
echo "🖋️  Generating OpenPGP detached signatures with sovereign release key..."
rm -f "${ARCHIVE_NAME}.asc" "SHA256SUMS.asc"
gpg --batch --yes --local-user "${KEY_ID}" --armor --detach-sign "${ARCHIVE_NAME}"
gpg --batch --yes --local-user "${KEY_ID}" --armor --detach-sign "SHA256SUMS"

echo "================================================================================"
echo "🎉 RELEASE ARTIFACTS STAGED SUCCESSFULLY IN: ${DIST_DIR}"
echo "   Archive:   ${DIST_DIR}/${ARCHIVE_NAME} ($(du -k "${ARCHIVE_NAME}" | cut -f1) KB)"
echo "   Checksum:  ${DIST_DIR}/${ARCHIVE_NAME}.sha256"
echo "   Signature: ${DIST_DIR}/${ARCHIVE_NAME}.asc"
echo "   Manifest:  ${DIST_DIR}/SHA256SUMS.asc"
echo "================================================================================"
