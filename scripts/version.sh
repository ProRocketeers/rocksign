#!/bin/bash
# Print the app version from Cargo.toml.
set -euo pipefail
cd "$(dirname "$0")/.."
awk '/^\[package\]/ { p = 1; next } /^\[/ { p = 0 } p && /^version *=/ { gsub(/[" ]/, "", $0); sub(/^version=/, "", $0); print; exit }' Cargo.toml
