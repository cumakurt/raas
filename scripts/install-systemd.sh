#!/usr/bin/env bash
# Wrapper — use ./install.sh from the repository root.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "${ROOT}/install.sh" "$@"
