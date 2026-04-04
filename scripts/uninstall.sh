#!/usr/bin/env bash
#
# Remove RAAS systemd service and optionally application files.
#
# Usage:
#   sudo ./scripts/uninstall.sh              # stop + disable unit (keeps /opt/raas)
#   sudo ./scripts/uninstall.sh --purge      # also remove INSTALL_ROOT (includes config/); leftover /etc/raas from old installs if present
#
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/raas}"
PURGE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    --help | -h)
      echo "Usage: sudo $0 [--purge]"
      exit 0
      ;;
    *)
      echo "Unknown: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop raas.service 2>/dev/null || true
  systemctl disable raas.service 2>/dev/null || true
fi

rm -f /etc/systemd/system/raas.service
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

echo "Removed raas.service from systemd."

if [[ "${PURGE}" -eq 1 ]]; then
  rm -rf "${INSTALL_ROOT}"
  rm -rf /etc/raas 2>/dev/null || true
  echo "Removed ${INSTALL_ROOT} (and /etc/raas if it existed)"
else
  echo "Left application files in place: ${INSTALL_ROOT}"
  echo "Delete manually or run: sudo $0 --purge"
fi
