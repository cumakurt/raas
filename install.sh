#!/usr/bin/env bash
#
# RAAS full installer: detects OS & dependencies, asks for confirmation, then installs
# to /opt/raas (including /opt/raas/config/config.yaml), venv + pip, systemd unit (root), starts service.
# If config.yaml already exists (reinstall/upgrade), it is never overwritten; the shipped example is
# written as config.yaml.new in the same directory so you can diff and merge new options manually.
#
# Optional OS packages (grim, ffmpeg, dbus tools for lock/screen): see DEPENDENCIES.md
#
# Usage (from repository root):
#   ./install.sh                         # will ask for sudo if not root
#   ./install.sh --yes                   # non-interactive (auto-install OS packages if needed)
#   ./install.sh --no-start              # do not start/restart service
#   sudo ./install.sh                    # optional: run as root directly
#
# Environment:
#   INSTALL_ROOT=/opt/raas  CFG_DIR=/opt/raas/config  START_SERVICE=0  ASSUME_YES=1
#
set -euo pipefail

# Require root: re-exec via sudo so the user can run ./install.sh without typing sudo first.
_SCRIPT="${BASH_SOURCE[0]}"
if command -v readlink >/dev/null 2>&1 && readlink -f "${_SCRIPT}" >/dev/null 2>&1; then
  _SCRIPT_PATH="$(readlink -f "${_SCRIPT}")"
else
  _SCRIPT_PATH="$(cd "$(dirname "${_SCRIPT}")" && pwd)/$(basename "${_SCRIPT}")"
fi
for _a in "$@"; do
  if [[ "${_a}" == "-h" ]] || [[ "${_a}" == "--help" ]]; then
    echo "Usage: $0 [--yes] [--no-start]"
    echo ""
    echo "  --yes, -y     Skip confirmation prompts (for scripts; also installs missing OS packages)"
    echo "  --no-start    Install but do not start/restart raas.service"
    echo ""
    echo "Run without sudo: the script will ask for your password via sudo when needed."
    echo "Environment: INSTALL_ROOT, CFG_DIR, START_SERVICE, ASSUME_YES"
    exit 0
  fi
done

if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "The RAAS installer requires root privileges."
  echo "You will be prompted for your sudo password if needed."
  exec sudo -E bash "${_SCRIPT_PATH}" "$@"
fi
unset _SCRIPT _SCRIPT_PATH

INSTALL_ROOT="${INSTALL_ROOT:-/opt/raas}"
CFG_DIR="${CFG_DIR:-${INSTALL_ROOT}/config}"
START_SERVICE="${START_SERVICE:-1}"
ASSUME_YES="${ASSUME_YES:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NO_START=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-start)
      NO_START=1
      shift
      ;;
    --yes | -y)
      ASSUME_YES=1
      shift
      ;;
    --help | -h)
      echo "Usage: $0 [--yes] [--no-start]"
      echo ""
      echo "  --yes, -y     Skip confirmation prompts (for scripts; also installs missing OS packages)"
      echo "  --no-start    Install but do not start/restart raas.service"
      echo ""
      echo "Environment: INSTALL_ROOT, CFG_DIR, START_SERVICE, ASSUME_YES"
      exit 0
      ;;
    *)
      echo "Unknown option: $1 (try --help)" >&2
      exit 1
      ;;
  esac
done

# --- OS detection ---
OS_ID=""
OS_VERSION=""
OS_PRETTY="Unknown"
if [[ -f /etc/os-release ]]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_VERSION="${VERSION_ID:-}"
  OS_PRETTY="${PRETTY_NAME:-${NAME:-$OS_ID}}"
fi

# --- Dependency checks ---
have_systemctl=0
have_python3=0
have_venv=0
have_rsync=0

check_runtime_deps() {
  have_systemctl=0
  have_python3=0
  have_venv=0
  have_rsync=0
  command -v systemctl >/dev/null 2>&1 && have_systemctl=1
  command -v python3 >/dev/null 2>&1 && have_python3=1
  command -v rsync >/dev/null 2>&1 && have_rsync=1
  if [[ "${have_python3}" -eq 1 ]] && python3 -m venv --help >/dev/null 2>&1; then
    have_venv=1
  fi
}

print_dep_status() {
  local name="$1" ok="$2"
  if [[ "${ok}" -eq 1 ]]; then
    printf '  %-18s %s\n' "${name}" "[OK]"
  else
    printf '  %-18s %s\n' "${name}" "[MISSING]"
  fi
}

install_os_packages() {
  echo ""
  echo "Installing required OS packages..."
  case "${OS_ID}" in
    debian | ubuntu | linuxmint | pop | kali | zorin | elementary)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y python3 python3-venv rsync
      ;;
    fedora)
      dnf install -y python3 rsync
      ;;
    rhel | centos | rocky | almalinux | ol | amzn)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 rsync
      elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 rsync
      else
        echo "No dnf/yum found." >&2
        return 1
      fi
      ;;
    arch | manjaro | endeavouros)
      pacman -Sy --needed --noconfirm python rsync
      ;;
    opensuse-tumbleweed | opensuse-leap | sled | sles | opensuse)
      zypper --non-interactive install -y python3 rsync
      ;;
    *)
      echo "Automatic package install is not defined for ID=${OS_ID}." >&2
      echo "Install manually: python3 (with venv), rsync, systemd." >&2
      return 1
      ;;
  esac
  return 0
}

prompt_yes_no() {
  local prompt="$1"
  local default_no="${2:-1}"
  local answer
  if [[ "${ASSUME_YES}" -eq 1 ]]; then
    return 0
  fi
  if [[ "${default_no}" -eq 1 ]]; then
    read -r -p "${prompt} [y/N] " answer || true
  else
    read -r -p "${prompt} [Y/n] " answer || true
  fi
  case "${answer,,}" in
    y | yes) return 0 ;;
    *) return 1 ;;
  esac
}

# --- Root & repo ---
if [[ ! -f "${REPO_ROOT}/raas.py" ]] || [[ ! -f "${REPO_ROOT}/systemd/raas.service.in" ]]; then
  echo "Run this script from the RAAS repository root (where raas.py lives)." >&2
  echo "Current: ${REPO_ROOT}" >&2
  exit 1
fi

check_runtime_deps

echo ""
echo "================================================================"
echo "  RAAS — installation plan"
echo "================================================================"
echo ""
echo "  Operating system"
echo "    ${OS_PRETTY}"
echo "    ID=${OS_ID}  VERSION=${OS_VERSION:-n/a}"
echo ""
echo "  Required components"
print_dep_status "systemd (systemctl)" "${have_systemctl}"
print_dep_status "python3" "${have_python3}"
print_dep_status "python3 venv module" "${have_venv}"
print_dep_status "rsync" "${have_rsync}"
echo ""
echo "  Installation targets"
echo "    Application:  ${INSTALL_ROOT}"
echo "    Configuration: ${CFG_DIR}/config.yaml"
echo "    Service:       raas.service (user=root)"
echo ""

if [[ "${have_systemctl}" -ne 1 ]]; then
  echo "systemd is required. This system has no usable systemctl." >&2
  exit 1
fi

need_os_packages=0
if [[ "${have_python3}" -ne 1 ]] || [[ "${have_venv}" -ne 1 ]] || [[ "${have_rsync}" -ne 1 ]]; then
  need_os_packages=1
fi

echo ""
if [[ "${need_os_packages}" -eq 1 ]]; then
  echo "Missing components will be installed with your package manager when you confirm."
  echo "Supported: Debian/Ubuntu family, Fedora/RHEL/Amazon Linux, Arch, openSUSE."
  echo ""
fi

INSTALL_EXTRA=""
if [[ "${need_os_packages}" -eq 1 ]]; then
  INSTALL_EXTRA=", and missing OS packages"
fi
if ! prompt_yes_no "Continue with installation (RAAS + systemd service${INSTALL_EXTRA})?"; then
  echo "Aborted by user."
  exit 0
fi

if [[ "${need_os_packages}" -eq 1 ]]; then
  if ! install_os_packages; then
    exit 1
  fi
  check_runtime_deps
fi

if [[ "${have_python3}" -ne 1 ]] || [[ "${have_venv}" -ne 1 ]] || [[ "${have_rsync}" -ne 1 ]]; then
  echo "Dependencies still not satisfied. Install python3 (with venv), rsync manually, then re-run." >&2
  exit 1
fi

echo ""
echo "----------------------------------------------------------------"
echo "  Installing RAAS"
echo "----------------------------------------------------------------"

echo ""
echo "[1/5] Copying application files..."
mkdir -p "${INSTALL_ROOT}"
# Never let rsync --delete remove the live config: it is not in the repo tree, so without
# protect it would be deleted and step [3/5] would mistakenly create a fresh config from example.
rsync -a --delete \
  --exclude='.git' \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.cursor' \
  --exclude='config/config.yaml' \
  --filter='P config/config.yaml' \
  "${REPO_ROOT}/" "${INSTALL_ROOT}/"

echo "[2/5] Python virtualenv and Python dependencies..."
python3 -m venv --clear "${INSTALL_ROOT}/.venv"
"${INSTALL_ROOT}/.venv/bin/pip" install --upgrade pip -q
"${INSTALL_ROOT}/.venv/bin/pip" install -r "${INSTALL_ROOT}/requirements.txt"

echo "[3/5] Configuration..."
mkdir -p "${CFG_DIR}"
CFG_CREATED=0
CFG_NEW_WRITTEN=0
if [[ ! -f "${CFG_DIR}/config.yaml" ]]; then
  cp "${INSTALL_ROOT}/config/config.yaml.example" "${CFG_DIR}/config.yaml"
  chmod 600 "${CFG_DIR}/config.yaml"
  CFG_CREATED=1
else
  # Upgrade/reinstall: keep live config; publish current example as config.yaml.new for manual merge.
  cp "${INSTALL_ROOT}/config/config.yaml.example" "${CFG_DIR}/config.yaml.new"
  chmod 600 "${CFG_DIR}/config.yaml.new"
  CFG_NEW_WRITTEN=1
fi

echo "[4/5] systemd unit..."
UNIT_DST="/etc/systemd/system/raas.service"
sed "s|@INSTALL_ROOT@|${INSTALL_ROOT}|g" "${INSTALL_ROOT}/systemd/raas.service.in" > "${UNIT_DST}"
chmod 644 "${UNIT_DST}"
systemctl daemon-reload
systemctl enable raas.service

SERVICE_ACTION="skipped"
echo "[5/5] Service..."
if [[ "${NO_START}" -eq 1 ]] || [[ "${START_SERVICE}" -eq 0 ]]; then
  SERVICE_ACTION="not started (--no-start or START_SERVICE=0)"
else
  if systemctl is-active --quiet raas.service 2>/dev/null; then
    systemctl restart raas.service
    SERVICE_ACTION="restarted"
  else
    systemctl start raas.service
    SERVICE_ACTION="started"
  fi
  sleep 1
fi

echo ""
echo "================================================================"
echo "  Installation finished"
echo "================================================================"
echo ""
echo "  System"
echo "    ${OS_PRETTY}"
echo ""
echo "  Paths"
echo "    Application directory:  ${INSTALL_ROOT}"
echo "    Configuration file:     ${CFG_DIR}/config.yaml"
if [[ "${CFG_NEW_WRITTEN}" -eq 1 ]]; then
  echo "    Shipped example (merge): ${CFG_DIR}/config.yaml.new"
fi
echo "    systemd unit:           ${UNIT_DST}"
echo ""
if [[ "${CFG_CREATED}" -eq 1 ]]; then
  echo "  Configuration"
  echo "    A new ${CFG_DIR}/config.yaml was created from the example."
  echo "    Edit at least:  telegram.bot_token  and  telegram.chat_id"
  echo "    Then run:         systemctl restart raas"
  echo ""
elif [[ "${CFG_NEW_WRITTEN}" -eq 1 ]]; then
  echo "  Configuration"
  echo "    Existing ${CFG_DIR}/config.yaml was NOT modified."
  echo "    The version shipped with this release was written as:"
  echo "      ${CFG_DIR}/config.yaml.new"
  echo "    Compare with your live config and merge new keys/options if you need them, then remove"
  echo "    or rename config.yaml.new. Restart the service only after editing config.yaml."
  echo ""
fi
echo "  Service"
echo "    Unit:           raas.service"
echo "    Runs as:        root"
echo "    Last action:    ${SERVICE_ACTION}"
if [[ "${NO_START}" -eq 0 ]] && [[ "${START_SERVICE}" -ne 0 ]]; then
  if systemctl is-active --quiet raas.service 2>/dev/null; then
    echo "    Active state:   active (running)"
  else
    echo "    Active state:   NOT active — check: journalctl -u raas -b"
  fi
  echo ""
  systemctl --no-pager --full status raas.service || true
fi
echo ""
echo "  Useful commands"
echo "    sudo systemctl status raas"
echo "    sudo systemctl restart raas"
echo "    sudo journalctl -u raas -f"
echo "    sudo journalctl -u raas -b --no-pager"
echo "    sudo tail -f /var/log/raas/alarms.jsonl   # live alerts (JSON Lines)"
echo ""
echo "  Uninstall"
echo "    sudo ${REPO_ROOT}/scripts/uninstall.sh"
echo "    sudo ${REPO_ROOT}/scripts/uninstall.sh --purge"
echo ""
echo "  Optional OS packages (lock screen + screen/webcam capture, DBus tools)"
echo "    See:  ${INSTALL_ROOT}/DEPENDENCIES.md"
echo "    TR:   ${INSTALL_ROOT}/DEPENDENCIES.tr.md"
echo ""
echo "================================================================"
