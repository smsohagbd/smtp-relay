#!/usr/bin/env bash
# One-shot installer: OS packages, Rust, config, build, systemd service.
# Empty answers keep the defaults: admin / admin, SMTP 1025, dashboard 8025
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

DEFAULT_USER="admin"
DEFAULT_PASS="admin"
DEFAULT_SMTP="1025"
DEFAULT_WEB="8025"

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif [ -n "$SUDO" ]; then
    "$SUDO" "$@"
  else
    echo "Need root (or sudo) to install packages: $*" >&2
    return 1
  fi
}

prompt() {
  local name="$1"
  local default="$2"
  local value=""
  read -r -p "${name} [${default}]: " value || true
  if [ -z "${value}" ]; then
    printf '%s' "$default"
  else
    printf '%s' "$value"
  fi
}

yaml_quote() {
  local s=$1
  s=${s//\'/\'\'}
  printf "'%s'" "$s"
}

is_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

load_cargo() {
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
  export PATH="$HOME/.cargo/bin:$PATH"
}

is_official_apt_source() {
  local base
  base="$(basename "$1")"
  case "$base" in
    ubuntu.sources|ubuntu.list|debian.sources|debian.list|ubuntu-sources.list) return 0 ;;
  esac
  return 1
}

disable_apt_source_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  case "$f" in
    *.disabled|*.bak|*.save|*.distUpgrade) return 0 ;;
  esac
  if is_official_apt_source "$f"; then
    return 0
  fi
  echo "    disabling broken apt repo: $f"
  as_root mv "$f" "${f}.disabled" || true
}

# Rename third-party list files that match a URL/host from a failed apt update.
disable_apt_files_matching() {
  local needle="$1"
  local f
  [ -n "$needle" ] || return 0
  if [ -f /etc/apt/sources.list ]; then
    if grep -qiF "$needle" /etc/apt/sources.list 2>/dev/null; then
      echo "    comment out matching lines in /etc/apt/sources.list ($needle)"
      as_root sed -i.bak-smtp-relay -E "s|^(deb(-src)?[[:space:]].*${needle})|# smtp-relay: \\1|" /etc/apt/sources.list || true
    fi
  fi
  shopt -s nullglob
  for f in /etc/apt/sources.list.d/*; do
    [ -f "$f" ] || continue
    if grep -qiF "$needle" "$f" 2>/dev/null; then
      disable_apt_source_file "$f"
    fi
  done
  shopt -u nullglob
}

disable_failed_apt_repos_from_log() {
  local log="$1"
  local url host path
  # Certbot PPA has no Ubuntu 24.04 (noble) packages — always drop it on failure.
  shopt -s nullglob
  for f in /etc/apt/sources.list.d/*certbot*; do
    disable_apt_source_file "$f"
  done
  shopt -u nullglob

  while IFS= read -r url; do
    [ -n "$url" ] || continue
    url="${url%/Release}"
    url="${url%/InRelease}"
    host="${url#http://}"
    host="${host#https://}"
    path="${host#*/}"
    host="${host%%/*}"
    case "$host" in
      archive.ubuntu.com|security.ubuntu.com|ports.ubuntu.com|deb.debian.org|security.debian.org|cdn-aws.deb.debian.org)
        continue
        ;;
    esac
    disable_apt_files_matching "$url"
    if [ -n "$host" ]; then
      disable_apt_files_matching "$host"
    fi
    if [ -n "$path" ]; then
      path="${path%% *}"
      disable_apt_files_matching "${host}/${path%%/*}"
    fi
  done <<EOF
$(grep -E '^Err:' "$log" 2>/dev/null | grep -oE 'https?://[^[:space:]]+' | sed 's|[[:punct:]]*$||' || true)
$(grep -oE "The repository '[^']+'" "$log" 2>/dev/null | sed "s/The repository '//;s/'\$//;s| Release\$||;s| InRelease\$||" || true)
EOF
}

disable_all_third_party_apt_repos() {
  local f
  echo "    disabling remaining third-party apt repos so Ubuntu/Debian archives can install packages"
  shopt -s nullglob
  for f in /etc/apt/sources.list.d/*; do
    disable_apt_source_file "$f"
  done
  shopt -u nullglob
}

apt_update_once() {
  local log="$1"
  set +e
  as_root apt-get update -y >"$log" 2>&1
  local rc=$?
  set -e
  cat "$log"
  return "$rc"
}

apt_update_debian() {
  local log
  log="$(mktemp /tmp/smtp-relay-apt.XXXXXX.log)"
  if apt_update_once "$log"; then
    rm -f "$log"
    return 0
  fi

  echo "apt-get update failed (broken third-party repo, not smtp-relay). Skipping the 404 source and retrying…"
  disable_failed_apt_repos_from_log "$log"
  if apt_update_once "$log"; then
    echo "apt-get update succeeded after disabling the broken repo."
    rm -f "$log"
    return 0
  fi

  disable_all_third_party_apt_repos
  if apt_update_once "$log"; then
    echo "apt-get update succeeded using distro archives only."
    rm -f "$log"
    return 0
  fi

  echo "apt-get update still failed. Inspect $log and the 404 repo, then re-run ./setup.sh" >&2
  cat "$log" >&2
  exit 1
}

install_system_packages() {
  echo
  echo "==> Installing build dependencies (compiler, OpenSSL, curl)…"

  if command -v apt-get >/dev/null 2>&1; then
    apt_update_debian
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential pkg-config libssl-dev
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl git ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    as_root yum install -y gcc gcc-c++ make pkgconfig openssl-devel curl git ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    as_root apk add --no-cache ca-certificates curl git build-base pkgconf openssl-dev
  elif command -v pacman >/dev/null 2>&1; then
    as_root pacman -Sy --noconfirm --needed base-devel openssl curl git pkgconf
  else
    echo "No known package manager (apt/dnf/yum/apk/pacman)."
    echo "Install gcc, make, pkg-config, libssl-dev and curl, then re-run."
  fi
}

install_rust() {
  load_cargo
  if command -v rustc >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
    echo "==> Rust already installed: $(rustc --version)"
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to install Rust." >&2
    exit 1
  fi

  echo "==> Installing Rust (rustup, stable)…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  load_cargo

  if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust install finished but cargo is not on PATH. Open a new shell or run:" >&2
    echo "  source \"\$HOME/.cargo/env\"" >&2
    exit 1
  fi
  echo "==> $(rustc --version)"
}

echo "smtp-relay setup"
echo "This script installs dependencies, writes config.yaml, builds the"
echo "binary and enables a systemd service. Press Enter to keep each default."
echo

install_system_packages
install_rust

ADMIN_USER="$(prompt "Admin username" "$DEFAULT_USER")"
ADMIN_PASS="$(prompt "Admin password" "$DEFAULT_PASS")"
SMTP_PORT="$(prompt "Inbound SMTP port" "$DEFAULT_SMTP")"
WEB_PORT="$(prompt "Dashboard / web port" "$DEFAULT_WEB")"

if [ -z "$ADMIN_USER" ]; then
  echo "admin username must not be empty" >&2
  exit 1
fi
if ! is_port "$SMTP_PORT"; then
  echo "SMTP port must be 1-65535 (got ${SMTP_PORT})" >&2
  exit 1
fi
if ! is_port "$WEB_PORT"; then
  echo "web port must be 1-65535 (got ${WEB_PORT})" >&2
  exit 1
fi

OUT="$ROOT/config.yaml"
WRITE_CONFIG=1
if [ -f "$OUT" ]; then
  ans=""
  read -r -p "${OUT} already exists. Overwrite? [y/N]: " ans || true
  case "$ans" in
    y|Y|yes|YES) WRITE_CONFIG=1 ;;
    *)
      WRITE_CONFIG=0
      echo "Keeping existing ${OUT}"
      ;;
  esac
fi

if [ "$WRITE_CONFIG" -eq 1 ]; then
  cat > "$OUT" <<EOF
# Generated by setup.sh. See config.example.yaml for every option.
# Add upstream SMTP providers from the dashboard after start.
# Change admin.password / server.auth_users later if you want.

server:
  bind_address: "0.0.0.0:${SMTP_PORT}"
  hostname: "smtp-proxy.local"
  require_auth: true
  auth_users:
    - username: $(yaml_quote "$ADMIN_USER")
      password: $(yaml_quote "$ADMIN_PASS")

admin:
  enabled: true
  bind_address: "0.0.0.0:${WEB_PORT}"
  username: $(yaml_quote "$ADMIN_USER")
  password: $(yaml_quote "$ADMIN_PASS")
  dashboard_enabled: true
  allow_config_write: true

queue:
  persist: true
  directory: "/var/lib/smtp-relay/spool"

logging:
  directory: "/var/log/smtp-relay"
  file_prefix: "smtp-relay"

relays: []
EOF
  echo
  echo "Wrote ${OUT}"
  echo "  SMTP listener : 0.0.0.0:${SMTP_PORT}"
  echo "  SMTP AUTH     : ${ADMIN_USER}  (same password as dashboard; edit config.yaml to change)"
  echo "  Dashboard     : http://0.0.0.0:${WEB_PORT}/  (user ${ADMIN_USER})"
fi

load_cargo
echo
echo "==> Building release binary…"
cargo build --release

BIN="$ROOT/target/release/smtp-relay"
if [ ! -x "$BIN" ]; then
  echo "Build finished but ${BIN} is missing." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
  echo
  echo "systemd not available. Start with:"
  echo "  ${BIN}"
  exit 0
fi

if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then
  echo "Need root to install the systemd service."
  echo "Start with: ${BIN}"
  exit 0
fi

echo
echo "==> Installing systemd service…"
as_root install -m 0755 "$BIN" /usr/local/bin/smtp-relay
as_root mkdir -p /etc/smtp-relay /var/lib/smtp-relay/spool /var/log/smtp-relay
as_root cp "$OUT" /etc/smtp-relay/config.yaml
as_root chmod 640 /etc/smtp-relay/config.yaml

as_root tee /etc/systemd/system/smtp-relay.service >/dev/null <<'UNIT'
[Unit]
Description=SMTP proxy and load-balancing relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/smtp-relay --config /etc/smtp-relay/config.yaml
WorkingDirectory=/var/lib/smtp-relay
Restart=on-failure
RestartSec=2s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

as_root systemctl daemon-reload
as_root systemctl enable smtp-relay
if as_root systemctl restart smtp-relay; then
  as_root systemctl --no-pager --full status smtp-relay || true
  HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo
  echo "smtp-relay is installed and running."
  echo "  Dashboard : http://${HOST_IP:-127.0.0.1}:${WEB_PORT}/"
  echo "  SMTP      : ${HOST_IP:-127.0.0.1}:${SMTP_PORT}  user ${ADMIN_USER}"
  echo
  echo "  sudo systemctl status smtp-relay"
  echo "  sudo systemctl restart smtp-relay"
  echo "  sudo journalctl -u smtp-relay -f"
else
  echo
  echo "Service installed but failed to start. Stop any foreground smtp-relay"
  echo "(Ctrl+C) and run: sudo systemctl restart smtp-relay"
  echo "Logs: sudo journalctl -u smtp-relay -e"
fi
