#!/usr/bin/env bash
# usage: scripts/install-service.sh [install|uninstall|status]
set -euo pipefail
cd "$(dirname "$0")/.."

PY="$PWD/.venv/bin/python"
[[ -x "$PY" ]] || { echo "no .venv, run scripts/setup.sh first" >&2; exit 1; }

case "${1:-install}" in
  install)
    "$PY" -m loghunt init-config >/dev/null
    "$PY" -m loghunt service install
    if ! id -nG | tr ' ' '\n' | grep -qx systemd-journal; then
      echo "your user is not in the group systemd-journal, so the sshd journal is not readable."
      echo "fix: sudo usermod -aG systemd-journal \$USER   (then log out and in again)"
    fi
    echo "test a notification: $PY -m loghunt watch --test-notify"
    ;;
  uninstall) "$PY" -m loghunt service uninstall ;;
  status)    "$PY" -m loghunt service status ;;
  *) echo "usage: $0 [install|uninstall|status]" >&2; exit 2 ;;
esac
