#!/usr/bin/env bash
# usage: scripts/setup.sh [clean]
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "clean" ]]; then
  rm -rf .venv var
  rm -f "$HOME/.local/bin/loghunt"
  echo "removed .venv and var/"
  exit 0
fi

command -v python >/dev/null || { echo "python is missing: sudo pacman -S python" >&2; exit 1; }
python -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -e .
mkdir -p var/live
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/.venv/bin/loghunt" "$HOME/.local/bin/loghunt"
.venv/bin/loghunt --version
case ":$PATH:" in
  *":$HOME/.local/bin:"*) echo "done, run: loghunt" ;;
  *) echo "done, but add ~/.local/bin to PATH: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc" ;;
esac
