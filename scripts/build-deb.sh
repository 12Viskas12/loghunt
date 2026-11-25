#!/usr/bin/env bash
# usage: scripts/build-deb.sh   builds dist/loghunt_<version>_all.deb
set -euo pipefail
cd "$(dirname "$0")/.."

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is missing, this script is for Debian and Ubuntu" >&2; exit 1; }

version=$(python3 -c "import re;print(re.search(r'__version__ = \"(.+?)\"', open('src/loghunt/__init__.py').read()).group(1))")
root=$(mktemp -d)
chmod 755 "$root"
trap 'rm -rf "$root"' EXIT

install -d "$root/usr/lib/python3/dist-packages" "$root/usr/bin" "$root/usr/lib/systemd/user" \
  "$root/usr/share/doc/loghunt" "$root/DEBIAN"
cp -r src/loghunt "$root/usr/lib/python3/dist-packages/"
find "$root" -name __pycache__ -prune -exec rm -rf {} +

cat > "$root/usr/bin/loghunt" <<'PY'
#!/usr/bin/python3
import sys

from loghunt.cli import main

sys.exit(main())
PY
chmod 755 "$root/usr/bin/loghunt"

install -m 644 packaging/loghunt.service "$root/usr/lib/systemd/user/loghunt.service"
install -m 644 LICENSE "$root/usr/share/doc/loghunt/copyright"
install -m 644 README.md "$root/usr/share/doc/loghunt/README.md"

cat > "$root/DEBIAN/control" <<CTRL
Package: loghunt
Version: $version
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.9)
Recommends: libnotify-bin
Maintainer: 12Viskas12 <noreply@users.noreply.github.com>
Homepage: https://github.com/12Viskas12/loghunt
Description: finds brute force, scans and web attacks in SSH and web logs
 Reads sshd and nginx or Apache logs, reports attacks with MITRE ATT&CK tags
 and sends alerts to the desktop and to Telegram while it runs as a service.
CTRL

cat > "$root/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
echo "loghunt installed. Next, as your normal user:"
echo "  loghunt service install   # enable the background service"
echo "  loghunt                   # the menu"
POST
chmod 755 "$root/DEBIAN/postinst"

cat > "$root/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
case "$1" in
  remove|purge) rm -rf /usr/lib/python3/dist-packages/loghunt ;;
esac
POSTRM
chmod 755 "$root/DEBIAN/postrm"

mkdir -p dist
dpkg-deb --root-owner-group --build "$root" "dist/loghunt_${version}_all.deb" >/dev/null
echo "built dist/loghunt_${version}_all.deb"
