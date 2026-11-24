import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from . import config as cfgmod

UNIT = "loghunt.service"

UNIT_TEXT = """[Unit]
Description=loghunt, alerts on SSH and web attacks
After=network.target

[Service]
Type=simple
ExecStart={python} -m loghunt watch
Environment=PYTHONUNBUFFERED=1
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=default.target
"""


def unit_dir() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "systemd" / "user"


def unit_path() -> Path:
    return unit_dir() / UNIT


def unit_text(python: Optional[str] = None) -> str:
    return UNIT_TEXT.format(python=python or sys.executable)


def systemctl(*args: str, capture: bool = True) -> Tuple[int, str]:
    exe = shutil.which("systemctl")
    if not exe:
        return 127, "systemctl not found, this machine does not use systemd"
    try:
        r = subprocess.run([exe, "--user", *args], capture_output=capture, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


def install(python: Optional[str] = None, start: bool = True) -> List[str]:
    notes = []
    if not cfgmod.config_path().exists():
        notes.append(f"config written to {cfgmod.write_default()}")
    path = unit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(unit_text(python), encoding="utf-8")
    notes.append(f"unit written to {path}")
    for args in (("daemon-reload",), ("enable", "--now", UNIT) if start else ("enable", UNIT)):
        code, out = systemctl(*args)
        if code != 0:
            notes.append(f"systemctl {' '.join(args)} failed: {out}")
            return notes
    notes.append("service enabled" + (" and started" if start else ""))
    return notes


def uninstall() -> List[str]:
    notes = []
    systemctl("disable", "--now", UNIT)
    if unit_path().exists():
        unit_path().unlink()
        notes.append(f"removed {unit_path()}")
    systemctl("daemon-reload")
    notes.append("service removed")
    return notes


def state() -> str:
    """active, inactive, failed, not-installed or no-systemd."""
    if not shutil.which("systemctl"):
        return "no-systemd"
    if not unit_path().exists():
        return "not-installed"
    _, out = systemctl("is-active", UNIT)
    return out.splitlines()[0] if out else "unknown"


def run(action: str) -> int:
    if action == "install":
        notes = install()
        for n in notes:
            print(n)
        if any("failed" in n for n in notes):
            return 1
        print("tip: loginctl enable-linger $USER keeps it running after you log out")
        return 0
    if action == "uninstall":
        for n in uninstall():
            print(n)
        return 0
    if action in ("start", "stop", "restart"):
        code, out = systemctl(action, UNIT)
        print(out or f"{action} ok" if code == 0 else out)
        return code
    if action == "status":
        code, out = systemctl("status", UNIT, "--no-pager", "-n", "15")
        print(out)
        return 0 if code in (0, 3) else code
    if action == "logs":
        exe = shutil.which("journalctl")
        if not exe:
            print("journalctl not found", file=sys.stderr)
            return 127
        return subprocess.call([exe, "--user-unit", UNIT, "-n", "40", "--no-pager"])
    print(f"unknown action {action}", file=sys.stderr)
    return 2
