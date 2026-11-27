import grp
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from . import config as cfgmod
from . import service
from .telegram import TOKEN_RE, TelegramError, api_call

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"
COLORS = {OK: "\033[92m", WARN: "\033[93m", FAIL: "\033[91m", SKIP: "\033[90m"}
RESET = "\033[0m"


@dataclass
class Check:
    status: str
    name: str
    detail: str = ""
    hint: str = ""


def run_cmd(args: List[str], timeout: float = 10.0) -> Tuple[int, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


def user_groups() -> List[str]:
    names = []
    for gid in os.getgroups():
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue
    return names


def check_python() -> Check:
    v = sys.version_info
    if v >= (3, 9):
        return Check(OK, "python", f"{v.major}.{v.minor}.{v.micro}")
    return Check(FAIL, "python", f"{v.major}.{v.minor}", "loghunt needs Python 3.9 or newer")


def check_config(s: cfgmod.Settings) -> List[Check]:
    path = cfgmod.config_path()
    out = [Check(OK, "config", str(path)) if path.exists()
           else Check(WARN, "config", f"{path} does not exist, defaults are used", "loghunt init-config")]
    if not s.has_sources:
        out.append(Check(FAIL, "sources", "nothing to watch", "loghunt detect --write"))
    return out


def check_files(s: cfgmod.Settings) -> List[Check]:
    out = []
    for path in s.ssh_logs + s.web_logs:
        if not os.path.exists(path):
            out.append(Check(FAIL, f"log {path}", "does not exist", "fix the path in the config or run: loghunt detect --write"))
        elif not os.access(path, os.R_OK):
            out.append(Check(FAIL, f"log {path}", "not readable for your user",
                             "sudo usermod -aG adm $USER (log out and in again), or run loghunt with sudo"))
        else:
            out.append(Check(OK, f"log {path}", "readable"))
    return out


def check_journal(s: cfgmod.Settings) -> List[Check]:
    if not s.ssh_journal:
        return []
    unit = s.ssh_journal
    if not shutil.which("journalctl"):
        return [Check(FAIL, f"journal {unit}", "journalctl not found", "this machine does not use systemd, use ssh_logs instead")]
    out = []
    code, text = run_cmd(["journalctl", "-u", unit, "-n", "1", "--no-pager"])
    in_group = bool({"systemd-journal", "adm", "wheel"} & set(user_groups())) or os.geteuid() == 0
    if code != 0 or "No journal files" in text:
        out.append(Check(FAIL, f"journal {unit}", "cannot read it",
                         "sudo usermod -aG systemd-journal $USER, then log out and in again"))
    elif not in_group:
        out.append(Check(WARN, f"journal {unit}", "readable now, but your user is in none of systemd-journal, adm, wheel",
                         "sudo usermod -aG systemd-journal $USER"))
    else:
        out.append(Check(OK, f"journal {unit}", "readable"))
    code, _ = run_cmd(["systemctl", "cat", unit])
    if code != 0:
        out.append(Check(WARN, f"unit {unit}", "systemd does not know this unit",
                         "Debian and Ubuntu call it ssh.service, Arch and Fedora sshd.service"))
    return out


def check_desktop(s: cfgmod.Settings) -> List[Check]:
    if not s.desktop:
        return [Check(SKIP, "desktop notifications", "turned off in the config")]
    if not shutil.which("notify-send"):
        return [Check(WARN, "desktop notifications", "notify-send not found", "sudo pacman -S libnotify  (Debian: apt install libnotify-bin)")]
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS") or f"/run/user/{os.getuid()}/bus"
    if os.environ.get("DBUS_SESSION_BUS_ADDRESS") or os.path.exists(bus):
        return [Check(OK, "desktop notifications", "notify-send and the session bus are there")]
    return [Check(WARN, "desktop notifications", "no session bus, popups cannot show up here",
                  "normal over plain SSH, run loghunt in the desktop session")]


def check_telegram(s: cfgmod.Settings, online: bool = True) -> List[Check]:
    if not s.has_telegram:
        return [Check(SKIP, "telegram", "not set up (optional)", "loghunt, then menu item 7")]
    if not TOKEN_RE.match(s.telegram_token):
        return [Check(FAIL, "telegram", "the token does not look right", "set it again in the menu, item 7")]
    if not online:
        return [Check(OK, "telegram", "token format is fine, not contacted")]
    try:
        name = api_call(s.telegram_token, "getMe", timeout=5)["result"].get("username", "?")
    except (TelegramError, KeyError) as exc:
        return [Check(FAIL, "telegram", str(exc), "check the token, the chat and your network")]
    return [Check(OK, "telegram", f"bot @{name} answers")]


def check_service() -> List[Check]:
    state = service.state()
    if state == "no-systemd":
        return [Check(SKIP, "service", "no systemd here")]
    if state == "not-installed":
        return [Check(WARN, "service", "not installed", "loghunt service install")]
    if state != "active":
        return [Check(FAIL, "service", state, "loghunt service logs")]
    out = [Check(OK, "service", "active")]
    code, text = run_cmd(["loginctl", "show-user", str(os.getuid()), "-p", "Linger"])
    if code == 0 and text.strip().endswith("=no"):
        out.append(Check(WARN, "linger", "the service stops when you log out", "loginctl enable-linger $USER"))
    return out


def check_alert_file(s: cfgmod.Settings) -> List[Check]:
    if not s.alert_file:
        return []
    folder = Path(s.alert_file).parent
    probe = folder
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    if os.access(probe, os.W_OK):
        return [Check(OK, "alert file", str(s.alert_file))]
    return [Check(FAIL, "alert file", f"cannot write into {probe}", "change [alerts] file in the config")]


def run_checks(s: cfgmod.Settings, online: bool = True) -> List[Check]:
    checks = [check_python()]
    for part in (check_config(s), check_files(s), check_journal(s), check_desktop(s),
                 check_telegram(s, online), check_service(), check_alert_file(s)):
        checks.extend(part)
    return checks


def render(checks: List[Check], color: bool = False) -> str:
    lines = []
    for c in checks:
        tag = f"[{c.status:^4}]"
        if color:
            tag = f"{COLORS[c.status]}{tag}{RESET}"
        lines.append(f"{tag} {c.name}: {c.detail}")
        if c.hint and c.status in (WARN, FAIL):
            lines.append(f"       fix: {c.hint}")
        elif c.hint and c.status == SKIP:
            lines.append(f"       to enable: {c.hint}")
    bad = sum(c.status == FAIL for c in checks)
    warn = sum(c.status == WARN for c in checks)
    lines.append("")
    lines.append("everything looks fine" if not bad and not warn else f"{bad} problems, {warn} warnings")
    return "\n".join(lines) + "\n"


def doctor_main(argv=None) -> int:
    argv = list(argv or [])
    s = cfgmod.load()
    checks = run_checks(s, online="--offline" not in argv)
    sys.stdout.write(render(checks, color=sys.stdout.isatty() and "NO_COLOR" not in os.environ))
    return 1 if any(c.status == FAIL for c in checks) else 0
