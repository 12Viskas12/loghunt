import configparser
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .detectors import Config as Detection
from .models import SEVERITIES


def _xdg(var: str, fallback: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / fallback)


def config_path() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / "loghunt" / "loghunt.ini"


def state_dir() -> Path:
    return _xdg("XDG_STATE_HOME", ".local/state") / "loghunt"


SSH_UNIT_FILES = (Path("/usr/lib/systemd/system/ssh.service"), Path("/lib/systemd/system/ssh.service"))


def default_ssh_unit() -> str:
    """Debian and Ubuntu call the unit ssh.service, Arch and most others sshd.service."""
    return "ssh.service" if any(p.exists() for p in SSH_UNIT_FILES) else "sshd.service"


SSH_LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")
WEB_LOG_CANDIDATES = ("/var/log/nginx/access.log", "/var/log/apache2/access.log",
                      "/var/log/httpd/access_log", "/var/log/httpd/access.log")


@dataclass
class Found:
    ssh_journal: str
    ssh_logs: List[str]
    web_logs: List[str]


def find_sources() -> Found:
    """Look for the logs that exist on this machine. A plain auth.log wins over the journal so lines are not read twice."""
    ssh_logs = [p for p in SSH_LOG_CANDIDATES if os.path.exists(p)]
    web_logs = [p for p in WEB_LOG_CANDIDATES if os.path.exists(p)]
    return Found("" if ssh_logs else default_ssh_unit(), ssh_logs, web_logs)


DEFAULT_INI = """[sources]
ssh_journal = {ssh_journal}
ssh_logs = {ssh_logs}
web_logs = {web_logs}

[detection]
window = 600
ssh_fails = 5
enum_users = 5
web_errors = 15
login_posts = 10
ignore_ips =

[alerts]
min_severity = medium
cooldown = 3600
console = yes
desktop = yes
file = {state}/alerts.jsonl

[telegram]
; fill both to get alerts in a Telegram chat, see docs/telegram.md
bot_token =
chat_id =
min_severity = high
"""


@dataclass
class Settings:
    ssh_journal: str = ""
    ssh_logs: List[str] = field(default_factory=list)
    web_logs: List[str] = field(default_factory=list)
    detection: Detection = field(default_factory=Detection)
    min_severity: str = "medium"
    cooldown: int = 3600
    console: bool = True
    desktop: bool = True
    alert_file: Optional[Path] = None
    state_file: Optional[Path] = None
    telegram_token: str = ""
    telegram_chat_id: str = ""
    telegram_min_severity: str = "high"

    @property
    def has_telegram(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)

    @property
    def has_sources(self) -> bool:
        return bool(self.ssh_journal or self.ssh_logs or self.web_logs)


def _list(value: str) -> List[str]:
    return [v.strip() for v in value.replace("\n", ",").split(",") if v.strip()]


def write_default(path: Optional[Path] = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    found = find_sources()
    path.write_text(DEFAULT_INI.format(state=state_dir(), ssh_journal=found.ssh_journal,
                                                 ssh_logs=", ".join(found.ssh_logs), web_logs=", ".join(found.web_logs)), encoding="utf-8")
    path.chmod(0o600)
    return path


def load(path: Optional[Path] = None) -> Settings:
    """Read the ini file. A missing file gives the defaults without any sources."""
    path = path or config_path()
    cp = configparser.ConfigParser(inline_comment_prefixes=(";",))
    if path.exists():
        cp.read(path, encoding="utf-8")
    g = cp.get
    s = Settings()
    s.ssh_journal = g("sources", "ssh_journal", fallback="").strip()
    s.ssh_logs = _list(g("sources", "ssh_logs", fallback=""))
    s.web_logs = _list(g("sources", "web_logs", fallback=""))
    s.detection = Detection(
        window=cp.getint("detection", "window", fallback=600),
        ssh_fail_threshold=cp.getint("detection", "ssh_fails", fallback=5),
        enum_threshold=cp.getint("detection", "enum_users", fallback=5),
        web_error_threshold=cp.getint("detection", "web_errors", fallback=15),
        login_post_threshold=cp.getint("detection", "login_posts", fallback=10),
        ignore_ips=_list(g("detection", "ignore_ips", fallback="")),
    )
    sev = g("alerts", "min_severity", fallback="medium").strip().lower()
    s.min_severity = sev if sev in SEVERITIES else "medium"
    s.cooldown = cp.getint("alerts", "cooldown", fallback=3600)
    s.console = cp.getboolean("alerts", "console", fallback=True)
    s.desktop = cp.getboolean("alerts", "desktop", fallback=True)
    target = g("alerts", "file", fallback="").strip()
    s.alert_file = Path(os.path.expanduser(target)) if target else state_dir() / "alerts.jsonl"
    s.state_file = state_dir() / "cooldown.json"
    # the environment wins over the file, so the token does not have to be stored on disk
    s.telegram_token = (os.environ.get("LOGHUNT_TELEGRAM_TOKEN") or g("telegram", "bot_token", fallback="")).strip()
    s.telegram_chat_id = (os.environ.get("LOGHUNT_TELEGRAM_CHAT_ID") or g("telegram", "chat_id", fallback="")).strip()
    tsev = g("telegram", "min_severity", fallback="high").strip().lower()
    s.telegram_min_severity = tsev if tsev in SEVERITIES else "high"
    return s


def save_values(section: str, values: dict, path: Optional[Path] = None) -> Path:
    """Set keys inside one section of the ini file. Other lines, sections and comments stay as they are."""
    path = path or config_path()
    if not path.exists():
        write_default(path)
    keys = "|".join(re.escape(k) for k in values)
    lines = path.read_text(encoding="utf-8").splitlines()
    out, in_section, seen, found = [], False, set(), False

    def missing():
        return [f"{k} = {v}" for k, v in values.items() if k not in seen]

    for line in lines:
        head = re.match(r"\s*\[(.+?)\]\s*$", line)
        if head:
            if in_section:
                out.extend(missing())
            in_section = head.group(1) == section
            found = found or in_section
        elif in_section:
            key = re.match(rf"\s*({keys})\s*=", line)
            if key:
                seen.add(key.group(1))
                line = f"{key.group(1)} = {values[key.group(1)]}"
        out.append(line)
    if in_section:
        out.extend(missing())
    if not found:
        out += ["", f"[{section}]"] + missing()
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def save_telegram(token: str, chat_id: str, path: Optional[Path] = None) -> Path:
    return save_values("telegram", {"bot_token": token, "chat_id": chat_id}, path)


def save_sources(found: Found, path: Optional[Path] = None) -> Path:
    return save_values("sources", {"ssh_journal": found.ssh_journal, "ssh_logs": ", ".join(found.ssh_logs),
                                   "web_logs": ", ".join(found.web_logs)}, path)
