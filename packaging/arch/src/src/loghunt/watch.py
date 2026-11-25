import argparse
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

from . import config as cfgmod
from .detectors import Config as Detection
from .detectors import run_all
from .models import Event, Finding, SEVERITIES, severity_rank
from .parsers import parse_lines
from .telegram import TelegramError, TelegramNotifier

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[93m", "low": "\033[96m"}
RESET = "\033[0m"
MAX_EXTERNAL_PER_TICK = 5


@dataclass
class Alert:
    finding: Finding
    sent_at: datetime

    @property
    def title(self) -> str:
        return f"loghunt: {self.finding.severity.upper()} {self.finding.rule}"

    @property
    def body(self) -> str:
        f = self.finding
        return f"{f.ip}\n{f.summary}\n{f.mitre}"

    def as_dict(self) -> dict:
        f = self.finding
        return {
            "time": self.sent_at.isoformat(timespec="seconds"), "severity": f.severity, "rule": f.rule,
            "ip": f.ip, "count": f.count, "summary": f.summary, "mitre": f.mitre,
            "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
        }


class Watcher:
    """Keeps recent events and reports a finding once, not on every new line."""

    def __init__(self, detection: Detection, min_severity: str = "medium", cooldown: int = 3600,
                 keep: int = 3600, year: Optional[int] = None, clock: Callable[[], float] = time.monotonic):
        self.detection = detection
        self.min_rank = severity_rank(min_severity)
        self.cooldown = cooldown
        self.keep = keep
        self.year = year
        self.clock = clock
        self.events: Deque[Event] = deque()
        self.alerted: Dict[Tuple[str, str], float] = {}

    def feed(self, lines: Iterable[str], kind: str) -> List[Alert]:
        new = list(parse_lines(lines, kind, self.year))
        if not new:
            return []
        self.events.extend(new)
        newest = max(e.ts for e in self.events)
        while self.events and (newest - self.events[0].ts).total_seconds() > self.keep:
            self.events.popleft()
        now = self.clock()
        out = []
        for f in run_all(list(self.events), self.detection):
            if severity_rank(f.severity) < self.min_rank:
                continue
            key = (f.rule, f.ip)
            last = self.alerted.get(key)
            if last is not None and now - last < self.cooldown:
                continue
            self.alerted[key] = now
            out.append(Alert(f, datetime.now()))
        return out


class ConsoleNotifier:
    name = "console"

    def __init__(self, stream=None, color: Optional[bool] = None):
        self.stream = stream or sys.stdout
        self.color = self.stream.isatty() and "NO_COLOR" not in os.environ if color is None else color

    def send(self, alert: Alert) -> None:
        f = alert.finding
        tag = f" {f.severity.upper()} "
        if self.color:
            tag = f"{COLORS[f.severity]}{tag}{RESET}"
        stamp = alert.sent_at.strftime("%H:%M:%S")
        print(f"{stamp} [{tag}] {f.rule}  {f.ip}  {f.summary}  ({f.mitre.split(' ')[0]})", file=self.stream, flush=True)


class FileNotifier:
    name = "file"

    def __init__(self, path: Path):
        self.path = Path(path)

    def send(self, alert: Alert) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.as_dict()) + "\n")


class DesktopNotifier:
    name = "desktop"
    URGENCY = {"critical": "critical", "high": "normal", "medium": "low", "low": "low"}

    def __init__(self, binary: Optional[str] = None):
        self.binary = shutil.which("notify-send") if binary is None else binary

    @property
    def available(self) -> bool:
        return bool(self.binary)

    def send(self, alert: Alert) -> None:
        if not self.binary:
            return
        subprocess.run([self.binary, "-a", "loghunt", "-u", self.URGENCY[alert.finding.severity],
                        alert.title, alert.body], timeout=5, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def build_notifiers(s: cfgmod.Settings, console: Optional[bool] = None, desktop: Optional[bool] = None,
                    telegram: Optional[bool] = None):
    out = []
    if s.console if console is None else console:
        out.append(ConsoleNotifier())
    if s.alert_file:
        out.append(FileNotifier(s.alert_file))
    if s.desktop if desktop is None else desktop:
        d = DesktopNotifier()
        if d.available:
            out.append(d)
    if (True if telegram is None else telegram) and s.has_telegram:
        try:
            out.append(TelegramNotifier(s.telegram_token, s.telegram_chat_id, s.telegram_min_severity))
        except ValueError as exc:
            print(f"loghunt: telegram disabled, {exc}", file=sys.stderr, flush=True)
    return out


def dispatch(alerts: List[Alert], notifiers) -> None:
    """Console and file get every alert. Desktop popups get at most a few per tick."""
    local = [n for n in notifiers if n.name in ("console", "file")]
    popups = [n for n in notifiers if n.name not in ("console", "file")]
    for a in alerts:
        for n in local:
            _safe(n, a)
    for i, a in enumerate(alerts):
        if i >= MAX_EXTERNAL_PER_TICK:
            break
        for n in popups:
            _safe(n, a)
    extra = len(alerts) - MAX_EXTERNAL_PER_TICK
    if extra > 0 and popups:
        more = Alert(Finding("more-alerts", "low", "-", extra, alerts[0].finding.first_seen,
                             alerts[0].finding.last_seen, f"{extra} more findings, see the alert file", "-"), datetime.now())
        for n in popups:
            _safe(n, more)


def _safe(notifier, alert: Alert) -> None:
    try:
        notifier.send(alert)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        detail = f" ({exc})" if isinstance(exc, TelegramError) else ""
        print(f"loghunt: {notifier.name} notifier failed: {type(exc).__name__}{detail}", file=sys.stderr, flush=True)


# ---- following sources: every source runs in a thread and puts (kind, line) on one queue

def follow_file(path: str, kind: str, out: "queue.Queue", stop: threading.Event, from_start: bool = False) -> None:
    fh = None
    inode = None
    pos = 0
    first = True
    while not stop.is_set():
        try:
            st = os.stat(path)
            if fh is None or st.st_ino != inode or st.st_size < pos:
                if fh:
                    fh.close()
                fh = open(path, "r", encoding="utf-8", errors="replace")
                inode = st.st_ino
                pos = 0
                if first and not from_start:
                    fh.seek(0, os.SEEK_END)
                    pos = fh.tell()
                first = False
            line = fh.readline()
            while line:
                if line.endswith("\n"):
                    out.put((kind, line.rstrip("\n")))
                    pos = fh.tell()
                    line = fh.readline()
                else:
                    fh.seek(pos)
                    break
        except OSError:
            fh = None
        stop.wait(0.5)
    if fh:
        fh.close()


def follow_journal(unit: str, out: "queue.Queue", stop: threading.Event) -> None:
    cmd = ["journalctl", "-u", unit, "-f", "-n", "0", "-o", "short-iso", "--no-pager"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    except OSError as exc:
        print(f"loghunt: cannot start journalctl: {exc.strerror}", file=sys.stderr, flush=True)
        return

    def errors():
        for line in proc.stderr:
            print(f"journalctl: {line.strip()}", file=sys.stderr, flush=True)

    threading.Thread(target=errors, daemon=True).start()

    def killer():
        stop.wait()
        proc.terminate()

    threading.Thread(target=killer, daemon=True).start()
    for line in proc.stdout:
        out.put(("ssh", line.rstrip("\n")))
    proc.wait()
    if not stop.is_set():
        print(f"loghunt: journalctl for {unit} ended (exit {proc.returncode}). Is your user in the group systemd-journal?",
              file=sys.stderr, flush=True)


def run_watch(s: cfgmod.Settings, notifiers, stop: threading.Event, from_start: bool = False,
              year: Optional[int] = None, tick: float = 1.0) -> int:
    if not s.has_sources:
        print("loghunt: no sources, edit the config or pass --web, --ssh-file or --journal", file=sys.stderr)
        return 2
    q: "queue.Queue" = queue.Queue()
    threads = []
    for path in s.web_logs:
        threads.append(threading.Thread(target=follow_file, args=(path, "web", q, stop, from_start), daemon=True))
    for path in s.ssh_logs:
        threads.append(threading.Thread(target=follow_file, args=(path, "ssh", q, stop, from_start), daemon=True))
    if s.ssh_journal:
        threads.append(threading.Thread(target=follow_journal, args=(s.ssh_journal, q, stop), daemon=True))
    for t in threads:
        t.start()

    watcher = Watcher(s.detection, s.min_severity, s.cooldown, year=year)
    while not stop.is_set():
        batch: Dict[str, List[str]] = {}
        try:
            kind, line = q.get(timeout=tick)
            batch.setdefault(kind, []).append(line)
            while True:
                kind, line = q.get_nowait()
                batch.setdefault(kind, []).append(line)
        except queue.Empty:
            pass
        for kind, lines in batch.items():
            dispatch(watcher.feed(lines, kind), notifiers)
    return 0


def test_alert() -> Alert:
    now = datetime.now()
    f = Finding("test-alert", "high", "203.0.113.1", 1, now, now,
                "this is a test, notifications work", "T0000 Test")
    return Alert(f, now)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loghunt watch", description="Follow logs and send an alert when an attack shows up.")
    p.add_argument("--config", type=Path, help=f"ini file (default {cfgmod.config_path()})")
    p.add_argument("--web", action="append", default=[], metavar="FILE", help="web access log to follow, can be repeated")
    p.add_argument("--ssh-file", action="append", default=[], metavar="FILE", help="sshd log file to follow")
    p.add_argument("--journal", metavar="UNIT", help="follow this unit in the journal, for example sshd.service")
    p.add_argument("--no-journal", action="store_true", help="ignore the journal source from the config")
    p.add_argument("--from-start", action="store_true", help="read the files from the beginning, not only new lines")
    p.add_argument("--min-severity", choices=SEVERITIES)
    p.add_argument("--no-desktop", action="store_true")
    p.add_argument("--no-console", action="store_true")
    p.add_argument("--no-telegram", action="store_true", help="do not send to Telegram even if it is configured")
    p.add_argument("--year", type=int, help="year for syslog timestamps")
    p.add_argument("--test-notify", action="store_true", help="send one test alert to every channel and exit")
    return p


def watch_main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    s = cfgmod.load(args.config)
    if args.web or args.ssh_file or args.journal:
        s.web_logs, s.ssh_logs, s.ssh_journal = args.web, args.ssh_file, args.journal or ""
    if args.no_journal:
        s.ssh_journal = ""
    if args.min_severity:
        s.min_severity = args.min_severity
    notifiers = build_notifiers(s, console=False if args.no_console else None, desktop=False if args.no_desktop else None,
                               telegram=False if args.no_telegram else None)
    if s.desktop and not args.no_desktop and not any(n.name == "desktop" for n in notifiers):
        print("loghunt: notify-send not found, no desktop popups. Install it: sudo pacman -S libnotify", file=sys.stderr)

    if args.test_notify:
        a = test_alert()
        print("channels: " + ", ".join(n.name for n in notifiers))
        dispatch([a], notifiers)
        return 0

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    print("watching " + ", ".join(
        ([f"journal:{s.ssh_journal}"] if s.ssh_journal else []) + s.ssh_logs + s.web_logs)
        + f"  (alerts from {s.min_severity} up; channels: {', '.join(n.name for n in notifiers)})", flush=True)
    return run_watch(s, notifiers, stop, from_start=args.from_start, year=args.year)
