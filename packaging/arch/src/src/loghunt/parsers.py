import gzip
import re
import sys
from itertools import chain, islice
from datetime import datetime
from typing import Iterator, Optional, Tuple

from .models import Event

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s")
ISO_TS = re.compile(r"^(?P<iso>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)")

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
SSH_FAILED = re.compile(
    r"sshd(?:\[\d+\])?: Failed (?P<method>[\w/-]+) for (?P<invalid>invalid user )?(?P<user>\S+) from " + IP)
SSH_INVALID = re.compile(r"sshd(?:\[\d+\])?: Invalid user (?P<user>\S*) from " + IP)
SSH_ACCEPTED = re.compile(r"sshd(?:\[\d+\])?: Accepted (?P<method>[\w-]+) for (?P<user>\S+) from " + IP)

WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "(?P<ref>[^"]*)" "(?P<agent>[^"]*)")?')


def _syslog_time(line: str, year: int) -> Optional[datetime]:
    m = SYSLOG_TS.match(line)
    if m:
        h, mi, s = (int(x) for x in m.group("time").split(":"))
        try:
            return datetime(year, MONTHS[m.group("mon")], int(m.group("day")), h, mi, s)
        except (KeyError, ValueError):
            return None
    m = ISO_TS.match(line)
    if m:
        return datetime.fromisoformat(m.group("iso").replace(" ", "T"))
    return None


def parse_ssh_line(line: str, year: int) -> Optional[Event]:
    ts = _syslog_time(line, year)
    if ts is None:
        return None
    m = SSH_FAILED.search(line)
    if m:
        kind = "ssh_fail_invalid" if m.group("invalid") else "ssh_fail"
        return Event(ts, m.group("ip"), kind, line, user=m.group("user"))
    m = SSH_INVALID.search(line)
    if m:
        return Event(ts, m.group("ip"), "ssh_invalid", line, user=m.group("user"))
    m = SSH_ACCEPTED.search(line)
    if m:
        return Event(ts, m.group("ip"), "ssh_accept", line, user=m.group("user"))
    return None


def parse_web_line(line: str) -> Optional[Event]:
    m = WEB_LINE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        return None
    return Event(ts, m.group("ip"), "http", line, method=m.group("method"), path=m.group("path"),
                 status=int(m.group("status")), agent=m.group("agent") or "")


def parse_lines(lines, kind: str, year: Optional[int] = None) -> Iterator[Event]:
    """Parse already loaded lines. kind is "ssh" or "web"."""
    year = year or datetime.now().year
    for line in lines:
        line = line.rstrip("\n")
        ev = parse_web_line(line) if kind == "web" else parse_ssh_line(line, year)
        if ev:
            yield ev


def sniff_type(lines) -> str:
    for line in lines:
        if WEB_LINE.match(line):
            return "web"
        if "sshd" in line:
            return "ssh"
    return "ssh"


def parse_file(path: str, kind: str = "auto", year: Optional[int] = None) -> Tuple[Iterator[Event], dict]:
    """Return (events, stats). Stats are filled while the iterator is consumed. "-" means stdin."""
    year = year or datetime.now().year
    stats = {"lines": 0, "parsed": 0, "type": kind}

    def open_log():
        if path == "-":
            return sys.stdin
        opener = gzip.open if path.endswith(".gz") else open
        return opener(path, "rt", encoding="utf-8", errors="replace")

    def gen():
        fh = open_log()
        try:
            lines = iter(fh)
            first = list(islice(lines, 50))
            k = kind if kind != "auto" else sniff_type(first)
            stats["type"] = k
            for line in chain(first, lines):
                line = line.rstrip("\n")
                stats["lines"] += 1
                ev = parse_web_line(line) if k == "web" else parse_ssh_line(line, year)
                if ev:
                    stats["parsed"] += 1
                    yield ev
        finally:
            if fh is not sys.stdin:
                fh.close()

    return gen(), stats
