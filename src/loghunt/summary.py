import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from . import config as cfgmod
from .models import SEVERITIES, severity_rank

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_since(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)\s*([smhdw])", text.strip().lower())
    if not m:
        raise ValueError(f"bad period {text!r}, use something like 30m, 24h or 7d")
    return timedelta(seconds=int(m.group(1)) * UNITS[m.group(2)])


def load_alerts(path: Path, since: Optional[timedelta], now: Optional[datetime] = None) -> List[dict]:
    """Alerts from the JSON lines file, newest period only. Test alerts are not attacks, so they are skipped."""
    path = Path(path)
    if not path.exists():
        return []
    limit = (now or datetime.now()) - since if since else None
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
            when = datetime.fromisoformat(row["time"])
            row["severity"], row["rule"], row["ip"]
        except (ValueError, KeyError, TypeError):
            continue
        if row["rule"] in ("test-alert", "more-alerts") or (limit and when < limit):
            continue
        rows.append(row)
    return rows


def summarize(rows: List[dict], limit: int = 10) -> dict:
    by_ip: Dict[str, List[dict]] = defaultdict(list)
    for r in rows:
        by_ip[r["ip"]].append(r)
    top = []
    for ip, items in by_ip.items():
        worst = max((i["severity"] for i in items), key=severity_rank)
        top.append({"ip": ip, "alerts": len(items), "worst": worst,
                    "rules": sorted({i["rule"] for i in items}), "last": max(i["time"] for i in items)})
    top.sort(key=lambda t: (-severity_rank(t["worst"]), -t["alerts"], t["ip"]))
    return {
        "total": len(rows),
        "addresses": len(by_ip),
        "by_severity": {s: n for s, n in ((s, sum(1 for r in rows if r["severity"] == s)) for s in reversed(SEVERITIES)) if n},
        "by_rule": dict(Counter(r["rule"] for r in rows).most_common()),
        "top": top[:limit],
    }


def render(info: dict, period: str) -> str:
    if not info["total"]:
        return f"no alerts in the last {period}\n"
    sev = ", ".join(f"{n} {s}" for s, n in info["by_severity"].items())
    out = [f"last {period}: {info['total']} alerts from {info['addresses']} addresses ({sev})", ""]
    out.append(f"{'LEVEL':8} {'ADDRESS':40} {'ALERTS':6}  LAST SEEN            RULES")
    for t in info["top"]:
        out.append(f"{t['worst']:8} {t['ip']:40} {t['alerts']:<6}  {t['last'].replace('T', ' ')}  {', '.join(t['rules'])}")
    out += ["", "by rule:"]
    out += [f"  {n:4}  {rule}" for rule, n in info["by_rule"].items()]
    return "\n".join(out) + "\n"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loghunt top", description="Who attacked you lately, from the alerts the watcher saved.")
    p.add_argument("--since", default="24h", help="period such as 30m, 24h or 7d (default 24h)")
    p.add_argument("--limit", type=int, default=10, help="how many addresses to show (default 10)")
    p.add_argument("--file", type=Path, help="alert file (default: the one in the config)")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    return p


def top_main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        delta = parse_since(args.since)
    except ValueError as exc:
        print(f"loghunt: {exc}", file=sys.stderr)
        return 2
    path = args.file or cfgmod.load().alert_file
    info = summarize(load_alerts(path, delta), args.limit)
    sys.stdout.write(json.dumps(info, indent=2) + "\n" if args.json else render(info, args.since))
    return 0
