import argparse
import sys
from typing import List, Optional

from . import __version__
from .detectors import Config, run_all
from .models import SEVERITIES, severity_rank
from .parsers import parse_file
from .report import RENDERERS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="loghunt", description="Find brute force, scans and web attacks in SSH and web server logs.",
        epilog="other commands: loghunt menu | watch | service {install,start,stop,status,logs,uninstall} | init-config")
    p.add_argument("files", nargs="+", help="auth.log, access.log or similar, - reads stdin")
    p.add_argument("--type", choices=["auto", "ssh", "web"], default="auto", help="log type, auto-detected by default")
    p.add_argument("--format", choices=sorted(RENDERERS), default="text")
    p.add_argument("--output", "-o", help="write the report to a file instead of stdout")
    p.add_argument("--year", type=int, help="year for syslog timestamps, they have none (default: this year)")
    p.add_argument("--window", type=int, default=600, help="seconds for the rate rules (default 600)")
    p.add_argument("--ssh-fails", type=int, default=5, help="failed logins in the window to call it brute force")
    p.add_argument("--enum-users", type=int, default=5, help="different invalid usernames to call it enumeration")
    p.add_argument("--web-errors", type=int, default=15, help="4xx answers in the window to call it a scan")
    p.add_argument("--login-posts", type=int, default=10, help="POSTs to a login page in the window")
    p.add_argument("--ignore-ip", action="append", default=[], metavar="IP", help="skip this address, can be repeated")
    p.add_argument("--fail-on", choices=SEVERITIES, help="exit with code 1 if there is a finding of this severity or higher")
    p.add_argument("--version", action="version", version=f"loghunt {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv and sys.stdin.isatty() and sys.stdout.isatty():
        argv = ["menu"]
    head = argv[0] if argv else ""
    if head == "watch":
        from .watch import watch_main
        return watch_main(argv[1:])
    if head == "menu":
        from .menu import menu_main
        return menu_main(argv[1:])
    if head == "service":
        from . import service
        return service.run(argv[1] if len(argv) > 1 else "status")
    if head == "init-config":
        from . import config
        print(config.write_default())
        return 0
    return analyze(argv)


def analyze(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config(window=args.window, ssh_fail_threshold=args.ssh_fails, enum_threshold=args.enum_users,
                 web_error_threshold=args.web_errors, login_post_threshold=args.login_posts,
                 ignore_ips=args.ignore_ip)

    events = []
    total = {"lines": 0, "parsed": 0, "files": len(args.files)}
    for path in args.files:
        try:
            it, stats = parse_file(path, args.type, args.year)
            events.extend(it)
        except OSError as exc:
            print(f"loghunt: cannot read {path}: {exc.strerror}", file=sys.stderr)
            return 2
        total["lines"] += stats["lines"]
        total["parsed"] += stats["parsed"]

    findings = run_all(events, cfg)
    text = RENDERERS[args.format](findings, total)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)

    if args.fail_on and any(severity_rank(f.severity) >= severity_rank(args.fail_on) for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
