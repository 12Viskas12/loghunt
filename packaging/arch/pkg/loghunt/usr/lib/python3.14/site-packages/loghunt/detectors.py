import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Tuple
from urllib.parse import unquote_plus

from .models import Event, Finding, severity_rank


@dataclass
class Config:
    window: int = 600
    ssh_fail_threshold: int = 5
    enum_threshold: int = 5
    web_error_threshold: int = 15
    sensitive_path_threshold: int = 3
    login_post_threshold: int = 10
    ignore_ips: List[str] = field(default_factory=list)


SENSITIVE_PATH = re.compile(
    r"(^|/)(\.env|\.git(/|$)|\.aws|\.ssh|wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|pma(/|$)|adminer"
    r"|id_rsa|backup\.(zip|sql|tar|gz)|config\.php|server-status|actuator|cgi-bin)", re.I)

LOGIN_PATH = re.compile(r"(login|signin|wp-login\.php|admin)", re.I)

SCANNER_AGENT = re.compile(
    r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|dirb|wpscan|hydra|zgrab|nuclei|acunetix|feroxbuster)", re.I)

PAYLOADS = {
    "sql injection": re.compile(
        r"(union\s+(all\s+)?select|\bor\s+1\s*=\s*1|'\s*or\s*'|sleep\(\d|benchmark\(|information_schema|;\s*drop\s+table)", re.I),
    "xss": re.compile(r"(<script|onerror\s*=|javascript:|<svg[^>]*onload)", re.I),
    "path traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)", re.I),
    "command injection": re.compile(r"(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", re.I),
    "log4shell": re.compile(r"\$\{jndi:", re.I),
}


def max_in_window(times: List[datetime], window: int) -> Tuple[int, int, int]:
    """Largest number of timestamps inside any span of `window` seconds. Returns (count, start, end)."""
    times = sorted(times)
    best = (0, 0, 0)
    lo = 0
    span = timedelta(seconds=window)
    for hi, t in enumerate(times):
        while t - times[lo] > span:
            lo += 1
        if hi - lo + 1 > best[0]:
            best = (hi - lo + 1, lo, hi)
    return best


def _short(line: str, n: int = 160) -> str:
    return line if len(line) <= n else line[: n - 3] + "..."


def _group(events: Iterable[Event], kinds, cfg: Config) -> Dict[str, List[Event]]:
    out: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.kind in kinds and e.ip not in cfg.ignore_ips:
            out[e.ip].append(e)
    return out


def detect_ssh(events: List[Event], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    fails = _group(events, ("ssh_fail", "ssh_fail_invalid"), cfg)
    names = _group(events, ("ssh_fail", "ssh_fail_invalid", "ssh_invalid"), cfg)
    accepts = _group(events, ("ssh_accept",), cfg)

    brute_ips = {}
    for ip, evs in fails.items():
        n, a, b = max_in_window([e.ts for e in evs], cfg.window)
        if n >= cfg.ssh_fail_threshold:
            evs = sorted(evs, key=lambda e: e.ts)
            users = sorted({e.user for e in evs if e.user})
            brute_ips[ip] = (n, evs[a].ts, evs[b].ts)
            findings.append(Finding(
                "ssh-bruteforce", "high", ip, n, evs[a].ts, evs[b].ts,
                f"{n} failed SSH logins in {cfg.window // 60} min, users tried: {', '.join(users[:6])}"
                + (" ..." if len(users) > 6 else ""),
                "T1110 Brute Force", [_short(e.raw) for e in evs[a:a + 3]]))

    for ip, evs in names.items():
        evs = sorted(evs, key=lambda e: e.ts)
        users = {e.user for e in evs if e.user and e.kind in ("ssh_invalid", "ssh_fail_invalid")}
        if len(users) >= cfg.enum_threshold:
            findings.append(Finding(
                "ssh-user-enumeration", "medium", ip, len(users), evs[0].ts, evs[-1].ts,
                f"{len(users)} different non-existing usernames tried",
                "T1110 Brute Force", [_short(e.raw) for e in evs[:3]]))

    for ip, evs in accepts.items():
        if ip not in brute_ips:
            continue
        _, start, end = brute_ips[ip]
        for acc in sorted(evs, key=lambda e: e.ts):
            if acc.ts >= start and acc.ts - end <= timedelta(seconds=cfg.window):
                findings.append(Finding(
                    "ssh-login-after-bruteforce", "critical", ip, 1, acc.ts, acc.ts,
                    f"successful login as '{acc.user}' right after a brute force, the account may be compromised",
                    "T1078 Valid Accounts", [_short(acc.raw)]))
                break
    return findings


def _decode(path: str) -> str:
    return unquote_plus(unquote_plus(path))


def detect_web(events: List[Event], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    by_ip = _group(events, ("http",), cfg)

    for ip, evs in by_ip.items():
        evs = sorted(evs, key=lambda e: e.ts)

        errors = [e for e in evs if e.status and 400 <= e.status < 500]
        n, a, b = max_in_window([e.ts for e in errors], cfg.window) if errors else (0, 0, 0)
        # POSTs to wp-login.php are password guessing, the login rule covers them
        sens = [e for e in evs if e.method != "POST" and SENSITIVE_PATH.search(_decode(e.path or ""))]
        sens_paths = {(e.path or "").split("?")[0] for e in sens}
        if n >= cfg.web_error_threshold or len(sens_paths) >= cfg.sensitive_path_threshold:
            related = sorted({id(e): e for e in errors + sens}.values(), key=lambda e: e.ts)
            shown = sens[:3] if len(sens_paths) >= cfg.sensitive_path_threshold else errors[a:a + 3]
            findings.append(Finding(
                "web-scan", "medium", ip, len(related), related[0].ts, related[-1].ts,
                f"{n} client errors in {cfg.window // 60} min, {len(sens_paths)} sensitive paths probed",
                "T1595 Active Scanning", [_short(e.raw) for e in shown]))

        agents = {e.agent for e in evs if e.agent and SCANNER_AGENT.search(e.agent)}
        if agents:
            hit = [e for e in evs if e.agent in agents]
            findings.append(Finding(
                "web-scanner-agent", "medium", ip, len(hit), hit[0].ts, hit[-1].ts,
                f"known scanner user agent: {', '.join(sorted(agents))}",
                "T1595 Active Scanning", [_short(hit[0].raw)]))

        for name, rx in PAYLOADS.items():
            # log4shell strings are usually sent in headers, so the user agent is checked too
            def text(e, name=name):
                extra = " " + _decode(e.agent or "") if name == "log4shell" else ""
                return _decode(e.path or "") + extra

            hit = [e for e in evs if rx.search(text(e))]
            if hit:
                findings.append(Finding(
                    f"web-attack-{name.replace(' ', '-')}", "high", ip, len(hit), hit[0].ts, hit[-1].ts,
                    f"{len(hit)} {'request' if len(hit) == 1 else 'requests'} with {name} patterns",
                    "T1190 Exploit Public-Facing Application", [_short(e.raw) for e in hit[:3]]))

        posts = [e for e in evs if e.method == "POST" and LOGIN_PATH.search((e.path or "").split("?")[0])]
        if posts:
            n, a, b = max_in_window([e.ts for e in posts], cfg.window)
            if n >= cfg.login_post_threshold:
                findings.append(Finding(
                    "web-login-bruteforce", "high", ip, n, posts[a].ts, posts[b].ts,
                    f"{n} POST requests to a login page in {cfg.window // 60} min",
                    "T1110 Brute Force", [_short(e.raw) for e in posts[a:a + 3]]))
    return findings


def run_all(events: List[Event], cfg: Config) -> List[Finding]:
    findings = detect_ssh(events, cfg) + detect_web(events, cfg)
    findings.sort(key=lambda f: (-severity_rank(f.severity), -f.count, f.ip))
    return findings
