from datetime import datetime, timedelta

from loghunt.detectors import Config, detect_ssh, detect_web, max_in_window, run_all
from loghunt.models import Event

T0 = datetime(2026, 11, 18, 9, 0, 0)


def ssh_fail(sec, ip="203.0.113.50", user="root", invalid=False):
    kind = "ssh_fail_invalid" if invalid else "ssh_fail"
    return Event(T0 + timedelta(seconds=sec), ip, kind, f"fail {user} {ip}", user=user)


def ssh_accept(sec, ip="203.0.113.50", user="root"):
    return Event(T0 + timedelta(seconds=sec), ip, "ssh_accept", f"accept {user} {ip}", user=user)


def http(sec, path, ip="203.0.113.9", method="GET", status=200, agent="Mozilla/5.0"):
    return Event(T0 + timedelta(seconds=sec), ip, "http", f"{ip} {method} {path} {status}",
                 method=method, path=path, status=status, agent=agent)


def rules(findings):
    return {f.rule for f in findings}


def test_max_in_window():
    times = [T0 + timedelta(seconds=s) for s in (0, 10, 20, 700, 710)]
    assert max_in_window(times, 60)[0] == 3
    assert max_in_window(times, 1000)[0] == 5
    assert max_in_window([], 60)[0] == 0


def test_bruteforce_needs_threshold():
    four = [ssh_fail(i) for i in range(4)]
    five = [ssh_fail(i) for i in range(5)]
    assert "ssh-bruteforce" not in rules(detect_ssh(four, Config()))
    assert "ssh-bruteforce" in rules(detect_ssh(five, Config()))


def test_slow_attempts_are_not_bruteforce():
    slow = [ssh_fail(i * 400) for i in range(10)]
    assert "ssh-bruteforce" not in rules(detect_ssh(slow, Config(window=600, ssh_fail_threshold=5)))


def test_two_typos_are_fine():
    events = [ssh_fail(0, ip="198.51.100.7", user="alice"), ssh_fail(20, ip="198.51.100.7", user="alice"),
              ssh_accept(60, ip="198.51.100.7", user="alice")]
    assert detect_ssh(events, Config()) == []


def test_failures_are_counted_per_address():
    events = [ssh_fail(i, ip=f"203.0.113.{i}") for i in range(10)]
    assert detect_ssh(events, Config()) == []


def test_user_enumeration():
    events = [ssh_fail(i, user=f"user{i}", invalid=True) for i in range(5)]
    assert "ssh-user-enumeration" in rules(detect_ssh(events, Config()))
    same = [ssh_fail(i, user="admin", invalid=True) for i in range(4)]
    assert "ssh-user-enumeration" not in rules(detect_ssh(same, Config()))


def test_login_after_bruteforce_is_critical():
    events = [ssh_fail(i, user="deploy") for i in range(6)] + [ssh_accept(30, user="deploy")]
    found = detect_ssh(events, Config())
    crit = [f for f in found if f.rule == "ssh-login-after-bruteforce"]
    assert len(crit) == 1
    assert crit[0].severity == "critical"
    assert "deploy" in crit[0].summary


def test_accept_long_after_bruteforce_is_not_critical():
    events = [ssh_fail(i) for i in range(6)] + [ssh_accept(5 * 3600)]
    assert "ssh-login-after-bruteforce" not in rules(detect_ssh(events, Config()))


def test_ignore_ip():
    events = [ssh_fail(i) for i in range(10)]
    assert detect_ssh(events, Config(ignore_ips=["203.0.113.50"])) == []


def test_web_scan_by_errors():
    events = [http(i, f"/nope{i}", status=404) for i in range(15)]
    assert "web-scan" in rules(detect_web(events, Config()))
    assert "web-scan" not in rules(detect_web(events[:14], Config()))


def test_web_scan_by_sensitive_paths():
    events = [http(0, "/.env"), http(1, "/.git/config"), http(2, "/wp-login.php")]
    assert "web-scan" in rules(detect_web(events, Config()))


def test_normal_browsing_is_quiet():
    events = [http(i * 30, p) for i, p in enumerate(["/", "/about", "/blog", "/contact"])]
    events.append(http(200, "/missing", status=404))
    assert detect_web(events, Config()) == []


def test_scanner_agent():
    found = detect_web([http(0, "/", agent="sqlmap/1.7")], Config())
    assert "web-scanner-agent" in rules(found)


def test_payload_categories():
    cases = {
        "web-attack-sql-injection": "/blog?id=1%20UNION%20SELECT%20password%20FROM%20users",
        "web-attack-xss": "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "web-attack-path-traversal": "/d?f=../../etc/passwd",
        "web-attack-command-injection": "/p?h=1;cat%20/etc/passwd",
        "web-attack-log4shell": "/?x=${jndi:ldap://x/a}",
    }
    for rule, path in cases.items():
        assert rule in rules(detect_web([http(0, path)], Config())), rule


def test_double_encoded_payload():
    assert "web-attack-path-traversal" in rules(detect_web([http(0, "/d?f=%252e%252e%252fetc%252fpasswd")], Config()))


def test_log4shell_in_user_agent():
    found = detect_web([http(0, "/", agent="${jndi:ldap://x/a}")], Config())
    assert "web-attack-log4shell" in rules(found)


def test_login_bruteforce():
    events = [http(i, "/wp-login.php", method="POST") for i in range(10)]
    assert "web-login-bruteforce" in rules(detect_web(events, Config()))
    assert "web-login-bruteforce" not in rules(detect_web(events[:9], Config()))


def test_get_requests_to_login_are_not_bruteforce():
    events = [http(i, "/login", method="GET") for i in range(30)]
    assert "web-login-bruteforce" not in rules(detect_web(events, Config()))


def test_sorted_by_severity():
    events = [ssh_fail(i, user="deploy") for i in range(6)] + [ssh_accept(30, user="deploy")]
    events += [http(0, "/", agent="nikto")]
    found = run_all(events, Config())
    assert found[0].severity == "critical"
    assert [f.severity for f in found] == sorted([f.severity for f in found],
                                                 key=["critical", "high", "medium", "low"].index)


def test_login_guessing_is_not_reported_as_a_scan():
    events = [http(i, "/wp-login.php", method="POST") for i in range(40)]
    found = rules(detect_web(events, Config()))
    assert "web-login-bruteforce" in found
    assert "web-scan" not in found


def test_scan_times_cover_only_the_scan():
    events = [http(0, "/")] + [http(3600 + i, p, status=404) for i, p in enumerate(["/.env", "/.git/config", "/wp-login.php"])]
    scan = [f for f in detect_web(events, Config()) if f.rule == "web-scan"][0]
    assert scan.first_seen == T0 + timedelta(seconds=3600)
    assert scan.count == 3


def test_single_request_wording():
    f = detect_web([http(0, "/s?q=%3Cscript%3E")], Config())[0]
    assert "1 request with" in f.summary
