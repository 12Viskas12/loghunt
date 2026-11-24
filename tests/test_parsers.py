from datetime import datetime

from loghunt.parsers import parse_ssh_line, parse_web_line, sniff_type

YEAR = 2026


def test_failed_password_valid_user():
    e = parse_ssh_line("Nov 18 09:12:10 web01 sshd[7156]: Failed password for root from 203.0.113.50 port 48493 ssh2", YEAR)
    assert e.kind == "ssh_fail"
    assert e.user == "root"
    assert e.ip == "203.0.113.50"
    assert e.ts == datetime(2026, 11, 18, 9, 12, 10)


def test_failed_password_invalid_user():
    e = parse_ssh_line("Nov  8 09:12:10 web01 sshd[1]: Failed password for invalid user oracle from 203.0.113.50 port 1 ssh2", YEAR)
    assert e.kind == "ssh_fail_invalid"
    assert e.user == "oracle"
    assert e.ts.day == 8


def test_invalid_user_line():
    e = parse_ssh_line("Nov 18 10:40:00 web01 sshd[3640]: Invalid user git from 203.0.113.77 port 46269", YEAR)
    assert e.kind == "ssh_invalid"
    assert e.user == "git"


def test_accepted():
    e = parse_ssh_line("Nov 18 12:06:30 web01 sshd[2]: Accepted publickey for alice from 198.51.100.7 port 51234 ssh2: RSA SHA256:x", YEAR)
    assert e.kind == "ssh_accept"
    assert e.user == "alice"


def test_ipv6_address():
    e = parse_ssh_line("Nov 18 12:06:30 web01 sshd[2]: Failed password for root from 2001:db8::1 port 22 ssh2", YEAR)
    assert e.ip == "2001:db8::1"


def test_iso_timestamp():
    e = parse_ssh_line("2026-11-18T09:12:10+00:00 web01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2", YEAR)
    assert e.ts == datetime(2026, 11, 18, 9, 12, 10)


def test_unrelated_lines_are_ignored():
    assert parse_ssh_line("Nov 18 09:12:10 web01 CRON[1]: session opened for user root", YEAR) is None
    assert parse_ssh_line("garbage", YEAR) is None


def test_web_combined_line():
    line = '203.0.113.9 - - [18/Nov/2026:09:30:00 +0000] "GET /.env HTTP/1.1" 404 162 "-" "curl/8.0"'
    e = parse_web_line(line)
    assert (e.ip, e.method, e.path, e.status, e.agent) == ("203.0.113.9", "GET", "/.env", 404, "curl/8.0")
    assert e.ts == datetime(2026, 11, 18, 9, 30, 0)


def test_web_line_without_agent():
    e = parse_web_line('203.0.113.9 - - [18/Nov/2026:09:30:00 +0000] "GET / HTTP/1.1" 200 5')
    assert e.status == 200
    assert e.agent == ""


def test_web_garbage():
    assert parse_web_line("not a log line") is None


def test_sniff_type():
    assert sniff_type(['1.2.3.4 - - [18/Nov/2026:09:30:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"']) == "web"
    assert sniff_type(["Nov 18 09:12:10 h sshd[1]: Invalid user a from 1.2.3.4 port 1"]) == "ssh"
