import io
import json
import queue
import stat
import threading
import time
from datetime import datetime


from loghunt import config as cfgmod
from loghunt.detectors import Config
from loghunt.models import Finding
from loghunt.watch import (Alert, ConsoleNotifier, DesktopNotifier, FileNotifier, Watcher,
                           dispatch, follow_file, run_watch, watch_main)

D = "203.0.113.50"


def fail(sec, ip=D, user="root"):
    return f"Nov 18 09:00:{sec:02d} web01 sshd[1]: Failed password for {user} from {ip} port 4000 ssh2"


def accept(sec, ip=D):
    return f"Nov 18 09:00:{sec:02d} web01 sshd[2]: Accepted password for root from {ip} port 4001 ssh2"


def watcher(**kw):
    clock = kw.pop("clock", None)
    args = dict(detection=Config(), min_severity="medium", cooldown=3600, year=2026)
    args.update(kw)
    if clock:
        args["clock"] = clock
    return Watcher(**args)


def test_alert_only_when_threshold_is_reached():
    w = watcher()
    assert w.feed([fail(i) for i in range(4)], "ssh") == []
    alerts = w.feed([fail(5)], "ssh")
    assert [a.finding.rule for a in alerts] == ["ssh-bruteforce"]


def test_same_finding_is_not_repeated():
    w = watcher()
    w.feed([fail(i) for i in range(5)], "ssh")
    assert w.feed([fail(6)], "ssh") == []
    assert w.feed([fail(7)], "ssh") == []


def test_alert_again_after_cooldown():
    now = [0.0]
    w = watcher(cooldown=100, clock=lambda: now[0])
    assert w.feed([fail(i) for i in range(5)], "ssh")
    now[0] = 50
    assert w.feed([fail(6)], "ssh") == []
    now[0] = 150
    assert w.feed([fail(7)], "ssh")


def test_new_finding_for_same_address_still_alerts():
    w = watcher()
    w.feed([fail(i) for i in range(6)], "ssh")
    alerts = w.feed([accept(30)], "ssh")
    assert [a.finding.rule for a in alerts] == ["ssh-login-after-bruteforce"]
    assert alerts[0].finding.severity == "critical"


def test_min_severity_filters():
    lines = [f"Nov 18 09:00:{i:02d} h sshd[1]: Failed password for invalid user u{i} from {D} port 1 ssh2" for i in range(6)]
    high = watcher(min_severity="high").feed(lines, "ssh")
    assert {a.finding.rule for a in high} == {"ssh-bruteforce"}
    medium = watcher(min_severity="medium").feed(lines, "ssh")
    assert {a.finding.rule for a in medium} == {"ssh-bruteforce", "ssh-user-enumeration"}


def test_different_addresses_alert_separately():
    w = watcher()
    alerts = w.feed([fail(i, ip=f"203.0.113.{k}") for k in (1, 2) for i in range(5)], "ssh")
    assert {a.finding.ip for a in alerts} == {"203.0.113.1", "203.0.113.2"}


def test_web_attack_alert():
    line = '203.0.113.15 - - [18/Nov/2026:10:10:00 +0000] "GET /b?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 5 "-" "x"'
    alerts = watcher().feed([line], "web")
    assert [a.finding.rule for a in alerts] == ["web-attack-sql-injection"]


def test_old_events_are_dropped():
    w = watcher(keep=60)
    w.feed([fail(0)], "ssh")
    w.feed(["Nov 18 11:00:00 h sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2"], "ssh")
    assert len(w.events) == 1


def make_alert(sev="high", rule="r", ip="1.2.3.4"):
    now = datetime(2026, 11, 18, 9, 0, 0)
    return Alert(Finding(rule, sev, ip, 3, now, now, "something happened", "T1110 Brute Force"), now)


def test_console_notifier_plain():
    out = io.StringIO()
    ConsoleNotifier(out, color=False).send(make_alert())
    text = out.getvalue()
    assert "HIGH" in text and "1.2.3.4" in text and "\033" not in text


def test_console_notifier_color():
    out = io.StringIO()
    ConsoleNotifier(out, color=True).send(make_alert("critical"))
    assert "\033[" in out.getvalue()


def test_file_notifier_writes_json_lines(tmp_path):
    n = FileNotifier(tmp_path / "state" / "alerts.jsonl")
    n.send(make_alert())
    n.send(make_alert("critical", rule="x"))
    rows = [json.loads(l) for l in (tmp_path / "state" / "alerts.jsonl").read_text().splitlines()]
    assert [r["rule"] for r in rows] == ["r", "x"]
    assert rows[0]["ip"] == "1.2.3.4"


def test_desktop_notifier_calls_notify_send(tmp_path):
    out = tmp_path / "args.txt"
    script = tmp_path / "notify-send"
    script.write_text(f'#!/bin/sh\nfor a in "$@"; do echo "$a" >> {out}; done\n')
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    DesktopNotifier(str(script)).send(make_alert("critical", rule="boom"))
    args = out.read_text().splitlines()
    assert "critical" in args and any("boom" in a for a in args)


def test_desktop_notifier_missing_binary_is_quiet():
    n = DesktopNotifier("")
    assert not n.available
    n.send(make_alert())


def test_failing_notifier_does_not_break_the_others(capsys):
    got = []

    class Rec:
        name = "console"

        def send(self, alert):
            got.append(alert)

    class Bad:
        name = "desktop"

        def send(self, alert):
            raise OSError("no bus")

    dispatch([make_alert()], [Bad(), Rec()])
    assert len(got) == 1
    assert "desktop notifier failed" in capsys.readouterr().err


def test_burst_is_limited_for_external_channels():
    local, popups = [], []

    class L:
        name = "console"
        send = lambda self, a: local.append(a)

    class R:
        name = "desktop"
        send = lambda self, a: popups.append(a)

    dispatch([make_alert(rule=f"r{i}") for i in range(8)], [L(), R()])
    assert len(local) == 8
    assert len(popups) == 6
    assert popups[-1].finding.rule == "more-alerts"
    assert popups[-1].finding.count == 3


def drain(q, want, timeout=5.0):
    got = []
    end = time.time() + timeout
    while len(got) < want and time.time() < end:
        try:
            got.append(q.get(timeout=0.2))
        except queue.Empty:
            pass
    return got


def test_follow_file_sees_only_new_lines(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("old line\n")
    q, stop = queue.Queue(), threading.Event()
    t = threading.Thread(target=follow_file, args=(str(log), "web", q, stop), daemon=True)
    t.start()
    time.sleep(0.8)
    with open(log, "a") as fh:
        fh.write("new 1\nnew 2\n")
    got = drain(q, 2)
    stop.set()
    assert got == [("web", "new 1"), ("web", "new 2")]


def test_follow_file_from_start_and_partial_line(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("one\ntw")
    q, stop = queue.Queue(), threading.Event()
    threading.Thread(target=follow_file, args=(str(log), "ssh", q, stop, True), daemon=True).start()
    assert drain(q, 1) == [("ssh", "one")]
    time.sleep(0.8)
    assert q.empty()
    with open(log, "a") as fh:
        fh.write("o\n")
    assert drain(q, 1) == [("ssh", "two")]
    stop.set()


def test_follow_file_survives_rotation(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("")
    q, stop = queue.Queue(), threading.Event()
    threading.Thread(target=follow_file, args=(str(log), "web", q, stop), daemon=True).start()
    time.sleep(0.8)
    with open(log, "a") as fh:
        fh.write("before\n")
    assert drain(q, 1) == [("web", "before")]
    log.rename(tmp_path / "a.log.1")
    log.write_text("after rotation\n")
    assert drain(q, 1) == [("web", "after rotation")]
    stop.set()


def test_run_watch_end_to_end(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("")
    s = cfgmod.Settings(web_logs=[str(log)], cooldown=3600)
    alerts = []

    class Rec:
        name = "console"
        send = lambda self, a: alerts.append(a)

    stop = threading.Event()
    th = threading.Thread(target=run_watch, args=(s, [Rec()], stop), kwargs={"tick": 0.2}, daemon=True)
    th.start()
    time.sleep(1.0)
    with open(log, "a") as fh:
        for i in range(10):
            fh.write(f'203.0.113.9 - - [18/Nov/2026:10:10:{i:02d} +0000] "POST /wp-login.php HTTP/1.1" 200 5 "-" "x"\n')
        fh.write('203.0.113.9 - - [18/Nov/2026:10:11:00 +0000] "GET /a?x=${jndi:ldap://x/a} HTTP/1.1" 200 5 "-" "x"\n')
    end = time.time() + 6
    while time.time() < end and len(alerts) < 2:
        time.sleep(0.2)
    stop.set()
    th.join(3)
    assert {a.finding.rule for a in alerts} == {"web-login-bruteforce", "web-attack-log4shell"}


def test_run_watch_without_sources(capsys):
    assert run_watch(cfgmod.Settings(), [], threading.Event()) == 2
    assert "no sources" in capsys.readouterr().err


def test_config_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    path = cfgmod.write_default(tmp_path / "loghunt.ini")
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    s = cfgmod.load(path)
    assert s.ssh_journal == "sshd.service"
    assert s.min_severity == "medium" and s.cooldown == 3600
    assert str(s.alert_file).startswith(str(tmp_path / "state"))
    path.write_text("[sources]\nweb_logs = /a.log, /b.log\n[alerts]\nmin_severity = high\n"
                    "[detection]\nssh_fails = 3\nignore_ips = 1.1.1.1, 2.2.2.2\n")
    s = cfgmod.load(path)
    assert s.web_logs == ["/a.log", "/b.log"]
    assert s.min_severity == "high"
    assert s.detection.ssh_fail_threshold == 3 and s.detection.ignore_ips == ["1.1.1.1", "2.2.2.2"]


def test_missing_config_gives_defaults(tmp_path):
    s = cfgmod.load(tmp_path / "nope.ini")
    assert not s.has_sources and s.min_severity == "medium"


def test_test_notify_flag(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    code = watch_main(["--config", str(tmp_path / "none.ini"), "--no-desktop", "--test-notify"])
    out = capsys.readouterr().out
    assert code == 0
    assert "channels: console, file" in out
    assert "test-alert" in out
    assert (tmp_path / "state" / "loghunt" / "alerts.jsonl").exists()


def test_desktop_notifier_reports_a_failing_binary(tmp_path, capsys):
    script = tmp_path / "notify-send"
    script.write_text("#!/bin/sh\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    dispatch([make_alert()], [DesktopNotifier(str(script))])
    assert "desktop notifier failed" in capsys.readouterr().err
