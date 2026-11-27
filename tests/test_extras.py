import io
import json
import time
from datetime import datetime, timedelta

import pytest

from loghunt import cli, config, doctor, service, summary
from loghunt.detectors import Config
from loghunt.menu import Menu
from loghunt.watch import Watcher

NOW = datetime(2026, 11, 25, 12, 0, 0)


def row(minutes_ago, severity="high", rule="ssh-bruteforce", ip="203.0.113.5"):
    return {"time": (NOW - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds"), "severity": severity,
            "rule": rule, "ip": ip, "count": 1, "summary": "x", "mitre": "T1110"}


def write_rows(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


# top

def test_parse_since():
    assert summary.parse_since("30m") == timedelta(minutes=30)
    assert summary.parse_since("24h") == timedelta(hours=24)
    assert summary.parse_since("7d") == timedelta(days=7)
    with pytest.raises(ValueError):
        summary.parse_since("soon")


def test_load_alerts_filters_period_tests_and_garbage(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join([json.dumps(row(10)), json.dumps(row(60 * 30)), json.dumps(row(5, rule="test-alert")),
                            "not json", json.dumps({"time": "bad"})]) + "\n")
    rows = summary.load_alerts(p, timedelta(hours=24), now=NOW)
    assert len(rows) == 1


def test_missing_alert_file_is_empty(tmp_path):
    assert summary.load_alerts(tmp_path / "none.jsonl", None) == []


def test_summarize_ranks_by_severity_then_count():
    rows = [row(1, "medium", "web-scan", "198.51.100.1")] * 5 + [row(2, "critical", "ssh-login-after-bruteforce", "192.0.2.99"),
                                                                    row(3, "high", "ssh-bruteforce", "192.0.2.99")]
    info = summary.summarize(rows)
    assert info["total"] == 7 and info["addresses"] == 2
    assert info["top"][0]["ip"] == "192.0.2.99" and info["top"][0]["worst"] == "critical"
    assert info["by_severity"] == {"critical": 1, "high": 1, "medium": 5}
    assert info["top"][0]["rules"] == ["ssh-bruteforce", "ssh-login-after-bruteforce"]


def test_render_empty_and_full():
    assert "no alerts" in summary.render(summary.summarize([]), "24h")
    text = summary.render(summary.summarize([row(1)]), "24h")
    assert "203.0.113.5" in text and "by rule" in text


def test_top_command(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    write_rows(p, [row(1, ip="198.51.100.77")])
    # the file holds a 2026 time, so ask for a very long period relative to the real clock
    assert cli.main(["top", "--file", str(p), "--since", "5000d", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["top"][0]["ip"] == "198.51.100.77"
    assert cli.main(["top", "--since", "xyz"]) == 2


# sources and config

def test_find_sources_prefers_the_log_file(tmp_path, monkeypatch):
    auth = tmp_path / "auth.log"
    auth.write_text("")
    web = tmp_path / "access.log"
    web.write_text("")
    monkeypatch.setattr(config, "SSH_LOG_CANDIDATES", (str(auth), str(tmp_path / "secure")))
    monkeypatch.setattr(config, "WEB_LOG_CANDIDATES", (str(web), str(tmp_path / "nope")))
    found = config.find_sources()
    assert found.ssh_logs == [str(auth)] and found.ssh_journal == "" and found.web_logs == [str(web)]


def test_find_sources_falls_back_to_the_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SSH_LOG_CANDIDATES", (str(tmp_path / "x"),))
    monkeypatch.setattr(config, "WEB_LOG_CANDIDATES", ())
    monkeypatch.setattr(config, "SSH_UNIT_FILES", ())
    found = config.find_sources()
    assert found.ssh_journal == "sshd.service" and found.ssh_logs == []


def test_default_config_uses_the_found_sources(tmp_path, monkeypatch):
    web = tmp_path / "access.log"
    web.write_text("")
    monkeypatch.setattr(config, "SSH_LOG_CANDIDATES", ())
    monkeypatch.setattr(config, "WEB_LOG_CANDIDATES", (str(web),))
    monkeypatch.setattr(config, "SSH_UNIT_FILES", ())
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    path = config.write_default(tmp_path / "x.ini")
    s = config.load(path)
    assert s.web_logs == [str(web)] and s.ssh_journal == "sshd.service"


def test_save_sources_updates_only_the_sources(tmp_path):
    p = tmp_path / "x.ini"
    p.write_text("[sources]\nssh_journal = sshd.service\nssh_logs =\nweb_logs =\n\n[alerts]\nmin_severity = high\n")
    config.save_sources(config.Found("", ["/var/log/auth.log"], ["/a.log", "/b.log"]), p)
    s = config.load(p)
    assert s.ssh_journal == "" and s.ssh_logs == ["/var/log/auth.log"] and s.web_logs == ["/a.log", "/b.log"]
    assert s.min_severity == "high"


def test_detect_command_writes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "s"))
    monkeypatch.setattr(config, "SSH_LOG_CANDIDATES", ())
    monkeypatch.setattr(config, "WEB_LOG_CANDIDATES", ())
    monkeypatch.setattr(config, "SSH_UNIT_FILES", ())
    assert cli.main(["detect"]) == 0
    assert "--write" in capsys.readouterr().out
    assert not config.config_path().exists()
    assert cli.main(["detect", "--write"]) == 0
    assert config.load().ssh_journal == "sshd.service"


# persistent cooldown

def test_cooldown_survives_a_restart(tmp_path):
    state = tmp_path / "cooldown.json"
    lines = [f"Nov 18 09:00:{i:02d} web01 sshd[1]: Failed password for root from 203.0.113.50 port 4000 ssh2" for i in range(6)]
    first = Watcher(Config(), "medium", 3600, year=2026, state_file=state)
    assert len(first.feed(lines, "ssh")) == 1
    assert state.exists()
    second = Watcher(Config(), "medium", 3600, year=2026, state_file=state)
    assert second.feed(lines, "ssh") == []


def test_old_state_is_forgotten(tmp_path):
    state = tmp_path / "cooldown.json"
    state.write_text(json.dumps({"ssh-bruteforce|203.0.113.50": time.time() - 7200}))
    lines = [f"Nov 18 09:00:{i:02d} web01 sshd[1]: Failed password for root from 203.0.113.50 port 4000 ssh2" for i in range(6)]
    assert len(Watcher(Config(), "medium", 3600, year=2026, state_file=state).feed(lines, "ssh")) == 1


def test_broken_state_file_is_ignored(tmp_path):
    state = tmp_path / "cooldown.json"
    state.write_text("{not json")
    w = Watcher(Config(), "medium", 3600, year=2026, state_file=state)
    assert w.alerted == {}


# doctor

def settings(**kw):
    s = config.Settings()
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def by_name(checks):
    return {c.name: c for c in checks}


def test_doctor_flags_missing_and_unreadable_logs(tmp_path):
    ok = tmp_path / "ok.log"
    ok.write_text("")
    c = by_name(doctor.check_files(settings(ssh_logs=[str(ok)], web_logs=[str(tmp_path / "gone.log")])))
    assert c[f"log {ok}"].status == "ok"
    assert c[f"log {tmp_path / 'gone.log'}"].status == "fail"


def test_doctor_journal_without_access(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(doctor, "run_cmd", lambda args, timeout=10: (1, "No journal files were found."))
    c = doctor.check_journal(settings(ssh_journal="sshd.service"))
    assert c[0].status == "fail" and "systemd-journal" in c[0].hint


def test_doctor_journal_ok_and_unknown_unit(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(doctor, "user_groups", lambda: ["systemd-journal"])
    monkeypatch.setattr(doctor, "run_cmd", lambda args, timeout=10: (0, "line") if args[0] == "journalctl" else (1, "not found"))
    c = doctor.check_journal(settings(ssh_journal="sshd.service"))
    assert c[0].status == "ok" and c[1].status == "warn" and "ssh.service" in c[1].hint


def test_doctor_desktop(monkeypatch):
    assert doctor.check_desktop(settings(desktop=False))[0].status == "skip"
    monkeypatch.setattr(doctor.shutil, "which", lambda n: None)
    assert doctor.check_desktop(settings(desktop=True))[0].status == "warn"


def test_doctor_telegram(monkeypatch):
    assert doctor.check_telegram(settings())[0].status == "skip"
    assert doctor.check_telegram(settings(telegram_token="bad", telegram_chat_id="1"))[0].status == "fail"
    token = "123456789:" + "A" * 35
    s = settings(telegram_token=token, telegram_chat_id="1")
    assert doctor.check_telegram(s, online=False)[0].status == "ok"
    monkeypatch.setattr(doctor, "api_call", lambda *a, **k: {"result": {"username": "mybot"}})
    assert "mybot" in doctor.check_telegram(s)[0].detail

    def boom(*a, **k):
        raise doctor.TelegramError("HTTP 401 Unauthorized")

    monkeypatch.setattr(doctor, "api_call", boom)
    c = doctor.check_telegram(s)[0]
    assert c.status == "fail" and token not in c.detail


def test_doctor_service_states(monkeypatch):
    monkeypatch.setattr(service, "state", lambda: "not-installed")
    assert doctor.check_service()[0].status == "warn"
    monkeypatch.setattr(service, "state", lambda: "failed")
    assert doctor.check_service()[0].status == "fail"
    monkeypatch.setattr(service, "state", lambda: "active")
    monkeypatch.setattr(doctor, "run_cmd", lambda args, timeout=10: (0, "Linger=no"))
    c = doctor.check_service()
    assert c[0].status == "ok" and c[1].status == "warn"


def test_doctor_render_and_exit_code(tmp_path, monkeypatch, capsys):
    text = doctor.render([doctor.Check("ok", "a", "fine"), doctor.Check("fail", "b", "broken", "do this")])
    assert "fix: do this" in text and "1 problems" in text
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "s"))
    monkeypatch.setattr(config, "SSH_LOG_CANDIDATES", ())
    assert cli.main(["doctor", "--offline"]) == 1
    assert "nothing to watch" in capsys.readouterr().out


# menu entries

def make_menu(tmp_path, answers):
    s = config.Settings()
    s.alert_file = tmp_path / "alerts.jsonl"
    s.desktop = False
    it = iter(answers)
    out = io.StringIO()
    return Menu(s, inp=lambda _p: next(it), out=out, color=False, anim=False), out


def test_menu_top(tmp_path):
    write_rows(tmp_path / "alerts.jsonl", [row(1, ip="198.51.100.77")])
    m, out = make_menu(tmp_path, ["9", "5000d", "", "0"])
    m.run()
    assert "198.51.100.77" in out.getvalue()


def test_menu_top_rejects_a_bad_period(tmp_path):
    m, out = make_menu(tmp_path, ["9", "soon", "", "0"])
    m.run()
    assert "bad period" in out.getvalue()


def test_menu_doctor(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "check_service", lambda: [doctor.Check("ok", "service", "active")])
    m, out = make_menu(tmp_path, ["10", "", "0"])
    m.run()
    assert "python:" in out.getvalue() and "service: active" in out.getvalue()


def test_menu_detect_saves(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "s"))
    monkeypatch.setattr(config, "SSH_LOG_CANDIDATES", ())
    monkeypatch.setattr(config, "WEB_LOG_CANDIDATES", ())
    monkeypatch.setattr(config, "SSH_UNIT_FILES", ())
    monkeypatch.setattr(service, "state", lambda: "not-installed")
    m, out = make_menu(tmp_path, ["11", "y", "", "0"])
    m.run()
    assert config.load().ssh_journal == "sshd.service"
    assert m.s.has_sources


def test_version_is_2_9_7(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "2.9.7" in capsys.readouterr().out
