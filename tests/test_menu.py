import io
import json

from loghunt import cli, config, service
from loghunt.menu import Menu


def make_menu(tmp_path, answers, **kw):
    s = config.Settings()
    s.alert_file = tmp_path / "alerts.jsonl"
    s.desktop = False
    it = iter(answers)
    out = io.StringIO()
    return Menu(s, inp=lambda _p: next(it), out=out, color=False, anim=False, **kw), out


def test_quit(tmp_path):
    m, out = make_menu(tmp_path, ["0"])
    assert m.run() == 0
    assert "analyze a log file" in out.getvalue()
    assert "bye" in out.getvalue()


def test_eof_quits(tmp_path):
    def boom(_):
        raise EOFError

    s = config.Settings()
    s.alert_file = tmp_path / "a.jsonl"
    m = Menu(s, inp=boom, out=io.StringIO(), color=False, anim=False)
    assert m.run() == 0


def test_unknown_choice_is_reported(tmp_path):
    m, out = make_menu(tmp_path, ["x", "0"])
    m.run()
    assert "unknown choice" in out.getvalue()


def test_analyze_file(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("".join(
        f"2026-11-18T09:00:{i:02d}+00:00 h sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
        for i in range(8)))
    m, out = make_menu(tmp_path, ["1", str(log), "n", "", "0"])
    m.run()
    assert "ssh-bruteforce" in capsys.readouterr().out


def test_recent_alerts(tmp_path):
    row = {"time": "2026-11-18T09:00:00", "severity": "high", "rule": "ssh-bruteforce", "ip": "203.0.113.5",
           "summary": "8 failed logins"}
    (tmp_path / "alerts.jsonl").write_text(json.dumps(row) + "\nnot json\n")
    m, out = make_menu(tmp_path, ["5", "", "0"])
    m.run()
    assert "ssh-bruteforce" in out.getvalue()
    assert "1 recorded" in out.getvalue()


def test_test_notification_goes_to_the_alert_file(tmp_path):
    m, _ = make_menu(tmp_path, ["6", "", "0"])
    m.run()
    assert "test-alert" in (tmp_path / "alerts.jsonl").read_text()


def test_unit_text_uses_the_given_python():
    text = service.unit_text("/opt/venv/bin/python")
    assert "ExecStart=/opt/venv/bin/python -m loghunt watch" in text
    assert "[Install]" in text


def test_install_writes_unit_and_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(service, "systemctl", lambda *a, **k: (0, ""))
    notes = service.install("/x/python")
    assert (tmp_path / "cfg" / "systemd" / "user" / "loghunt.service").exists()
    assert (tmp_path / "cfg" / "loghunt" / "loghunt.ini").exists()
    assert notes[-1].startswith("service enabled")


def test_uninstall_removes_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(service, "systemctl", lambda *a, **k: (0, ""))
    service.unit_path().parent.mkdir(parents=True)
    service.unit_path().write_text("x")
    service.uninstall()
    assert not service.unit_path().exists()


def test_state_without_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(service.shutil, "which", lambda n: "/usr/bin/systemctl")
    assert service.state() == "not-installed"


def test_cli_init_config(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert cli.main(["init-config"]) == 0
    assert (tmp_path / "loghunt" / "loghunt.ini").exists()


def test_cli_routes_to_watch_test_notify(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "s"))
    assert cli.main(["watch", "--test-notify", "--no-desktop"]) == 0
    assert "channels:" in capsys.readouterr().out


def test_inline_comments_in_ini(tmp_path):
    p = tmp_path / "x.ini"
    p.write_text("[alerts]\nmin_severity = high     ; low, medium\ncooldown = 60  ; seconds\n")
    s = config.load(p)
    assert s.min_severity == "high"
    assert s.cooldown == 60


def test_inline_comment_after_a_single_space(tmp_path):
    p = tmp_path / "x.ini"
    p.write_text("[alerts]\nmin_severity = critical ; note\n[detection]\nignore_ips = 1.1.1.1;2\n")
    s = config.load(p)
    assert s.min_severity == "critical"
    assert s.detection.ignore_ips == ["1.1.1.1;2"]
