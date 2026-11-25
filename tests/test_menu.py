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


import urllib.error

from loghunt import telegram

TOKEN = "123456789:" + "A" * 35


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_telegram(monkeypatch, updates=None, good_token=TOKEN):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if f"/bot{good_token}/" not in req.full_url:
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
        if req.full_url.endswith("/getMe"):
            return FakeResponse({"ok": True, "result": {"username": "my_loghunt_bot"}})
        if req.full_url.endswith("/getUpdates"):
            return FakeResponse({"ok": True, "result": updates if updates is not None
                                 else [{"update_id": 1, "message": {"chat": {"id": 777}}}]})
        return FakeResponse({"ok": True})

    monkeypatch.setattr(telegram.urllib.request, "urlopen", fake_urlopen)
    return calls


def test_menu_telegram_setup_saves_token_and_chat(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.delenv("LOGHUNT_TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("LOGHUNT_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setattr(service, "state", lambda: "not-installed")
    calls = fake_telegram(monkeypatch)
    m, out = make_menu(tmp_path, ["7", "1", TOKEN, "", "2", "0", "", "0"])
    m.run()
    text = out.getvalue()
    assert "@my_loghunt_bot" in text and "chat id found: 777" in text and "sent, look at your chat" in text
    assert calls[-1].endswith("/sendMessage")
    loaded = config.load()
    assert loaded.telegram_token == TOKEN and loaded.telegram_chat_id == "777"
    assert oct(config.config_path().stat().st_mode & 0o777) == "0o600"


def test_menu_telegram_rejects_a_malformed_token_without_network(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    calls = fake_telegram(monkeypatch)
    m, out = make_menu(tmp_path, ["7", "1", "not-a-token", "0", "", "0"])
    m.run()
    assert "does not look like a token" in out.getvalue()
    assert calls == []
    assert not config.config_path().exists()


def test_menu_telegram_rejects_a_wrong_token(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    fake_telegram(monkeypatch, good_token="999999999:" + "B" * 35)
    m, out = make_menu(tmp_path, ["7", "1", TOKEN, "0", "", "0"])
    m.run()
    text = out.getvalue()
    assert "the token does not work: HTTP 401" in text
    assert TOKEN not in text
    assert not config.config_path().exists()


def test_menu_telegram_asks_for_the_chat_when_nothing_was_sent(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.delenv("LOGHUNT_TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("LOGHUNT_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setattr(service, "state", lambda: "not-installed")
    fake_telegram(monkeypatch, updates=[])
    m, out = make_menu(tmp_path, ["7", "1", TOKEN, "", "-100123", "0", "", "0"])
    m.run()
    assert "chat id found" not in out.getvalue()
    assert config.load().telegram_chat_id == "-100123"


def test_menu_telegram_remove(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.delenv("LOGHUNT_TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("LOGHUNT_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setattr(service, "state", lambda: "not-installed")
    config.save_telegram(TOKEN, "5")
    m, _ = make_menu(tmp_path, ["7", "3", "0", "", "0"])
    m.s.telegram_token, m.s.telegram_chat_id = TOKEN, "5"
    m.run()
    assert not config.load().has_telegram


def test_api_call_errors_never_contain_the_token(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError(ConnectionRefusedError())

    monkeypatch.setattr(telegram.urllib.request, "urlopen", boom)
    exc = None
    try:
        telegram.api_call(TOKEN, "getMe")
    except telegram.TelegramError as e:
        exc = e
    assert exc is not None and TOKEN not in str(exc) and "ConnectionRefusedError" in str(exc)


def test_save_telegram_keeps_comments_and_other_sections(tmp_path):
    p = tmp_path / "x.ini"
    p.write_text("[sources]\nweb_logs = /a.log\n\n[telegram]\n; fill both\nbot_token =\nchat_id =\nmin_severity = medium\n"
                 "\n[alerts]\nmin_severity = high\n")
    config.save_telegram(TOKEN, "5", p)
    text = p.read_text()
    assert "; fill both" in text
    s = config.load(p)
    assert s.web_logs == ["/a.log"] and s.min_severity == "high"
    assert s.telegram_token == TOKEN and s.telegram_chat_id == "5" and s.telegram_min_severity == "medium"


def test_save_telegram_adds_the_section_when_missing(tmp_path):
    p = tmp_path / "x.ini"
    p.write_text("[sources]\nweb_logs = /a.log\n")
    config.save_telegram(TOKEN, "5", p)
    s = config.load(p)
    assert s.web_logs == ["/a.log"] and s.telegram_chat_id == "5"


def test_save_telegram_fills_missing_keys_in_the_last_section(tmp_path):
    p = tmp_path / "x.ini"
    p.write_text("[telegram]\nmin_severity = high\n")
    config.save_telegram(TOKEN, "5", p)
    assert config.load(p).has_telegram


def test_install_uses_the_packaged_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    packaged = tmp_path / "loghunt.service"
    packaged.write_text("[Service]\nExecStart=/usr/bin/loghunt watch\n")
    monkeypatch.setattr(service, "PACKAGED_UNITS", (packaged,))
    calls = []
    monkeypatch.setattr(service, "systemctl", lambda *a, **k: calls.append(a) or (0, ""))
    notes = service.install()
    assert not service.unit_path().exists()
    assert any("from the package" in n for n in notes)
    assert ("enable", "--now", "loghunt.service") in calls


def test_default_ssh_unit_follows_the_distribution(tmp_path, monkeypatch):
    unit = tmp_path / "ssh.service"
    monkeypatch.setattr(config, "SSH_UNIT_FILES", (unit,))
    assert config.default_ssh_unit() == "sshd.service"
    unit.write_text("")
    assert config.default_ssh_unit() == "ssh.service"
