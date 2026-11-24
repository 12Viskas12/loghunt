import io
import json
import urllib.error
import urllib.parse
from datetime import datetime

from loghunt import config as cfgmod
from loghunt.models import Finding
from loghunt.telegram import TelegramError, TelegramNotifier, format_message
from loghunt.watch import Alert, build_notifiers, dispatch, watch_main

TOKEN = "123456789:" + "A" * 35
CHAT = "-1001234567890"


def make_alert(severity="high", rule="ssh-bruteforce", ip="192.0.2.99", summary="6 failed SSH logins"):
    now = datetime(2026, 11, 24, 14, 59, 38)
    return Alert(Finding(rule, severity, ip, 6, now, now, summary, "T1110 Brute Force"), now)


class Response:
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Opener:
    """Stands in for urlopen and remembers what was sent."""

    def __init__(self, body=b'{"ok": true}', error=None):
        self.body, self.error, self.calls = body, error, []

    def __call__(self, req, timeout=None):
        self.calls.append((req, timeout))
        if self.error:
            raise self.error
        return Response(self.body)


def raises(exc_type, fn, *args):
    try:
        fn(*args)
    except exc_type as exc:
        return exc
    raise AssertionError(f"{exc_type.__name__} was not raised")


def test_message_is_plain_text_with_the_facts():
    text = format_message(make_alert("critical", "ssh-login-after-bruteforce"))
    assert "CRITICAL" in text and "ssh-login-after-bruteforce" in text
    assert "192.0.2.99" in text and "T1110" in text and "2026-11-24 14:59:38" in text


def test_message_drops_control_characters_and_is_cut():
    text = format_message(make_alert(summary="users: a\x1b[31m\x00b " + "x" * 5000))
    assert "\x1b" not in text and "\x00" not in text
    assert len(text) <= 1000 and text.endswith("...")


def test_send_posts_to_the_bot_api():
    op = Opener()
    TelegramNotifier(TOKEN, CHAT, opener=op).send(make_alert())
    req, timeout = op.calls[0]
    assert req.full_url == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert req.get_method() == "POST" and timeout == 5.0
    form = urllib.parse.parse_qs(req.data.decode())
    assert form["chat_id"] == [CHAT]
    assert "ssh-bruteforce" in form["text"][0]
    assert form["disable_web_page_preview"] == ["true"]
    assert "parse_mode" not in form


def test_minimum_level_filters_but_test_and_summary_always_go():
    op = Opener()
    n = TelegramNotifier(TOKEN, CHAT, min_severity="high", opener=op)
    n.send(make_alert("medium"))
    assert op.calls == []
    n.send(make_alert("high"))
    n.send(make_alert("low", rule="test-alert"))
    n.send(make_alert("low", rule="more-alerts"))
    assert len(op.calls) == 3


def test_bad_token_or_chat_is_rejected_without_echoing_it():
    exc = raises(ValueError, TelegramNotifier, "not-a-token", CHAT)
    assert "not-a-token" not in str(exc)
    raises(ValueError, TelegramNotifier, TOKEN, "some chat")
    raises(ValueError, TelegramNotifier, "", CHAT)
    TelegramNotifier(TOKEN, "@my_channel")
    TelegramNotifier(TOKEN, "123456")


def test_http_error_gives_the_reason_but_never_the_token(capsys):
    body = io.BytesIO(b'{"ok": false, "description": "Unauthorized"}')
    err = urllib.error.HTTPError(f"https://api.telegram.org/bot{TOKEN}/sendMessage", 401, "Unauthorized", {}, body)
    exc = raises(TelegramError, TelegramNotifier(TOKEN, CHAT, opener=Opener(error=err)).send, make_alert())
    assert "401" in str(exc) and "Unauthorized" in str(exc) and TOKEN not in str(exc)
    assert exc.__cause__ is None and exc.__suppress_context__
    err2 = urllib.error.HTTPError("https://x", 400, "Bad", {}, io.BytesIO(b'{"ok": false, "description": "Bad Request: chat not found"}'))
    dispatch([make_alert()], [TelegramNotifier(TOKEN, CHAT, opener=Opener(error=err2))])
    out = capsys.readouterr().err
    assert "telegram notifier failed" in out and "chat not found" in out and TOKEN not in out


def test_network_error_is_reported_by_type_only(capsys):
    err = urllib.error.URLError(f"cannot reach https://api.telegram.org/bot{TOKEN}/sendMessage")
    dispatch([make_alert()], [TelegramNotifier(TOKEN, CHAT, opener=Opener(error=err))])
    out = capsys.readouterr().err
    assert "telegram notifier failed: URLError" in out and TOKEN not in out


def test_ok_false_in_a_200_answer_is_an_error():
    raises(TelegramError, TelegramNotifier(TOKEN, CHAT, opener=Opener(body=b'{"ok": false}')).send, make_alert())
    raises(ValueError, TelegramNotifier(TOKEN, CHAT, opener=Opener(body=b"<html>")).send, make_alert())


def test_default_config_has_an_empty_telegram_section(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("LOGHUNT_TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("LOGHUNT_TELEGRAM_CHAT_ID", raising=False)
    path = cfgmod.write_default(tmp_path / "loghunt.ini")
    assert "[telegram]" in path.read_text()
    s = cfgmod.load(path)
    assert not s.has_telegram and s.telegram_min_severity == "high"


def test_config_reads_the_telegram_section_and_env_wins(tmp_path, monkeypatch):
    monkeypatch.delenv("LOGHUNT_TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("LOGHUNT_TELEGRAM_CHAT_ID", raising=False)
    path = tmp_path / "loghunt.ini"
    path.write_text(f"[telegram]\nbot_token = {TOKEN}\nchat_id = {CHAT}\nmin_severity = critical ; only the worst\n")
    s = cfgmod.load(path)
    assert s.has_telegram and s.telegram_token == TOKEN and s.telegram_chat_id == CHAT
    assert s.telegram_min_severity == "critical"
    monkeypatch.setenv("LOGHUNT_TELEGRAM_TOKEN", "987654321:" + "B" * 35)
    assert cfgmod.load(path).telegram_token.startswith("987654321:")
    path.write_text("[telegram]\nmin_severity = nonsense\n")
    monkeypatch.delenv("LOGHUNT_TELEGRAM_TOKEN")
    assert cfgmod.load(path).telegram_min_severity == "high"


def settings(**kw):
    s = cfgmod.Settings(console=False, desktop=False, alert_file=None)
    s.telegram_token, s.telegram_chat_id = TOKEN, CHAT
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def test_build_notifiers_adds_telegram_only_when_configured():
    assert [n.name for n in build_notifiers(settings())] == ["telegram"]
    assert build_notifiers(settings(telegram_token="")) == []
    assert build_notifiers(settings(), telegram=False) == []


def test_build_notifiers_warns_about_a_bad_token(capsys):
    assert build_notifiers(settings(telegram_token="oops")) == []
    err = capsys.readouterr().err
    assert "telegram disabled" in err and "oops" not in err


def test_telegram_counts_as_an_external_channel():
    op = Opener()
    n = TelegramNotifier(TOKEN, CHAT, opener=op)
    dispatch([make_alert(rule=f"r{i}") for i in range(8)], [n])
    assert len(op.calls) == 6   # five alerts and one summary


def test_test_notify_reaches_telegram(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("LOGHUNT_TELEGRAM_CHAT_ID", raising=False)
    op = Opener()
    monkeypatch.setattr("urllib.request.urlopen", op)
    ini = tmp_path / "loghunt.ini"
    ini.write_text(f"[telegram]\nbot_token = {TOKEN}\nchat_id = {CHAT}\n")
    monkeypatch.delenv("LOGHUNT_TELEGRAM_TOKEN", raising=False)
    code = watch_main(["--config", str(ini), "--no-desktop", "--test-notify"])
    assert code == 0
    assert "channels: console, file, telegram" in capsys.readouterr().out
    assert len(op.calls) == 1
    code = watch_main(["--config", str(ini), "--no-desktop", "--no-telegram", "--test-notify"])
    assert len(op.calls) == 1
