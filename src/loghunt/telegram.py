"""Telegram channel: sends an alert as a bot message. Standard library only."""
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional

from .models import SEVERITIES, severity_rank

API = "https://api.telegram.org/bot{token}/sendMessage"
API_METHOD = "https://api.telegram.org/bot{token}/{method}"
TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{20,}$")
CHAT_RE = re.compile(r"^(-?\d+|@[A-Za-z][A-Za-z0-9_]{4,})$")
ICONS = {"critical": "\U0001F6A8", "high": "\U0001F534", "medium": "\U0001F7E0", "low": "\U0001F535"}
ALWAYS = ("test-alert", "more-alerts")   # sent whatever the minimum level is
MAX_TEXT = 1000
CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")


class TelegramError(ValueError):
    """The Telegram API refused the message. The text never contains the token."""


def clean(text: str) -> str:
    """Log lines are written by the attacker. Drop control characters and keep the message short."""
    text = CONTROL.sub("?", text)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 3] + "..."


def format_message(alert) -> str:
    """Plain text on purpose: no parse_mode, so nothing from a log line can become formatting or a link preview."""
    f = alert.finding
    lines = [f"{ICONS.get(f.severity, '')} {f.severity.upper()}  {f.rule}"]
    if f.ip != "-":
        lines.append(f"address: {f.ip}")
    lines.append(f.summary)
    if f.mitre != "-":
        lines.append(f.mitre)
    lines.append(alert.sent_at.strftime("%Y-%m-%d %H:%M:%S"))
    return clean("\n".join(lines))


def _description(exc: urllib.error.HTTPError) -> str:
    try:
        return str(json.loads(exc.read().decode("utf-8", "replace")).get("description", ""))[:80]
    except (ValueError, OSError, AttributeError):
        return ""


class TelegramNotifier:
    name = "telegram"

    def __init__(self, token: str, chat_id: str, min_severity: str = "high", timeout: float = 5.0,
                 opener: Optional[Callable] = None):
        if not TOKEN_RE.match(token or ""):
            raise ValueError("the bot token does not look right, it should be like 123456789:AA...")
        if not CHAT_RE.match(str(chat_id or "")):
            raise ValueError("chat_id must be a number (negative for groups) or @channelname")
        self.token = token
        self.chat_id = str(chat_id)
        self.min_rank = severity_rank(min_severity if min_severity in SEVERITIES else "high")
        self.timeout = timeout
        self.opener = opener

    def send(self, alert) -> None:
        f = alert.finding
        if f.rule not in ALWAYS and severity_rank(f.severity) < self.min_rank:
            return
        data = urllib.parse.urlencode({
            "chat_id": self.chat_id,
            "text": format_message(alert),
            "disable_web_page_preview": "true",
        }).encode("ascii")
        req = urllib.request.Request(API.format(token=self.token), data=data, method="POST")
        opener = self.opener or urllib.request.urlopen
        try:
            with opener(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            # "from None": the original error carries the URL, and the URL carries the token
            raise TelegramError(f"HTTP {exc.code} {_description(exc)}".strip()) from None
        if not isinstance(body, dict) or not body.get("ok"):
            raise TelegramError("Telegram answered ok=false")


def api_call(token: str, method: str, opener: Optional[Callable] = None, timeout: float = 10.0) -> dict:
    """GET a Bot API method such as getMe or getUpdates. Errors never contain the token."""
    req = urllib.request.Request(API_METHOD.format(token=token, method=method))
    try:
        with (opener or urllib.request.urlopen)(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        raise TelegramError(f"HTTP {exc.code} {_description(exc)}".strip()) from None
    except urllib.error.URLError as exc:
        raise TelegramError(f"cannot reach Telegram ({type(exc.reason).__name__})") from None
    if not isinstance(body, dict) or not body.get("ok"):
        raise TelegramError("Telegram answered ok=false")
    return body


def find_chat_id(token: str, opener: Optional[Callable] = None) -> Optional[str]:
    """The chat of the newest message the bot has received, or None."""
    for upd in reversed(api_call(token, "getUpdates", opener).get("result", [])):
        for key in ("message", "channel_post", "edited_message"):
            chat = (upd.get(key) or {}).get("chat")
            if chat and "id" in chat:
                return str(chat["id"])
    return None
