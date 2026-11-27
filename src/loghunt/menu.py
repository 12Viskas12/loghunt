import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from . import __version__
from . import config as cfgmod
from . import service
from .cli import analyze
from . import doctor as doctormod
from . import summary
from .telegram import CHAT_RE, TOKEN_RE, TelegramError, TelegramNotifier, api_call, find_chat_id
from .watch import build_notifiers, dispatch, run_watch, test_alert

BANNER = r"""
  _               _                 _
 | | ___   __ _  | |__  _   _ _ __ | |_
 | |/ _ \ / _` | | '_ \| | | | '_ \| __|
 | | (_) | (_| | | | | | |_| | | | | |_
 |_|\___/ \__, | |_| |_|\__,_|_| |_|\__|
          |___/
"""

G, DG, R, Y, C, B, X = "\033[92m", "\033[32m", "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"


class Menu:
    def __init__(self, settings: cfgmod.Settings, inp: Callable[[str], str] = input, out=None,
                 color: Optional[bool] = None, anim: bool = True):
        self.s = settings
        self.inp = inp
        self.out = out or sys.stdout
        self.color = self.out.isatty() and "NO_COLOR" not in os.environ if color is None else color
        self.anim = anim and self.out.isatty()

    def paint(self, text: str, code: str) -> str:
        return f"{code}{text}{X}" if self.color else text

    def say(self, text: str = "", code: str = "") -> None:
        print(self.paint(text, code) if code else text, file=self.out, flush=True)

    def type_out(self, text: str, code: str = G, delay: float = 0.004) -> None:
        if not self.anim:
            self.say(text, code)
            return
        for ch in text:
            self.out.write(self.paint(ch, code) if self.color else ch)
            self.out.flush()
            time.sleep(delay)
        self.out.write("\n")

    def banner(self) -> None:
        self.say(BANNER, G)
        self.type_out(f"  log hunter {__version__}  //  ssh + web attack detection  //  desktop and telegram alerts", DG)
        self.say()

    def status_lines(self) -> List[str]:
        svc = service.state()
        alerts = self.recent_alerts(1000)
        chans = [n.name for n in build_notifiers(self.s)]
        srcs = ([f"journal:{self.s.ssh_journal}"] if self.s.ssh_journal else []) + self.s.ssh_logs + self.s.web_logs
        return [
            f"service   : {svc}",
            f"sources   : {', '.join(srcs) if srcs else 'none, edit ' + str(cfgmod.config_path())}",
            f"channels  : {', '.join(chans) or 'none'}",
            f"min level : {self.s.min_severity}",
            f"alerts    : {len(alerts)} recorded",
        ]

    def panel(self, title: str, lines: List[str]) -> None:
        width = max([len(title) + 4] + [len(l) + 4 for l in lines])
        self.say("+-[ " + title + " ]" + "-" * (width - len(title) - 6) + "+", DG)
        for l in lines:
            self.say("| " + l.ljust(width - 3) + "|", DG)
        self.say("+" + "-" * (width - 2) + "+", DG)

    def ask(self, prompt: str) -> str:
        try:
            return self.inp(self.paint(prompt, G) if self.color else prompt).strip()
        except EOFError:
            return "0"

    def recent_alerts(self, n: int = 15) -> List[dict]:
        path = self.s.alert_file
        if not path or not Path(path).exists():
            return []
        rows = []
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines()[-n:]:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        return rows

    def pause(self) -> None:
        self.ask("\n[enter] back to menu ")

    def do_analyze_file(self) -> None:
        path = self.ask("path to a log file: ")
        if not path:
            return
        analyze([os.path.expanduser(path), "--format", "brief"])
        if self.ask("full details? [y/N] ").lower().startswith("y"):
            analyze([os.path.expanduser(path)])

    def do_analyze_journal(self) -> None:
        unit = self.s.ssh_journal or "sshd.service"
        self.say(f"reading journal of {unit} ...", DG)
        try:
            r = subprocess.run(["journalctl", "-u", unit, "-o", "short-iso", "--no-pager", "-n", "5000"],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            self.say(f"cannot run journalctl: {exc}", R)
            return
        if r.returncode != 0 or not r.stdout.strip():
            self.say(r.stderr.strip() or "the journal is empty", R)
            self.say("tip: add yourself to the group: sudo usermod -aG systemd-journal $USER", Y)
            return
        tmp = cfgmod.state_dir() / "journal.log"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(r.stdout, encoding="utf-8")
        analyze([str(tmp), "--type", "ssh", "--format", "brief"])

    def do_live(self) -> None:
        if not self.s.has_sources:
            self.say(f"no sources configured, edit {cfgmod.config_path()}", R)
            return
        self.say("live monitor, Ctrl+C to go back", Y)
        stop = threading.Event()
        t = threading.Thread(target=run_watch, args=(self.s, build_notifiers(self.s), stop), daemon=True)
        t.start()
        try:
            while t.is_alive():
                time.sleep(0.3)
        except KeyboardInterrupt:
            pass
        stop.set()
        t.join(timeout=3)
        self.say()

    def do_service(self) -> None:
        while True:
            self.panel("service", [f"state: {service.state()}", "",
                                   "1  install and start", "2  start", "3  stop", "4  status", "5  logs",
                                   "6  uninstall", "0  back"])
            choice = self.ask("service> ")
            actions = {"1": "install", "2": "start", "3": "stop", "4": "status", "5": "logs", "6": "uninstall"}
            if choice in ("0", "q", ""):
                return
            if choice in actions:
                service.run(actions[choice])
            else:
                self.say("unknown choice", R)

    def do_alerts(self) -> None:
        rows = self.recent_alerts()
        if not rows:
            self.say("no alerts yet", DG)
            return
        for a in rows:
            col = {"critical": R, "high": R, "medium": Y}.get(a["severity"], C)
            self.say(f"{a['time']}  {a['severity'].upper():8} {a['rule']:28} {a['ip']:16} {a['summary'][:60]}", col)

    def do_test(self) -> None:
        notifiers = build_notifiers(self.s)
        self.say("channels: " + ", ".join(n.name for n in notifiers))
        dispatch([test_alert()], notifiers)

    def do_telegram(self) -> None:
        s = self.s
        while True:
            state = f"bot set up, chat {s.telegram_chat_id}" if s.has_telegram else "not set up"
            self.panel("telegram", [f"state: {state}", "", "1  set the bot token and chat", "2  send a test message",
                                    "3  remove the bot", "0  back"])
            choice = self.ask("telegram> ")
            if choice in ("0", "q", ""):
                return
            if choice == "1":
                self.telegram_setup()
            elif choice == "2":
                self.telegram_test()
            elif choice == "3":
                cfgmod.save_telegram("", "")
                s.telegram_token = s.telegram_chat_id = ""
                self.say("removed", DG)
                self.restart_service()
            else:
                self.say("unknown choice", R)

    def telegram_test(self) -> None:
        s = self.s
        if not s.has_telegram:
            self.say("set the token first", R)
            return
        try:
            TelegramNotifier(s.telegram_token, s.telegram_chat_id, s.telegram_min_severity).send(test_alert())
            self.say("sent, look at your chat", G)
        except (ValueError, OSError) as exc:
            self.say(f"telegram refused it: {exc}", R)

    def telegram_setup(self) -> None:
        self.say("1. In Telegram open @BotFather, send /newbot and copy the token it gives you.", DG)
        token = self.ask("bot token: ")
        if not token:
            return
        if not TOKEN_RE.match(token):
            self.say("that does not look like a token, it should be like 123456789:AA...", R)
            return
        try:
            me = api_call(token, "getMe")["result"]
        except (TelegramError, KeyError) as exc:
            self.say(f"the token does not work: {exc}", R)
            return
        self.say(f"bot found: @{me.get('username', '?')}", G)
        self.say("2. Open your bot in Telegram, press Start and send it any message.", DG)
        self.ask("[enter] when you have sent it ")
        chat = None
        try:
            chat = find_chat_id(token)
        except TelegramError as exc:
            self.say(f"cannot read the bot updates: {exc}", R)
        if chat:
            self.say(f"chat id found: {chat}", G)
        else:
            chat = self.ask("no message found, type the chat id by hand (empty to cancel): ")
            if not chat:
                return
            if not CHAT_RE.match(chat):
                self.say("the chat id must be a number or @channelname", R)
                return
        path = cfgmod.save_telegram(token, chat)
        self.s.telegram_token, self.s.telegram_chat_id = token, chat
        self.say(f"saved to {path}", G)
        self.restart_service()

    def restart_service(self) -> None:
        if service.state() == "active":
            service.run("restart")
            self.say("service restarted with the new settings", DG)

    def do_top(self) -> None:
        period = self.ask("period [24h]: ") or "24h"
        try:
            delta = summary.parse_since(period)
        except ValueError as exc:
            self.say(str(exc), R)
            return
        rows = summary.load_alerts(self.s.alert_file, delta)
        self.say(summary.render(summary.summarize(rows), period), G)

    def do_doctor(self) -> None:
        self.say(doctormod.render(doctormod.run_checks(self.s), self.color))

    def do_detect(self) -> None:
        found = cfgmod.find_sources()
        self.say(f"sshd journal : {found.ssh_journal or 'not used, a log file was found'}")
        self.say(f"ssh log files: {', '.join(found.ssh_logs) or 'none'}")
        self.say(f"web log files: {', '.join(found.web_logs) or 'none'}")
        if self.ask("save this into the config? [y/N] ").lower().startswith("y"):
            self.say(f"saved to {cfgmod.save_sources(found)}", G)
            self.s.ssh_journal, self.s.ssh_logs, self.s.web_logs = found.ssh_journal, found.ssh_logs, found.web_logs
            self.restart_service()

    def do_config(self) -> None:
        path = cfgmod.config_path()
        if not path.exists():
            self.say(f"{path} does not exist, writing the default one")
            cfgmod.write_default()
        self.say(f"config: {path}")
        editor = os.environ.get("EDITOR")
        if editor and self.ask(f"open in {editor}? [y/N] ").lower().startswith("y"):
            subprocess.call([editor, str(path)])
            self.s = cfgmod.load()

    def items(self):
        return [
            ("1", "analyze a log file", self.do_analyze_file),
            ("2", "analyze the sshd journal", self.do_analyze_journal),
            ("3", "live monitor", self.do_live),
            ("4", "background service (systemd)", self.do_service),
            ("5", "recent alerts", self.do_alerts),
            ("6", "send a test notification", self.do_test),
            ("7", "telegram bot", self.do_telegram),
            ("8", "config", self.do_config),
            ("9", "top attackers", self.do_top),
            ("10", "doctor, check everything", self.do_doctor),
            ("11", "find log sources", self.do_detect),
            ("0", "quit", None),
        ]

    def run(self) -> int:
        self.banner()
        while True:
            self.panel("status", self.status_lines())
            self.say()
            for key, label, _ in self.items():
                self.say(f"  [{key}] {label}", G)
            choice = self.ask("\nloghunt> ")
            if choice in ("0", "q", "quit", "exit"):
                self.say("bye", DG)
                return 0
            action = {k: f for k, _, f in self.items()}.get(choice)
            if action is None:
                self.say("unknown choice", R)
                continue
            self.say()
            try:
                action()
            except KeyboardInterrupt:
                self.say("\ninterrupted", Y)
            self.pause()
            if self.anim:
                self.out.write("\033[2J\033[H")


def menu_main(argv: Optional[List[str]] = None) -> int:
    argv = list(argv or [])
    s = cfgmod.load()
    return Menu(s, anim="--no-anim" not in argv).run()
