# Running loghunt in the background

## Install

```bash
loghunt service install
```

This writes `~/.config/loghunt/loghunt.ini` if it is missing, then runs `systemctl --user enable --now loghunt.service`. The pacman and apt packages ship the unit in `/usr/lib/systemd/user`, and it is used as it is. After a plain pip install the command writes its own unit into `~/.config/systemd/user` that starts the same Python.

Check it:

```bash
systemctl --user status loghunt
journalctl --user -u loghunt -f
loghunt watch --test-notify
```

## Access to the sshd journal

On Arch sshd logs only to the journal. A normal user can read it after joining a group:

```bash
sudo usermod -aG systemd-journal $USER
```

Log out and in again. If you skip this, the service starts but sees no sshd lines, and `journalctl --user -u loghunt` says so.

You can follow plain files instead. In `loghunt.ini`:

```ini
[sources]
ssh_journal =
web_logs = /var/log/nginx/access.log
```

The user needs read access to those files too.

## Keep it running after logout

User services stop with the last session unless lingering is on:

```bash
loginctl enable-linger $USER
```

## Config

```ini
[alerts]
min_severity = medium     ; low, medium, high, critical
cooldown = 3600           ; seconds before the same rule and address is reported again
console = yes
desktop = yes
file = ~/.local/state/loghunt/alerts.jsonl
```

Restart after changes: `loghunt service restart`.

## Telegram

Set the bot up from the menu (`loghunt`, then 7) or add a `[telegram]` section to `loghunt.ini` by hand (see [telegram.md](telegram.md)), and restart the service. The menu restarts it for you. Environment variables from your shell are not visible to the unit, so use the file.

## Desktop notifications

They are ordinary system popups from `notify-send` (package `libnotify`: `sudo pacman -S libnotify`) and need a notification daemon in your session, which every desktop environment has. The unit points `DBUS_SESSION_BUS_ADDRESS` at the user bus. A window manager without a daemon needs `dunst`.

## Remove

```bash
loghunt service uninstall
```
