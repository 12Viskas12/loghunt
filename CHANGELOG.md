# Changelog

## 2.9.7

Added

- `loghunt doctor` checks the whole setup (log access, journal group, notify-send, session bus, Telegram, service, linger) and prints what to fix for every problem. The exit code is 1 when something is broken.
- `loghunt top [--since 24h]` shows who attacked you lately, from the alerts the watcher saved: addresses ranked by severity, counts and rules.
- `loghunt detect [--write]` finds the logs on this machine (auth.log or secure, nginx, Apache) and writes them into the config. `init-config` now does the same, so a fresh config already points at real files.
- The watcher remembers which rule and address it has reported, in `~/.local/state/loghunt/cooldown.json`. A restart no longer repeats every alert.
- The menu has Telegram setup (7), top attackers (9), doctor (10) and source detection (11).
- Packages: PKGBUILD for Arch, `scripts/build-deb.sh` for Debian and Ubuntu, `loghunt service install` uses the unit that the package ships.
- A release workflow builds the `.deb` on every `v*` tag and attaches it to the GitHub release.

Changed

- The default sshd unit is `ssh.service` on Debian and Ubuntu and `sshd.service` elsewhere.
- Settings in `loghunt.ini` are changed in place, comments and other sections stay as they were.

Fixed

- Desktop notifications report a failing `notify-send` instead of ignoring it.
