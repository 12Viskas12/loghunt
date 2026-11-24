# Rules

All rate rules count events from one address inside a sliding window. The default window is 600 seconds (`--window`). Addresses given with `--ignore-ip` are skipped everywhere.

## SSH

Only sshd lines are used: `Failed password`, `Failed publickey`, `Invalid user` and `Accepted`.

ssh-bruteforce (high, T1110). At least `--ssh-fails` failed logins (default 5) from one address inside the window. The report lists the usernames that were tried. Two typos by a real user don't reach the threshold.

ssh-user-enumeration (medium, T1110). At least `--enum-users` different usernames (default 5) that don't exist on the machine, from one address. sshd writes both an `Invalid user` line and a `Failed password for invalid user` line for one attempt, the tool counts each name once.

ssh-login-after-bruteforce (critical, T1078). An `Accepted` line from an address that matched ssh-bruteforce, during or up to one window after the failures. This is the finding to look at first: the guessing may have worked.

## Web

The log has to be in the `combined` format. The user agent is optional, so the plain `common` format works for most rules.

web-scan (medium, T1595). Either `--web-errors` answers with a 4xx status (default 15) inside the window, or at least 3 different sensitive paths requested. Sensitive paths are things like `/.env`, `/.git/`, `/.aws`, `/wp-login.php`, `/xmlrpc.php`, `/phpmyadmin`, `/adminer`, `/actuator`, `/server-status`, `backup.zip` and `config.php`.

web-scanner-agent (medium, T1595). The user agent contains the name of a known tool: sqlmap, nikto, nmap, masscan, gobuster, dirbuster, dirb, wpscan, hydra, zgrab, nuclei, acunetix or feroxbuster. An attacker can change this string, so its absence means nothing.

web-attack-sql-injection, web-attack-xss, web-attack-path-traversal, web-attack-command-injection, web-attack-log4shell (high, T1190). The URL, decoded twice so `%252e%252e%252f` is caught, matches a pattern of that attack. Log4shell is also searched for in the user agent, where it is usually sent. These rules fire on the first match, because one such request is already worth a look. Whether it worked depends on the status code and the application.

web-login-bruteforce (high, T1110). At least `--login-posts` POST requests (default 10) to a path with `login`, `signin`, `wp-login.php` or `admin` in it, inside the window.

## Adding a rule

A rule is a function in `src/loghunt/detectors.py` that takes the list of events and returns findings. Add it to `detect_ssh` or `detect_web`, and write a test in `tests/test_detectors.py` for the case that triggers it and the case that must stay quiet.
