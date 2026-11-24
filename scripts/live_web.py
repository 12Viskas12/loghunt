"""A tiny web server that writes an access log in the nginx/Apache combined format.
Gives a real access log from real requests."""
import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGES = {"/", "/about", "/blog", "/contact", "/favicon.ico"}


class Handler(BaseHTTPRequestHandler):
    log_file = None

    def _answer(self):
        path = self.path.split("?")[0]
        ok = path in PAGES or (self.command == "POST" and path == "/wp-login.php")
        body = b"ok\n" if ok else b"not found\n"
        self.send_response(200 if ok else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_HEAD = _answer

    def log_request(self, code="-", size="-"):
        now = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
        ref = self.headers.get("Referer", "-")
        agent = self.headers.get("User-Agent", "-")
        line = f'{self.client_address[0]} - - [{now}] "{self.requestline}" {code} {size} "{ref}" "{agent}"\n'
        with open(self.log_file, "a", encoding="utf-8") as fh:
            fh.write(line)

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--log", required=True)
    args = ap.parse_args()
    Handler.log_file = args.log
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"listening on 127.0.0.1:{args.port}, writing {args.log}, Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
