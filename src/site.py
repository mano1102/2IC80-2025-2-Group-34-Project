#!/usr/bin/env python3
"""
SSL stripping demo test site:

"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import threading
import os
import subprocess

CERT_PATH = "server.pem"
HTTP_PORT = 80
HTTPS_PORT = 443


def ensure_cert():
    """Create a self-signed cert+key PEM if missing."""
    if os.path.exists(CERT_PATH):
        return

    print("[*] Generating self-signed certificate...", flush=True)
    subprocess.run([
        "openssl", "req", "-new", "-x509",
        "-keyout", CERT_PATH,
        "-out", CERT_PATH,
        "-days", "365",
        "-nodes",
        "-subj", "/C=NL/O=TestLab/CN=testsite.local"
    ], check=True)
    print("[+] Certificate generated", flush=True)


def get_host_no_port(handler: BaseHTTPRequestHandler) -> str:
    # Host header might be "ip:port" (especially on HTTP). Strip port if present.
    return handler.headers.get("Host", "localhost").split(":")[0]


class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("Host", "localhost").split(":")[0]

        # === HTTP /secure ===
        if self.path == "/secure":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"""<!doctype html>
<html>
<body style="background:#f8d7da;padding:20px;font-family:Arial;">
<h1>site</h1>
<p><b>HTTP /secure (INSECURE)</b></p>
<p>This page is served over HTTP.</p>
<p>No encryption. No padlock.</p>
<p><a href="http://{host}:{HTTP_PORT}/">back</a></p>
</body>
</html>
""".encode())
            return

        # === HTTP home ===
        https_url = f"https://{host}/secure"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"""<!doctype html>
<html>
<body style="padding:20px;font-family:Arial;">
<h1>site</h1>
<p>HTTP home page</p>
<p><a href="{https_url}">go to https secure page</a></p>
</body>
</html>
""".encode())

    def log_message(self, fmt, *args):
        print(f"[HTTP] {self.client_address[0]} - {fmt % args}", flush=True)


    def log_message(self, fmt, *args):
        print(f"[HTTP] {self.client_address[0]} - {fmt % args}", flush=True)


class HTTPSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        host = get_host_no_port(self)
        http_url = f"http://{host}/"

        if self.path != "/secure":
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        self.wfile.write(f"""<!doctype html>
<html><body style="background:#d4edda;padding:20px;font-family:Arial;">
<h1>site</h1>
<p><b>HTTPS (SECURE)</b></p>
<p><a href="{http_url}">back to http</a></p>
</body></html>
""".encode())

    def log_message(self, fmt, *args):
        print(f"[HTTPS] {self.client_address[0]} - {fmt % args}", flush=True)


def run_http_server():
    try:
        server = HTTPServer(("0.0.0.0", HTTP_PORT), HTTPHandler)
        print(f"[+] HTTP server listening on 0.0.0.0:{HTTP_PORT}", flush=True)
        server.serve_forever()
    except Exception as e:
        print(f"[HTTP] FAILED to start: {e}", flush=True)


def run_https_server():
    try:
        ensure_cert()
        server = HTTPServer(("0.0.0.0", HTTPS_PORT), HTTPSHandler)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_PATH, keyfile=CERT_PATH)
        server.socket = context.wrap_socket(server.socket, server_side=True)

        print(f"[+] HTTPS server listening on 0.0.0.0:{HTTPS_PORT}", flush=True)
        server.serve_forever()
    except Exception as e:
        print(f"[HTTPS] FAILED to start: {e}", flush=True)


def main():
    print("=" * 60, flush=True)
    print("SSL Stripping Demo - Test Site", flush=True)
    print("=" * 60, flush=True)
    print("HTTP :  http://[IP]/", flush=True)
    print("HTTPS:  https://[IP]/secure", flush=True)
    print("=" * 60, flush=True)

    http_thread = threading.Thread(target=run_http_server, daemon=False, name="HTTP")
    https_thread = threading.Thread(target=run_https_server, daemon=False, name="HTTPS")

    http_thread.start()
    https_thread.start()

    print("\n[+] Both servers running (Ctrl+C to stop)\n", flush=True)
    http_thread.join()
    https_thread.join()


if __name__ == "__main__":
    main()

