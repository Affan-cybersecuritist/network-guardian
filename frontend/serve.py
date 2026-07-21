"""
Dev static file server for the Network Guardian dashboard.

Plain `python -m http.server` lets browsers cache index.html/app.js/styles.css
aggressively (no Cache-Control header at all), which made earlier edits look
like they "weren't working" -- the browser was just showing a stale copy.
This adds a no-cache header to every response so a normal reload always
picks up the latest files.
"""
import http.server
import socketserver
import os

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        super().end_headers()


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), NoCacheHandler) as httpd:
        print(f"Serving Network Guardian frontend (no-cache) on http://localhost:{PORT}")
        httpd.serve_forever()
