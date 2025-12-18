from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import subprocess
import os

PORT = 8000

class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def do_GET(self):
        if self.path == "/api/scan":
            print("Running AWS security scan...")
            subprocess.run(["python", "backend/fetch_and_analyze.py"])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Scan completed")
        else:
            super().do_GET()

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/..")
    print(f"✅ Backend running at http://localhost:{PORT}")
    with TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()
