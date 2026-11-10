"""
MetaX High-Performance Local Forensic Web Server.
Pure Python standard library implementation.
Compatible with Python 3.9+ and Python 3.13+.
"""

from email.parser import BytesParser
from email.policy import default
import io
import json
import mimetypes
import os
import socket
from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler
import tempfile
import urllib.parse
import webbrowser
from typing import Optional, Dict, Any, Tuple

from metax.core import extract_metadata
from metax.sanitizer import strip_image_bytes, strip_image_metadata


WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def parse_multipart(headers: Any, rfile: Any) -> Tuple[Dict[str, str], Dict[str, Dict[str, Any]]]:
    """Parses multipart/form-data using standard library email.parser (Python 3.13 compliant)."""
    content_type = headers.get("Content-Type", "")
    content_length = int(headers.get("Content-Length", 0))
    body = rfile.read(content_length)

    header_bytes = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    msg = BytesParser(policy=default).parsebytes(header_bytes + body)

    fields: Dict[str, str] = {}
    files: Dict[str, Dict[str, Any]] = {}

    if msg.is_multipart():
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()

            if filename:
                files[name or "file"] = {
                    "filename": filename,
                    "content": part.get_payload(decode=True) or b"",
                    "content_type": part.get_content_type()
                }
            else:
                payload = part.get_payload(decode=True)
                if payload is not None:
                    fields[name or "field"] = payload.decode("utf-8", errors="replace")

    return fields, files


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handles requests in separate threads for zero-latency concurrent operations."""
    daemon_threads = True


class MetaXRequestHandler(BaseHTTPRequestHandler):
    server_version = "MetaX-Engine/0.2.0"

    def log_message(self, format, *args):
        pass

    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. API: Sample File Extraction
        if path == "/api/sample":
            sample_name = os.path.basename(query.get("name", ["test.jpg"])[0])
            sample_path = os.path.join(os.getcwd(), sample_name)
            if not os.path.exists(sample_path):
                sample_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), sample_name)

            if os.path.exists(sample_path):
                data = extract_metadata(sample_path)
                self.send_json_response(data)
            else:
                self.send_json_response({"error": f"Sample file '{sample_name}' not found"}, status=404)
            return

        # 2. API: Thumbnail / Preview
        if path == "/api/thumbnail":
            sample_name = os.path.basename(query.get("name", ["test.jpg"])[0])
            sample_path = os.path.join(os.getcwd(), sample_name)
            if not os.path.exists(sample_path):
                sample_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), sample_name)

            if os.path.exists(sample_path):
                mime, _ = mimetypes.guess_type(sample_path)
                with open(sample_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime or "application/octet-stream")
                self.send_header("Content-Length", str(len(content)))
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()
            return

        # 3. API: Strip Sample Image
        if path == "/api/strip" and "sample" in query:
            sample_name = os.path.basename(query.get("sample", ["test.jpg"])[0])
            sample_path = os.path.join(os.getcwd(), sample_name)
            if not os.path.exists(sample_path):
                sample_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), sample_name)

            if os.path.exists(sample_path):
                with open(sample_path, "rb") as f:
                    in_bytes = f.read()
                clean_bytes, _ = strip_image_bytes(in_bytes, filename=sample_name)
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Disposition", f'attachment; filename="clean_{sample_name}"')
                self.send_header("Content-Length", str(len(clean_bytes)))
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(clean_bytes)
            else:
                self.send_json_response({"error": "File not found"}, status=404)
            return

        # 4. API: Health Check
        if path == "/api/status":
            self.send_json_response({"status": "active", "version": "0.2.0"})
            return

        # 5. Static Files Serving
        if path in ["/", "/index.html"]:
            self.serve_file(os.path.join(WEB_DIR, "index.html"), "text/html; charset=utf-8")
        elif path == "/style.css":
            self.serve_file(os.path.join(WEB_DIR, "style.css"), "text/css; charset=utf-8")
        elif path == "/app.js":
            self.serve_file(os.path.join(WEB_DIR, "app.js"), "application/javascript; charset=utf-8")
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/analyze":
            content_type = self.headers.get("Content-Type", "")
            content_length = int(self.headers.get("Content-Length", 0))

            if "multipart/form-data" in content_type:
                fields, files = parse_multipart(self.headers, self.rfile)
                file_info = files.get("file") or (list(files.values())[0] if files else None)

                if file_info:
                    filename = os.path.basename(file_info["filename"] or "upload.bin")
                    file_bytes = file_info["content"]

                    suffix = os.path.splitext(filename)[1]
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                        tmp.write(file_bytes)
                        tmp_path = tmp.name

                    try:
                        data = extract_metadata(tmp_path)
                        data["filename"] = filename
                        data["file"] = filename
                    finally:
                        try:
                            os.remove(tmp_path)
                        except OSError:
                            pass

                    self.send_json_response(data)
                    return
                else:
                    self.send_json_response({"error": "No file uploaded in form data"}, status=400)
                    return
            else:
                filename = self.headers.get("X-Filename", "artifact.bin")
                raw_bytes = self.rfile.read(content_length)
                suffix = os.path.splitext(filename)[1]
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(raw_bytes)
                    tmp_path = tmp.name

                try:
                    data = extract_metadata(tmp_path)
                    data["filename"] = filename
                    data["file"] = filename
                finally:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

                self.send_json_response(data)
                return

        if path == "/api/strip":
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" in content_type:
                fields, files = parse_multipart(self.headers, self.rfile)
                file_info = files.get("file") or (list(files.values())[0] if files else None)

                if file_info:
                    filename = os.path.basename(file_info["filename"] or "sanitized.jpg")
                    in_bytes = file_info["content"]
                    clean_bytes, info = strip_image_bytes(in_bytes, filename=filename)

                    self.send_response(200)
                    self.send_header("Content-Type", "image/jpeg")
                    self.send_header("Content-Disposition", f'attachment; filename="clean_{filename}"')
                    self.send_header("Content-Length", str(len(clean_bytes)))
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(clean_bytes)
                    return

            self.send_json_response({"error": "Invalid upload for strip"}, status=400)
            return

        self.send_response(404)
        self.end_headers()

    def serve_file(self, filepath: str, content_type: str):
        if not os.path.exists(filepath):
            self.send_response(404)
            self.end_headers()
            return

        with open(filepath, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(content)

    def send_json_response(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(body)


def find_free_port(start_port: int = 8765) -> int:
    """Finds an available local port starting from start_port."""
    for port in range(start_port, start_port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port


def start_server(host: str = "127.0.0.1", port: Optional[int] = None, open_browser: bool = True):
    """Starts the MetaX local web server and opens the browser."""
    if port is None:
        port = find_free_port(8765)

    server = ThreadedHTTPServer((host, port), MetaXRequestHandler)
    url = f"http://{host}:{port}"

    print(f"\n========================================================")
    print(f"  🧠 METAX — Minimalist Forensic Studio Active")
    print(f"  URL: {url}")
    print(f"  Press Ctrl+C to terminate the local server.")
    print(f"========================================================\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] MetaX server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    start_server()

