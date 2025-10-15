"""Minimal HTTP server exposing the bastion management API."""
from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple

from fastapi.exceptions import HTTPException

from .main import app as bastion_app

LOGGER = logging.getLogger(__name__)


class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - signature required by BaseHTTPRequestHandler
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch(expect_body=True)

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch(expect_body=True)

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch(expect_body=True)

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def log_message(self, format: str, *args) -> None:  # noqa: A003 - method from parent class
        LOGGER.info("%s - %s", self.address_string(), format % args)

    def _dispatch(self, expect_body: bool = False) -> None:
        body: Optional[Dict] = None
        if expect_body:
            length_header = self.headers.get("Content-Length")
            length = int(length_header or 0)
            raw = self.rfile.read(length) if length else b""
            if raw:
                try:
                    body = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    self._write_response(400, {"detail": f"Invalid JSON payload: {exc}"})
                    return
        try:
            status_code, payload = bastion_app.handle_request(self.command, self.path, body)
        except HTTPException as exc:
            status_code, payload = exc.status_code, {"detail": exc.detail}
        except Exception:  # pragma: no cover - defensive logging branch
            LOGGER.exception("Unhandled error while processing request")
            status_code, payload = 500, {"detail": "Internal Server Error"}
        self._write_response(status_code, payload)

    def _write_response(self, status_code: int, payload: Dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def create_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    """Create an HTTP server exposing the bastion management API."""
    return ThreadingHTTPServer((host, port), _RequestHandler)


def run(host: str = "0.0.0.0", port: int = 8000) -> Tuple[str, int]:
    """Start the HTTP server and keep it serving until interrupted."""
    server = create_server(host, port)
    host, port = server.server_address
    LOGGER.info("Bastion management service listening on http://%s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - manual shutdown
        LOGGER.info("Shutting down bastion management service")
    finally:
        server.server_close()
    return host, port


if __name__ == "__main__":  # pragma: no cover - manual entry point
    logging.basicConfig(level=logging.INFO)
    run()
