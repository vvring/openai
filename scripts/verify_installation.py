"""End-to-end smoke test for the bastion prototype HTTP API.

The script bootstraps a fresh SQLite database, launches the bundled
HTTP server on an ephemeral port, and walks through a representative
management and connection workflow. The output doubles as living
documentation that the deployed service can create users, manage
assets, grant access, and generate login instructions for operators.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("BASTION_DATABASE_URL", "sqlite:///demo-bastion.db")

from app import database, server  # noqa: E402


@dataclass
class ApiResult:
    description: str
    payload: Any


class ApiClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}{path}"
        data: Optional[bytes] = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read().decode("utf-8") or "null"
                return json.loads(raw)
        except urllib.error.HTTPError as exc:  # pragma: no cover - exercised manually
            detail = exc.read().decode("utf-8")
            try:
                parsed = json.loads(detail)
            except json.JSONDecodeError:
                parsed = {"detail": detail or exc.reason}
            raise RuntimeError(f"{method} {path} failed with {exc.code}: {parsed}") from exc

    def post(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("POST", path, payload)

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def patch(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("PATCH", path, payload)

    def put(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("PUT", path, payload)


class BastionSmokeTest:
    def __init__(self) -> None:
        database.init_db()
        self.httpd = server.create_server("127.0.0.1", 0)
        host, port = self.httpd.server_address
        self.base_url = f"http://{host}:{port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.2)  # Give the server a moment to bind and start.
        self.client = ApiClient(self.base_url)
        self.results: list[ApiResult] = []

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def record(self, description: str, payload: Any) -> None:
        self.results.append(ApiResult(description=description, payload=payload))

    def run(self) -> None:
        admin = self.client.post(
            "/users",
            {
                "username": "admin",
                "full_name": "Default Administrator",
                "email": "admin@example.com",
                "roles": ["admin", "operator"],
            },
        )
        self.record("Created administrator", admin)

        operator = self.client.post(
            "/users",
            {
                "username": "ops",
                "full_name": "Operations Engineer",
                "email": "ops@example.com",
                "roles": ["operator"],
            },
        )
        self.record("Created operator", operator)

        gateway = self.client.post(
            "/protocol-gateways",
            {
                "name": "default-ssh-gateway",
                "protocol": "ssh",
                "endpoint_host": "gateway.internal",
                "endpoint_port": 2222,
                "tls_enabled": True,
                "description": "Demo SSH bastion gateway",
            },
        )
        self.record("Provisioned SSH gateway", gateway)

        host = self.client.post(
            "/hosts",
            {
                "name": "intranet-01",
                "hostname": "intranet.internal",
                "port": 22,
                "operating_system": "linux",
                "protocols": ["ssh", "sftp"],
                "tls_enabled": True,
                "rdp_nla": True,
                "tags": ["core", "demo"],
                "environment": "staging",
                "business_unit": "infrastructure",
                "performed_by": admin["id"],
            },
        )
        self.record("Registered managed host", host)

        self.client.put(
            f"/hosts/{host['id']}/gateways/ssh",
            {"gateway_id": gateway["id"], "performed_by": admin["id"]},
        )
        bindings = self.client.get(f"/hosts/{host['id']}/gateways")
        self.record("Bound host to SSH gateway", bindings)

        credential = self.client.post(
            "/credentials",
            {
                "host_id": host["id"],
                "name": "ops-user",
                "username": "ops",
                "secret": "example-password",
                "secret_type": "password",
                "performed_by": admin["id"],
                "description": "Demo credential for operations",
            },
        )
        self.record("Stored host credential", credential)

        self.client.post(
            "/authorizations",
            {
                "user_id": operator["id"],
                "host_id": host["id"],
                "privileges": "read-write",
                "performed_by": admin["id"],
                "source_cidrs": ["10.0.0.0/24"],
            },
        )
        authorizations = self.client.get(f"/authorizations?user_id={operator['id']}")
        self.record("Granted operator access", authorizations)

        session = self.client.post(
            "/sessions",
            {
                "user_id": operator["id"],
                "host_id": host["id"],
                "protocol": "ssh",
                "source_ip": "10.0.0.12",
                "requested_commands": ["sudo systemctl status nginx"],
            },
        )
        self.record("Started session", session)

        connection = self.client.post(
            f"/sessions/{session['id']}/connections",
            {
                "initiated_by": operator["id"],
                "credential_id": credential["id"],
            },
        )
        self.record("Generated connection instructions", connection)

        summary = {
            "base_url": self.base_url,
            "users": self.client.get("/users"),
            "hosts": self.client.get("/hosts"),
            "sessions": self.client.get("/sessions"),
            "audit_events": self.client.get("/audit-events?limit=5"),
        }
        self.record("Service summary", summary)

    def print_results(self) -> None:
        for item in self.results:
            print(f"\n# {item.description}\n{json.dumps(item.payload, indent=2, ensure_ascii=False)}")


def _cleanup_demo_db() -> None:
    db_url = os.environ["BASTION_DATABASE_URL"]
    if db_url.startswith("sqlite:///"):
        db_path = Path(db_url.replace("sqlite:///", "", 1))
        if db_path.exists():
            db_path.unlink()


def main() -> None:
    _cleanup_demo_db()
    test = BastionSmokeTest()
    try:
        test.run()
        test.print_results()
    finally:
        test.close()


if __name__ == "__main__":  # pragma: no cover - manual execution entrypoint
    main()
