import os
from pathlib import Path

import pytest

TEST_DB = Path('test-bastion.db')
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ['BASTION_DATABASE_URL'] = f'sqlite:///{TEST_DB}'
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_user_host_flow():
    user_payload = {
        "username": "alice",
        "full_name": "Alice Admin",
        "email": "alice@example.com",
        "roles": ["admin", "auditor"],
    }
    resp = client.post("/users", json=user_payload)
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["id"]

    host_payload = {
        "name": "linux-jump",
        "hostname": "10.0.0.10",
        "port": 22,
        "operating_system": "linux",
        "protocols": ["ssh", "sftp", "vnc"],
        "tls_enabled": True,
        "rdp_nla": False,
    }
    resp = client.post("/hosts", json=host_payload)
    assert resp.status_code == 201, resp.text
    host_id = resp.json()["id"]

    resp = client.post(
        "/authorizations",
        json={"user_id": user_id, "host_id": host_id, "privileges": "admin"},
    )
    assert resp.status_code == 204, resp.text

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": host_id, "protocol": "ssh"},
    )
    assert resp.status_code == 201, resp.text
    session_id = resp.json()["id"]

    resp = client.post(
        f"/sessions/{session_id}/end",
        json={"recording_path": "/recordings/alice-ssh.cast", "metadata": {"size": 1234}},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["recording_path"] == "/recordings/alice-ssh.cast"
    assert body["metadata"]["size"] == 1234

    resp = client.get("/sessions")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1



@pytest.fixture(autouse=True, scope='module')
def cleanup_db():
    yield
    if TEST_DB.exists():
        TEST_DB.unlink()
