import os
from pathlib import Path

import pytest

from app.database import get_connection

TEST_DB = Path('test-bastion.db')
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ['BASTION_DATABASE_URL'] = f'sqlite:///{TEST_DB}'
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_database():
    with get_connection() as conn:
        for table in ("recordings", "sessions", "authorizations", "hosts", "users"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    yield
    with get_connection() as conn:
        for table in ("recordings", "sessions", "authorizations", "hosts", "users"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()


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
        json={
            "recording": {
                "storage_path": "/recordings/alice-ssh.cast",
                "size_bytes": 1234,
                "duration_seconds": 65.5,
                "checksum": "deadbeef",
                "metadata": {"format": "asciinema"},
            },
            "metadata": {"size": 1234},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["recording_path"] == "/recordings/alice-ssh.cast"
    assert body["metadata"]["size"] == 1234

    resp = client.get("/recordings")
    assert resp.status_code == 200, resp.text
    recordings = resp.json()
    assert len(recordings) == 1
    assert recordings[0]["session_id"] == session_id
    assert recordings[0]["storage_path"] == "/recordings/alice-ssh.cast"
    assert recordings[0]["size_bytes"] == 1234
    assert recordings[0]["duration_seconds"] == pytest.approx(65.5, rel=1e-3)
    assert recordings[0]["metadata"]["format"] == "asciinema"

    rec_id = recordings[0]["id"]
    resp = client.get(f"/recordings/{rec_id}")
    assert resp.status_code == 200, resp.text
    fetched = resp.json()
    assert fetched["id"] == rec_id
    assert fetched["session_id"] == session_id

    resp = client.get(f"/recordings?session_id={session_id}")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp = client.get("/sessions")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_authorization_enforcement_and_listing():
    user_payload = {
        "username": "bob",
        "full_name": "Bob Operator",
        "email": "bob@example.com",
        "roles": ["operator"],
    }
    resp = client.post("/users", json=user_payload)
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["id"]

    host_payload = {
        "name": "mixed-host",
        "hostname": "10.0.0.20",
        "port": 22,
        "operating_system": "linux",
        "protocols": ["ssh", "rdp"],
        "tls_enabled": True,
        "rdp_nla": True,
    }
    resp = client.post("/hosts", json=host_payload)
    assert resp.status_code == 201, resp.text
    host_id = resp.json()["id"]

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": host_id, "protocol": "ssh"},
    )
    assert resp.status_code == 400
    assert "access" in resp.json()["detail"]

    resp = client.post(
        "/authorizations",
        json={"user_id": user_id, "host_id": host_id, "privileges": "read"},
    )
    assert resp.status_code == 204, resp.text

    resp = client.get(f"/authorizations?user_id={user_id}")
    assert resp.status_code == 200
    authorizations = resp.json()
    assert len(authorizations) == 1
    assert authorizations[0]["privileges"] == "read"

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": host_id, "protocol": "ssh"},
    )
    assert resp.status_code == 201, resp.text

    authorization_id = authorizations[0]["id"]
    resp = client.delete(f"/authorizations/{authorization_id}")
    assert resp.status_code == 204, resp.text

    resp = client.get(f"/authorizations?user_id={user_id}")
    assert resp.status_code == 200
    assert resp.json() == []

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": host_id, "protocol": "ssh"},
    )
    assert resp.status_code == 400

    resp = client.post(
        "/authorizations",
        json={"user_id": user_id, "host_id": host_id, "privileges": "invalid"},
    )
    assert resp.status_code == 400


def test_protocol_and_nla_enforcement():
    user_payload = {
        "username": "charlie",
        "full_name": "Charlie Operator",
        "email": "charlie@example.com",
        "roles": ["operator"],
    }
    resp = client.post("/users", json=user_payload)
    user_id = resp.json()["id"]

    host_payload = {
        "name": "ssh-only",
        "hostname": "10.0.0.30",
        "port": 22,
        "operating_system": "linux",
        "protocols": ["ssh"],
        "tls_enabled": True,
        "rdp_nla": False,
    }
    resp = client.post("/hosts", json=host_payload)
    host_id = resp.json()["id"]

    client.post(
        "/authorizations",
        json={"user_id": user_id, "host_id": host_id, "privileges": "read-write"},
    )

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": host_id, "protocol": "rdp"},
    )
    assert resp.status_code == 400
    assert "protocol" in resp.json()["detail"]

    resp = client.post(
        "/hosts",
        json={
            "name": "rdp-host",
            "hostname": "10.0.0.31",
            "port": 3389,
            "operating_system": "windows",
            "protocols": ["rdp"],
            "tls_enabled": True,
            "rdp_nla": False,
        },
    )
    rdp_host_id = resp.json()["id"]

    client.post(
        "/authorizations",
        json={"user_id": user_id, "host_id": rdp_host_id, "privileges": "read-write"},
    )

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": rdp_host_id, "protocol": "rdp"},
    )
    assert resp.status_code == 400
    assert "NLA" in resp.json()["detail"]

    resp = client.post(
        "/hosts",
        json={
            "name": "rdp-host-secure",
            "hostname": "10.0.0.32",
            "port": 3389,
            "operating_system": "windows",
            "protocols": ["rdp"],
            "tls_enabled": True,
            "rdp_nla": True,
        },
    )
    secure_rdp_host_id = resp.json()["id"]

    client.post(
        "/authorizations",
        json={"user_id": user_id, "host_id": secure_rdp_host_id, "privileges": "admin"},
    )

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": secure_rdp_host_id, "protocol": "rdp"},
    )
    assert resp.status_code == 201, resp.text

    admin_payload = {
        "username": "dana",
        "full_name": "Dana Admin",
        "email": "dana@example.com",
        "roles": ["admin"],
    }
    resp = client.post("/users", json=admin_payload)
    admin_id = resp.json()["id"]

    resp = client.post(
        "/sessions",
        json={"user_id": admin_id, "host_id": host_id, "protocol": "ssh"},
    )
    assert resp.status_code == 201, resp.text


def test_user_activation_and_host_updates():
    user_payload = {
        "username": "eve",
        "full_name": "Eve Operator",
        "email": "eve@example.com",
        "roles": ["operator"],
    }
    resp = client.post("/users", json=user_payload)
    assert resp.status_code == 201, resp.text
    user = resp.json()
    user_id = user["id"]

    resp = client.get(f"/users/{user_id}")
    assert resp.status_code == 200
    assert resp.json()["username"] == "eve"

    resp = client.patch(
        f"/users/{user_id}",
        json={"full_name": "Evelyn Operator", "roles": ["operator", "auditor"]},
    )
    assert resp.status_code == 200
    updated_user = resp.json()
    assert updated_user["full_name"] == "Evelyn Operator"
    assert set(updated_user["roles"]) == {"operator", "auditor"}

    resp = client.patch(f"/users/{user_id}", json={"is_active": False})
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False

    host_payload = {
        "name": "app-host",
        "hostname": "10.0.0.40",
        "port": 22,
        "operating_system": "linux",
        "protocols": ["ssh"],
        "tls_enabled": True,
        "rdp_nla": True,
    }
    resp = client.post("/hosts", json=host_payload)
    assert resp.status_code == 201
    host_id = resp.json()["id"]

    resp = client.post(
        "/authorizations",
        json={"user_id": user_id, "host_id": host_id, "privileges": "read-write"},
    )
    assert resp.status_code == 204

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": host_id, "protocol": "ssh"},
    )
    assert resp.status_code == 400
    assert "inactive" in resp.json()["detail"]

    resp = client.patch(f"/users/{user_id}", json={"is_active": True})
    assert resp.status_code == 200

    resp = client.post(
        "/sessions",
        json={"user_id": user_id, "host_id": host_id, "protocol": "ssh"},
    )
    assert resp.status_code == 201

    resp = client.patch(
        f"/hosts/{host_id}",
        json={"protocols": ["ssh", "rdp"], "rdp_nla": True},
    )
    assert resp.status_code == 200
    assert set(resp.json()["protocols"]) == {"ssh", "rdp"}

    resp = client.patch(f"/hosts/{host_id}", json={"port": 2222})
    assert resp.status_code == 200
    assert resp.json()["port"] == 2222

    resp = client.patch(f"/hosts/{host_id}", json={"rdp_nla": False})
    assert resp.status_code == 400
    assert "NLA" in resp.json()["detail"]

    resp = client.patch(f"/users/{user_id}", json={"roles": ["invalid"]})
    assert resp.status_code == 400


def test_session_filters_and_recording_search():
    admin_payload = {
        "username": "filter-admin",
        "full_name": "Filter Admin",
        "email": "filter-admin@example.com",
        "roles": ["admin"],
    }
    resp = client.post("/users", json=admin_payload)
    assert resp.status_code == 201
    admin = resp.json()

    operator_payload = {
        "username": "filter-op",
        "full_name": "Filter Operator",
        "email": "filter-op@example.com",
        "roles": ["operator"],
    }
    resp = client.post("/users", json=operator_payload)
    assert resp.status_code == 201
    operator = resp.json()

    host_a_payload = {
        "name": "audit-linux",
        "hostname": "10.0.0.50",
        "port": 22,
        "operating_system": "linux",
        "protocols": ["ssh", "sftp"],
        "tls_enabled": True,
        "rdp_nla": True,
    }
    resp = client.post("/hosts", json=host_a_payload)
    host_a = resp.json()

    host_b_payload = {
        "name": "audit-windows",
        "hostname": "10.0.0.51",
        "port": 3389,
        "operating_system": "windows",
        "protocols": ["rdp"],
        "tls_enabled": True,
        "rdp_nla": True,
    }
    resp = client.post("/hosts", json=host_b_payload)
    host_b = resp.json()

    for host in (host_a, host_b):
        resp = client.post(
            "/authorizations",
            json={"user_id": operator["id"], "host_id": host["id"], "privileges": "read-write"},
        )
        assert resp.status_code == 204

    resp = client.post(
        "/sessions",
        json={"user_id": admin["id"], "host_id": host_a["id"], "protocol": "ssh"},
    )
    assert resp.status_code == 201
    admin_session = resp.json()

    resp = client.post(
        "/sessions",
        json={"user_id": operator["id"], "host_id": host_a["id"], "protocol": "ssh"},
    )
    assert resp.status_code == 201
    operator_session_active = resp.json()

    resp = client.post(f"/sessions/{admin_session['id']}/end", json={})
    assert resp.status_code == 200

    resp = client.post(
        "/sessions",
        json={"user_id": operator["id"], "host_id": host_b["id"], "protocol": "rdp"},
    )
    assert resp.status_code == 201
    operator_session_rdp = resp.json()

    resp = client.post(
        f"/sessions/{operator_session_rdp['id']}/end",
        json={
            "recording": {
                "storage_path": "/recordings/rdp-session.mp4",
                "size_bytes": 4096,
                "duration_seconds": 120.0,
                "checksum": "cafebabe",
                "metadata": {"codec": "h264"},
            }
        },
    )
    assert resp.status_code == 200

    resp = client.get(f"/sessions?user_id={operator['id']}")
    assert resp.status_code == 200
    assert {session["id"] for session in resp.json()} == {
        operator_session_active["id"],
        operator_session_rdp["id"],
    }

    resp = client.get(f"/sessions?host_id={host_a['id']}&only_active=true")
    assert resp.status_code == 200
    sessions = resp.json()
    assert len(sessions) == 1
    assert sessions[0]["id"] == operator_session_active["id"]

    resp = client.get(f"/sessions?protocol=rdp&only_active=false")
    assert resp.status_code == 200
    rdp_sessions = resp.json()
    assert len(rdp_sessions) == 1
    assert rdp_sessions[0]["id"] == operator_session_rdp["id"]

    detail_resp = client.get(f"/sessions/{operator_session_rdp['id']}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == operator_session_rdp["id"]
    assert detail["recordings"]
    assert detail["recordings"][0]["storage_path"] == "/recordings/rdp-session.mp4"

    resp = client.get(f"/recordings?user_id={operator['id']}&protocol=rdp")
    assert resp.status_code == 200
    filtered_recordings = resp.json()
    assert len(filtered_recordings) == 1
    assert filtered_recordings[0]["session_id"] == operator_session_rdp["id"]
    assert filtered_recordings[0]["metadata"]["codec"] == "h264"


@pytest.fixture(autouse=True, scope='module')
def cleanup_db():
    yield
    if TEST_DB.exists():
        TEST_DB.unlink()
