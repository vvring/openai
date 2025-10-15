import os
from datetime import datetime, timedelta, timezone
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
        for table in (
            "audit_events",
            "session_connections",
            "recordings",
            "sessions",
            "access_requests",
            "credentials",
            "authorizations",
            "command_policies",
            "host_group_members",
            "host_groups",
            "hosts",
            "users",
            "access_windows",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    yield
    with get_connection() as conn:
        for table in (
            "audit_events",
            "session_connections",
            "recordings",
            "sessions",
            "access_requests",
            "credentials",
            "authorizations",
            "command_policies",
            "host_group_members",
            "host_groups",
            "hosts",
            "users",
            "access_windows",
        ):
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
        json={
            "user_id": user_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "203.0.113.10",
        },
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


def test_host_group_lifecycle():
    admin_resp = client.post(
        "/users",
        json={
            "username": "group-admin",
            "full_name": "Group Admin",
            "email": "group-admin@example.com",
            "roles": ["admin"],
            "source_ip": "198.51.100.10",
        },
    )
    assert admin_resp.status_code == 201, admin_resp.text
    admin_id = admin_resp.json()["id"]

    first_host_resp = client.post(
        "/hosts",
        json={
            "name": "db-01",
            "hostname": "10.1.0.10",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh"],
            "tls_enabled": True,
            "rdp_nla": False,
            "performed_by": admin_id,
        },
    )
    assert first_host_resp.status_code == 201, first_host_resp.text
    first_host = first_host_resp.json()

    second_host_resp = client.post(
        "/hosts",
        json={
            "name": "db-02",
            "hostname": "10.1.0.11",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh"],
            "tls_enabled": True,
            "rdp_nla": False,
            "performed_by": admin_id,
        },
    )
    assert second_host_resp.status_code == 201, second_host_resp.text
    second_host = second_host_resp.json()

    create_group_resp = client.post(
        "/host-groups",
        json={
            "name": "Database Servers",
            "description": "Primary database cluster",
            "host_ids": [first_host["id"]],
            "performed_by": admin_id,
        },
    )
    assert create_group_resp.status_code == 201, create_group_resp.text
    group = create_group_resp.json()
    assert group["host_ids"] == [first_host["id"]]
    assert group["name"] == "Database Servers"

    host_detail = client.get(f"/hosts/{first_host['id']}")
    assert host_detail.status_code == 200
    assert host_detail.json()["groups"][0]["name"] == "Database Servers"

    list_resp = client.get("/host-groups?include_hosts=true")
    assert list_resp.status_code == 200
    groups = list_resp.json()
    assert groups[0]["hosts"][0]["id"] == first_host["id"]

    add_member_resp = client.post(
        f"/host-groups/{group['id']}/hosts",
        json={"host_id": second_host["id"], "performed_by": admin_id},
    )
    assert add_member_resp.status_code == 200, add_member_resp.text
    updated_group = add_member_resp.json()
    assert sorted(updated_group["host_ids"]) == sorted(
        [first_host["id"], second_host["id"]]
    )

    detail_resp = client.get(f"/host-groups/{group['id']}?include_hosts=true")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert {host["id"] for host in detail["hosts"]} == {
        first_host["id"],
        second_host["id"],
    }
    for host in detail["hosts"]:
        assert any(g["id"] == group["id"] for g in host["groups"])

    filter_resp = client.get(f"/host-groups?host_id={second_host['id']}")
    assert filter_resp.status_code == 200
    assert len(filter_resp.json()) == 1

    patch_resp = client.patch(
        f"/host-groups/{group['id']}",
        json={"name": "DB Production", "performed_by": admin_id},
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["name"] == "DB Production"

    removal_resp = client.delete(
        f"/host-groups/{group['id']}/hosts/{first_host['id']}?performed_by={admin_id}"
    )
    assert removal_resp.status_code == 200, removal_resp.text
    removal_body = removal_resp.json()
    assert first_host["id"] not in removal_body["host_ids"]

    refreshed_host = client.get(f"/hosts/{first_host['id']}")
    assert refreshed_host.status_code == 200
    assert refreshed_host.json()["groups"] == []

    delete_resp = client.delete(
        f"/host-groups/{group['id']}?performed_by={admin_id}"
    )
    assert delete_resp.status_code == 204, delete_resp.text

    final_list = client.get("/host-groups")
    assert final_list.status_code == 200
    assert final_list.json() == []


def test_credential_lifecycle():
    admin_resp = client.post(
        "/users",
        json={
            "username": "cred-admin",
            "full_name": "Credential Admin",
            "email": "cred-admin@example.com",
            "roles": ["admin"],
        },
    )
    assert admin_resp.status_code == 201, admin_resp.text
    admin_id = admin_resp.json()["id"]

    host_resp = client.post(
        "/hosts",
        json={
            "name": "vault-host",
            "hostname": "10.2.0.5",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh", "sftp"],
            "tls_enabled": True,
            "rdp_nla": False,
            "performed_by": admin_id,
        },
    )
    assert host_resp.status_code == 201, host_resp.text
    host_id = host_resp.json()["id"]

    create_resp = client.post(
        "/credentials",
        json={
            "host_id": host_id,
            "name": "root-admin",
            "username": "root",
            "secret": "super-secret-value",
            "secret_type": "password",
            "rotation_frequency_days": 90,
            "performed_by": admin_id,
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    credential = create_resp.json()
    assert credential["host_id"] == host_id
    assert credential["secret_preview"] == "alue"
    assert credential["created_by"] == admin_id
    assert credential["rotation_frequency_days"] == 90

    list_resp = client.get("/credentials")
    assert list_resp.status_code == 200
    assert any(item["id"] == credential["id"] for item in list_resp.json())

    filter_resp = client.get(f"/credentials?host_id={host_id}&is_active=true")
    assert filter_resp.status_code == 200
    filtered = filter_resp.json()
    assert len(filtered) == 1
    assert filtered[0]["name"] == "root-admin"

    detail_resp = client.get(f"/credentials/{credential['id']}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["secret_preview"] == "alue"

    update_resp = client.patch(
        f"/credentials/{credential['id']}",
        json={
            "description": "Rotated secret",
            "secret": "rotated-secret-material",
            "rotation_frequency_days": 45,
            "is_active": False,
            "performed_by": admin_id,
        },
    )
    assert update_resp.status_code == 200, update_resp.text
    updated = update_resp.json()
    assert updated["secret_preview"] == "rial"
    assert updated["is_active"] is False
    assert updated["rotation_frequency_days"] == 45

    clear_rotation_resp = client.patch(
        f"/credentials/{credential['id']}",
        json={
            "rotation_frequency_days": None,
            "performed_by": admin_id,
        },
    )
    assert clear_rotation_resp.status_code == 200, clear_rotation_resp.text
    cleared = clear_rotation_resp.json()
    assert cleared["rotation_frequency_days"] is None

    inactive_resp = client.get("/credentials?is_active=true")
    assert inactive_resp.status_code == 200
    assert all(item["is_active"] for item in inactive_resp.json())

    disabled_resp = client.get("/credentials?is_active=false")
    assert disabled_resp.status_code == 200
    disabled = disabled_resp.json()
    assert len(disabled) == 1
    assert disabled[0]["id"] == credential["id"]


def test_session_connection_attempt_flow():
    admin_resp = client.post(
        "/users",
        json={
            "username": "connect-admin",
            "full_name": "Connect Admin",
            "email": "connect-admin@example.com",
            "roles": ["admin"],
        },
    )
    assert admin_resp.status_code == 201, admin_resp.text
    admin_id = admin_resp.json()["id"]

    operator_resp = client.post(
        "/users",
        json={
            "username": "connect-operator",
            "full_name": "Connect Operator",
            "email": "connect-operator@example.com",
            "roles": ["operator"],
        },
    )
    assert operator_resp.status_code == 201, operator_resp.text
    operator_id = operator_resp.json()["id"]

    host_resp = client.post(
        "/hosts",
        json={
            "name": "connect-host",
            "hostname": "10.5.0.10",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh", "sftp"],
            "tls_enabled": True,
            "rdp_nla": True,
            "performed_by": admin_id,
        },
    )
    assert host_resp.status_code == 201, host_resp.text
    host_id = host_resp.json()["id"]

    credential_resp = client.post(
        "/credentials",
        json={
            "host_id": host_id,
            "name": "connect-root",
            "username": "root",
            "secret": "root-password",
            "secret_type": "password",
            "performed_by": admin_id,
        },
    )
    assert credential_resp.status_code == 201, credential_resp.text
    credential_id = credential_resp.json()["id"]

    auth_resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read-write",
        },
    )
    assert auth_resp.status_code == 204, auth_resp.text

    session_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.77",
        },
    )
    assert session_resp.status_code == 201, session_resp.text
    session_id = session_resp.json()["id"]

    attempt_resp = client.post(
        f"/sessions/{session_id}/connections",
        json={
            "initiated_by": operator_id,
            "credential_id": credential_id,
        },
    )
    assert attempt_resp.status_code == 201, attempt_resp.text
    attempt = attempt_resp.json()
    assert attempt["status"] == "pending"
    assert attempt["instructions"]["command"].startswith("ssh root@10.5.0.10")

    list_resp = client.get(f"/sessions/{session_id}/connections")
    assert list_resp.status_code == 200, list_resp.text
    attempts = list_resp.json()
    assert len(attempts) == 1
    assert attempts[0]["credential_id"] == credential_id
    assert attempts[0]["instructions"]["credential_hint"]["secret_preview"] == "word"

    update_resp = client.patch(
        f"/session-connections/{attempt['id']}",
        json={"status": "succeeded", "performed_by": operator_id},
    )
    assert update_resp.status_code == 200, update_resp.text
    updated_attempt = update_resp.json()
    assert updated_attempt["status"] == "succeeded"
    assert updated_attempt["failure_reason"] is None

    second_attempt_resp = client.post(
        f"/sessions/{session_id}/connections",
        json={
            "initiated_by": operator_id,
            "credential_id": credential_id,
        },
    )
    assert second_attempt_resp.status_code == 201, second_attempt_resp.text
    second_attempt = second_attempt_resp.json()

    fail_resp = client.patch(
        f"/session-connections/{second_attempt['id']}",
        json={
            "status": "failed",
            "performed_by": admin_id,
            "failure_reason": "SSH host key mismatch",
        },
    )
    assert fail_resp.status_code == 200, fail_resp.text
    failed_attempt = fail_resp.json()
    assert failed_attempt["status"] == "failed"
    assert failed_attempt["failure_reason"] == "SSH host key mismatch"

    final_list = client.get(f"/sessions/{session_id}/connections")
    assert final_list.status_code == 200
    final_attempts = final_list.json()
    assert len(final_attempts) == 2
    assert {item["status"] for item in final_attempts} == {"succeeded", "failed"}


def test_credential_secret_type_validation():
    admin_resp = client.post(
        "/users",
        json={
            "username": "cred-validator",
            "full_name": "Credential Validator",
            "email": "cred-validator@example.com",
            "roles": ["admin"],
        },
    )
    assert admin_resp.status_code == 201, admin_resp.text
    admin_id = admin_resp.json()["id"]

    host_resp = client.post(
        "/hosts",
        json={
            "name": "invalid-host",
            "hostname": "10.2.0.6",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh"],
            "tls_enabled": True,
            "rdp_nla": False,
            "performed_by": admin_id,
        },
    )
    assert host_resp.status_code == 201, host_resp.text
    host_id = host_resp.json()["id"]

    bad_resp = client.post(
        "/credentials",
        json={
            "host_id": host_id,
            "name": "bad",
            "username": "root",
            "secret": "secret",
            "secret_type": "token",
            "performed_by": admin_id,
        },
    )
    assert bad_resp.status_code == 400
    assert "Unsupported credential" in bad_resp.text


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
        json={
            "user_id": user_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
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
    assert authorizations[0]["access_window_id"] is None
    assert authorizations[0]["command_policy_id"] is None

    resp = client.get(f"/authorizations?access_window_id=1")
    assert resp.status_code == 200
    assert resp.json() == []

    resp = client.post(
        "/sessions",
        json={
            "user_id": user_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
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
        json={
            "user_id": user_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert resp.status_code == 400

    resp = client.post(
        "/authorizations",
        json={"user_id": user_id, "host_id": host_id, "privileges": "invalid"},
    )
    assert resp.status_code == 400


def test_authorization_source_cidr_enforcement():
    operator_resp = client.post(
        "/users",
        json={
            "username": "cidr-operator",
            "full_name": "CIDR Operator",
            "email": "cidr-operator@example.com",
            "roles": ["operator"],
        },
    )
    assert operator_resp.status_code == 201
    operator_id = operator_resp.json()["id"]

    host_resp = client.post(
        "/hosts",
        json={
            "name": "cidr-host",
            "hostname": "10.0.0.55",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh"],
            "tls_enabled": True,
            "rdp_nla": True,
        },
    )
    assert host_resp.status_code == 201
    host_id = host_resp.json()["id"]

    invalid_resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read",
            "source_cidrs": ["not-a-cidr"],
        },
    )
    assert invalid_resp.status_code == 400
    assert "CIDR" in invalid_resp.json()["detail"]

    resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read",
            "source_cidrs": ["203.0.113.0/24", "2001:db8::/64"],
        },
    )
    assert resp.status_code == 204

    missing_ip_resp = client.post(
        "/sessions",
        json={"user_id": operator_id, "host_id": host_id, "protocol": "ssh"},
    )
    assert missing_ip_resp.status_code == 400
    assert "source_ip" in missing_ip_resp.json()["detail"]

    allowed_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "203.0.113.42",
        },
    )
    assert allowed_resp.status_code == 201, allowed_resp.text

    denied_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.99",
        },
    )
    assert denied_resp.status_code == 400
    assert "source_ip" in denied_resp.json()["detail"]


def test_command_policy_lifecycle_and_enforcement():
    admin_resp = client.post(
        "/users",
        json={
            "username": "policy-admin",
            "full_name": "Policy Admin",
            "email": "policy-admin@example.com",
            "roles": ["admin"],
        },
    )
    assert admin_resp.status_code == 201
    admin_id = admin_resp.json()["id"]

    operator_resp = client.post(
        "/users",
        json={
            "username": "policy-operator",
            "full_name": "Policy Operator",
            "email": "policy-operator@example.com",
            "roles": ["operator"],
        },
    )
    assert operator_resp.status_code == 201
    operator_id = operator_resp.json()["id"]

    host_resp = client.post(
        "/hosts",
        json={
            "name": "policy-host",
            "hostname": "10.0.0.88",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh"],
            "tls_enabled": True,
            "rdp_nla": True,
        },
    )
    assert host_resp.status_code == 201
    host_id = host_resp.json()["id"]

    policy_resp = client.post(
        "/command-policies",
        json={
            "name": "shell-guard",
            "description": "Protect shell operations",
            "allowed_patterns": ["sudo *", "ls *"],
            "denied_patterns": ["rm -rf *", "shutdown*"],
            "performed_by": admin_id,
        },
    )
    assert policy_resp.status_code == 201, policy_resp.text
    policy_body = policy_resp.json()
    policy_id = policy_body["id"]
    assert "rm -rf *" in policy_body["denied_patterns"]

    assign_resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read-write",
            "command_policy_id": policy_id,
        },
    )
    assert assign_resp.status_code == 204, assign_resp.text

    missing_command_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.50",
        },
    )
    assert missing_command_resp.status_code == 400
    assert "requested_commands" in missing_command_resp.json()["detail"]

    denied_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.50",
            "requested_commands": ["rm -rf /var/tmp"],
        },
    )
    assert denied_resp.status_code == 400
    assert "violates" in denied_resp.json()["detail"]

    allowed_commands = ["sudo systemctl status sshd"]
    allowed_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.50",
            "requested_commands": allowed_commands,
        },
    )
    assert allowed_resp.status_code == 201, allowed_resp.text
    session_body = allowed_resp.json()
    assert session_body["metadata"]["requested_commands"] == allowed_commands
    assert session_body["metadata"]["command_policy_id"] == policy_id

    list_resp = client.get("/command-policies")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    filtered_resp = client.get(f"/command-policies?created_by={admin_id}")
    assert filtered_resp.status_code == 200
    assert len(filtered_resp.json()) == 1

    update_resp = client.patch(
        f"/command-policies/{policy_id}",
        json={
            "allowed_patterns": ["sudo *", "ls *", "cat *"],
            "performed_by": admin_id,
        },
    )
    assert update_resp.status_code == 200
    assert "cat *" in update_resp.json()["allowed_patterns"]

    delete_blocked = client.delete(f"/command-policies/{policy_id}")
    assert delete_blocked.status_code == 400
    assert "assigned" in delete_blocked.json()["detail"]

    remove_policy_resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read-write",
            "command_policy_id": None,
        },
    )
    assert remove_policy_resp.status_code == 204

    no_policy_session = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.51",
        },
    )
    assert no_policy_session.status_code == 201, no_policy_session.text

    delete_resp = client.delete(
        f"/command-policies/{policy_id}?performed_by={admin_id}"
    )
    assert delete_resp.status_code == 204, delete_resp.text

    final_list = client.get("/command-policies")
    assert final_list.status_code == 200
    assert final_list.json() == []


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
        json={
            "user_id": user_id,
            "host_id": host_id,
            "protocol": "rdp",
            "source_ip": "198.51.100.10",
        },
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
        json={
            "user_id": user_id,
            "host_id": rdp_host_id,
            "protocol": "rdp",
            "source_ip": "198.51.100.10",
        },
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
        json={
            "user_id": user_id,
            "host_id": secure_rdp_host_id,
            "protocol": "rdp",
            "source_ip": "198.51.100.10",
        },
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
        json={
            "user_id": admin_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert resp.status_code == 201, resp.text


def test_access_window_crud_and_enforcement():
    admin_resp = client.post(
        "/users",
        json={
            "username": "schedule-admin",
            "full_name": "Schedule Admin",
            "email": "sched-admin@example.com",
            "roles": ["admin"],
        },
    )
    admin_id = admin_resp.json()["id"]

    operator_resp = client.post(
        "/users",
        json={
            "username": "window-operator",
            "full_name": "Window Operator",
            "email": "window-op@example.com",
            "roles": ["operator"],
        },
    )
    operator_id = operator_resp.json()["id"]

    host_resp = client.post(
        "/hosts",
        json={
            "name": "window-host",
            "hostname": "10.0.0.200",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh"],
            "tls_enabled": True,
            "rdp_nla": True,
        },
    )
    host_id = host_resp.json()["id"]

    current_weekday = datetime.now().strftime("%A").lower()
    all_days = [
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ]
    restricted_day = next(day for day in all_days if day != current_weekday)

    create_resp = client.post(
        "/access-windows",
        json={
            "name": "Business Hours",
            "allowed_start": "00:00",
            "allowed_end": "23:59",
            "days_of_week": [current_weekday],
            "performed_by": admin_id,
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    access_window = create_resp.json()
    access_window_id = access_window["id"]
    assert current_weekday in access_window["days_of_week"]

    list_resp = client.get("/access-windows")
    assert list_resp.status_code == 200
    assert list_resp.json()[0]["id"] == access_window_id

    detail_resp = client.get(f"/access-windows/{access_window_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["name"] == "Business Hours"

    assign_resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read",
            "access_window_id": access_window_id,
            "performed_by": admin_id,
        },
    )
    assert assign_resp.status_code == 204, assign_resp.text

    session_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert session_resp.status_code == 201, session_resp.text

    update_resp = client.patch(
        f"/access-windows/{access_window_id}",
        json={
            "days_of_week": [restricted_day],
            "performed_by": admin_id,
        },
    )
    assert update_resp.status_code == 200, update_resp.text
    assert update_resp.json()["days_of_week"] == [restricted_day]

    denied_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert denied_resp.status_code == 400
    assert "weekday" in denied_resp.json()["detail"].lower() or "time" in denied_resp.json()["detail"].lower()

    delete_resp = client.delete(f"/access-windows/{access_window_id}")
    assert delete_resp.status_code == 400
    assert "assigned" in delete_resp.json()["detail"].lower()

    reassigned_resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read",
            "performed_by": admin_id,
        },
    )
    assert reassigned_resp.status_code == 204, reassigned_resp.text

    delete_resp = client.delete(
        f"/access-windows/{access_window_id}?performed_by={admin_id}"
    )
    assert delete_resp.status_code == 204, delete_resp.text

    list_resp = client.get("/access-windows")
    assert list_resp.status_code == 200
    assert list_resp.json() == []

    filter_resp = client.get(f"/authorizations?access_window_id={access_window_id}")
    assert filter_resp.status_code == 200
    assert filter_resp.json() == []


def test_audit_event_catalog():
    admin_payload = {
        "username": "admin",
        "full_name": "Primary Admin",
        "email": "admin@example.com",
        "roles": ["admin"],
    }
    resp = client.post("/users", json=admin_payload)
    assert resp.status_code == 201
    admin_id = resp.json()["id"]

    operator_payload = {
        "username": "operator",
        "full_name": "Ops User",
        "email": "ops@example.com",
        "roles": ["operator"],
        "performed_by": admin_id,
    }
    resp = client.post("/users", json=operator_payload)
    assert resp.status_code == 201
    operator_id = resp.json()["id"]

    resp = client.patch(
        f"/users/{operator_id}",
        json={"email": "ops+updated@example.com", "performed_by": admin_id},
    )
    assert resp.status_code == 200

    host_payload = {
        "name": "audit-host",
        "hostname": "10.0.0.40",
        "port": 22,
        "operating_system": "linux",
        "protocols": ["ssh", "rdp"],
        "tls_enabled": True,
        "rdp_nla": True,
        "performed_by": admin_id,
    }
    resp = client.post("/hosts", json=host_payload)
    assert resp.status_code == 201
    host_id = resp.json()["id"]

    resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read-write",
            "performed_by": admin_id,
        },
    )
    assert resp.status_code == 204

    resp = client.get(f"/authorizations?user_id={operator_id}")
    authorization_id = resp.json()[0]["id"]

    resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert resp.status_code == 201
    session_id = resp.json()["id"]

    resp = client.post(
        f"/sessions/{session_id}/end",
        json={"metadata": {"ended": True}},
    )
    assert resp.status_code == 200

    resp = client.delete(
        f"/authorizations/{authorization_id}?performed_by={admin_id}"
    )
    assert resp.status_code == 204

    resp = client.get(f"/audit-events?actor_id={admin_id}")
    assert resp.status_code == 200
    admin_events = resp.json()
    actions = {event["action"] for event in admin_events}
    assert {
        "user.created",
        "user.updated",
        "host.created",
        "authorization.granted",
        "authorization.revoked",
    }.issubset(actions)
    grant_event = next(event for event in admin_events if event["action"] == "authorization.granted")
    assert grant_event["metadata"]["privileges"] == "read-write"

    resp = client.get(f"/audit-events?target_type=session&target_id={session_id}")
    assert resp.status_code == 200
    session_events = resp.json()
    assert {event["action"] for event in session_events} == {
        "session.started",
        "session.ended",
    }
    ended_event = next(event for event in session_events if event["action"] == "session.ended")
    assert ended_event["metadata"]["recording_created"] is False
    assert ended_event["metadata"]["host_id"] == host_id


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
        json={
            "user_id": user_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert resp.status_code == 400
    assert "inactive" in resp.json()["detail"]

    resp = client.patch(f"/users/{user_id}", json={"is_active": True})
    assert resp.status_code == 200

    resp = client.post(
        "/sessions",
        json={
            "user_id": user_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
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


def test_host_taxonomy_and_filtering():
    payloads = [
        {
            "name": "prod-gateway",
            "hostname": "10.0.0.60",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh", "sftp"],
            "tls_enabled": True,
            "rdp_nla": True,
            "tags": ["production", "core"],
            "environment": "production",
            "business_unit": "platform",
        },
        {
            "name": "staging-rdp",
            "hostname": "10.0.0.61",
            "port": 3389,
            "operating_system": "windows",
            "protocols": ["rdp"],
            "tls_enabled": True,
            "rdp_nla": True,
            "tags": ["staging", "rdp"],
            "environment": "staging",
            "business_unit": "qa",
        },
    ]
    created = []
    for payload in payloads:
        resp = client.post("/hosts", json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert set(body["tags"]) == set(payload["tags"])
        assert body["environment"] == payload["environment"]
        assert body["business_unit"] == payload["business_unit"]
        created.append(body)

    resp = client.get("/hosts?environment=production")
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["name"] == "prod-gateway"

    resp = client.get("/hosts?protocol=rdp")
    assert resp.status_code == 200
    names = {host["name"] for host in resp.json()}
    assert names == {"staging-rdp"}

    resp = client.get("/hosts?tag=core")
    assert resp.status_code == 200
    assert {host["name"] for host in resp.json()} == {"prod-gateway"}

    resp = client.get("/hosts?search=10.0.0.6")
    assert resp.status_code == 200
    assert {host["name"] for host in resp.json()} == {"prod-gateway", "staging-rdp"}

    host_id = created[0]["id"]
    resp = client.patch(
        f"/hosts/{host_id}",
        json={"tags": ["production", "ssh"], "business_unit": "sre"},
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert set(updated["tags"]) == {"production", "ssh"}
    assert updated["business_unit"] == "sre"

    resp = client.get("/hosts?tag=ssh")
    assert resp.status_code == 200
    assert {host["name"] for host in resp.json()} == {"prod-gateway"}

    resp = client.get("/hosts?environment=invalid")
    assert resp.status_code == 400
    assert "environment" in resp.json()["detail"].lower()


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
        json={
            "user_id": admin["id"],
            "host_id": host_a["id"],
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert resp.status_code == 201
    admin_session = resp.json()

    resp = client.post(
        "/sessions",
        json={
            "user_id": operator["id"],
            "host_id": host_a["id"],
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert resp.status_code == 201
    operator_session_active = resp.json()

    resp = client.post(f"/sessions/{admin_session['id']}/end", json={})
    assert resp.status_code == 200

    resp = client.post(
        "/sessions",
        json={
            "user_id": operator["id"],
            "host_id": host_b["id"],
            "protocol": "rdp",
            "source_ip": "198.51.100.10",
        },
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


def test_list_endpoints_support_pagination():
    seed_resp = client.post(
        "/users",
        json={
            "username": "seed-admin",
            "full_name": "Seed Admin",
            "email": "seed@example.com",
            "roles": ["admin"],
        },
    )
    actor_id = seed_resp.json()["id"]
    for idx in range(1, 5):
        resp = client.post(
            "/users",
            json={
                "username": f"paginated-user-{idx}",
                "full_name": f"Paginated User {idx}",
                "email": f"paginated{idx}@example.com",
                "roles": ["operator"],
                "performed_by": actor_id,
            },
        )
        assert resp.status_code == 201

    resp = client.get("/users?limit=2")
    assert resp.status_code == 200
    users = resp.json()
    assert [user["username"] for user in users] == ["seed-admin", "paginated-user-1"]

    resp = client.get("/users?offset=3")
    assert resp.status_code == 200
    assert [user["username"] for user in resp.json()] == [
        "paginated-user-3",
        "paginated-user-4",
    ]

    resp = client.get("/users?limit=2&offset=1")
    assert resp.status_code == 200
    assert [user["username"] for user in resp.json()] == [
        "paginated-user-1",
        "paginated-user-2",
    ]

    for idx in range(3):
        resp = client.post(
            "/hosts",
            json={
                "name": f"asset-{idx}",
                "hostname": f"10.0.1.{idx}",
                "port": 22,
                "operating_system": "linux",
                "protocols": ["ssh"],
                "tls_enabled": True,
                "rdp_nla": False,
                "performed_by": actor_id,
            },
        )
        assert resp.status_code == 201

    resp = client.get("/hosts?limit=1&offset=1")
    assert resp.status_code == 200
    hosts = resp.json()
    assert len(hosts) == 1
    assert hosts[0]["name"] == "asset-1"

    resp = client.get("/hosts?offset=10")
    assert resp.status_code == 200
    assert resp.json() == []

    resp = client.get("/hosts?limit=-1")
    assert resp.status_code == 400

    resp = client.get("/audit-events?limit=1")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp = client.get("/audit-events?offset=2")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    resp = client.get("/audit-events?offset=-5")
    assert resp.status_code == 400


def test_access_request_approval_flow():
    admin_resp = client.post(
        "/users",
        json={
            "username": "sec-admin",
            "full_name": "Security Admin",
            "email": "sec-admin@example.com",
            "roles": ["admin", "auditor"],
        },
    )
    assert admin_resp.status_code == 201, admin_resp.text
    admin_id = admin_resp.json()["id"]

    operator_resp = client.post(
        "/users",
        json={
            "username": "ops-user",
            "full_name": "Ops User",
            "email": "ops@example.com",
            "roles": ["operator"],
        },
    )
    assert operator_resp.status_code == 201, operator_resp.text
    operator_id = operator_resp.json()["id"]

    host_resp = client.post(
        "/hosts",
        json={
            "name": "ops-host",
            "hostname": "10.2.0.5",
            "port": 22,
            "operating_system": "linux",
            "protocols": ["ssh"],
            "tls_enabled": True,
            "rdp_nla": False,
            "performed_by": admin_id,
        },
    )
    assert host_resp.status_code == 201, host_resp.text
    host_id = host_resp.json()["id"]

    assign_resp = client.post(
        "/authorizations",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "privileges": "read",
            "performed_by": admin_id,
            "requires_approval": True,
        },
    )
    assert assign_resp.status_code == 204, assign_resp.text

    auth_list = client.get(f"/authorizations?user_id={operator_id}&host_id={host_id}")
    assert auth_list.status_code == 200, auth_list.text
    authorization = auth_list.json()[0]
    assert authorization["requires_approval"] is True
    auth_id = authorization["id"]

    filtered = client.get("/authorizations?requires_approval=true")
    assert filtered.status_code == 200
    assert any(item["id"] == auth_id for item in filtered.json())

    start_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert start_resp.status_code == 400
    assert "requires an approved request" in start_resp.json()["detail"].lower()

    request_resp = client.post(
        "/access-requests",
        json={
            "authorization_id": auth_id,
            "requested_by": operator_id,
            "reason": "weekly maintenance",
        },
    )
    assert request_resp.status_code == 201, request_resp.text
    request_id = request_resp.json()["id"]
    assert request_resp.json()["status"] == "pending"

    duplicate_resp = client.post(
        "/access-requests",
        json={"authorization_id": auth_id, "requested_by": operator_id},
    )
    assert duplicate_resp.status_code == 400

    pending_resp = client.get("/access-requests?status=pending")
    assert pending_resp.status_code == 200
    assert any(item["id"] == request_id for item in pending_resp.json())

    expiry = (datetime.now(tz=timezone.utc) + timedelta(hours=1)).isoformat()
    approve_resp = client.post(
        f"/access-requests/{request_id}/approve",
        json={"reviewer_id": admin_id, "expires_at": expiry, "note": "approved"},
    )
    assert approve_resp.status_code == 200, approve_resp.text
    assert approve_resp.json()["status"] == "approved"

    session_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert session_resp.status_code == 201, session_resp.text

    approved_resp = client.get(f"/access-requests?authorization_id={auth_id}&status=approved")
    assert approved_resp.status_code == 200
    assert len(approved_resp.json()) == 1

    revoke_resp = client.post(
        f"/access-requests/{request_id}/revoke",
        json={"reviewer_id": admin_id, "note": "expired window"},
    )
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json()["status"] == "revoked"

    blocked_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert blocked_resp.status_code == 400

    admin_request_resp = client.post(
        "/access-requests",
        json={
            "authorization_id": auth_id,
            "requested_by": admin_id,
            "reason": "emergency access",
        },
    )
    assert admin_request_resp.status_code == 201, admin_request_resp.text
    admin_request_id = admin_request_resp.json()["id"]
    assert admin_request_resp.json()["user_id"] == operator_id

    deny_resp = client.post(
        f"/access-requests/{admin_request_id}/deny",
        json={"reviewer_id": admin_id, "note": "not needed"},
    )
    assert deny_resp.status_code == 200, deny_resp.text
    assert deny_resp.json()["status"] == "denied"

    denied_list = client.get("/access-requests?status=denied")
    assert denied_list.status_code == 200
    assert any(item["id"] == admin_request_id for item in denied_list.json())

    final_resp = client.post(
        "/sessions",
        json={
            "user_id": operator_id,
            "host_id": host_id,
            "protocol": "ssh",
            "source_ip": "198.51.100.10",
        },
    )
    assert final_resp.status_code == 400


@pytest.fixture(autouse=True, scope='module')
def cleanup_db():
    yield
    if TEST_DB.exists():
        TEST_DB.unlink()
