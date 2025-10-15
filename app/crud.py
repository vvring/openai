"""CRUD helpers implemented on top of sqlite3."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List

from .database import get_connection
from .models import ROLE_ADMIN, ROLE_AUDITOR, ROLE_OPERATOR, SUPPORTED_PROTOCOLS


class ValidationError(ValueError):
    """Raised when input validation fails."""


def _json_loads(value: str | None):
    if value in (None, ""):
        return None
    return json.loads(value)


def _row_to_user(row) -> Dict:
    roles = _json_loads(row["roles"])
    return {
        "id": row["id"],
        "username": row["username"],
        "full_name": row["full_name"],
        "email": row["email"],
        "is_active": bool(row["is_active"]),
        "roles": roles if isinstance(roles, list) else [],
    }


def _row_to_host(row) -> Dict:
    protocols = _json_loads(row["protocols"])
    return {
        "id": row["id"],
        "name": row["name"],
        "hostname": row["hostname"],
        "port": row["port"],
        "operating_system": row["operating_system"],
        "protocols": protocols if isinstance(protocols, list) else [],
        "tls_enabled": bool(row["tls_enabled"]),
        "rdp_nla": bool(row["rdp_nla"]),
    }


def _row_to_session(row) -> Dict:
    metadata = _json_loads(row["metadata"]) if row["metadata"] else None
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "host_id": row["host_id"],
        "protocol": row["protocol"],
        "started_at": row["started_at"],
        "ended_at": row["ended_at"],
        "recording_path": row["recording_path"],
        "metadata": metadata,
    }


def _validate_roles(roles: List[str]) -> None:
    allowed = {ROLE_ADMIN, ROLE_AUDITOR, ROLE_OPERATOR}
    for role in roles:
        if role not in allowed:
            raise ValidationError(f"Unsupported role '{role}'")


def _validate_protocols(protocols: List[str]) -> None:
    for proto in protocols:
        if proto not in SUPPORTED_PROTOCOLS:
            raise ValidationError(f"Unsupported protocol '{proto}'")


def create_user(*, username: str, full_name: str, email: str, roles: List[str] | None = None) -> Dict:
    if not username or not full_name or not email:
        raise ValidationError("username, full_name and email are required")
    roles = roles or []
    _validate_roles(roles)
    with get_connection() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, full_name, email, roles) VALUES (?, ?, ?, ?)",
                (username, full_name, email, json.dumps(roles)),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Username already exists") from exc
        row = conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return _row_to_user(row)


def list_users() -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
        return [_row_to_user(row) for row in rows]


def create_host(
    *,
    name: str,
    hostname: str,
    port: int,
    operating_system: str,
    protocols: List[str],
    tls_enabled: bool,
    rdp_nla: bool,
) -> Dict:
    if not name or not hostname or not operating_system:
        raise ValidationError("name, hostname and operating_system are required")
    if not isinstance(port, int) or port <= 0:
        raise ValidationError("port must be a positive integer")
    protocols = protocols or []
    _validate_protocols(protocols)
    with get_connection() as conn:
        try:
            cursor = conn.execute(
                """
                INSERT INTO hosts (name, hostname, port, operating_system, protocols, tls_enabled, rdp_nla)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    hostname,
                    port,
                    operating_system,
                    json.dumps(protocols),
                    int(bool(tls_enabled)),
                    int(bool(rdp_nla)),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Host already exists") from exc
        row = conn.execute("SELECT * FROM hosts WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return _row_to_host(row)


def list_hosts() -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM hosts ORDER BY id ASC").fetchall()
        return [_row_to_host(row) for row in rows]


def authorize_user(user_id: int, host_id: int, privileges: str) -> None:
    if not privileges:
        raise ValidationError("privileges must be provided")
    with get_connection() as conn:
        user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        host = conn.execute("SELECT id FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not user:
            raise ValidationError(f"User {user_id} not found")
        if not host:
            raise ValidationError(f"Host {host_id} not found")
        conn.execute(
            """
            INSERT INTO authorizations (user_id, host_id, privileges)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, host_id) DO UPDATE SET privileges = excluded.privileges
            """,
            (user_id, host_id, privileges),
        )
        conn.commit()


def start_session(*, user_id: int, host_id: int, protocol: str) -> Dict:
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValidationError(f"Unsupported protocol '{protocol}'")
    with get_connection() as conn:
        user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        host = conn.execute("SELECT id FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not user or not host:
            raise ValidationError("User or host not found")
        started_at = datetime.now(tz=timezone.utc).isoformat()
        cursor = conn.execute(
            """
            INSERT INTO sessions (user_id, host_id, protocol, started_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, host_id, protocol, started_at),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return _row_to_session(row)


def end_session(record_id: int, *, recording_path: str | None, metadata: Dict | None) -> Dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (record_id,)).fetchone()
        if not row:
            raise ValidationError(f"Session {record_id} not found")
        ended_at = datetime.now(tz=timezone.utc).isoformat()
        conn.execute(
            """
            UPDATE sessions
            SET ended_at = ?, recording_path = ?, metadata = ?
            WHERE id = ?
            """,
            (ended_at, recording_path, json.dumps(metadata) if metadata is not None else None, record_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (record_id,)).fetchone()
        return _row_to_session(row)


def list_sessions() -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM sessions ORDER BY id ASC").fetchall()
        return [_row_to_session(row) for row in rows]
