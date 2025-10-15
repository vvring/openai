"""CRUD helpers implemented on top of sqlite3."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .database import get_connection
from .models import (
    ROLE_ADMIN,
    ROLE_AUDITOR,
    ROLE_OPERATOR,
    SUPPORTED_PRIVILEGES,
    SUPPORTED_PROTOCOLS,
)


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


def _row_to_authorization(row) -> Dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "host_id": row["host_id"],
        "privileges": row["privileges"],
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


def _row_to_recording(row) -> Dict:
    metadata = _json_loads(row["metadata"]) if row["metadata"] else None
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "storage_path": row["storage_path"],
        "size_bytes": row["size_bytes"],
        "duration_seconds": row["duration_seconds"],
        "checksum": row["checksum"],
        "created_at": row["created_at"],
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


def _validate_privileges(privileges: str) -> None:
    if privileges not in SUPPORTED_PRIVILEGES:
        raise ValidationError(f"Unsupported privileges '{privileges}'")


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
    _validate_privileges(privileges)
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


def list_authorizations(*, user_id: Optional[int] = None, host_id: Optional[int] = None) -> List[Dict]:
    with get_connection() as conn:
        clauses = []
        params: List[int] = []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if host_id is not None:
            clauses.append("host_id = ?")
            params.append(host_id)
        if clauses:
            query = "SELECT * FROM authorizations WHERE " + " AND ".join(clauses) + " ORDER BY id ASC"
        else:
            query = "SELECT * FROM authorizations ORDER BY id ASC"
        rows = conn.execute(query, params).fetchall()
        return [_row_to_authorization(row) for row in rows]


def revoke_authorization(authorization_id: int) -> None:
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM authorizations WHERE id = ?",
            (authorization_id,),
        )
        if cursor.rowcount == 0:
            raise ValidationError(f"Authorization {authorization_id} not found")
        conn.commit()


def start_session(*, user_id: int, host_id: int, protocol: str) -> Dict:
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValidationError(f"Unsupported protocol '{protocol}'")
    with get_connection() as conn:
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        host_row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not user_row or not host_row:
            raise ValidationError("User or host not found")
        if not bool(user_row["is_active"]):
            raise ValidationError("User is inactive")
        host_protocols = _json_loads(host_row["protocols"]) or []
        if protocol not in host_protocols:
            raise ValidationError("Requested protocol is not enabled for the host")
        if protocol == "rdp" and not bool(host_row["rdp_nla"]):
            raise ValidationError("RDP sessions require NLA to be enabled for the host")
        roles = _json_loads(user_row["roles"]) or []
        if ROLE_ADMIN not in roles:
            auth = conn.execute(
                "SELECT * FROM authorizations WHERE user_id = ? AND host_id = ?",
                (user_id, host_id),
            ).fetchone()
            if not auth:
                raise ValidationError("User does not have access to the requested host")
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


def _validate_recording_payload(payload: Dict) -> Dict:
    if not payload:
        raise ValidationError("recording information must include storage_path")
    storage_path = payload.get("storage_path")
    if not storage_path:
        raise ValidationError("recording.storage_path is required")
    size_bytes = payload.get("size_bytes")
    if size_bytes is not None:
        try:
            size_bytes = int(size_bytes)
        except (TypeError, ValueError) as exc:
            raise ValidationError("recording.size_bytes must be an integer") from exc
        if size_bytes < 0:
            raise ValidationError("recording.size_bytes must be positive")
    duration_seconds = payload.get("duration_seconds")
    if duration_seconds is not None:
        try:
            duration_seconds = float(duration_seconds)
        except (TypeError, ValueError) as exc:
            raise ValidationError("recording.duration_seconds must be a number") from exc
        if duration_seconds < 0:
            raise ValidationError("recording.duration_seconds must be positive")
    checksum = payload.get("checksum")
    metadata = payload.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise ValidationError("recording.metadata must be an object")
    return {
        "storage_path": storage_path,
        "size_bytes": size_bytes,
        "duration_seconds": duration_seconds,
        "checksum": checksum,
        "metadata": metadata,
    }


def end_session(
    record_id: int,
    *,
    recording_path: Optional[str] = None,
    metadata: Optional[Dict] = None,
    recording: Optional[Dict] = None,
) -> Dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (record_id,)).fetchone()
        if not row:
            raise ValidationError(f"Session {record_id} not found")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValidationError("metadata must be an object")
        recording_payload: Optional[Dict] = None
        if recording:
            recording_payload = _validate_recording_payload(recording)
        elif recording_path:
            recording_payload = _validate_recording_payload(
                {"storage_path": recording_path, "metadata": metadata}
            )
        if recording_payload and recording_path is None:
            recording_path = recording_payload["storage_path"]
        ended_at = datetime.now(tz=timezone.utc).isoformat()
        conn.execute(
            """
            UPDATE sessions
            SET ended_at = ?, recording_path = ?, metadata = ?
            WHERE id = ?
            """,
            (ended_at, recording_path, json.dumps(metadata) if metadata is not None else None, record_id),
        )
        if recording_payload:
            recording_payload.setdefault("metadata", metadata)
            conn.execute(
                """
                INSERT INTO recordings (
                    session_id,
                    storage_path,
                    size_bytes,
                    duration_seconds,
                    checksum,
                    created_at,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    recording_payload["storage_path"],
                    recording_payload["size_bytes"],
                    recording_payload["duration_seconds"],
                    recording_payload["checksum"],
                    ended_at,
                    json.dumps(recording_payload["metadata"]) if recording_payload["metadata"] else None,
                ),
            )
        conn.commit()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (record_id,)).fetchone()
        return _row_to_session(row)


def list_sessions() -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM sessions ORDER BY id ASC").fetchall()
        return [_row_to_session(row) for row in rows]


def list_recordings(*, session_id: Optional[int] = None) -> List[Dict]:
    with get_connection() as conn:
        if session_id is not None:
            rows = conn.execute(
                "SELECT * FROM recordings WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM recordings ORDER BY id ASC").fetchall()
        return [_row_to_recording(row) for row in rows]


def get_recording(recording_id: int) -> Dict:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM recordings WHERE id = ?",
            (recording_id,),
        ).fetchone()
        if not row:
            raise ValidationError(f"Recording {recording_id} not found")
        return _row_to_recording(row)
