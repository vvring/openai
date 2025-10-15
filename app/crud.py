"""CRUD helpers implemented on top of sqlite3."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .database import get_connection
from .models import (
    ROLE_ADMIN,
    ROLE_AUDITOR,
    ROLE_OPERATOR,
    SUPPORTED_ENVIRONMENTS,
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
    columns = set(row.keys())
    tags = _json_loads(row["tags"]) if "tags" in columns else None
    return {
        "id": row["id"],
        "name": row["name"],
        "hostname": row["hostname"],
        "port": row["port"],
        "operating_system": row["operating_system"],
        "protocols": protocols if isinstance(protocols, list) else [],
        "tls_enabled": bool(row["tls_enabled"]),
        "rdp_nla": bool(row["rdp_nla"]),
        "tags": tags if isinstance(tags, list) else [],
        "environment": row["environment"] if "environment" in columns else None,
        "business_unit": row["business_unit"] if "business_unit" in columns else None,
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


def _row_to_audit_event(row) -> Dict:
    metadata = _json_loads(row["metadata"]) if row["metadata"] else None
    return {
        "id": row["id"],
        "actor_id": row["actor_id"],
        "action": row["action"],
        "target_type": row["target_type"],
        "target_id": row["target_id"],
        "metadata": metadata,
        "created_at": row["created_at"],
    }


def _validate_pagination(limit: Optional[int], offset: Optional[int]) -> None:
    if limit is not None and limit <= 0:
        raise ValidationError("limit must be greater than zero")
    if offset is not None and offset < 0:
        raise ValidationError("offset must be greater than or equal to zero")


def _apply_pagination(
    sql: str, params: List[Any], limit: Optional[int], offset: Optional[int]
) -> Tuple[str, List[Any]]:
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
        if offset is not None:
            sql += " OFFSET ?"
            params.append(offset)
    elif offset is not None:
        sql += " LIMIT -1 OFFSET ?"
        params.append(offset)
    return sql, params


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


def _validate_environment(environment: Optional[str]) -> None:
    if environment is None:
        return
    if environment not in SUPPORTED_ENVIRONMENTS:
        raise ValidationError(
            f"Unsupported environment '{environment}'. Supported values: {sorted(SUPPORTED_ENVIRONMENTS)}"
        )


def _normalize_tags(tags: Optional[List[str]]) -> List[str]:
    if tags is None:
        return []
    if not isinstance(tags, list):
        raise ValidationError("tags must be provided as a list")
    normalized: List[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            raise ValidationError("tags must contain only strings")
        cleaned = tag.strip()
        if not cleaned:
            raise ValidationError("tags cannot be empty strings")
        if len(cleaned) > 50:
            raise ValidationError("tags cannot exceed 50 characters")
        normalized.append(cleaned)
    # Deduplicate while preserving order
    deduped: List[str] = []
    seen = set()
    for tag in normalized:
        if tag not in seen:
            deduped.append(tag)
            seen.add(tag)
    if len(deduped) > 20:
        raise ValidationError("no more than 20 tags may be assigned to a host")
    return deduped


def _ensure_actor(conn: sqlite3.Connection, actor_id: Optional[int]) -> Optional[int]:
    if actor_id is None:
        return None
    try:
        actor_int = int(actor_id)
    except (TypeError, ValueError) as exc:
        raise ValidationError("performed_by must be an integer") from exc
    row = conn.execute("SELECT id FROM users WHERE id = ?", (actor_int,)).fetchone()
    if not row:
        raise ValidationError(f"Actor user {actor_int} not found")
    return actor_int


def _record_audit_event(
    conn: sqlite3.Connection,
    *,
    actor_id: Optional[int],
    action: str,
    target_type: str,
    target_id: Optional[int],
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    if actor_id is None:
        return
    if not action:
        raise ValidationError("Audit events require an action description")
    if not target_type:
        raise ValidationError("Audit events require a target_type")
    created_at = datetime.now(tz=timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO audit_events (actor_id, action, target_type, target_id, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            action,
            target_type,
            target_id,
            json.dumps(metadata) if metadata is not None else None,
            created_at,
        ),
    )


def create_user(
    *,
    username: str,
    full_name: str,
    email: str,
    roles: List[str] | None = None,
    performed_by: Optional[int] = None,
) -> Dict:
    if not username or not full_name or not email:
        raise ValidationError("username, full_name and email are required")
    roles = roles or []
    _validate_roles(roles)
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, full_name, email, roles) VALUES (?, ?, ?, ?)",
                (username, full_name, email, json.dumps(roles)),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Username already exists") from exc
        user_id = cursor.lastrowid
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="user.created",
            target_type="user",
            target_id=user_id,
            metadata={
                "username": username,
                "roles": roles,
            },
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_user(row)


def list_users(*, limit: Optional[int] = None, offset: Optional[int] = None) -> List[Dict]:
    _validate_pagination(limit, offset)
    with get_connection() as conn:
        query = "SELECT * FROM users ORDER BY id ASC"
        params: List[Any] = []
        query, params = _apply_pagination(query, params, limit, offset)
        rows = conn.execute(query, tuple(params)).fetchall()
        return [_row_to_user(row) for row in rows]


def get_user(user_id: int) -> Dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise ValidationError(f"User {user_id} not found")
        return _row_to_user(row)


def update_user(
    user_id: int,
    *,
    full_name: Optional[str] = None,
    email: Optional[str] = None,
    roles: Optional[List[str]] = None,
    is_active: Optional[bool] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    if roles is not None:
        if not isinstance(roles, list):
            raise ValidationError("roles must be provided as a list")
        _validate_roles(roles)
    if full_name is not None and not full_name:
        raise ValidationError("full_name cannot be empty")
    if email is not None and not email:
        raise ValidationError("email cannot be empty")
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise ValidationError(f"User {user_id} not found")
        updates: List[str] = []
        params: List[object] = []
        changes: Dict[str, Any] = {}
        if full_name is not None:
            updates.append("full_name = ?")
            params.append(full_name)
            changes["full_name"] = full_name
        if email is not None:
            updates.append("email = ?")
            params.append(email)
            changes["email"] = email
        if roles is not None:
            updates.append("roles = ?")
            params.append(json.dumps(roles))
            changes["roles"] = roles
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(int(bool(is_active)))
            changes["is_active"] = bool(is_active)
        if not updates:
            raise ValidationError("No fields provided for update")
        conn.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
            (*params, user_id),
        )
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="user.updated",
            target_type="user",
            target_id=user_id,
            metadata=changes,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_user(row)


def create_host(
    *,
    name: str,
    hostname: str,
    port: int,
    operating_system: str,
    protocols: List[str],
    tls_enabled: bool,
    rdp_nla: bool,
    tags: Optional[List[str]] = None,
    environment: Optional[str] = None,
    business_unit: Optional[str] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    if not name or not hostname or not operating_system:
        raise ValidationError("name, hostname and operating_system are required")
    if not isinstance(port, int) or port <= 0:
        raise ValidationError("port must be a positive integer")
    protocols = protocols or []
    _validate_protocols(protocols)
    _validate_environment(environment)
    normalized_tags = _normalize_tags(tags)
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        try:
            cursor = conn.execute(
                """
                INSERT INTO hosts (
                    name,
                    hostname,
                    port,
                    operating_system,
                    protocols,
                    tls_enabled,
                    rdp_nla,
                    tags,
                    environment,
                    business_unit
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    hostname,
                    port,
                    operating_system,
                    json.dumps(protocols),
                    int(bool(tls_enabled)),
                    int(bool(rdp_nla)),
                    json.dumps(normalized_tags),
                    environment,
                    business_unit,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Host already exists") from exc
        host_id = cursor.lastrowid
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="host.created",
            target_type="host",
            target_id=host_id,
            metadata={
                "name": name,
                "protocols": protocols,
                "environment": environment,
                "tags": normalized_tags,
            },
        )
        conn.commit()
        row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return _row_to_host(row)


def list_hosts(
    *,
    protocol: Optional[str] = None,
    environment: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    if protocol is not None and protocol not in SUPPORTED_PROTOCOLS:
        raise ValidationError(f"Unsupported protocol '{protocol}'")
    _validate_environment(environment)
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM hosts ORDER BY id ASC").fetchall()
        hosts = [_row_to_host(row) for row in rows]
    if environment is not None:
        hosts = [host for host in hosts if host["environment"] == environment]
    if protocol is not None:
        hosts = [host for host in hosts if protocol in host["protocols"]]
    if tag is not None:
        hosts = [host for host in hosts if tag in host["tags"]]
    if search is not None:
        lowered = search.lower()
        hosts = [
            host
            for host in hosts
            if lowered in host["name"].lower() or lowered in host["hostname"].lower()
        ]
    if offset:
        hosts = hosts[offset:]
    if limit is not None:
        hosts = hosts[:limit]
    return hosts


def get_host(host_id: int) -> Dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not row:
            raise ValidationError(f"Host {host_id} not found")
        return _row_to_host(row)


def update_host(
    host_id: int,
    *,
    name: Optional[str] = None,
    hostname: Optional[str] = None,
    port: Optional[int] = None,
    operating_system: Optional[str] = None,
    protocols: Optional[List[str]] = None,
    tls_enabled: Optional[bool] = None,
    rdp_nla: Optional[bool] = None,
    tags: Optional[List[str]] = None,
    environment: Optional[str] = None,
    business_unit: Optional[str] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    if port is not None:
        if not isinstance(port, int) or port <= 0:
            raise ValidationError("port must be a positive integer")
    if name is not None and not name:
        raise ValidationError("name cannot be empty")
    if hostname is not None and not hostname:
        raise ValidationError("hostname cannot be empty")
    if operating_system is not None and not operating_system:
        raise ValidationError("operating_system cannot be empty")
    if protocols is not None:
        if not isinstance(protocols, list):
            raise ValidationError("protocols must be provided as a list")
        _validate_protocols(protocols)
    _validate_environment(environment)
    normalized_tags = _normalize_tags(tags) if tags is not None else None
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not row:
            raise ValidationError(f"Host {host_id} not found")
        updates: List[str] = []
        params: List[object] = []
        changes: Dict[str, Any] = {}
        if name is not None:
            updates.append("name = ?")
            params.append(name)
            changes["name"] = name
        if hostname is not None:
            updates.append("hostname = ?")
            params.append(hostname)
            changes["hostname"] = hostname
        if port is not None:
            updates.append("port = ?")
            params.append(port)
            changes["port"] = port
        if operating_system is not None:
            updates.append("operating_system = ?")
            params.append(operating_system)
            changes["operating_system"] = operating_system
        effective_protocols = protocols if protocols is not None else _json_loads(row["protocols"]) or []
        if protocols is not None:
            updates.append("protocols = ?")
            params.append(json.dumps(protocols))
            changes["protocols"] = protocols
        effective_rdp_nla = bool(row["rdp_nla"]) if rdp_nla is None else bool(rdp_nla)
        if rdp_nla is not None:
            updates.append("rdp_nla = ?")
            params.append(int(bool(rdp_nla)))
            changes["rdp_nla"] = bool(rdp_nla)
        if tls_enabled is not None:
            updates.append("tls_enabled = ?")
            params.append(int(bool(tls_enabled)))
            changes["tls_enabled"] = bool(tls_enabled)
        if normalized_tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(normalized_tags))
            changes["tags"] = normalized_tags
        if environment is not None:
            updates.append("environment = ?")
            params.append(environment)
            changes["environment"] = environment
        if business_unit is not None:
            updates.append("business_unit = ?")
            params.append(business_unit)
            changes["business_unit"] = business_unit
        if "rdp" in effective_protocols and not effective_rdp_nla:
            raise ValidationError("Hosts exposing RDP must enable NLA")
        if not updates:
            raise ValidationError("No fields provided for update")
        try:
            conn.execute(
                f"UPDATE hosts SET {', '.join(updates)} WHERE id = ?",
                (*params, host_id),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Host already exists") from exc
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="host.updated",
            target_type="host",
            target_id=host_id,
            metadata=changes,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return _row_to_host(row)


def authorize_user(
    user_id: int,
    host_id: int,
    privileges: str,
    *,
    performed_by: Optional[int] = None,
) -> None:
    if not privileges:
        raise ValidationError("privileges must be provided")
    _validate_privileges(privileges)
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        host = conn.execute("SELECT id FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not user:
            raise ValidationError(f"User {user_id} not found")
        if not host:
            raise ValidationError(f"Host {host_id} not found")
        existing = conn.execute(
            "SELECT * FROM authorizations WHERE user_id = ? AND host_id = ?",
            (user_id, host_id),
        ).fetchone()
        conn.execute(
            """
            INSERT INTO authorizations (user_id, host_id, privileges)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, host_id) DO UPDATE SET privileges = excluded.privileges
            """,
            (user_id, host_id, privileges),
        )
        row = conn.execute(
            "SELECT * FROM authorizations WHERE user_id = ? AND host_id = ?",
            (user_id, host_id),
        ).fetchone()
        action = "authorization.updated" if existing else "authorization.granted"
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action=action,
            target_type="authorization",
            target_id=row["id"] if row else None,
            metadata={"privileges": privileges},
        )
        conn.commit()


def list_authorizations(
    *,
    user_id: Optional[int] = None,
    host_id: Optional[int] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    with get_connection() as conn:
        clauses = []
        params: List[Any] = []
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
        query, params = _apply_pagination(query, params, limit, offset)
        rows = conn.execute(query, tuple(params)).fetchall()
        return [_row_to_authorization(row) for row in rows]


def revoke_authorization(authorization_id: int, *, performed_by: Optional[int] = None) -> None:
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        row = conn.execute(
            "SELECT * FROM authorizations WHERE id = ?",
            (authorization_id,),
        ).fetchone()
        if not row:
            raise ValidationError(f"Authorization {authorization_id} not found")
        conn.execute(
            "DELETE FROM authorizations WHERE id = ?",
            (authorization_id,),
        )
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="authorization.revoked",
            target_type="authorization",
            target_id=authorization_id,
            metadata={"user_id": row["user_id"], "host_id": row["host_id"]},
        )
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
        session_id = cursor.lastrowid
        _record_audit_event(
            conn,
            actor_id=user_id,
            action="session.started",
            target_type="session",
            target_id=session_id,
            metadata={"host_id": host_id, "protocol": protocol},
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
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
        audit_metadata: Dict[str, Any] = {
            "host_id": row["host_id"],
            "recording_path": recording_path,
            "recording_created": bool(recording_payload),
        }
        if recording_payload and recording_payload.get("checksum"):
            audit_metadata["checksum"] = recording_payload["checksum"]
        _record_audit_event(
            conn,
            actor_id=row["user_id"],
            action="session.ended",
            target_type="session",
            target_id=record_id,
            metadata=audit_metadata,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (record_id,)).fetchone()
        return _row_to_session(row)


def list_sessions(
    *,
    user_id: Optional[int] = None,
    host_id: Optional[int] = None,
    protocol: Optional[str] = None,
    only_active: Optional[bool] = None,
    started_after: Optional[str] = None,
    started_before: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    if protocol is not None and protocol not in SUPPORTED_PROTOCOLS:
        raise ValidationError(f"Unsupported protocol '{protocol}'")
    clauses: List[str] = []
    params: List[object] = []
    if user_id is not None:
        clauses.append("user_id = ?")
        params.append(user_id)
    if host_id is not None:
        clauses.append("host_id = ?")
        params.append(host_id)
    if protocol is not None:
        clauses.append("protocol = ?")
        params.append(protocol)
    if only_active is True:
        clauses.append("ended_at IS NULL")
    elif only_active is False:
        clauses.append("ended_at IS NOT NULL")
    if started_after is not None:
        clauses.append("started_at >= ?")
        params.append(started_after)
    if started_before is not None:
        clauses.append("started_at <= ?")
        params.append(started_before)
    query = "SELECT * FROM sessions"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id ASC"
    with get_connection() as conn:
        query, params = _apply_pagination(query, params, limit, offset)
        rows = conn.execute(query, tuple(params)).fetchall()
        return [_row_to_session(row) for row in rows]


def get_session(record_id: int) -> Dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (record_id,)).fetchone()
        if not row:
            raise ValidationError(f"Session {record_id} not found")
        session = _row_to_session(row)
        recordings = conn.execute(
            "SELECT * FROM recordings WHERE session_id = ? ORDER BY id ASC",
            (record_id,),
        ).fetchall()
        session["recordings"] = [_row_to_recording(recording) for recording in recordings]
        return session


def list_recordings(
    *,
    session_id: Optional[int] = None,
    user_id: Optional[int] = None,
    host_id: Optional[int] = None,
    protocol: Optional[str] = None,
    created_after: Optional[str] = None,
    created_before: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    if protocol is not None and protocol not in SUPPORTED_PROTOCOLS:
        raise ValidationError(f"Unsupported protocol '{protocol}'")
    clauses: List[str] = []
    params: List[object] = []
    join_sessions = any(value is not None for value in (user_id, host_id, protocol))
    if session_id is not None:
        clauses.append("recordings.session_id = ?")
        params.append(session_id)
    if user_id is not None:
        clauses.append("sessions.user_id = ?")
        params.append(user_id)
    if host_id is not None:
        clauses.append("sessions.host_id = ?")
        params.append(host_id)
    if protocol is not None:
        clauses.append("sessions.protocol = ?")
        params.append(protocol)
    if created_after is not None:
        clauses.append("recordings.created_at >= ?")
        params.append(created_after)
    if created_before is not None:
        clauses.append("recordings.created_at <= ?")
        params.append(created_before)
    query = "SELECT recordings.* FROM recordings"
    if join_sessions:
        query += " JOIN sessions ON recordings.session_id = sessions.id"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY recordings.id ASC"
    with get_connection() as conn:
        query, params = _apply_pagination(query, params, limit, offset)
        rows = conn.execute(query, tuple(params)).fetchall()
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


def list_audit_events(
    *,
    actor_id: Optional[int] = None,
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    created_after: Optional[str] = None,
    created_before: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    clauses: List[str] = []
    params: List[object] = []
    if actor_id is not None:
        clauses.append("actor_id = ?")
        params.append(actor_id)
    if action is not None:
        clauses.append("action = ?")
        params.append(action)
    if target_type is not None:
        clauses.append("target_type = ?")
        params.append(target_type)
    if target_id is not None:
        clauses.append("target_id = ?")
        params.append(target_id)
    if created_after is not None:
        clauses.append("created_at >= ?")
        params.append(created_after)
    if created_before is not None:
        clauses.append("created_at <= ?")
        params.append(created_before)
    query = "SELECT * FROM audit_events"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC"
    with get_connection() as conn:
        query, params = _apply_pagination(query, params, limit, offset)
        rows = conn.execute(query, tuple(params)).fetchall()
        return [_row_to_audit_event(row) for row in rows]
