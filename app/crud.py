"""CRUD helpers implemented on top of sqlite3."""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import sqlite3
from datetime import datetime, time, timezone
from typing import Any, Dict, List, Optional, Tuple


UNSET = object()

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .database import get_connection
from .models import (
    ACCESS_REQUEST_STATUSES,
    ACCESS_REQUEST_STATUS_APPROVED,
    ACCESS_REQUEST_STATUS_DENIED,
    ACCESS_REQUEST_STATUS_PENDING,
    ACCESS_REQUEST_STATUS_REVOKED,
    ROLE_ADMIN,
    ROLE_AUDITOR,
    ROLE_OPERATOR,
    SESSION_CONNECTION_STATUSES,
    SESSION_CONNECTION_STATUS_FAILED,
    SESSION_CONNECTION_STATUS_PENDING,
    SESSION_CONNECTION_STATUS_SUCCEEDED,
    SUPPORTED_CREDENTIAL_SECRET_TYPES,
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


def _row_to_host(row, *, groups: Optional[List[Dict]] = None) -> Dict:
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
        "groups": groups if groups is not None else [],
    }


def _row_to_host_group(row, *, host_ids: Optional[List[int]] = None) -> Dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "host_ids": host_ids if host_ids is not None else [],
    }


def _row_to_host_group_summary(row) -> Dict:
    return {
        "id": row["group_id"] if "group_id" in row.keys() else row["id"],
        "name": row["name"],
        "description": row["description"],
    }


def _row_to_authorization(row) -> Dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "host_id": row["host_id"],
        "privileges": row["privileges"],
        "access_window_id": row["access_window_id"],
        "requires_approval": bool(row["requires_approval"])
        if "requires_approval" in row.keys()
        else False,
        "source_cidrs": _json_loads(row["source_cidrs"]) or []
        if "source_cidrs" in row.keys()
        else [],
        "command_policy_id": row["command_policy_id"]
        if "command_policy_id" in row.keys()
        else None,
    }


def _row_to_access_request(row) -> Dict:
    return {
        "id": row["id"],
        "authorization_id": row["authorization_id"],
        "user_id": row["user_id"],
        "host_id": row["host_id"],
        "status": row["status"],
        "reason": row["reason"],
        "requested_by": row["requested_by"],
        "reviewer_id": row["reviewer_id"],
        "reviewer_note": row["reviewer_note"],
        "reviewed_at": row["reviewed_at"],
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
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


def _row_to_connection_attempt(row) -> Dict:
    instructions = _json_loads(row["instructions"]) if row["instructions"] else None
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "initiated_by": row["initiated_by"],
        "credential_id": row["credential_id"],
        "protocol": row["protocol"],
        "status": row["status"],
        "instructions": instructions,
        "failure_reason": row["failure_reason"],
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
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


def _row_to_credential(row) -> Dict:
    secret = row["secret"] or ""
    preview = None
    if secret:
        preview = secret[-4:] if len(secret) > 4 else secret
    return {
        "id": row["id"],
        "host_id": row["host_id"],
        "name": row["name"],
        "username": row["username"],
        "secret_type": row["secret_type"],
        "secret_preview": preview,
        "rotation_frequency_days": row["rotation_frequency_days"],
        "last_rotated_at": row["last_rotated_at"],
        "description": row["description"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "created_by": row["created_by"],
    }


def _row_to_access_window(row) -> Dict:
    days = _json_loads(row["days_of_week"]) or []
    return {
        "id": row["id"],
        "name": row["name"],
        "allowed_start": row["allowed_start"],
        "allowed_end": row["allowed_end"],
        "days_of_week": days if isinstance(days, list) else [],
        "timezone": row["timezone"],
        "description": row["description"],
    }


def _row_to_command_policy(row) -> Dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "allowed_patterns": _json_loads(row["allowed_patterns"]) or [],
        "denied_patterns": _json_loads(row["denied_patterns"]) or [],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "created_by": row["created_by"],
    }


def _normalize_source_cidrs(value) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError("source_cidrs must be provided as a list of CIDR strings")
    normalized: List[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValidationError("source_cidrs entries must be strings")
        candidate = item.strip()
        if not candidate:
            raise ValidationError("source_cidrs entries cannot be empty")
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise ValidationError(f"Invalid CIDR '{candidate}' in source_cidrs") from exc
        canonical = str(network)
        if canonical in seen:
            continue
        normalized.append(canonical)
        seen.add(canonical)
    if len(normalized) > 50:
        raise ValidationError("source_cidrs cannot include more than 50 entries")
    return normalized


_VALID_WEEKDAYS = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
]

_VALID_WEEKDAY_SET = set(_VALID_WEEKDAYS)


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


def _map_host_groups(conn: sqlite3.Connection, host_ids: List[int]) -> Dict[int, List[Dict]]:
    if not host_ids:
        return {}
    placeholders = ",".join(["?"] * len(host_ids))
    rows = conn.execute(
        f"""
        SELECT
            hgm.host_id AS host_id,
            hg.id AS group_id,
            hg.name AS name,
            hg.description AS description
        FROM host_group_members hgm
        JOIN host_groups hg ON hgm.group_id = hg.id
        WHERE hgm.host_id IN ({placeholders})
        ORDER BY hg.name ASC
        """,
        tuple(host_ids),
    ).fetchall()
    mapping: Dict[int, List[Dict]] = {host_id: [] for host_id in host_ids}
    for row in rows:
        mapping.setdefault(row["host_id"], []).append(_row_to_host_group_summary(row))
    return mapping


def _get_group_host_ids(conn: sqlite3.Connection, group_id: int) -> List[int]:
    rows = conn.execute(
        "SELECT host_id FROM host_group_members WHERE group_id = ? ORDER BY host_id ASC",
        (group_id,),
    ).fetchall()
    return [row["host_id"] for row in rows]


def _fetch_hosts_for_group(conn: sqlite3.Connection, group_id: int) -> List[Dict]:
    host_rows = conn.execute(
        """
        SELECT h.*
        FROM host_group_members hgm
        JOIN hosts h ON hgm.host_id = h.id
        WHERE hgm.group_id = ?
        ORDER BY h.name ASC
        """,
        (group_id,),
    ).fetchall()
    host_ids = [row["id"] for row in host_rows]
    groups_map = _map_host_groups(conn, host_ids)
    return [_row_to_host(row, groups=groups_map.get(row["id"], [])) for row in host_rows]


def _normalize_host_ids(host_ids: Optional[List[int]]) -> List[int]:
    if host_ids is None:
        return []
    if not isinstance(host_ids, list):
        raise ValidationError("host_ids must be provided as a list")
    normalized: List[int] = []
    seen = set()
    for value in host_ids:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("host_ids must contain integers") from exc
        if parsed <= 0:
            raise ValidationError("host_ids must reference positive identifiers")
        if parsed not in seen:
            normalized.append(parsed)
            seen.add(parsed)
    return normalized


def _ensure_host_group(conn: sqlite3.Connection, group_id: int):
    row = conn.execute("SELECT * FROM host_groups WHERE id = ?", (group_id,)).fetchone()
    if not row:
        raise ValidationError(f"Host group {group_id} not found")
    return row


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


def _normalize_command_patterns(patterns: Optional[List[str]], field: str) -> List[str]:
    if patterns is None:
        return []
    if not isinstance(patterns, list):
        raise ValidationError(f"{field} must be provided as a list")
    normalized: List[str] = []
    seen = set()
    for pattern in patterns:
        if not isinstance(pattern, str):
            raise ValidationError(f"{field} must contain only strings")
        cleaned = pattern.strip()
        if not cleaned:
            raise ValidationError(f"{field} cannot contain empty strings")
        if len(cleaned) > 200:
            raise ValidationError(f"{field} entries cannot exceed 200 characters")
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)
    if len(normalized) > 100:
        raise ValidationError(f"{field} cannot contain more than 100 entries")
    return normalized


def _require_non_empty_string(value: Optional[str], field: str, *, max_length: Optional[int] = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    cleaned = value.strip()
    if max_length is not None and len(cleaned) > max_length:
        raise ValidationError(f"{field} cannot exceed {max_length} characters")
    return cleaned


def _normalize_requested_commands(commands: Optional[List[str]]) -> List[str]:
    if commands is None:
        return []
    if not isinstance(commands, list):
        raise ValidationError("requested_commands must be provided as a list")
    normalized: List[str] = []
    for command in commands:
        if not isinstance(command, str):
            raise ValidationError("requested_commands must contain only strings")
        cleaned = command.strip()
        if not cleaned:
            raise ValidationError("requested_commands cannot contain empty commands")
        if len(cleaned) > 1024:
            raise ValidationError("requested_commands entries cannot exceed 1024 characters")
        normalized.append(cleaned)
    if len(normalized) > 50:
        raise ValidationError("requested_commands cannot contain more than 50 entries")
    return normalized


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


def _ensure_active_actor(
    conn: sqlite3.Connection, actor_id: Optional[int], *, field: str
) -> int:
    actor = _ensure_actor(conn, actor_id)
    if actor is None:
        raise ValidationError(f"{field} must be provided")
    row = _ensure_user_row(conn, actor)
    if not bool(row["is_active"]):
        raise ValidationError(f"{field} must reference an active user")
    return actor


def _ensure_user_row(conn: sqlite3.Connection, user_id: int):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise ValidationError(f"User {user_id} not found")
    return row


def _ensure_reviewer(conn: sqlite3.Connection, reviewer_id: Optional[int]) -> int:
    actor_id = _ensure_actor(conn, reviewer_id)
    if actor_id is None:
        raise ValidationError("reviewer must be provided")
    row = _ensure_user_row(conn, actor_id)
    if not bool(row["is_active"]):
        raise ValidationError("reviewer must be an active user")
    roles = _json_loads(row["roles"]) or []
    if ROLE_ADMIN not in roles and ROLE_AUDITOR not in roles:
        raise ValidationError("reviewer must have admin or auditor role")
    return actor_id


def _ensure_authorization(conn: sqlite3.Connection, authorization_id: int):
    row = conn.execute(
        "SELECT * FROM authorizations WHERE id = ?",
        (authorization_id,),
    ).fetchone()
    if not row:
        raise ValidationError(f"Authorization {authorization_id} not found")
    return row


def _ensure_host(conn: sqlite3.Connection, host_id: int):
    row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if not row:
        raise ValidationError(f"Host {host_id} not found")
    return row


def _ensure_session(conn: sqlite3.Connection, session_id: int):
    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not row:
        raise ValidationError(f"Session {session_id} not found")
    return row


def _ensure_credential_row(conn: sqlite3.Connection, credential_id: int):
    row = conn.execute(
        "SELECT * FROM credentials WHERE id = ?",
        (credential_id,),
    ).fetchone()
    if not row:
        raise ValidationError(f"Credential {credential_id} not found")
    return row


def _parse_time_of_day(value: str, field: str) -> time:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a HH:MM string")
    try:
        parsed = datetime.strptime(value, "%H:%M").time()
    except ValueError as exc:
        raise ValidationError(f"{field} must be formatted as HH:MM (24h)") from exc
    return parsed


def _parse_datetime(value: str, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an ISO formatted datetime string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError(f"{field} must be an ISO formatted datetime string") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _validate_rotation_frequency(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if not isinstance(value, int):
        raise ValidationError("rotation_frequency_days must be an integer")
    if value <= 0:
        raise ValidationError("rotation_frequency_days must be greater than zero")
    if value > 3650:
        raise ValidationError("rotation_frequency_days cannot exceed 3650 days")
    return value


def _normalize_days_of_week(days: List[str]) -> List[str]:
    if not isinstance(days, list) or not days:
        raise ValidationError("days_of_week must be a non-empty list of weekdays")
    normalized: List[str] = []
    seen = set()
    for day in days:
        if not isinstance(day, str):
            raise ValidationError("days_of_week must contain only strings")
        lowered = day.strip().lower()
        if lowered not in _VALID_WEEKDAY_SET:
            raise ValidationError(
                "days_of_week must contain valid weekday names (e.g. monday, tuesday)"
            )
        if lowered not in seen:
            normalized.append(lowered)
            seen.add(lowered)
    # Preserve canonical order for determinism
    ordered = [day for day in _VALID_WEEKDAYS if day in seen]
    return ordered


def _ensure_timezone(value: str) -> str:
    tz_value = value or "UTC"
    if not isinstance(tz_value, str):
        raise ValidationError("timezone must be a string")
    try:
        ZoneInfo(tz_value)
    except ZoneInfoNotFoundError as exc:
        raise ValidationError(f"Unknown timezone '{tz_value}'") from exc
    return tz_value


def _ensure_access_window(conn: sqlite3.Connection, access_window_id: Optional[int]) -> Optional[Dict]:
    if access_window_id is None:
        return None
    row = conn.execute(
        "SELECT * FROM access_windows WHERE id = ?",
        (access_window_id,),
    ).fetchone()
    if not row:
        raise ValidationError(f"Access window {access_window_id} not found")
    return _row_to_access_window(row)


def _ensure_command_policy(
    conn: sqlite3.Connection, command_policy_id: Optional[int]
) -> Optional[Dict]:
    if command_policy_id is None:
        return None
    row = conn.execute(
        "SELECT * FROM command_policies WHERE id = ?",
        (command_policy_id,),
    ).fetchone()
    if not row:
        raise ValidationError(f"Command policy {command_policy_id} not found")
    return _row_to_command_policy(row)


def _build_connection_instructions(
    host_row,
    credential_row,
    protocol: str,
) -> Dict:
    secret = credential_row["secret"] or ""
    preview = secret[-4:] if secret else None
    notes: List[str] = []
    hostname = host_row["hostname"]
    port = host_row["port"]
    username = credential_row["username"]
    command: Optional[str] = None
    if protocol == "ssh":
        command = f"ssh {username}@{hostname} -p {port}"
        notes.append("Verify host key fingerprint before accepting the SSH connection.")
    elif protocol == "sftp":
        command = f"sftp -P {port} {username}@{hostname}"
        notes.append("Use the bastion recording agent if file transfer sessions require capture.")
    elif protocol == "vnc":
        command = f"vncviewer {hostname}::{port}"
        notes.append("Establish an SSH tunnel or TLS if the VNC client supports it.")
    elif protocol == "rdp":
        command = f"xfreerdp /v:{hostname}:{port} /u:{username}"
        notes.append("Network Level Authentication (NLA) is required for this host.")
        if bool(host_row["tls_enabled"]):
            notes.append("Import the host certificate or enable /cert:tofu when testing.")
    instructions: Dict[str, Any] = {
        "protocol": protocol,
        "host": {
            "id": host_row["id"],
            "name": host_row["name"],
            "hostname": hostname,
            "port": port,
            "tls_enabled": bool(host_row["tls_enabled"]),
            "rdp_nla": bool(host_row["rdp_nla"]),
        },
        "credential_hint": {
            "name": credential_row["name"],
            "username": username,
            "secret_type": credential_row["secret_type"],
            "secret_preview": preview,
            "last_rotated_at": credential_row["last_rotated_at"],
            "rotation_frequency_days": credential_row["rotation_frequency_days"],
        },
        "command": command,
        "notes": notes,
    }
    return instructions


def _validate_access_window_payload(
    *,
    name: Optional[str] = None,
    allowed_start: Optional[str] = None,
    allowed_end: Optional[str] = None,
    days_of_week: Optional[List[str]] = None,
    timezone: Optional[str] = None,
    description: Optional[str] = None,
    allow_partial: bool = False,
) -> Dict:
    if not allow_partial:
        if not name or not isinstance(name, str):
            raise ValidationError("name is required")
        if allowed_start is None or allowed_end is None:
            raise ValidationError("allowed_start and allowed_end are required")
        if days_of_week is None:
            raise ValidationError("days_of_week is required")
    updates: Dict[str, Any] = {}
    if name is not None:
        if not isinstance(name, str) or not name.strip():
            raise ValidationError("name must be a non-empty string")
        if len(name.strip()) > 100:
            raise ValidationError("name cannot exceed 100 characters")
        updates["name"] = name.strip()
    parsed_start: Optional[time] = None
    parsed_end: Optional[time] = None
    if allowed_start is not None:
        parsed_start = _parse_time_of_day(allowed_start, "allowed_start")
        updates["allowed_start"] = parsed_start.strftime("%H:%M")
    if allowed_end is not None:
        parsed_end = _parse_time_of_day(allowed_end, "allowed_end")
        updates["allowed_end"] = parsed_end.strftime("%H:%M")
    if parsed_start and parsed_end and parsed_start >= parsed_end:
        raise ValidationError("allowed_end must be later than allowed_start")
    if days_of_week is not None:
        normalized_days = _normalize_days_of_week(days_of_week)
        updates["days_of_week"] = normalized_days
    if timezone is not None:
        updates["timezone"] = _ensure_timezone(timezone)
    if description is not None:
        if description and not isinstance(description, str):
            raise ValidationError("description must be a string if provided")
        updates["description"] = description.strip() if isinstance(description, str) else None
    return updates


def _enforce_access_window(conn: sqlite3.Connection, auth_row) -> None:
    access_window_id = auth_row["access_window_id"]
    if access_window_id is None:
        return
    window = _ensure_access_window(conn, access_window_id)
    now_utc = datetime.now(tz=timezone.utc)
    tz = ZoneInfo(window["timezone"])
    now_local = now_utc.astimezone(tz)
    weekday = now_local.strftime("%A").lower()
    if weekday not in window["days_of_week"]:
        raise ValidationError("Access is not permitted on the current weekday")
    allowed_start = _parse_time_of_day(window["allowed_start"], "allowed_start")
    allowed_end = _parse_time_of_day(window["allowed_end"], "allowed_end")
    current_time = now_local.time().replace(second=0, microsecond=0)
    if current_time < allowed_start or current_time >= allowed_end:
        raise ValidationError("Access is not permitted at the current time")


def _enforce_access_request(conn: sqlite3.Connection, authorization_id: int, user_id: int) -> None:
    row = conn.execute(
        """
        SELECT * FROM access_requests
        WHERE authorization_id = ?
          AND user_id = ?
          AND status = ?
        ORDER BY reviewed_at DESC, updated_at DESC
        LIMIT 1
        """,
        (authorization_id, user_id, ACCESS_REQUEST_STATUS_APPROVED),
    ).fetchone()
    if not row:
        raise ValidationError("Access requires an approved request")
    expires_at = row["expires_at"]
    if expires_at:
        expires_dt = _parse_datetime(expires_at, "expires_at")
        now = datetime.now(tz=timezone.utc)
        if expires_dt < now:
            raise ValidationError("Access approval has expired")


def _enforce_command_policy(
    conn: sqlite3.Connection,
    policy_id: Optional[int],
    commands: List[str],
) -> None:
    if not policy_id:
        return
    row = conn.execute(
        "SELECT * FROM command_policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    if not row:
        raise ValidationError(
            "Command policy referenced by the authorization is no longer available"
        )
    policy = _row_to_command_policy(row)
    allowed = policy["allowed_patterns"]
    denied = policy["denied_patterns"]
    if (allowed or denied) and not commands:
        raise ValidationError(
            "requested_commands must be provided when a command policy is enforced"
        )
    for command in commands:
        for pattern in denied:
            if fnmatch.fnmatchcase(command, pattern):
                raise ValidationError(
                    f"Command '{command}' violates denied pattern '{pattern}'"
                )
        if allowed and not any(fnmatch.fnmatchcase(command, pattern) for pattern in allowed):
            raise ValidationError(
                f"Command '{command}' is not permitted by the assigned policy"
            )


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


def create_access_window(
    *,
    name: str,
    allowed_start: str,
    allowed_end: str,
    days_of_week: List[str],
    timezone: str = "UTC",
    description: Optional[str] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    validated = _validate_access_window_payload(
        name=name,
        allowed_start=allowed_start,
        allowed_end=allowed_end,
        days_of_week=days_of_week,
        timezone=timezone,
        description=description,
    )
    if "timezone" not in validated:
        validated["timezone"] = _ensure_timezone("UTC")
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        try:
            cursor = conn.execute(
                """
                INSERT INTO access_windows (name, allowed_start, allowed_end, days_of_week, timezone, description)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    validated["name"],
                    validated["allowed_start"],
                    validated["allowed_end"],
                    json.dumps(validated["days_of_week"]),
                    validated.get("timezone", "UTC"),
                    validated.get("description"),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Access window name already exists") from exc
        window_id = cursor.lastrowid
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="access_window.created",
            target_type="access_window",
            target_id=window_id,
            metadata={
                "name": validated["name"],
                "allowed_start": validated["allowed_start"],
                "allowed_end": validated["allowed_end"],
                "days_of_week": validated["days_of_week"],
                "timezone": validated.get("timezone", "UTC"),
            },
        )
        conn.commit()
        row = conn.execute("SELECT * FROM access_windows WHERE id = ?", (window_id,)).fetchone()
        return _row_to_access_window(row)


def list_access_windows(
    *,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    with get_connection() as conn:
        query = "SELECT * FROM access_windows ORDER BY id ASC"
        params: List[Any] = []
        query, params = _apply_pagination(query, params, limit, offset)
        rows = conn.execute(query, tuple(params)).fetchall()
        return [_row_to_access_window(row) for row in rows]


def get_access_window(access_window_id: int) -> Dict:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM access_windows WHERE id = ?",
            (access_window_id,),
        ).fetchone()
        if not row:
            raise ValidationError(f"Access window {access_window_id} not found")
        return _row_to_access_window(row)


def update_access_window(
    access_window_id: int,
    *,
    name: Optional[str] = None,
    allowed_start: Optional[str] = None,
    allowed_end: Optional[str] = None,
    days_of_week: Optional[List[str]] = None,
    timezone: Optional[str] = None,
    description: Optional[str] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    validated = _validate_access_window_payload(
        name=name,
        allowed_start=allowed_start,
        allowed_end=allowed_end,
        days_of_week=days_of_week,
        timezone=timezone,
        description=description,
        allow_partial=True,
    )
    if not validated:
        raise ValidationError("No fields provided for update")
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        existing_row = conn.execute(
            "SELECT * FROM access_windows WHERE id = ?",
            (access_window_id,),
        ).fetchone()
        if not existing_row:
            raise ValidationError(f"Access window {access_window_id} not found")
        current = _row_to_access_window(existing_row)
        start_value = validated.get("allowed_start", current["allowed_start"])
        end_value = validated.get("allowed_end", current["allowed_end"])
        if start_value is not None and end_value is not None:
            start_time = _parse_time_of_day(start_value, "allowed_start")
            end_time = _parse_time_of_day(end_value, "allowed_end")
            if start_time >= end_time:
                raise ValidationError("allowed_end must be later than allowed_start")
        assignments: List[str] = []
        params: List[Any] = []
        metadata_changes: Dict[str, Any] = {}
        for field, value in validated.items():
            if field == "days_of_week":
                assignments.append("days_of_week = ?")
                params.append(json.dumps(value))
                metadata_changes[field] = value
            else:
                assignments.append(f"{field} = ?")
                params.append(value)
                metadata_changes[field] = value
        params.append(access_window_id)
        conn.execute(
            f"UPDATE access_windows SET {', '.join(assignments)} WHERE id = ?",
            tuple(params),
        )
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="access_window.updated",
            target_type="access_window",
            target_id=access_window_id,
            metadata=metadata_changes,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM access_windows WHERE id = ?", (access_window_id,)).fetchone()
        return _row_to_access_window(row)


def delete_access_window(
    access_window_id: int,
    *,
    performed_by: Optional[int] = None,
) -> None:
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        row = conn.execute(
            "SELECT * FROM access_windows WHERE id = ?",
            (access_window_id,),
        ).fetchone()
        if not row:
            raise ValidationError(f"Access window {access_window_id} not found")
        usage = conn.execute(
            "SELECT COUNT(*) AS cnt FROM authorizations WHERE access_window_id = ?",
            (access_window_id,),
        ).fetchone()
        if usage["cnt"]:
            raise ValidationError("Access window is still assigned to authorizations")
        conn.execute("DELETE FROM access_windows WHERE id = ?", (access_window_id,))
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="access_window.deleted",
            target_type="access_window",
            target_id=access_window_id,
            metadata=None,
        )
        conn.commit()


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
        return _row_to_host(row, groups=[])


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
        host_ids = [row["id"] for row in rows]
        groups_map = _map_host_groups(conn, host_ids)
        hosts = [
            _row_to_host(row, groups=groups_map.get(row["id"], [])) for row in rows
        ]
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
        groups_map = _map_host_groups(conn, [host_id])
        return _row_to_host(row, groups=groups_map.get(host_id, []))


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
        groups_map = _map_host_groups(conn, [host_id])
        return _row_to_host(row, groups=groups_map.get(host_id, []))


def create_host_group(
    *,
    name: str,
    description: Optional[str] = None,
    host_ids: Optional[List[int]] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    if not name or not isinstance(name, str):
        raise ValidationError("name is required")
    normalized_name = name.strip()
    if not normalized_name:
        raise ValidationError("name must not be empty")
    if len(normalized_name) > 120:
        raise ValidationError("name cannot exceed 120 characters")
    if description is not None and description != "" and not isinstance(description, str):
        raise ValidationError("description must be a string if provided")
    host_id_list = _normalize_host_ids(host_ids)
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        for host_id in host_id_list:
            exists = conn.execute(
                "SELECT id FROM hosts WHERE id = ?",
                (host_id,),
            ).fetchone()
            if not exists:
                raise ValidationError(f"Host {host_id} not found")
        try:
            cursor = conn.execute(
                "INSERT INTO host_groups (name, description) VALUES (?, ?)",
                (normalized_name, description.strip() if isinstance(description, str) else None),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Host group already exists") from exc
        group_id = cursor.lastrowid
        for host_id in host_id_list:
            conn.execute(
                "INSERT OR IGNORE INTO host_group_members (group_id, host_id) VALUES (?, ?)",
                (group_id, host_id),
            )
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="host_group.created",
            target_type="host_group",
            target_id=group_id,
            metadata={"name": normalized_name, "host_ids": host_id_list},
        )
        conn.commit()
        row = conn.execute("SELECT * FROM host_groups WHERE id = ?", (group_id,)).fetchone()
        host_ids_result = _get_group_host_ids(conn, group_id)
        return _row_to_host_group(row, host_ids=host_ids_result)


def list_host_groups(
    *,
    host_id: Optional[int] = None,
    search: Optional[str] = None,
    include_hosts: bool = False,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    with get_connection() as conn:
        clauses: List[str] = []
        params: List[Any] = []
        query = "SELECT DISTINCT hg.* FROM host_groups hg"
        if host_id is not None:
            query += " JOIN host_group_members hgm ON hg.id = hgm.group_id"
            clauses.append("hgm.host_id = ?")
            params.append(host_id)
        if search is not None:
            if not isinstance(search, str):
                raise ValidationError("search must be a string")
            like = f"%{search.lower()}%"
            clauses.append("(LOWER(hg.name) LIKE ? OR LOWER(COALESCE(hg.description, '')) LIKE ?)")
            params.extend([like, like])
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY hg.name ASC"
        query, params = _apply_pagination(query, params, limit, offset)
        rows = conn.execute(query, tuple(params)).fetchall()
        groups: List[Dict] = []
        for row in rows:
            host_ids_for_group = _get_group_host_ids(conn, row["id"])
            payload = _row_to_host_group(row, host_ids=host_ids_for_group)
            if include_hosts:
                payload["hosts"] = _fetch_hosts_for_group(conn, row["id"])
            groups.append(payload)
        return groups


def get_host_group(group_id: int, *, include_hosts: bool = False) -> Dict:
    with get_connection() as conn:
        row = _ensure_host_group(conn, group_id)
        host_ids = _get_group_host_ids(conn, group_id)
        payload = _row_to_host_group(row, host_ids=host_ids)
        if include_hosts:
            payload["hosts"] = _fetch_hosts_for_group(conn, group_id)
        return payload


def update_host_group(
    group_id: int,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    updates: List[str] = []
    params: List[Any] = []
    changes: Dict[str, Any] = {}
    if name is not None:
        if not isinstance(name, str) or not name.strip():
            raise ValidationError("name must be a non-empty string")
        if len(name.strip()) > 120:
            raise ValidationError("name cannot exceed 120 characters")
        updates.append("name = ?")
        params.append(name.strip())
        changes["name"] = name.strip()
    if description is not None:
        if description != "" and not isinstance(description, str):
            raise ValidationError("description must be a string if provided")
        cleaned = description.strip() if isinstance(description, str) else None
        updates.append("description = ?")
        params.append(cleaned)
        changes["description"] = cleaned
    if not updates:
        raise ValidationError("No fields provided for update")
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        _ensure_host_group(conn, group_id)
        try:
            conn.execute(
                f"UPDATE host_groups SET {', '.join(updates)} WHERE id = ?",
                (*params, group_id),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Host group already exists") from exc
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="host_group.updated",
            target_type="host_group",
            target_id=group_id,
            metadata=changes,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM host_groups WHERE id = ?", (group_id,)).fetchone()
        host_ids = _get_group_host_ids(conn, group_id)
        return _row_to_host_group(row, host_ids=host_ids)


def delete_host_group(group_id: int, *, performed_by: Optional[int] = None) -> None:
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        row = _ensure_host_group(conn, group_id)
        conn.execute("DELETE FROM host_groups WHERE id = ?", (group_id,))
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="host_group.deleted",
            target_type="host_group",
            target_id=group_id,
            metadata={"name": row["name"]},
        )
        conn.commit()


def add_host_to_group(
    *, group_id: int, host_id: int, performed_by: Optional[int] = None
) -> Dict:
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        group_row = _ensure_host_group(conn, group_id)
        host_row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not host_row:
            raise ValidationError(f"Host {host_id} not found")
        conn.execute(
            "INSERT OR IGNORE INTO host_group_members (group_id, host_id) VALUES (?, ?)",
            (group_id, host_id),
        )
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="host_group.host_added",
            target_type="host_group",
            target_id=group_id,
            metadata={"host_id": host_id},
        )
        conn.commit()
        host_ids = _get_group_host_ids(conn, group_id)
        payload = _row_to_host_group(group_row, host_ids=host_ids)
        payload["hosts"] = _fetch_hosts_for_group(conn, group_id)
        return payload


def remove_host_from_group(
    *, group_id: int, host_id: int, performed_by: Optional[int] = None
) -> Dict:
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        group_row = _ensure_host_group(conn, group_id)
        conn.execute(
            "DELETE FROM host_group_members WHERE group_id = ? AND host_id = ?",
            (group_id, host_id),
        )
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="host_group.host_removed",
            target_type="host_group",
            target_id=group_id,
            metadata={"host_id": host_id},
        )
        conn.commit()
        host_ids = _get_group_host_ids(conn, group_id)
        payload = _row_to_host_group(group_row, host_ids=host_ids)
        payload["hosts"] = _fetch_hosts_for_group(conn, group_id)
        return payload


def create_command_policy(
    *,
    name: str,
    description: Optional[str] = None,
    allowed_patterns: Optional[List[str]] = None,
    denied_patterns: Optional[List[str]] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    normalized_name = _require_non_empty_string(name, "name", max_length=120)
    normalized_description: Optional[str] = None
    if description is not None:
        if description != "" and not isinstance(description, str):
            raise ValidationError("description must be a string if provided")
        normalized_description = description.strip() if isinstance(description, str) else None
        if normalized_description == "":
            normalized_description = None
    allow_list = _normalize_command_patterns(allowed_patterns, "allowed_patterns")
    deny_list = _normalize_command_patterns(denied_patterns, "denied_patterns")
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        cursor = conn.cursor()
        now = datetime.now(tz=timezone.utc).isoformat()
        try:
            cursor.execute(
                """
                INSERT INTO command_policies (
                    name,
                    description,
                    allowed_patterns,
                    denied_patterns,
                    created_at,
                    updated_at,
                    created_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_name,
                    normalized_description,
                    json.dumps(allow_list),
                    json.dumps(deny_list),
                    now,
                    now,
                    actor_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Command policy name already exists") from exc
        policy_id = cursor.lastrowid
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="command_policy.created",
            target_type="command_policy",
            target_id=policy_id,
            metadata={
                "name": normalized_name,
                "allowed_patterns": allow_list,
                "denied_patterns": deny_list,
            },
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM command_policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        return _row_to_command_policy(row)


def list_command_policies(
    *,
    search: Optional[str] = None,
    created_by: Optional[int] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    clauses: List[str] = []
    params: List[Any] = []
    if search is not None:
        if not isinstance(search, str):
            raise ValidationError("search must be a string")
        cleaned = f"%{search.lower()}%"
        clauses.append(
            "(LOWER(name) LIKE ? OR LOWER(COALESCE(description, '')) LIKE ?)"
        )
        params.extend([cleaned, cleaned])
    if created_by is not None:
        clauses.append("created_by = ?")
        params.append(created_by)
    query = "SELECT * FROM command_policies"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY name ASC"
    query, params = _apply_pagination(query, params, limit, offset)
    with get_connection() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return [_row_to_command_policy(row) for row in rows]


def get_command_policy(policy_id: int) -> Dict:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM command_policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        if not row:
            raise ValidationError(f"Command policy {policy_id} not found")
        return _row_to_command_policy(row)


def update_command_policy(
    policy_id: int,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    allowed_patterns: Optional[List[str]] = None,
    denied_patterns: Optional[List[str]] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    updates: List[str] = []
    params: List[Any] = []
    metadata_changes: Dict[str, Any] = {}
    if name is not None:
        normalized_name = _require_non_empty_string(name, "name", max_length=120)
        updates.append("name = ?")
        params.append(normalized_name)
        metadata_changes["name"] = normalized_name
    if description is not None:
        if description != "" and not isinstance(description, str):
            raise ValidationError("description must be a string if provided")
        normalized_description = description.strip() if isinstance(description, str) else None
        if normalized_description == "":
            normalized_description = None
        updates.append("description = ?")
        params.append(normalized_description)
        metadata_changes["description"] = normalized_description
    if allowed_patterns is not None:
        allow_list = _normalize_command_patterns(allowed_patterns, "allowed_patterns")
        updates.append("allowed_patterns = ?")
        params.append(json.dumps(allow_list))
        metadata_changes["allowed_patterns"] = allow_list
    if denied_patterns is not None:
        deny_list = _normalize_command_patterns(denied_patterns, "denied_patterns")
        updates.append("denied_patterns = ?")
        params.append(json.dumps(deny_list))
        metadata_changes["denied_patterns"] = deny_list
    if not updates:
        raise ValidationError("No fields provided for update")
    updates.append("updated_at = ?")
    now = datetime.now(tz=timezone.utc).isoformat()
    params.append(now)
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        row = conn.execute(
            "SELECT * FROM command_policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        if not row:
            raise ValidationError(f"Command policy {policy_id} not found")
        try:
            conn.execute(
                f"UPDATE command_policies SET {', '.join(updates)} WHERE id = ?",
                (*params, policy_id),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Command policy name already exists") from exc
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="command_policy.updated",
            target_type="command_policy",
            target_id=policy_id,
            metadata=metadata_changes,
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM command_policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        return _row_to_command_policy(updated)


def delete_command_policy(policy_id: int, *, performed_by: Optional[int] = None) -> None:
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        row = conn.execute(
            "SELECT * FROM command_policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        if not row:
            raise ValidationError(f"Command policy {policy_id} not found")
        in_use = conn.execute(
            "SELECT COUNT(1) FROM authorizations WHERE command_policy_id = ?",
            (policy_id,),
        ).fetchone()[0]
        if in_use:
            raise ValidationError("Command policy is still assigned to authorizations")
        conn.execute("DELETE FROM command_policies WHERE id = ?", (policy_id,))
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="command_policy.deleted",
            target_type="command_policy",
            target_id=policy_id,
            metadata={"name": row["name"]},
        )
        conn.commit()


def create_credential(
    *,
    host_id: int,
    name: str,
    username: str,
    secret: str,
    secret_type: str,
    rotation_frequency_days: Optional[int] = None,
    last_rotated_at: Optional[str] = None,
    description: Optional[str] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    if not isinstance(host_id, int):
        raise ValidationError("host_id must be an integer")
    normalized_name = _require_non_empty_string(name, "name", max_length=120)
    normalized_username = _require_non_empty_string(username, "username", max_length=120)
    if not isinstance(secret, str) or not secret:
        raise ValidationError("secret must be a non-empty string")
    if len(secret) > 4096:
        raise ValidationError("secret cannot exceed 4096 characters")
    if secret_type not in SUPPORTED_CREDENTIAL_SECRET_TYPES:
        raise ValidationError("Unsupported credential secret_type")
    rotation_frequency = _validate_rotation_frequency(rotation_frequency_days)
    normalized_description: Optional[str] = None
    if description is not None:
        if description != "" and not isinstance(description, str):
            raise ValidationError("description must be a string if provided")
        normalized_description = description.strip() if isinstance(description, str) else None
        if normalized_description == "":
            normalized_description = None
    created_at = datetime.now(tz=timezone.utc).isoformat()
    last_rotated_iso: str
    if last_rotated_at is not None:
        last_rotated_iso = _parse_datetime(last_rotated_at, "last_rotated_at").isoformat()
    else:
        last_rotated_iso = created_at
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        _ensure_host(conn, host_id)
        try:
            cursor = conn.execute(
                """
                INSERT INTO credentials (
                    host_id,
                    name,
                    username,
                    secret,
                    secret_type,
                    rotation_frequency_days,
                    last_rotated_at,
                    description,
                    is_active,
                    created_at,
                    updated_at,
                    created_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    host_id,
                    normalized_name,
                    normalized_username,
                    secret,
                    secret_type,
                    rotation_frequency,
                    last_rotated_iso,
                    normalized_description,
                    created_at,
                    created_at,
                    actor_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Credential name already exists for host") from exc
        credential_id = cursor.lastrowid
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="credential.created",
            target_type="credential",
            target_id=credential_id,
            metadata={
                "host_id": host_id,
                "name": normalized_name,
                "username": normalized_username,
                "secret_type": secret_type,
                "rotation_frequency_days": rotation_frequency,
                "last_rotated_at": last_rotated_iso,
            },
        )
        conn.commit()
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        return _row_to_credential(row)


def list_credentials(
    *,
    host_id: Optional[int] = None,
    is_active: Optional[bool] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    clauses: List[str] = []
    params: List[Any] = []
    if host_id is not None:
        if not isinstance(host_id, int):
            raise ValidationError("host_id must be an integer")
        clauses.append("host_id = ?")
        params.append(host_id)
    if is_active is not None:
        if not isinstance(is_active, bool):
            raise ValidationError("is_active must be a boolean")
        clauses.append("is_active = ?")
        params.append(int(is_active))
    query = "SELECT * FROM credentials"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id ASC"
    query, params = _apply_pagination(query, params, limit, offset)
    with get_connection() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return [_row_to_credential(row) for row in rows]


def get_credential(credential_id: int) -> Dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        if not row:
            raise ValidationError(f"Credential {credential_id} not found")
        return _row_to_credential(row)


def update_credential(
    credential_id: int,
    *,
    name: Optional[str] = None,
    username: Optional[str] = None,
    secret: Optional[str] = None,
    secret_type: Optional[str] = None,
    rotation_frequency_days: Optional[int] = None,
    update_rotation_frequency: bool = False,
    last_rotated_at: Optional[str] = None,
    description: Optional[str] = None,
    is_active: Optional[bool] = None,
    performed_by: Optional[int] = None,
) -> Dict:
    updates: List[str] = []
    params: List[Any] = []
    changes: Dict[str, Any] = {}
    normalized_name: Optional[str] = None
    normalized_username: Optional[str] = None
    normalized_description: Optional[str] = None
    if name is not None:
        normalized_name = _require_non_empty_string(name, "name", max_length=120)
    if username is not None:
        normalized_username = _require_non_empty_string(username, "username", max_length=120)
    if secret is not None:
        if not isinstance(secret, str) or not secret:
            raise ValidationError("secret must be a non-empty string")
        if len(secret) > 4096:
            raise ValidationError("secret cannot exceed 4096 characters")
    if secret_type is not None and secret_type not in SUPPORTED_CREDENTIAL_SECRET_TYPES:
        raise ValidationError("Unsupported credential secret_type")
    if description is not None:
        if description != "" and not isinstance(description, str):
            raise ValidationError("description must be a string if provided")
        normalized_description = description.strip() if isinstance(description, str) else None
        if normalized_description == "":
            normalized_description = None
    rotation_frequency: Optional[int] = None
    if update_rotation_frequency:
        rotation_frequency = _validate_rotation_frequency(rotation_frequency_days)
    last_rotated_iso: Optional[str] = None
    if last_rotated_at is not None:
        last_rotated_iso = _parse_datetime(last_rotated_at, "last_rotated_at").isoformat()
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        if not row:
            raise ValidationError(f"Credential {credential_id} not found")
        if normalized_name is not None:
            updates.append("name = ?")
            params.append(normalized_name)
            changes["name"] = normalized_name
        if normalized_username is not None:
            updates.append("username = ?")
            params.append(normalized_username)
            changes["username"] = normalized_username
        if secret_type is not None:
            updates.append("secret_type = ?")
            params.append(secret_type)
            changes["secret_type"] = secret_type
        secret_rotated = False
        if secret is not None:
            updates.append("secret = ?")
            params.append(secret)
            secret_rotated = True
        if update_rotation_frequency:
            updates.append("rotation_frequency_days = ?")
            params.append(rotation_frequency)
            changes["rotation_frequency_days"] = rotation_frequency
        if normalized_description is not None or description == "":
            updates.append("description = ?")
            params.append(normalized_description)
            changes["description"] = normalized_description
        if is_active is not None:
            if not isinstance(is_active, bool):
                raise ValidationError("is_active must be a boolean")
            updates.append("is_active = ?")
            params.append(int(is_active))
            changes["is_active"] = bool(is_active)
        if secret_rotated and last_rotated_iso is None:
            last_rotated_iso = datetime.now(tz=timezone.utc).isoformat()
        if last_rotated_iso is not None:
            updates.append("last_rotated_at = ?")
            params.append(last_rotated_iso)
            changes["last_rotated_at"] = last_rotated_iso
        if not updates:
            raise ValidationError("No fields provided for update")
        updates.append("updated_at = ?")
        updated_at = datetime.now(tz=timezone.utc).isoformat()
        params.append(updated_at)
        try:
            conn.execute(
                f"UPDATE credentials SET {', '.join(updates)} WHERE id = ?",
                (*params, credential_id),
            )
        except sqlite3.IntegrityError as exc:
            raise ValidationError("Credential name already exists for host") from exc
        audit_metadata = dict(changes)
        if secret_rotated:
            audit_metadata["secret_rotated"] = True
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="credential.updated",
            target_type="credential",
            target_id=credential_id,
            metadata=audit_metadata,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        return _row_to_credential(row)


def authorize_user(
    user_id: int,
    host_id: int,
    privileges: str,
    *,
    access_window_id: Optional[int] = None,
    requires_approval: bool = False,
    source_cidrs: Optional[List[str]] = None,
    command_policy_id=UNSET,
    performed_by: Optional[int] = None,
) -> None:
    if not privileges:
        raise ValidationError("privileges must be provided")
    _validate_privileges(privileges)
    normalized_cidrs = _normalize_source_cidrs(source_cidrs)
    cidr_payload = json.dumps(normalized_cidrs)
    policy_id: Optional[int] = None
    policy_provided = command_policy_id is not UNSET
    if policy_provided and command_policy_id is not None:
        try:
            policy_id = int(command_policy_id)
        except (TypeError, ValueError) as exc:
            raise ValidationError("command_policy_id must be an integer") from exc
    with get_connection() as conn:
        actor_id = _ensure_actor(conn, performed_by)
        user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        host = conn.execute("SELECT id FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not user:
            raise ValidationError(f"User {user_id} not found")
        if not host:
            raise ValidationError(f"Host {host_id} not found")
        window_id: Optional[int] = None
        if access_window_id is not None:
            try:
                window_id = int(access_window_id)
            except (TypeError, ValueError) as exc:
                raise ValidationError("access_window_id must be an integer") from exc
            _ensure_access_window(conn, window_id)
        existing = conn.execute(
            "SELECT * FROM authorizations WHERE user_id = ? AND host_id = ?",
            (user_id, host_id),
        ).fetchone()
        if not policy_provided and existing:
            policy_id = existing["command_policy_id"]
        if policy_id is not None:
            _ensure_command_policy(conn, policy_id)
        conn.execute(
            """
            INSERT INTO authorizations (
                user_id,
                host_id,
                privileges,
                access_window_id,
                requires_approval,
                source_cidrs,
                command_policy_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, host_id) DO UPDATE SET
                privileges = excluded.privileges,
                access_window_id = excluded.access_window_id,
                requires_approval = excluded.requires_approval,
                source_cidrs = excluded.source_cidrs,
                command_policy_id = excluded.command_policy_id
            """,
            (
                user_id,
                host_id,
                privileges,
                window_id,
                int(bool(requires_approval)),
                cidr_payload,
                policy_id,
            ),
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
            metadata={
                "privileges": privileges,
                "access_window_id": row["access_window_id"],
                "requires_approval": bool(row["requires_approval"]),
                "source_cidrs": normalized_cidrs,
                "command_policy_id": row["command_policy_id"],
            },
        )
        conn.commit()


def list_authorizations(
    *,
    user_id: Optional[int] = None,
    host_id: Optional[int] = None,
    access_window_id: Optional[int] = None,
    requires_approval: Optional[bool] = None,
    command_policy_id: Optional[int] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    with get_connection() as conn:
        clauses: List[str] = []
        params: List[Any] = []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if host_id is not None:
            clauses.append("host_id = ?")
            params.append(host_id)
        if access_window_id is not None:
            clauses.append("access_window_id = ?")
            params.append(access_window_id)
        if requires_approval is not None:
            clauses.append("requires_approval = ?")
            params.append(int(bool(requires_approval)))
        if command_policy_id is not None:
            clauses.append("command_policy_id = ?")
            params.append(command_policy_id)
        query = "SELECT * FROM authorizations"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id ASC"
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
            metadata={
                "user_id": row["user_id"],
                "host_id": row["host_id"],
                "access_window_id": row["access_window_id"],
                "source_cidrs": _json_loads(row["source_cidrs"]) or [],
            },
        )
        conn.commit()


def create_access_request(
    authorization_id: int,
    *,
    requested_by: int,
    reason: Optional[str] = None,
) -> Dict:
    if requested_by is None:
        raise ValidationError("requested_by is required")
    with get_connection() as conn:
        auth = _ensure_authorization(conn, authorization_id)
        requester_id = _ensure_actor(conn, requested_by)
        requester_row = _ensure_user_row(conn, requester_id)
        if not bool(requester_row["is_active"]):
            raise ValidationError("requester must be an active user")
        subject_user_id = auth["user_id"]
        if requester_id != subject_user_id:
            roles = _json_loads(requester_row["roles"]) or []
            if ROLE_ADMIN not in roles and ROLE_AUDITOR not in roles:
                raise ValidationError(
                    "Only admins or auditors may request access on behalf of another user"
                )
        if reason is not None:
            if not isinstance(reason, str):
                raise ValidationError("reason must be a string if provided")
            reason = reason.strip()
            if len(reason) > 500:
                raise ValidationError("reason must be 500 characters or fewer")
            if not reason:
                reason = None
        existing = conn.execute(
            """
            SELECT id FROM access_requests
            WHERE authorization_id = ? AND user_id = ? AND status = ?
            """,
            (authorization_id, subject_user_id, ACCESS_REQUEST_STATUS_PENDING),
        ).fetchone()
        if existing:
            raise ValidationError("An access request is already pending for this authorization")
        now = datetime.now(tz=timezone.utc).isoformat()
        cursor = conn.execute(
            """
            INSERT INTO access_requests (
                authorization_id,
                user_id,
                host_id,
                status,
                reason,
                requested_by,
                reviewer_id,
                reviewer_note,
                reviewed_at,
                expires_at,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
            """,
            (
                authorization_id,
                subject_user_id,
                auth["host_id"],
                ACCESS_REQUEST_STATUS_PENDING,
                reason,
                requester_id,
                now,
                now,
            ),
        )
        request_id = cursor.lastrowid
        _record_audit_event(
            conn,
            actor_id=requester_id,
            action="access_request.created",
            target_type="access_request",
            target_id=request_id,
            metadata={
                "authorization_id": authorization_id,
                "user_id": subject_user_id,
                "host_id": auth["host_id"],
            },
        )
        conn.commit()
        row = conn.execute("SELECT * FROM access_requests WHERE id = ?", (request_id,)).fetchone()
        return _row_to_access_request(row)


def list_access_requests(
    *,
    authorization_id: Optional[int] = None,
    user_id: Optional[int] = None,
    host_id: Optional[int] = None,
    status: Optional[str] = None,
    requested_by: Optional[int] = None,
    reviewer_id: Optional[int] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    with get_connection() as conn:
        clauses = []
        params: List[Any] = []
        if authorization_id is not None:
            clauses.append("authorization_id = ?")
            params.append(authorization_id)
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if host_id is not None:
            clauses.append("host_id = ?")
            params.append(host_id)
        if status is not None:
            if status not in ACCESS_REQUEST_STATUSES:
                raise ValidationError("Unsupported access request status")
            clauses.append("status = ?")
            params.append(status)
        if requested_by is not None:
            clauses.append("requested_by = ?")
            params.append(requested_by)
        if reviewer_id is not None:
            clauses.append("reviewer_id = ?")
            params.append(reviewer_id)
        base = "SELECT * FROM access_requests"
        if clauses:
            base += " WHERE " + " AND ".join(clauses)
        base += " ORDER BY created_at DESC"
        base, params = _apply_pagination(base, params, limit, offset)
        rows = conn.execute(base, tuple(params)).fetchall()
        return [_row_to_access_request(row) for row in rows]


def approve_access_request(
    request_id: int,
    *,
    reviewer_id: int,
    expires_at: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict:
    with get_connection() as conn:
        request = conn.execute(
            "SELECT * FROM access_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        if not request:
            raise ValidationError(f"Access request {request_id} not found")
        if request["status"] != ACCESS_REQUEST_STATUS_PENDING:
            raise ValidationError("Only pending requests can be approved")
        reviewer = _ensure_reviewer(conn, reviewer_id)
        expires_iso: Optional[str] = None
        if expires_at is not None:
            parsed = _parse_datetime(expires_at, "expires_at")
            if parsed <= datetime.now(tz=timezone.utc):
                raise ValidationError("expires_at must be in the future")
            expires_iso = parsed.isoformat()
        reviewer_note: Optional[str] = None
        if note is not None:
            if not isinstance(note, str):
                raise ValidationError("note must be a string if provided")
            cleaned = note.strip()
            if len(cleaned) > 500:
                raise ValidationError("note must be 500 characters or fewer")
            reviewer_note = cleaned or None
        now = datetime.now(tz=timezone.utc).isoformat()
        conn.execute(
            """
            UPDATE access_requests
            SET status = ?,
                reviewer_id = ?,
                reviewer_note = ?,
                reviewed_at = ?,
                expires_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                ACCESS_REQUEST_STATUS_APPROVED,
                reviewer,
                reviewer_note,
                now,
                expires_iso,
                now,
                request_id,
            ),
        )
        _record_audit_event(
            conn,
            actor_id=reviewer,
            action="access_request.approved",
            target_type="access_request",
            target_id=request_id,
            metadata={
                "expires_at": expires_iso,
                "note": reviewer_note,
            },
        )
        conn.commit()
        row = conn.execute("SELECT * FROM access_requests WHERE id = ?", (request_id,)).fetchone()
        return _row_to_access_request(row)


def deny_access_request(
    request_id: int,
    *,
    reviewer_id: int,
    note: Optional[str] = None,
) -> Dict:
    with get_connection() as conn:
        request = conn.execute(
            "SELECT * FROM access_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        if not request:
            raise ValidationError(f"Access request {request_id} not found")
        if request["status"] != ACCESS_REQUEST_STATUS_PENDING:
            raise ValidationError("Only pending requests can be denied")
        reviewer = _ensure_reviewer(conn, reviewer_id)
        reviewer_note: Optional[str] = None
        if note is not None:
            if not isinstance(note, str):
                raise ValidationError("note must be a string if provided")
            cleaned = note.strip()
            if len(cleaned) > 500:
                raise ValidationError("note must be 500 characters or fewer")
            reviewer_note = cleaned or None
        now = datetime.now(tz=timezone.utc).isoformat()
        conn.execute(
            """
            UPDATE access_requests
            SET status = ?,
                reviewer_id = ?,
                reviewer_note = ?,
                reviewed_at = ?,
                expires_at = NULL,
                updated_at = ?
            WHERE id = ?
            """,
            (
                ACCESS_REQUEST_STATUS_DENIED,
                reviewer,
                reviewer_note,
                now,
                now,
                request_id,
            ),
        )
        _record_audit_event(
            conn,
            actor_id=reviewer,
            action="access_request.denied",
            target_type="access_request",
            target_id=request_id,
            metadata={"note": reviewer_note},
        )
        conn.commit()
        row = conn.execute("SELECT * FROM access_requests WHERE id = ?", (request_id,)).fetchone()
        return _row_to_access_request(row)


def revoke_access_request(
    request_id: int,
    *,
    reviewer_id: int,
    note: Optional[str] = None,
) -> Dict:
    with get_connection() as conn:
        request = conn.execute(
            "SELECT * FROM access_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        if not request:
            raise ValidationError(f"Access request {request_id} not found")
        if request["status"] != ACCESS_REQUEST_STATUS_APPROVED:
            raise ValidationError("Only approved requests can be revoked")
        reviewer = _ensure_reviewer(conn, reviewer_id)
        reviewer_note: Optional[str] = None
        if note is not None:
            if not isinstance(note, str):
                raise ValidationError("note must be a string if provided")
            cleaned = note.strip()
            if len(cleaned) > 500:
                raise ValidationError("note must be 500 characters or fewer")
            reviewer_note = cleaned or None
        now = datetime.now(tz=timezone.utc).isoformat()
        conn.execute(
            """
            UPDATE access_requests
            SET status = ?,
                reviewer_id = ?,
                reviewer_note = ?,
                reviewed_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                ACCESS_REQUEST_STATUS_REVOKED,
                reviewer,
                reviewer_note,
                now,
                now,
                request_id,
            ),
        )
        _record_audit_event(
            conn,
            actor_id=reviewer,
            action="access_request.revoked",
            target_type="access_request",
            target_id=request_id,
            metadata={"note": reviewer_note},
        )
        conn.commit()
        row = conn.execute("SELECT * FROM access_requests WHERE id = ?", (request_id,)).fetchone()
        return _row_to_access_request(row)


def start_session(
    *,
    user_id: int,
    host_id: int,
    protocol: str,
    source_ip: str,
    requested_commands: Optional[List[str]] = None,
) -> Dict:
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValidationError(f"Unsupported protocol '{protocol}'")
    if not source_ip:
        raise ValidationError("source_ip is required")
    try:
        client_ip = ipaddress.ip_address(str(source_ip).strip())
    except ValueError as exc:
        raise ValidationError("source_ip must be a valid IPv4 or IPv6 address") from exc
    normalized_commands = _normalize_requested_commands(requested_commands)
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
        command_policy_id: Optional[int] = None
        if ROLE_ADMIN not in roles:
            auth = conn.execute(
                "SELECT * FROM authorizations WHERE user_id = ? AND host_id = ?",
                (user_id, host_id),
            ).fetchone()
            if not auth:
                raise ValidationError("User does not have access to the requested host")
            _enforce_access_window(conn, auth)
            if bool(auth["requires_approval"]):
                _enforce_access_request(conn, auth["id"], user_id)
            allowed_cidrs = _json_loads(auth["source_cidrs"]) or []
            if allowed_cidrs:
                allowed = False
                for cidr in allowed_cidrs:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        continue
                    if client_ip in network:
                        allowed = True
                        break
                if not allowed:
                    raise ValidationError(
                        "source_ip is not permitted by the authorization's source_cidrs"
                    )
            command_policy_id = auth["command_policy_id"]
            _enforce_command_policy(conn, command_policy_id, normalized_commands)
        started_at = datetime.now(tz=timezone.utc).isoformat()
        session_metadata: Dict[str, Any] = {}
        if normalized_commands:
            session_metadata["requested_commands"] = normalized_commands
        if command_policy_id is not None:
            session_metadata["command_policy_id"] = command_policy_id
        metadata_json = json.dumps(session_metadata) if session_metadata else None
        cursor = conn.execute(
            """
            INSERT INTO sessions (user_id, host_id, protocol, started_at, metadata)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, host_id, protocol, started_at, metadata_json),
        )
        session_id = cursor.lastrowid
        audit_metadata: Dict[str, Any] = {
            "host_id": host_id,
            "protocol": protocol,
            "source_ip": str(client_ip),
        }
        if normalized_commands:
            audit_metadata["requested_commands"] = normalized_commands
        if command_policy_id is not None:
            audit_metadata["command_policy_id"] = command_policy_id
        _record_audit_event(
            conn,
            actor_id=user_id,
            action="session.started",
            target_type="session",
            target_id=session_id,
            metadata=audit_metadata,
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


def create_session_connection(
    session_id: int,
    *,
    initiated_by: int,
    credential_id: int,
    protocol: Optional[str] = None,
) -> Dict:
    with get_connection() as conn:
        session_row = _ensure_session(conn, session_id)
        if session_row["ended_at"] is not None:
            raise ValidationError("Cannot initiate connections for a session that has ended")
        actor_id = _ensure_active_actor(conn, initiated_by, field="initiated_by")
        actor_row = _ensure_user_row(conn, actor_id)
        actor_roles = _json_loads(actor_row["roles"]) or []
        if (
            actor_id != session_row["user_id"]
            and ROLE_ADMIN not in actor_roles
            and ROLE_OPERATOR not in actor_roles
        ):
            raise ValidationError(
                "initiated_by must be the session owner or have admin/operator role"
            )
        chosen_protocol = protocol or session_row["protocol"]
        if chosen_protocol not in SUPPORTED_PROTOCOLS:
            raise ValidationError("Unsupported protocol for connection attempt")
        if chosen_protocol != session_row["protocol"]:
            raise ValidationError("protocol must match the session's protocol")
        credential_row = _ensure_credential_row(conn, credential_id)
        if credential_row["host_id"] != session_row["host_id"]:
            raise ValidationError("credential must belong to the session's host")
        if not bool(credential_row["is_active"]):
            raise ValidationError("credential must be active")
        host_row = _ensure_host(conn, session_row["host_id"])
        instructions = _build_connection_instructions(host_row, credential_row, chosen_protocol)
        now = datetime.now(tz=timezone.utc).isoformat()
        cursor = conn.execute(
            """
            INSERT INTO session_connections (
                session_id,
                initiated_by,
                credential_id,
                protocol,
                status,
                instructions,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                actor_id,
                credential_id,
                chosen_protocol,
                SESSION_CONNECTION_STATUS_PENDING,
                json.dumps(instructions),
                now,
            ),
        )
        attempt_id = cursor.lastrowid
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action="session_connection.requested",
            target_type="session_connection",
            target_id=attempt_id,
            metadata={
                "session_id": session_id,
                "protocol": chosen_protocol,
                "credential_id": credential_id,
            },
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM session_connections WHERE id = ?",
            (attempt_id,),
        ).fetchone()
        return _row_to_connection_attempt(row)


def list_session_connections(
    session_id: int,
    *,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[Dict]:
    _validate_pagination(limit, offset)
    with get_connection() as conn:
        _ensure_session(conn, session_id)
        query = "SELECT * FROM session_connections WHERE session_id = ? ORDER BY id ASC"
        params: List[Any] = [session_id]
        query, params = _apply_pagination(query, params, limit, offset)
        rows = conn.execute(query, tuple(params)).fetchall()
        return [_row_to_connection_attempt(row) for row in rows]


def update_session_connection(
    attempt_id: int,
    *,
    status: str,
    performed_by: int,
    failure_reason: Optional[str] = None,
) -> Dict:
    if status not in SESSION_CONNECTION_STATUSES:
        raise ValidationError("Unsupported status for session connection")
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM session_connections WHERE id = ?",
            (attempt_id,),
        ).fetchone()
        if not row:
            raise ValidationError(f"Session connection {attempt_id} not found")
        if row["status"] == status:
            return _row_to_connection_attempt(row)
        if row["status"] != SESSION_CONNECTION_STATUS_PENDING:
            raise ValidationError("Only pending connection attempts can be updated")
        actor_id = _ensure_active_actor(conn, performed_by, field="performed_by")
        actor_row = _ensure_user_row(conn, actor_id)
        actor_roles = _json_loads(actor_row["roles"]) or []
        if (
            actor_id != row["initiated_by"]
            and ROLE_ADMIN not in actor_roles
            and ROLE_OPERATOR not in actor_roles
        ):
            raise ValidationError(
                "performed_by must be the initiator or have admin/operator role"
            )
        update_fields = ["status = ?", "completed_at = ?"]
        params: List[Any] = []
        now = datetime.now(tz=timezone.utc).isoformat()
        params.append(status)
        params.append(now)
        reason_value: Optional[str] = None
        if status == SESSION_CONNECTION_STATUS_FAILED:
            if failure_reason is None:
                raise ValidationError("failure_reason is required when marking as failed")
            if not isinstance(failure_reason, str):
                raise ValidationError("failure_reason must be a string")
            cleaned = failure_reason.strip()
            if not cleaned:
                raise ValidationError("failure_reason cannot be empty")
            if len(cleaned) > 500:
                raise ValidationError("failure_reason cannot exceed 500 characters")
            reason_value = cleaned
        elif failure_reason is not None:
            raise ValidationError("failure_reason can only be provided for failed status")
        update_fields.append("failure_reason = ?")
        params.append(reason_value)
        params.append(attempt_id)
        conn.execute(
            f"UPDATE session_connections SET {', '.join(update_fields)} WHERE id = ?",
            tuple(params),
        )
        action = "session_connection.succeeded"
        metadata: Dict[str, Any] = {
            "session_id": row["session_id"],
            "protocol": row["protocol"],
        }
        if status == SESSION_CONNECTION_STATUS_FAILED:
            action = "session_connection.failed"
            metadata["failure_reason"] = reason_value
        _record_audit_event(
            conn,
            actor_id=actor_id,
            action=action,
            target_type="session_connection",
            target_id=attempt_id,
            metadata=metadata,
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM session_connections WHERE id = ?",
            (attempt_id,),
        ).fetchone()
        return _row_to_connection_attempt(updated)


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
