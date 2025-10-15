"""SQLite-backed storage helpers for the bastion prototype."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

_DB_URL = os.getenv("BASTION_DATABASE_URL", "sqlite:///bastion.db")
if not _DB_URL.startswith("sqlite:///"):
    raise ValueError("Only sqlite URLs are supported in the prototype")
_DB_PATH = Path(_DB_URL.replace("sqlite:///", "", 1))
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_host_columns(cursor: sqlite3.Cursor) -> None:
    cursor.execute("PRAGMA table_info(hosts)")
    existing = {row[1] for row in cursor.fetchall()}
    if "tags" not in existing:
        cursor.execute("ALTER TABLE hosts ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'")
    if "environment" not in existing:
        cursor.execute("ALTER TABLE hosts ADD COLUMN environment TEXT")
    if "business_unit" not in existing:
        cursor.execute("ALTER TABLE hosts ADD COLUMN business_unit TEXT")
    cursor.execute("UPDATE hosts SET tags = '[]' WHERE tags IS NULL")


def _ensure_authorization_columns(cursor: sqlite3.Cursor) -> None:
    cursor.execute("PRAGMA table_info(authorizations)")
    existing = {row[1] for row in cursor.fetchall()}
    if "access_window_id" not in existing:
        cursor.execute("ALTER TABLE authorizations ADD COLUMN access_window_id INTEGER")
    if "requires_approval" not in existing:
        cursor.execute(
            "ALTER TABLE authorizations ADD COLUMN requires_approval INTEGER NOT NULL DEFAULT 0"
        )
    if "source_cidrs" not in existing:
        cursor.execute(
            "ALTER TABLE authorizations ADD COLUMN source_cidrs TEXT NOT NULL DEFAULT '[]'"
        )
        cursor.execute("UPDATE authorizations SET source_cidrs = '[]' WHERE source_cidrs IS NULL")
    if "command_policy_id" not in existing:
        cursor.execute(
            "ALTER TABLE authorizations ADD COLUMN command_policy_id INTEGER"
        )


def _ensure_access_request_columns(cursor: sqlite3.Cursor) -> None:
    cursor.execute("PRAGMA table_info(access_requests)")
    existing = {row[1] for row in cursor.fetchall()}
    required_columns = {
        "authorization_id",
        "user_id",
        "host_id",
        "status",
        "reason",
        "requested_by",
        "reviewer_id",
        "reviewer_note",
        "reviewed_at",
        "expires_at",
        "created_at",
        "updated_at",
    }
    missing = required_columns - existing
    if missing and existing:
        raise RuntimeError(
            "Existing access_requests table is missing columns: " + ", ".join(sorted(missing))
        )


def init_db() -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                roles TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL,
                operating_system TEXT NOT NULL,
                protocols TEXT NOT NULL,
                tls_enabled INTEGER NOT NULL DEFAULT 1,
                rdp_nla INTEGER NOT NULL DEFAULT 1,
                tags TEXT NOT NULL DEFAULT '[]',
                environment TEXT,
                business_unit TEXT
            )
            """
        )
        _ensure_host_columns(cursor)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS protocol_gateways (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                protocol TEXT NOT NULL,
                endpoint_host TEXT NOT NULL,
                endpoint_port INTEGER NOT NULL,
                tls_enabled INTEGER NOT NULL DEFAULT 1,
                nla_required INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                description TEXT,
                last_health_status TEXT NOT NULL DEFAULT 'unknown',
                last_health_message TEXT,
                last_health_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_protocol_gateways_protocol ON protocol_gateways(protocol)"
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS host_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS host_group_members (
                group_id INTEGER NOT NULL,
                host_id INTEGER NOT NULL,
                PRIMARY KEY (group_id, host_id),
                FOREIGN KEY(group_id) REFERENCES host_groups(id) ON DELETE CASCADE,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS host_gateway_bindings (
                host_id INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                gateway_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                created_by INTEGER,
                PRIMARY KEY (host_id, protocol),
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                FOREIGN KEY(gateway_id) REFERENCES protocol_gateways(id) ON DELETE CASCADE,
                FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_host_gateway_bindings_gateway ON host_gateway_bindings(gateway_id)"
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS command_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                allowed_patterns TEXT NOT NULL DEFAULT '[]',
                denied_patterns TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by INTEGER,
                FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                secret TEXT NOT NULL,
                secret_type TEXT NOT NULL,
                rotation_frequency_days INTEGER,
                last_rotated_at TEXT,
                description TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by INTEGER,
                UNIQUE(host_id, name),
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_credentials_host ON credentials(host_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_credentials_active ON credentials(is_active)"
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS authorizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                host_id INTEGER NOT NULL,
                privileges TEXT NOT NULL,
                access_window_id INTEGER,
                requires_approval INTEGER NOT NULL DEFAULT 0,
                source_cidrs TEXT NOT NULL DEFAULT '[]',
                command_policy_id INTEGER,
                UNIQUE(user_id, host_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                FOREIGN KEY(command_policy_id) REFERENCES command_policies(id) ON DELETE SET NULL
            )
            """
        )
        _ensure_authorization_columns(cursor)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                authorization_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                host_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                requested_by INTEGER,
                reviewer_id INTEGER,
                reviewer_note TEXT,
                reviewed_at TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(authorization_id) REFERENCES authorizations(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                FOREIGN KEY(requested_by) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY(reviewer_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        _ensure_access_request_columns(cursor)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_access_requests_authorization ON access_requests(authorization_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status)"
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS access_windows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                allowed_start TEXT NOT NULL,
                allowed_end TEXT NOT NULL,
                days_of_week TEXT NOT NULL,
                timezone TEXT NOT NULL DEFAULT 'UTC',
                description TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                host_id INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                recording_path TEXT,
                metadata TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS recordings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                storage_path TEXT NOT NULL,
                size_bytes INTEGER,
                duration_seconds REAL,
                checksum TEXT,
                created_at TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_recordings_session_id ON recordings(session_id)"
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS session_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                initiated_by INTEGER NOT NULL,
                credential_id INTEGER,
                protocol TEXT NOT NULL,
                status TEXT NOT NULL,
                instructions TEXT,
                failure_reason TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                FOREIGN KEY(initiated_by) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE SET NULL
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_connections_session ON session_connections(session_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_connections_status ON session_connections(status)"
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER,
                metadata TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_target ON audit_events(target_type, target_id)"
        )
        conn.commit()


# Ensure tables exist when the module is imported by the application.
init_db()
