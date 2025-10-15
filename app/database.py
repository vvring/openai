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
            CREATE TABLE IF NOT EXISTS authorizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                host_id INTEGER NOT NULL,
                privileges TEXT NOT NULL,
                access_window_id INTEGER,
                UNIQUE(user_id, host_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            )
            """
        )
        _ensure_authorization_columns(cursor)
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
