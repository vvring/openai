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
                rdp_nla INTEGER NOT NULL DEFAULT 1
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
                UNIQUE(user_id, host_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
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
        conn.commit()


# Ensure tables exist when the module is imported by the application.
init_db()
