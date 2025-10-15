"""Domain constants used throughout the bastion prototype."""
from __future__ import annotations

ROLE_ADMIN = "admin"
ROLE_AUDITOR = "auditor"
ROLE_OPERATOR = "operator"

SUPPORTED_PROTOCOLS = {
    "ssh",
    "sftp",
    "vnc",
    "rdp",
}

SUPPORTED_PRIVILEGES = {
    "read",
    "read-write",
    "admin",
}

SUPPORTED_ENVIRONMENTS = {
    "production",
    "staging",
    "testing",
    "development",
}

SUPPORTED_CREDENTIAL_SECRET_TYPES = {
    "password",
    "ssh_key",
}

SESSION_CONNECTION_STATUS_PENDING = "pending"
SESSION_CONNECTION_STATUS_SUCCEEDED = "succeeded"
SESSION_CONNECTION_STATUS_FAILED = "failed"

SESSION_CONNECTION_STATUSES = {
    SESSION_CONNECTION_STATUS_PENDING,
    SESSION_CONNECTION_STATUS_SUCCEEDED,
    SESSION_CONNECTION_STATUS_FAILED,
}

ACCESS_REQUEST_STATUS_PENDING = "pending"
ACCESS_REQUEST_STATUS_APPROVED = "approved"
ACCESS_REQUEST_STATUS_DENIED = "denied"
ACCESS_REQUEST_STATUS_REVOKED = "revoked"

ACCESS_REQUEST_STATUSES = {
    ACCESS_REQUEST_STATUS_PENDING,
    ACCESS_REQUEST_STATUS_APPROVED,
    ACCESS_REQUEST_STATUS_DENIED,
    ACCESS_REQUEST_STATUS_REVOKED,
}
