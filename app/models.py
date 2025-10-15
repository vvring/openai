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
