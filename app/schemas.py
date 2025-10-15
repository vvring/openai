"""Lightweight data schema helpers used for documentation only."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass(slots=True)
class User:
    id: int
    username: str
    full_name: str
    email: str
    roles: List[str] = field(default_factory=list)
    is_active: bool = True


@dataclass(slots=True)
class Host:
    id: int
    name: str
    hostname: str
    port: int
    operating_system: str
    protocols: List[str]
    tls_enabled: bool = True
    rdp_nla: bool = True
    tags: List[str] = field(default_factory=list)
    environment: Optional[str] = None
    business_unit: Optional[str] = None


@dataclass(slots=True)
class Authorization:
    id: int
    user_id: int
    host_id: int
    privileges: str


@dataclass(slots=True)
class SessionRecord:
    id: int
    user_id: int
    host_id: int
    protocol: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    recording_path: Optional[str] = None
    metadata: Optional[Dict] = None
