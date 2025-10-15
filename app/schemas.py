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
class Credential:
    id: int
    host_id: int
    name: str
    username: str
    secret_type: str
    secret_preview: Optional[str] = None
    rotation_frequency_days: Optional[int] = None
    last_rotated_at: datetime = field(default_factory=datetime.utcnow)
    description: Optional[str] = None
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[int] = None


@dataclass(slots=True)
class HostGroup:
    id: int
    name: str
    description: Optional[str] = None
    host_ids: List[int] = field(default_factory=list)


@dataclass(slots=True)
class Authorization:
    id: int
    user_id: int
    host_id: int
    privileges: str
    access_window_id: Optional[int] = None
    requires_approval: bool = False
    source_cidrs: List[str] = field(default_factory=list)


@dataclass(slots=True)
class AccessWindow:
    id: int
    name: str
    allowed_start: str
    allowed_end: str
    days_of_week: List[str]
    timezone: str
    description: Optional[str] = None


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


@dataclass(slots=True)
class AuditEvent:
    id: int
    actor_id: int
    action: str
    target_type: str
    target_id: Optional[int]
    created_at: datetime
    metadata: Optional[Dict] = None


@dataclass(slots=True)
class AccessRequest:
    id: int
    authorization_id: int
    user_id: int
    host_id: int
    status: str
    reason: Optional[str]
    requested_by: int
    reviewer_id: Optional[int]
    reviewer_note: Optional[str]
    reviewed_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
