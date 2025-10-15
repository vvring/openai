"""Database operations for bastion management service."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, List, Optional

from sqlalchemy import and_
from sqlalchemy.orm import Session

from . import models


def ensure_roles(session: Session, roles: Iterable[str]) -> List[models.Role]:
    resolved_roles: List[models.Role] = []
    for role_name in roles:
        role = (
            session.query(models.Role)
            .filter(models.Role.name == role_name)
            .one_or_none()
        )
        if not role:
            role = models.Role(name=role_name, description=f"Auto-created role {role_name}")
            session.add(role)
            session.flush()
        resolved_roles.append(role)
    return resolved_roles


def create_user(
    session: Session,
    *,
    username: str,
    full_name: str,
    email: str,
    roles: Iterable[str],
) -> models.User:
    user = models.User(
        username=username,
        full_name=full_name,
        email=email,
    )
    user.roles = ensure_roles(session, roles)
    session.add(user)
    session.flush()
    return user


def list_users(session: Session) -> List[models.User]:
    return session.query(models.User).all()


def create_host(
    session: Session,
    *,
    name: str,
    hostname: str,
    port: int,
    operating_system: str,
    protocols: List[str],
    tls_enabled: bool,
    rdp_nla: bool,
) -> models.Host:
    host = models.Host(
        name=name,
        hostname=hostname,
        port=port,
        operating_system=operating_system,
        protocols=list(sorted(set(protocols))),
        tls_enabled=tls_enabled,
        rdp_nla=rdp_nla,
    )
    session.add(host)
    session.flush()
    return host


def list_hosts(session: Session) -> List[models.Host]:
    return session.query(models.Host).all()


def authorize_user(session: Session, user_id: int, host_id: int, privileges: str) -> None:
    user = session.get(models.User, user_id)
    host = session.get(models.Host, host_id)
    if not user or not host:
        raise ValueError("User or host not found")
    session.execute(
        models.user_host_authorizations.delete().where(
            and_(
                models.user_host_authorizations.c.user_id == user_id,
                models.user_host_authorizations.c.host_id == host_id,
            )
        )
    )
    session.execute(
        models.user_host_authorizations.insert().values(
            user_id=user_id,
            host_id=host_id,
            privileges=privileges,
        )
    )


def start_session(
    session: Session,
    *,
    user_id: int,
    host_id: int,
    protocol: str,
) -> models.SessionRecord:
    record = models.SessionRecord(
        user_id=user_id,
        host_id=host_id,
        protocol=protocol,
        started_at=datetime.utcnow(),
    )
    session.add(record)
    session.flush()
    return record


def end_session(
    session: Session,
    record_id: int,
    *,
    recording_path: Optional[str],
    metadata: Optional[dict],
) -> models.SessionRecord:
    record = session.get(models.SessionRecord, record_id)
    if not record:
        raise ValueError("Session record not found")
    record.ended_at = datetime.utcnow()
    record.recording_path = recording_path
    if metadata is not None:
        record.metadata = metadata
    session.add(record)
    session.flush()
    return record


def list_sessions(session: Session) -> List[models.SessionRecord]:
    return (
        session.query(models.SessionRecord)
        .order_by(models.SessionRecord.started_at.desc())
        .all()
    )
