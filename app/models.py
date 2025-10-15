"""SQLAlchemy models for bastion system entities."""

from __future__ import annotations

from datetime import datetime
from typing import List

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


ROLE_ADMIN = "admin"
ROLE_AUDITOR = "auditor"
ROLE_OPERATOR = "operator"

SUPPORTED_PROTOCOLS = {
    "ssh",
    "sftp",
    "vnc",
    "rdp",
}

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id"), primary_key=True),
    Column("role_id", ForeignKey("roles.id"), primary_key=True),
)

user_host_authorizations = Table(
    "user_host_authorizations",
    Base.metadata,
    Column("user_id", ForeignKey("users.id"), primary_key=True),
    Column("host_id", ForeignKey("hosts.id"), primary_key=True),
    Column("privileges", String, nullable=False, default="read"),
)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    users: Mapped[List["User"]] = relationship(
        "User", secondary=user_roles, back_populates="roles"
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    roles: Mapped[List[Role]] = relationship(
        "Role", secondary=user_roles, back_populates="users"
    )
    authorizations: Mapped[List["Host"]] = relationship(
        "Host", secondary=user_host_authorizations, back_populates="authorized_users"
    )
    sessions: Mapped[List["SessionRecord"]] = relationship(
        "SessionRecord", back_populates="user", cascade="all, delete-orphan"
    )


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    operating_system: Mapped[str] = mapped_column(String(64), nullable=False)
    protocols: Mapped[List[str]] = mapped_column(JSON, nullable=False)
    tls_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    rdp_nla: Mapped[bool] = mapped_column(Boolean, default=True)

    authorized_users: Mapped[List[User]] = relationship(
        "User", secondary=user_host_authorizations, back_populates="authorizations"
    )
    sessions: Mapped[List["SessionRecord"]] = relationship(
        "SessionRecord", back_populates="host", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("hostname", "port", name="uq_host_endpoint"),
    )


class SessionRecord(Base):
    __tablename__ = "session_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    recording_path: Mapped[str | None] = mapped_column(String(512))
    metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    user: Mapped[User] = relationship("User", back_populates="sessions")
    host: Mapped[Host] = relationship("Host", back_populates="sessions")

    __table_args__ = (
        UniqueConstraint("user_id", "host_id", "started_at", name="uq_session_unique"),
    )
