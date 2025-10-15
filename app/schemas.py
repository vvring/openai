"""Pydantic schemas for request and response models."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, validator

from .models import ROLE_ADMIN, ROLE_AUDITOR, ROLE_OPERATOR, SUPPORTED_PROTOCOLS


class RoleBase(BaseModel):
    name: str = Field(..., description="Unique role name")
    description: Optional[str] = Field(None, description="Human readable description")


class RoleCreate(RoleBase):
    pass


class RoleRead(RoleBase):
    id: int

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    is_active: bool = True


class UserCreate(UserBase):
    roles: List[str] = Field(default_factory=list)

    @validator("roles", each_item=True)
    def validate_role(cls, role: str) -> str:
        allowed = {ROLE_ADMIN, ROLE_AUDITOR, ROLE_OPERATOR}
        if role not in allowed:
            raise ValueError(f"Unsupported role '{role}'")
        return role


class UserRead(UserBase):
    id: int
    roles: List[RoleRead] = Field(default_factory=list)

    class Config:
        orm_mode = True


class HostBase(BaseModel):
    name: str
    hostname: str
    port: int
    operating_system: str
    protocols: List[str]
    tls_enabled: bool = True
    rdp_nla: bool = True

    @validator("protocols", each_item=True)
    def validate_protocol(cls, value: str) -> str:
        value = value.lower()
        if value not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"Unsupported protocol '{value}'")
        return value


class HostCreate(HostBase):
    pass


class HostRead(HostBase):
    id: int

    class Config:
        orm_mode = True


class AuthorizationRequest(BaseModel):
    user_id: int
    host_id: int
    privileges: str = Field("read", description="Authorization level for the host")


class SessionStartRequest(BaseModel):
    user_id: int
    host_id: int
    protocol: str

    @validator("protocol")
    def validate_protocol(cls, value: str) -> str:
        value = value.lower()
        if value not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"Unsupported protocol '{value}'")
        return value


class SessionEndRequest(BaseModel):
    recording_path: Optional[str] = None
    metadata: Optional[dict] = None


class SessionRead(BaseModel):
    id: int
    user_id: int
    host_id: int
    protocol: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    recording_path: Optional[str] = None
    metadata: Optional[dict] = None

    class Config:
        orm_mode = True
