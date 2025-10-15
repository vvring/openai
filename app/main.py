"""Bastion management API built on the lightweight FastAPI shim."""
from __future__ import annotations

from typing import Dict, List

from fastapi import FastAPI, HTTPException, status

from . import crud
from .crud import ValidationError

app = FastAPI(title="Bastion Management Service", version="0.2.0")


def _handle_validation_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return wrapper


def _parse_int(value, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Field '{field}' must be an integer") from exc


@app.post("/users", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_user(payload: Dict) -> Dict:
    return crud.create_user(
        username=payload.get("username"),
        full_name=payload.get("full_name"),
        email=payload.get("email"),
        roles=payload.get("roles", []),
    )


@app.get("/users")
def get_users() -> List[Dict]:
    return crud.list_users()


@app.post("/hosts", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_host(payload: Dict) -> Dict:
    return crud.create_host(
        name=payload.get("name"),
        hostname=payload.get("hostname"),
        port=_parse_int(payload.get("port"), "port"),
        operating_system=payload.get("operating_system"),
        protocols=payload.get("protocols", []),
        tls_enabled=bool(payload.get("tls_enabled", True)),
        rdp_nla=bool(payload.get("rdp_nla", True)),
    )


@app.get("/hosts")
def get_hosts() -> List[Dict]:
    return crud.list_hosts()


@app.post("/authorizations", status_code=status.HTTP_204_NO_CONTENT)
@_handle_validation_error
def assign_authorization(payload: Dict):
    user_id = _parse_int(payload.get("user_id"), "user_id")
    host_id = _parse_int(payload.get("host_id"), "host_id")
    crud.authorize_user(user_id, host_id, payload.get("privileges", "read"))
    return None


@app.post("/sessions", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def start_session(payload: Dict) -> Dict:
    return crud.start_session(
        user_id=_parse_int(payload.get("user_id"), "user_id"),
        host_id=_parse_int(payload.get("host_id"), "host_id"),
        protocol=payload.get("protocol"),
    )


@app.post("/sessions/{record_id}/end")
@_handle_validation_error
def end_session(record_id: str, payload: Dict) -> Dict:
    return crud.end_session(
        _parse_int(record_id, "record_id"),
        recording_path=payload.get("recording_path"),
        metadata=payload.get("metadata"),
    )


@app.get("/sessions")
def list_sessions() -> List[Dict]:
    return crud.list_sessions()
