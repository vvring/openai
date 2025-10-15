"""Bastion management API built on the lightweight FastAPI shim."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, status

from . import crud
from .crud import ValidationError

app = FastAPI(title="Bastion Management Service", version="0.13.0")


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


def _parse_bool(value, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    raise ValidationError(f"Field '{field}' must be a boolean")


def _parse_datetime(value: str, field: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Field '{field}' must be an ISO formatted datetime") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat()


def _parse_positive_int(value, field: str) -> int:
    parsed = _parse_int(value, field)
    if parsed <= 0:
        raise ValidationError(f"Field '{field}' must be greater than zero")
    return parsed


def _parse_non_negative_int(value, field: str) -> int:
    parsed = _parse_int(value, field)
    if parsed < 0:
        raise ValidationError(f"Field '{field}' must be greater than or equal to zero")
    return parsed


@app.post("/users", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_user(payload: Dict) -> Dict:
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.create_user(
        username=payload.get("username"),
        full_name=payload.get("full_name"),
        email=payload.get("email"),
        roles=payload.get("roles", []),
        performed_by=parsed_actor,
    )


@app.get("/users")
@_handle_validation_error
def get_users(limit: Optional[str] = None, offset: Optional[str] = None) -> List[Dict]:
    parsed_limit: Optional[int] = None
    parsed_offset: Optional[int] = None
    if limit is not None:
        parsed_limit = _parse_positive_int(limit, "limit")
    if offset is not None:
        parsed_offset = _parse_non_negative_int(offset, "offset")
    return crud.list_users(limit=parsed_limit, offset=parsed_offset)


@app.get("/users/{user_id}")
@_handle_validation_error
def get_user(user_id: str) -> Dict:
    return crud.get_user(_parse_int(user_id, "user_id"))


@app.patch("/users/{user_id}")
@_handle_validation_error
def update_user(user_id: str, payload: Dict) -> Dict:
    roles = payload.get("roles")
    if roles is not None and not isinstance(roles, list):
        raise ValidationError("roles must be provided as a list")
    is_active = payload.get("is_active")
    if is_active is not None and not isinstance(is_active, bool):
        raise ValidationError("is_active must be a boolean")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.update_user(
        _parse_int(user_id, "user_id"),
        full_name=payload.get("full_name"),
        email=payload.get("email"),
        roles=roles,
        is_active=is_active,
        performed_by=parsed_actor,
    )


@app.post("/hosts", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_host(payload: Dict) -> Dict:
    tags = payload.get("tags")
    if tags is not None and not isinstance(tags, list):
        raise ValidationError("tags must be provided as a list")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.create_host(
        name=payload.get("name"),
        hostname=payload.get("hostname"),
        port=_parse_int(payload.get("port"), "port"),
        operating_system=payload.get("operating_system"),
        protocols=payload.get("protocols", []),
        tls_enabled=bool(payload.get("tls_enabled", True)),
        rdp_nla=bool(payload.get("rdp_nla", True)),
        tags=tags,
        environment=payload.get("environment"),
        business_unit=payload.get("business_unit"),
        performed_by=parsed_actor,
    )


@app.get("/hosts")
@_handle_validation_error
def get_hosts(
    protocol: Optional[str] = None,
    environment: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    parsed_limit: Optional[int] = None
    parsed_offset: Optional[int] = None
    if limit is not None:
        parsed_limit = _parse_positive_int(limit, "limit")
    if offset is not None:
        parsed_offset = _parse_non_negative_int(offset, "offset")
    return crud.list_hosts(
        protocol=protocol,
        environment=environment,
        tag=tag,
        search=search,
        limit=parsed_limit,
        offset=parsed_offset,
    )


@app.get("/hosts/{host_id}")
@_handle_validation_error
def get_host(host_id: str) -> Dict:
    return crud.get_host(_parse_int(host_id, "host_id"))


@app.patch("/hosts/{host_id}")
@_handle_validation_error
def update_host(host_id: str, payload: Dict) -> Dict:
    protocols = payload.get("protocols")
    if protocols is not None and not isinstance(protocols, list):
        raise ValidationError("protocols must be provided as a list")
    tls_enabled = payload.get("tls_enabled")
    if tls_enabled is not None and not isinstance(tls_enabled, bool):
        raise ValidationError("tls_enabled must be a boolean")
    rdp_nla = payload.get("rdp_nla")
    if rdp_nla is not None and not isinstance(rdp_nla, bool):
        raise ValidationError("rdp_nla must be a boolean")
    port = payload.get("port")
    parsed_port: Optional[int] = None
    if port is not None:
        parsed_port = _parse_int(port, "port")
    tags = payload.get("tags")
    if tags is not None and not isinstance(tags, list):
        raise ValidationError("tags must be provided as a list")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.update_host(
        _parse_int(host_id, "host_id"),
        name=payload.get("name"),
        hostname=payload.get("hostname"),
        port=parsed_port,
        operating_system=payload.get("operating_system"),
        protocols=protocols,
        tls_enabled=tls_enabled,
        rdp_nla=rdp_nla,
        tags=tags,
        environment=payload.get("environment"),
        business_unit=payload.get("business_unit"),
        performed_by=parsed_actor,
    )


@app.post("/host-groups", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_host_group(payload: Dict) -> Dict:
    host_ids = payload.get("host_ids")
    if host_ids is not None and not isinstance(host_ids, list):
        raise ValidationError("host_ids must be provided as a list")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.create_host_group(
        name=payload.get("name"),
        description=payload.get("description"),
        host_ids=host_ids,
        performed_by=parsed_actor,
    )


@app.get("/host-groups")
@_handle_validation_error
def list_host_groups(
    host_id: Optional[str] = None,
    search: Optional[str] = None,
    include_hosts: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    parsed_host: Optional[int] = None
    parsed_limit: Optional[int] = None
    parsed_offset: Optional[int] = None
    include_details = False
    if host_id is not None:
        parsed_host = _parse_int(host_id, "host_id")
    if include_hosts is not None:
        include_details = _parse_bool(include_hosts, "include_hosts")
    if limit is not None:
        parsed_limit = _parse_positive_int(limit, "limit")
    if offset is not None:
        parsed_offset = _parse_non_negative_int(offset, "offset")
    return crud.list_host_groups(
        host_id=parsed_host,
        search=search,
        include_hosts=include_details,
        limit=parsed_limit,
        offset=parsed_offset,
    )


@app.get("/host-groups/{group_id}")
@_handle_validation_error
def get_host_group(group_id: str, include_hosts: Optional[str] = None) -> Dict:
    include_details = False
    if include_hosts is not None:
        include_details = _parse_bool(include_hosts, "include_hosts")
    return crud.get_host_group(
        _parse_int(group_id, "group_id"), include_hosts=include_details
    )


@app.patch("/host-groups/{group_id}")
@_handle_validation_error
def update_host_group(group_id: str, payload: Dict) -> Dict:
    if "host_ids" in payload:
        raise ValidationError("host_ids must be managed via membership endpoints")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.update_host_group(
        _parse_int(group_id, "group_id"),
        name=payload.get("name"),
        description=payload.get("description"),
        performed_by=parsed_actor,
    )


@app.delete("/host-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
@_handle_validation_error
def delete_host_group(group_id: str, performed_by: Optional[str] = None):
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    crud.delete_host_group(
        _parse_int(group_id, "group_id"), performed_by=parsed_actor
    )
    return None


@app.post("/host-groups/{group_id}/hosts")
@_handle_validation_error
def add_host_group_member(group_id: str, payload: Dict) -> Dict:
    host_id = payload.get("host_id")
    if host_id is None:
        raise ValidationError("host_id is required")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.add_host_to_group(
        group_id=_parse_int(group_id, "group_id"),
        host_id=_parse_int(host_id, "host_id"),
        performed_by=parsed_actor,
    )


@app.delete("/host-groups/{group_id}/hosts/{host_id}")
@_handle_validation_error
def remove_host_group_member(
    group_id: str, host_id: str, performed_by: Optional[str] = None
) -> Dict:
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.remove_host_from_group(
        group_id=_parse_int(group_id, "group_id"),
        host_id=_parse_int(host_id, "host_id"),
        performed_by=parsed_actor,
    )


@app.post("/command-policies", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_command_policy(payload: Dict) -> Dict:
    allowed = payload.get("allowed_patterns")
    if allowed is not None and not isinstance(allowed, list):
        raise ValidationError("allowed_patterns must be provided as a list")
    denied = payload.get("denied_patterns")
    if denied is not None and not isinstance(denied, list):
        raise ValidationError("denied_patterns must be provided as a list")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.create_command_policy(
        name=payload.get("name"),
        description=payload.get("description"),
        allowed_patterns=allowed,
        denied_patterns=denied,
        performed_by=parsed_actor,
    )


@app.get("/command-policies")
@_handle_validation_error
def list_command_policies(
    search: Optional[str] = None,
    created_by: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    parsed_created: Optional[int] = None
    parsed_limit: Optional[int] = None
    parsed_offset: Optional[int] = None
    if created_by is not None:
        parsed_created = _parse_int(created_by, "created_by")
    if limit is not None:
        parsed_limit = _parse_positive_int(limit, "limit")
    if offset is not None:
        parsed_offset = _parse_non_negative_int(offset, "offset")
    return crud.list_command_policies(
        search=search,
        created_by=parsed_created,
        limit=parsed_limit,
        offset=parsed_offset,
    )


@app.get("/command-policies/{policy_id}")
@_handle_validation_error
def get_command_policy(policy_id: str) -> Dict:
    return crud.get_command_policy(_parse_int(policy_id, "policy_id"))


@app.patch("/command-policies/{policy_id}")
@_handle_validation_error
def update_command_policy(policy_id: str, payload: Dict) -> Dict:
    allowed = payload.get("allowed_patterns") if "allowed_patterns" in payload else None
    if "allowed_patterns" in payload and allowed is not None and not isinstance(allowed, list):
        raise ValidationError("allowed_patterns must be provided as a list")
    denied = payload.get("denied_patterns") if "denied_patterns" in payload else None
    if "denied_patterns" in payload and denied is not None and not isinstance(denied, list):
        raise ValidationError("denied_patterns must be provided as a list")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    description = payload.get("description") if "description" in payload else None
    if "description" in payload and description is None:
        description = ""
    return crud.update_command_policy(
        _parse_int(policy_id, "policy_id"),
        name=payload.get("name"),
        description=description,
        allowed_patterns=allowed,
        denied_patterns=denied,
        performed_by=parsed_actor,
    )


@app.delete("/command-policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
@_handle_validation_error
def delete_command_policy(policy_id: str, performed_by: Optional[str] = None):
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    crud.delete_command_policy(
        _parse_int(policy_id, "policy_id"),
        performed_by=parsed_actor,
    )
    return None


@app.post("/credentials", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_credential(payload: Dict) -> Dict:
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    rotation_frequency = payload.get("rotation_frequency_days")
    parsed_rotation: Optional[int] = None
    if rotation_frequency is not None:
        parsed_rotation = _parse_positive_int(rotation_frequency, "rotation_frequency_days")
    host_id = _parse_int(payload.get("host_id"), "host_id")
    return crud.create_credential(
        host_id=host_id,
        name=payload.get("name"),
        username=payload.get("username"),
        secret=payload.get("secret"),
        secret_type=payload.get("secret_type"),
        rotation_frequency_days=parsed_rotation,
        last_rotated_at=payload.get("last_rotated_at"),
        description=payload.get("description"),
        performed_by=parsed_actor,
    )


@app.get("/credentials")
@_handle_validation_error
def list_credentials(
    host_id: Optional[str] = None,
    is_active: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    parsed_host_id: Optional[int] = None
    parsed_is_active: Optional[bool] = None
    if host_id is not None:
        parsed_host_id = _parse_int(host_id, "host_id")
    if is_active is not None:
        parsed_is_active = _parse_bool(is_active, "is_active")
    parsed_limit: Optional[int] = None
    parsed_offset: Optional[int] = None
    if limit is not None:
        parsed_limit = _parse_positive_int(limit, "limit")
    if offset is not None:
        parsed_offset = _parse_non_negative_int(offset, "offset")
    return crud.list_credentials(
        host_id=parsed_host_id,
        is_active=parsed_is_active,
        limit=parsed_limit,
        offset=parsed_offset,
    )


@app.get("/credentials/{credential_id}")
@_handle_validation_error
def get_credential(credential_id: str) -> Dict:
    return crud.get_credential(_parse_int(credential_id, "credential_id"))


@app.patch("/credentials/{credential_id}")
@_handle_validation_error
def update_credential(credential_id: str, payload: Dict) -> Dict:
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    rotation_frequency_present = "rotation_frequency_days" in payload
    rotation_frequency = payload.get("rotation_frequency_days")
    parsed_rotation: Optional[int] = None
    if rotation_frequency_present and rotation_frequency is not None:
        parsed_rotation = _parse_positive_int(rotation_frequency, "rotation_frequency_days")
    is_active_value = payload.get("is_active") if "is_active" in payload else None
    parsed_is_active: Optional[bool] = None
    if "is_active" in payload:
        parsed_is_active = _parse_bool(is_active_value, "is_active")
    description = payload.get("description") if "description" in payload else None
    if "description" in payload and description is None:
        description = ""
    secret_value = payload.get("secret") if "secret" in payload else None
    return crud.update_credential(
        _parse_int(credential_id, "credential_id"),
        name=payload.get("name"),
        username=payload.get("username"),
        secret=secret_value,
        secret_type=payload.get("secret_type"),
        rotation_frequency_days=parsed_rotation,
        update_rotation_frequency=rotation_frequency_present,
        last_rotated_at=payload.get("last_rotated_at"),
        description=description,
        is_active=parsed_is_active,
        performed_by=parsed_actor,
    )


@app.post("/access-windows", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_access_window(payload: Dict) -> Dict:
    days = payload.get("days_of_week")
    if days is None or not isinstance(days, list):
        raise ValidationError("days_of_week must be provided as a list")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.create_access_window(
        name=payload.get("name"),
        allowed_start=payload.get("allowed_start"),
        allowed_end=payload.get("allowed_end"),
        days_of_week=days,
        timezone=payload.get("timezone", "UTC"),
        description=payload.get("description"),
        performed_by=parsed_actor,
    )


@app.get("/access-windows")
@_handle_validation_error
def list_access_windows(limit: Optional[str] = None, offset: Optional[str] = None) -> List[Dict]:
    parsed_limit: Optional[int] = None
    parsed_offset: Optional[int] = None
    if limit is not None:
        parsed_limit = _parse_positive_int(limit, "limit")
    if offset is not None:
        parsed_offset = _parse_non_negative_int(offset, "offset")
    return crud.list_access_windows(limit=parsed_limit, offset=parsed_offset)


@app.get("/access-windows/{access_window_id}")
@_handle_validation_error
def get_access_window(access_window_id: str) -> Dict:
    return crud.get_access_window(_parse_int(access_window_id, "access_window_id"))


@app.patch("/access-windows/{access_window_id}")
@_handle_validation_error
def update_access_window(access_window_id: str, payload: Dict) -> Dict:
    days = payload.get("days_of_week")
    if days is not None and not isinstance(days, list):
        raise ValidationError("days_of_week must be provided as a list")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    return crud.update_access_window(
        _parse_int(access_window_id, "access_window_id"),
        name=payload.get("name"),
        allowed_start=payload.get("allowed_start"),
        allowed_end=payload.get("allowed_end"),
        days_of_week=days,
        timezone=payload.get("timezone"),
        description=payload.get("description"),
        performed_by=parsed_actor,
    )


@app.delete("/access-windows/{access_window_id}", status_code=status.HTTP_204_NO_CONTENT)
@_handle_validation_error
def delete_access_window(access_window_id: str, performed_by: Optional[str] = None):
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    crud.delete_access_window(
        _parse_int(access_window_id, "access_window_id"),
        performed_by=parsed_actor,
    )
    return None


@app.post("/authorizations", status_code=status.HTTP_204_NO_CONTENT)
@_handle_validation_error
def assign_authorization(payload: Dict):
    user_id = _parse_int(payload.get("user_id"), "user_id")
    host_id = _parse_int(payload.get("host_id"), "host_id")
    performed_by = payload.get("performed_by")
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    access_window_id = payload.get("access_window_id")
    parsed_window: Optional[int] = None
    if access_window_id is not None:
        parsed_window = _parse_int(access_window_id, "access_window_id")
    requires_approval = payload.get("requires_approval")
    parsed_requires = False
    if requires_approval is not None:
        parsed_requires = _parse_bool(requires_approval, "requires_approval")
    source_cidrs = payload.get("source_cidrs")
    if source_cidrs is not None and not isinstance(source_cidrs, list):
        raise ValidationError("source_cidrs must be provided as a list")
    command_policy_value = crud.UNSET
    if "command_policy_id" in payload:
        policy_value = payload.get("command_policy_id")
        if policy_value is not None:
            command_policy_value = _parse_int(policy_value, "command_policy_id")
        else:
            command_policy_value = None
    crud.authorize_user(
        user_id,
        host_id,
        payload.get("privileges", "read"),
        access_window_id=parsed_window,
        requires_approval=parsed_requires,
        source_cidrs=source_cidrs,
        command_policy_id=command_policy_value,
        performed_by=parsed_actor,
    )
    return None


@app.get("/authorizations")
@_handle_validation_error
def list_authorizations(
    user_id: Optional[str] = None,
    host_id: Optional[str] = None,
    access_window_id: Optional[str] = None,
    requires_approval: Optional[str] = None,
    command_policy_id: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    parsed_user: Optional[int] = None
    parsed_host: Optional[int] = None
    parsed_window: Optional[int] = None
    parsed_requires: Optional[bool] = None
    parsed_policy: Optional[int] = None
    parsed_limit: Optional[int] = None
    parsed_offset: Optional[int] = None
    if user_id is not None:
        parsed_user = _parse_int(user_id, "user_id")
    if host_id is not None:
        parsed_host = _parse_int(host_id, "host_id")
    if access_window_id is not None:
        parsed_window = _parse_int(access_window_id, "access_window_id")
    if requires_approval is not None:
        parsed_requires = _parse_bool(requires_approval, "requires_approval")
    if command_policy_id is not None:
        parsed_policy = _parse_int(command_policy_id, "command_policy_id")
    if limit is not None:
        parsed_limit = _parse_positive_int(limit, "limit")
    if offset is not None:
        parsed_offset = _parse_non_negative_int(offset, "offset")
    return crud.list_authorizations(
        user_id=parsed_user,
        host_id=parsed_host,
        access_window_id=parsed_window,
        requires_approval=parsed_requires,
        command_policy_id=parsed_policy,
        limit=parsed_limit,
        offset=parsed_offset,
    )


@app.delete("/authorizations/{authorization_id}", status_code=status.HTTP_204_NO_CONTENT)
@_handle_validation_error
def delete_authorization(authorization_id: str, performed_by: Optional[str] = None):
    parsed_actor: Optional[int] = None
    if performed_by is not None:
        parsed_actor = _parse_int(performed_by, "performed_by")
    crud.revoke_authorization(
        _parse_int(authorization_id, "authorization_id"),
        performed_by=parsed_actor,
    )
    return None


@app.post("/access-requests", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def create_access_request(payload: Dict) -> Dict:
    authorization_id = _parse_int(payload.get("authorization_id"), "authorization_id")
    requested_by = _parse_int(payload.get("requested_by"), "requested_by")
    return crud.create_access_request(
        authorization_id,
        requested_by=requested_by,
        reason=payload.get("reason"),
    )


@app.get("/access-requests")
@_handle_validation_error
def list_access_requests(
    authorization_id: Optional[str] = None,
    user_id: Optional[str] = None,
    host_id: Optional[str] = None,
    status: Optional[str] = None,
    requested_by: Optional[str] = None,
    reviewer_id: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    params: Dict[str, object] = {}
    if authorization_id is not None:
        params["authorization_id"] = _parse_int(authorization_id, "authorization_id")
    if user_id is not None:
        params["user_id"] = _parse_int(user_id, "user_id")
    if host_id is not None:
        params["host_id"] = _parse_int(host_id, "host_id")
    if status is not None:
        params["status"] = status.strip().lower()
    if requested_by is not None:
        params["requested_by"] = _parse_int(requested_by, "requested_by")
    if reviewer_id is not None:
        params["reviewer_id"] = _parse_int(reviewer_id, "reviewer_id")
    if limit is not None:
        params["limit"] = _parse_positive_int(limit, "limit")
    if offset is not None:
        params["offset"] = _parse_non_negative_int(offset, "offset")
    return crud.list_access_requests(**params)


@app.post("/access-requests/{request_id}/approve")
@_handle_validation_error
def approve_access_request(request_id: str, payload: Dict) -> Dict:
    reviewer_id = _parse_int(payload.get("reviewer_id"), "reviewer_id")
    expires_at = payload.get("expires_at")
    parsed_expires: Optional[str] = None
    if expires_at is not None:
        parsed_expires = _parse_datetime(expires_at, "expires_at")
    return crud.approve_access_request(
        _parse_int(request_id, "request_id"),
        reviewer_id=reviewer_id,
        expires_at=parsed_expires,
        note=payload.get("note"),
    )


@app.post("/access-requests/{request_id}/deny")
@_handle_validation_error
def deny_access_request(request_id: str, payload: Dict) -> Dict:
    reviewer_id = _parse_int(payload.get("reviewer_id"), "reviewer_id")
    return crud.deny_access_request(
        _parse_int(request_id, "request_id"),
        reviewer_id=reviewer_id,
        note=payload.get("note"),
    )


@app.post("/access-requests/{request_id}/revoke")
@_handle_validation_error
def revoke_access_request(request_id: str, payload: Dict) -> Dict:
    reviewer_id = _parse_int(payload.get("reviewer_id"), "reviewer_id")
    return crud.revoke_access_request(
        _parse_int(request_id, "request_id"),
        reviewer_id=reviewer_id,
        note=payload.get("note"),
    )


@app.post("/sessions", status_code=status.HTTP_201_CREATED)
@_handle_validation_error
def start_session(payload: Dict) -> Dict:
    requested_commands = payload.get("requested_commands")
    if requested_commands is not None and not isinstance(requested_commands, list):
        raise ValidationError("requested_commands must be provided as a list")
    return crud.start_session(
        user_id=_parse_int(payload.get("user_id"), "user_id"),
        host_id=_parse_int(payload.get("host_id"), "host_id"),
        protocol=payload.get("protocol"),
        source_ip=payload.get("source_ip"),
        requested_commands=requested_commands,
    )


@app.post("/sessions/{record_id}/end")
@_handle_validation_error
def end_session(record_id: str, payload: Dict) -> Dict:
    return crud.end_session(
        _parse_int(record_id, "record_id"),
        recording_path=payload.get("recording_path"),
        metadata=payload.get("metadata"),
        recording=payload.get("recording"),
    )


@app.get("/sessions")
@_handle_validation_error
def list_sessions(
    user_id: Optional[str] = None,
    host_id: Optional[str] = None,
    protocol: Optional[str] = None,
    only_active: Optional[str] = None,
    started_after: Optional[str] = None,
    started_before: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    params: Dict[str, object] = {}
    if user_id is not None:
        params["user_id"] = _parse_int(user_id, "user_id")
    if host_id is not None:
        params["host_id"] = _parse_int(host_id, "host_id")
    if protocol is not None:
        params["protocol"] = protocol
    if only_active is not None:
        params["only_active"] = _parse_bool(only_active, "only_active")
    if started_after is not None:
        params["started_after"] = _parse_datetime(started_after, "started_after")
    if started_before is not None:
        params["started_before"] = _parse_datetime(started_before, "started_before")
    if limit is not None:
        params["limit"] = _parse_positive_int(limit, "limit")
    if offset is not None:
        params["offset"] = _parse_non_negative_int(offset, "offset")
    return crud.list_sessions(**params)


@app.get("/sessions/{session_id}")
@_handle_validation_error
def get_session(session_id: str) -> Dict:
    return crud.get_session(_parse_int(session_id, "session_id"))


@app.get("/recordings")
@_handle_validation_error
def list_recordings(
    session_id: Optional[str] = None,
    user_id: Optional[str] = None,
    host_id: Optional[str] = None,
    protocol: Optional[str] = None,
    created_after: Optional[str] = None,
    created_before: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    params: Dict[str, object] = {}
    if session_id is not None:
        params["session_id"] = _parse_int(session_id, "session_id")
    if user_id is not None:
        params["user_id"] = _parse_int(user_id, "user_id")
    if host_id is not None:
        params["host_id"] = _parse_int(host_id, "host_id")
    if protocol is not None:
        params["protocol"] = protocol
    if created_after is not None:
        params["created_after"] = _parse_datetime(created_after, "created_after")
    if created_before is not None:
        params["created_before"] = _parse_datetime(created_before, "created_before")
    if limit is not None:
        params["limit"] = _parse_positive_int(limit, "limit")
    if offset is not None:
        params["offset"] = _parse_non_negative_int(offset, "offset")
    return crud.list_recordings(**params)


@app.get("/recordings/{recording_id}")
@_handle_validation_error
def get_recording(recording_id: str) -> Dict:
    return crud.get_recording(_parse_int(recording_id, "recording_id"))


@app.get("/audit-events")
@_handle_validation_error
def list_audit_events(
    actor_id: Optional[str] = None,
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    created_after: Optional[str] = None,
    created_before: Optional[str] = None,
    limit: Optional[str] = None,
    offset: Optional[str] = None,
) -> List[Dict]:
    params: Dict[str, object] = {}
    if actor_id is not None:
        params["actor_id"] = _parse_int(actor_id, "actor_id")
    if action is not None:
        params["action"] = action
    if target_type is not None:
        params["target_type"] = target_type
    if target_id is not None:
        params["target_id"] = _parse_int(target_id, "target_id")
    if created_after is not None:
        params["created_after"] = _parse_datetime(created_after, "created_after")
    if created_before is not None:
        params["created_before"] = _parse_datetime(created_before, "created_before")
    if limit is not None:
        params["limit"] = _parse_positive_int(limit, "limit")
    if offset is not None:
        params["offset"] = _parse_non_negative_int(offset, "offset")
    return crud.list_audit_events(**params)
