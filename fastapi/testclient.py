"""Simplified TestClient compatible with the lightweight FastAPI shim."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .exceptions import HTTPException


@dataclass
class _Response:
    status_code: int
    data: Any

    @property
    def text(self) -> str:
        if self.data is None:
            return ""
        if isinstance(self.data, (dict, list)):
            return json.dumps(self.data)
        return str(self.data)

    def json(self) -> Any:
        return self.data


class TestClient:
    __test__ = False  # Prevent pytest from collecting this helper as a test class.
    def __init__(self, app: Any) -> None:
        self.app = app

    def _request(self, method: str, path: str, json_body: Optional[Dict[str, Any]] = None) -> _Response:
        try:
            status_code, payload = self.app.handle_request(method, path, json_body)
            return _Response(status_code=status_code, data=payload)
        except HTTPException as exc:
            return _Response(status_code=exc.status_code, data={"detail": exc.detail})

    def post(self, path: str, json: Optional[Dict[str, Any]] = None) -> _Response:
        return self._request("POST", path, json)

    def get(self, path: str) -> _Response:
        return self._request("GET", path)

    def delete(self, path: str) -> _Response:
        return self._request("DELETE", path)
