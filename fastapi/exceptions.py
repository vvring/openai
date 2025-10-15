"""Exception definitions for the lightweight FastAPI shim."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class HTTPException(Exception):
    status_code: int
    detail: Any = None

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"HTTP {self.status_code}: {self.detail}"
