"""Very small subset of FastAPI features needed for unit testing."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .exceptions import HTTPException
from .status import HTTP_404_NOT_FOUND


@dataclass
class Route:
    method: str
    path: str
    handler: Callable[..., Any]
    status_code: int
    expects_body: bool

    def __post_init__(self) -> None:
        cleaned = self.path.strip("/")
        self._segments: List[str] = cleaned.split("/") if cleaned else []

    def match(self, path: str) -> Optional[Dict[str, str]]:
        cleaned = path.strip("/")
        incoming_segments = cleaned.split("/") if cleaned else []
        if len(incoming_segments) != len(self._segments):
            return None
        params: Dict[str, str] = {}
        for expected, actual in zip(self._segments, incoming_segments):
            if expected.startswith("{") and expected.endswith("}"):
                params[expected[1:-1]] = actual
            elif expected != actual:
                return None
        return params


class FastAPI:
    """A minimal request router compatible with the tests."""

    def __init__(self, *, title: str = "", version: str = "") -> None:
        self.title = title
        self.version = version
        self._routes: List[Route] = []

    def post(self, path: str, *, response_model: Any = None, status_code: int = 200):
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self._routes.append(
                Route("POST", path, handler=func, status_code=status_code, expects_body=True)
            )
            return func

        return decorator

    def get(self, path: str, *, response_model: Any = None, status_code: int = 200):
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self._routes.append(
                Route("GET", path, handler=func, status_code=status_code, expects_body=False)
            )
            return func

        return decorator

    def handle_request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        for route in self._routes:
            if route.method != method:
                continue
            params = route.match(path)
            if params is None:
                continue
            ordered_params = [params[key] for key in self._iter_param_names(route)]
            try:
                if route.expects_body:
                    return route.status_code, route.handler(*ordered_params, body or {})
                return route.status_code, route.handler(*ordered_params)
            except HTTPException:
                raise
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Not Found")

    @staticmethod
    def _iter_param_names(route: Route) -> List[str]:
        names: List[str] = []
        for segment in route._segments:
            if segment.startswith("{") and segment.endswith("}"):
                names.append(segment[1:-1])
        return names
