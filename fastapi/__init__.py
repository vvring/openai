"""Minimal FastAPI-compatible interface for offline testing."""

from .app import FastAPI
from .exceptions import HTTPException
from . import status

__all__ = ["FastAPI", "HTTPException", "status"]
