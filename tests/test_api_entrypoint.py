"""Tests for deployment ASGI entrypoint."""

from fastapi import FastAPI

from api.index import app


def test_asgi_entrypoint_exports_app() -> None:
    """Deployment entrypoint exposes an ASGI app object."""
    assert isinstance(app, FastAPI)
