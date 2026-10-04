"""FastAPI Application Factory for EFT Air-Gapped Web Server."""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from eft.server.routes import router


def _parse_cors_origins() -> list[str]:
    """Parse CORS origins from environment for split frontend/backend deployments."""
    env_value = os.getenv("EFT_CORS_ALLOW_ORIGINS", "")
    if env_value.strip():
        return [origin.strip() for origin in env_value.split(",") if origin.strip()]
    return [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance.

    Returns:
        Configured FastAPI app.
    """
    app = FastAPI(
        title="Email Forensic Tool (EFT)",
        description="Air-Gapped Digital Forensics & Incident Response (DFIR) Email Analysis Server",
        version="1.0.0",
        docs_url="/docs",
        redoc_url=None,
    )

    # CORS defaults are local-only. Set EFT_CORS_ALLOW_ORIGINS for deployed frontends.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_parse_cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API and UI routes
    app.include_router(router)

    return app
