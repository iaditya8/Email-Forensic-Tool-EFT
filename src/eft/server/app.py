"""FastAPI Application Factory for EFT Air-Gapped Web Server."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from eft.server.routes import router


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

    # Air-Gapped CORS (Allow localhost / local loopback origins)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API and UI routes
    app.include_router(router)

    return app
