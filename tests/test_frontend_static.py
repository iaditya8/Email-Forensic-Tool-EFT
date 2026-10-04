"""Tests for split-deployment static frontend assets."""

from pathlib import Path


def test_frontend_index_uses_vite_api_base_env() -> None:
    """Static frontend reads API base URL from Vite env placeholder."""
    index_html = (
        Path(__file__).resolve().parent.parent / "frontend" / "index.html"
    ).read_text(encoding="utf-8")
    assert "import.meta.env.VITE_API_BASE_URL" in index_html
    assert "function apiUrl(path)" in index_html
