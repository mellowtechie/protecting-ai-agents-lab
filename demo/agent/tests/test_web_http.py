"""Exercise the browser guide as a real HTTP service without Cloudflare traffic."""

from http.server import HTTPServer
from pathlib import Path
from threading import Thread

import httpx
import pytest

from demo_agent import web


@pytest.fixture
def guide_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    site = tmp_path / "index.html"
    favicon = tmp_path / "favicon.png"
    index = tmp_path / "llms.txt"
    site.write_text("<h1>Lab guide</h1>", encoding="utf-8")
    favicon.write_bytes(b"example PNG bytes")
    index.write_text("Lab index\n", encoding="utf-8")
    monkeypatch.setattr(web, "SITE_FILE", site)
    monkeypatch.setattr(web, "FAVICON_FILE", favicon)
    monkeypatch.setattr(web, "LLMS_FILE", index)
    server = HTTPServer(("127.0.0.1", 0), web.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_guide_serves_page_assets_and_safe_config(guide_url: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "0" * 32)
    monkeypatch.setenv("DEMO_AGENT_API_URL", "https://api.example.com/inventory")
    monkeypatch.setenv("DEMO_AGENT_SAAS_URL", "https://saas.example.com/ingest")

    assert httpx.get(guide_url + "/").text == "<h1>Lab guide</h1>"
    assert httpx.get(guide_url + "/favicon.png").content == b"example PNG bytes"
    assert httpx.get(guide_url + "/llms.txt").text == "Lab index\n"
    assert httpx.get(guide_url + "/health").json() == {"status": "ok"}
    config = httpx.get(guide_url + "/config.json")
    assert config.json() == {
        "account_id": "0" * 32,
        "api_host": "api.example.com",
        "saas_host": "saas.example.com",
    }
    assert config.headers["cache-control"] == "no-store"


def test_guide_accepts_only_fixed_cli_modes(guide_url: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(web, "load_config", lambda: object())
    monkeypatch.setattr(web, "execute_mode", lambda mode, _config: {"mode": mode})

    accepted = httpx.post(guide_url + "/run", json={"mode": "identity"})
    rejected = httpx.post(guide_url + "/run", json={"mode": "shell"})
    assert accepted.status_code == 200
    assert accepted.json() == {"mode": "identity"}
    assert rejected.status_code == 400
