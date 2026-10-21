"""Loopback-only, fixed-command HTTP bridge for the live demo guide."""

import json
import os
import re
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .cli import (
    EXPECTED_RECORD,
    MODES,
    Config,
    default_factory,
    load_config,
    run,
)


MAX_BODY = 128
PORT = 8765
SITE_FILE = Path("/opt/demo-agent/site/index.html")
FAVICON_FILE = SITE_FILE.with_name("favicon.png")
LLMS_FILE = SITE_FILE.with_name("llms.txt")
REDACTED = "[protected synthetic marker]"


class RecordingClient:
    def __init__(self, underlying, certificate: bool, calls: list[dict[str, Any]]):
        self.underlying = underlying
        self.certificate = certificate
        self.calls = calls

    def __enter__(self):
        self.client = self.underlying.__enter__()
        return self

    def __exit__(self, *args):
        return self.underlying.__exit__(*args)

    def get(self, url, headers=None):
        started = time.monotonic()
        response = self.client.get(url, headers=headers)
        self.calls.append({
            "method": "GET", "url": url, "certificate": self.certificate,
            "service_token": bool(headers), "body": None, "response": response,
            "duration_ms": round((time.monotonic() - started) * 1000),
        })
        return response

    def post(self, url, json=None, headers=None):
        started = time.monotonic()
        response = self.client.post(url, json=json, headers=headers)
        self.calls.append({
            "method": "POST", "url": url, "certificate": self.certificate,
            "service_token": False, "body": json, "response": response,
            "duration_ms": round((time.monotonic() - started) * 1000),
        })
        return response


def public_call(call: dict[str, Any], config: Config) -> dict[str, Any]:
    response = call["response"]
    body = call["body"]
    if body is not None:
        body = {key: REDACTED if key == "classification" else value for key, value in body.items()}
    if call["url"] == config.api_url:
        response_body: Any = (
            {key: REDACTED if key == "classification" else value
             for key, value in response.json().items()}
            if response.status_code == 200 else "[Access response body omitted]"
        )
        credential = "service token and client certificate" if call["certificate"] else (
            "service token only" if call["service_token"] else "none"
        )
    elif call["url"] == config.saas_url:
        response_body = response.json() if response.status_code == 200 else "[Gateway block response body omitted]"
        credential = "controlled endpoint bearer token"
    else:
        raise ValueError("unexpected destination")
    return {
        "request": {
            "method": call["method"], "url": call["url"],
            "credentials": credential, "body": body,
        },
        "response": {
            "status": response.status_code, "body": response_body,
            "cf_ray": response.headers.get("cf-ray"),
        },
        "duration_ms": call["duration_ms"],
    }


def execute_mode(mode: str, config: Config, factory=default_factory) -> dict[str, Any]:
    if mode not in MODES:
        raise ValueError("unsupported mode")
    calls: list[dict[str, Any]] = []

    def recording_factory(certificate: bool, current_config: Config):
        return RecordingClient(factory(certificate, current_config), certificate, calls)

    result = run(mode, config, recording_factory)
    explanation = result.explanation.replace(EXPECTED_RECORD["classification"], REDACTED)
    explanation = re.sub(r"SHA256=[0-9a-f:]+", "SHA256=[fingerprint omitted]", explanation)
    return {
        "mode": mode,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "purpose": result.purpose,
            "expectation": result.expectation,
            "http_result": result.outcome,
            "explanation": explanation,
        },
        "exchanges": [public_call(call, config) for call in calls],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoAgentBridge"

    def log_message(self, format, *args):
        # Do not emit request data, response bodies, headers, or credentials.
        pass

    def send_json(self, status: int, value: dict[str, Any]):
        payload = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/config.json":
            account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
            api_host = urlparse(os.environ.get("DEMO_AGENT_API_URL", "")).hostname
            saas_host = urlparse(os.environ.get("DEMO_AGENT_SAAS_URL", "")).hostname
            if not re.fullmatch(r"[0-9a-f]{32}", account_id) or not api_host or not saas_host:
                self.send_json(503, {"error": "lab configuration unavailable"})
                return
            self.send_json(200, {"account_id": account_id, "api_host": api_host, "saas_host": saas_host})
        elif self.path in ("/", "/favicon.png", "/llms.txt"):
            requested_file, content_type = {
                "/": (SITE_FILE, "text/html; charset=utf-8"),
                "/favicon.png": (FAVICON_FILE, "image/png"),
                "/llms.txt": (LLMS_FILE, "text/plain; charset=utf-8"),
            }[self.path]
            try:
                payload = requested_file.read_bytes()
            except OSError:
                self.send_json(503, {"error": "guide unavailable"})
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "public, max-age=86400" if self.path == "/favicon.png" else "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path == "/health":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/run" or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or set(data) != {"mode"} or data["mode"] not in MODES:
                raise ValueError
        except (ValueError, TypeError, json.JSONDecodeError):
            self.send_json(400, {"error": "invalid command"})
            return
        try:
            self.send_json(200, execute_mode(data["mode"], load_config()))
        except Exception:
            # The CLI can receive response bodies containing sensitive material.
            self.send_json(502, {"error": "demo agent command failed"})


def main():
    if os.geteuid() == 0:
        raise SystemExit("refusing to run as root")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
