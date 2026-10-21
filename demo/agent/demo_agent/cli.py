import argparse
import json
import os
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


MODES = ("identity", "no-auth", "token-only", "authorized", "send-safe", "send-raw")
API_URL = "https://api.example.invalid/inventory"
SAAS_URL = "https://saas.example.invalid/ingest"
EXPECTED_RECORD = {
    "asset": "demo-laptop-042",
    "owner": "example-user",
    "classification": "ACME-SECRET-74291364",
}


@dataclass(frozen=True)
class Config:
    api_url: str
    saas_url: str
    client_id: str
    client_secret: str
    controlled_endpoint_token: str
    certificate: Path
    private_key: Path


@dataclass(frozen=True)
class Result:
    purpose: str
    expectation: str
    outcome: str
    explanation: str

    def render(self) -> str:
        return "\n".join(
            (
                f"Purpose: {self.purpose}",
                f"Policy expectation: {self.expectation}",
                f"HTTP result: {self.outcome}",
                f"Explanation: {self.explanation}",
            )
        )


class HTTPClient(Protocol):
    def __enter__(self): ...

    def __exit__(self, *args): ...

    def get(self, url: str, headers: dict[str, str] | None = None): ...

    def post(
        self,
        url: str,
        json: dict[str, str],
        headers: dict[str, str] | None = None,
    ): ...


ClientFactory = Callable[[bool, Config], HTTPClient]


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "demo-agent: error: invalid command line\n")


def default_factory(with_certificate: bool, config: Config) -> httpx.Client:
    context = ssl.create_default_context()
    if with_certificate:
        context.load_cert_chain(config.certificate, config.private_key)
    return httpx.Client(verify=context, timeout=15, follow_redirects=False)


def access_headers(config: Config) -> dict[str, str]:
    return {
        "CF-Access-Client-Id": config.client_id,
        "CF-Access-Client-Secret": config.client_secret,
    }


def validated_record(response) -> dict[str, str]:
    try:
        record = response.json()
    except ValueError:
        raise RuntimeError("private API returned an unexpected record") from None
    if record != EXPECTED_RECORD:
        raise RuntimeError("private API returned an unexpected record")
    return record


def require_policy_status(response, expected_status: int) -> None:
    if response.status_code != expected_status:
        raise RuntimeError("unexpected policy outcome")


def require_dlp_block(response) -> None:
    if response.status_code == 403:
        return
    if response.status_code == 302:
        location = urlparse(response.headers.get("location", ""))
        if (
            location.scheme.lower() == "https"
            and location.netloc.lower() == "blocked.teams.cloudflare.com"
        ):
            return
    raise RuntimeError("unexpected policy outcome")


def fetch_record(config: Config, factory: ClientFactory) -> dict[str, str]:
    with factory(True, config) as client:
        response = client.get(config.api_url, headers=access_headers(config))
    if response.status_code != 200:
        raise RuntimeError(f"private API returned HTTP {response.status_code}")
    return validated_record(response)


def identity(config: Config) -> Result:
    certificate = x509.load_pem_x509_certificate(config.certificate.read_bytes())
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != "demo-agent":
        raise RuntimeError("invalid certificate identity")
    common_name = common_names[0].value
    metadata = (
        f"CN={common_name}; "
        f"issuer={certificate.issuer.rfc4514_string()}; "
        f"SHA256={certificate.fingerprint(hashes.SHA256()).hex(':')}; "
        f"expires={certificate.not_valid_after_utc.isoformat()}"
    )
    return Result(
        "Show workload certificate metadata",
        "No policy decision",
        "not sent",
        metadata,
    )


def run(
    mode: str,
    config: Config,
    factory: ClientFactory = default_factory,
) -> Result:
    if mode not in MODES:
        raise ValueError(f"unknown mode: {mode}")
    expected_api = os.environ.get("DEMO_AGENT_API_URL", API_URL)
    expected_saas = os.environ.get("DEMO_AGENT_SAAS_URL", SAAS_URL)
    if (
        config.api_url != expected_api
        or config.saas_url != expected_saas
        or urlparse(config.api_url).scheme != "https"
        or urlparse(config.saas_url).scheme != "https"
        or urlparse(config.api_url).path != "/inventory"
        or urlparse(config.saas_url).path != "/ingest"
        or not urlparse(config.api_url).hostname
        or not urlparse(config.saas_url).hostname
    ):
        raise ValueError("invalid endpoint configuration")
    if mode in {"send-safe", "send-raw"} and not config.controlled_endpoint_token:
        raise RuntimeError("controlled endpoint authentication unavailable")
    if mode == "identity":
        return identity(config)
    if mode in {"no-auth", "token-only", "authorized"}:
        use_token = mode != "no-auth"
        use_certificate = mode == "authorized"
        headers = access_headers(config) if use_token else {}
        with factory(use_certificate, config) as client:
            response = client.get(config.api_url, headers=headers)
        require_policy_status(response, 200 if mode == "authorized" else 403)
        expectations = {
            "no-auth": "Access denies missing token and certificate",
            "token-only": "Access denies missing certificate",
            "authorized": "Access permits the exact token and demo-agent certificate",
        }
        explanation = "Access evaluated machine credentials at the edge"
        if mode == "authorized":
            record = validated_record(response)
            explanation = f"Private API returned {json.dumps(record, sort_keys=True)}"
        return Result(
            f"Private API request in {mode} mode",
            expectations[mode],
            str(response.status_code),
            explanation,
        )

    record = fetch_record(config, factory)
    if mode == "send-safe":
        payload = {"asset": record["asset"], "owner": record["owner"]}
        expectation = "Gateway allows a sanitized POST"
    else:
        payload = record.copy()
        expectation = "Gateway DLP blocks the protected marker"
    with factory(False, config) as client:
        response = client.post(
            config.saas_url,
            json=payload,
            headers={
                "Authorization": f"Bearer {config.controlled_endpoint_token}"
            },
        )
    if mode == "send-safe":
        require_policy_status(response, 200)
    else:
        require_dlp_block(response)
    explanation = "Gateway evaluated destination, method, and request-body DLP profile"
    if mode == "send-safe":
        try:
            received = response.json()
        except ValueError:
            raise RuntimeError("controlled endpoint returned an unexpected response") from None
        if received != {"received": payload}:
            raise RuntimeError("controlled endpoint returned an unexpected response")
        explanation = "Controlled endpoint accepted the sanitized payload"
    return Result(
        f"Outbound {mode} POST",
        expectation,
        str(response.status_code),
        explanation,
    )


def load_config() -> Config:
    return Config(
        api_url=os.environ.get("DEMO_AGENT_API_URL", API_URL),
        saas_url=os.environ.get("DEMO_AGENT_SAAS_URL", SAAS_URL),
        client_id=os.environ["CF_ACCESS_CLIENT_ID"],
        client_secret=os.environ["CF_ACCESS_CLIENT_SECRET"],
        controlled_endpoint_token=os.environ.get("CONTROLLED_ENDPOINT_TOKEN", ""),
        certificate=Path(
            os.environ.get("DEMO_AGENT_CERT", "/etc/demo-agent/pki/demo-agent.crt")
        ),
        private_key=Path(
            os.environ.get("DEMO_AGENT_KEY", "/etc/demo-agent/pki/demo-agent.key")
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(prog="demo-agent")
    parser.add_argument("mode", metavar="{" + ",".join(MODES) + "}")
    args = parser.parse_args(argv)
    if args.mode not in MODES:
        parser.error("unsupported mode")
    try:
        result = run(args.mode, load_config())
    except (
        KeyError,
        OSError,
        RuntimeError,
        ValueError,
        httpx.HTTPError,
        httpx.InvalidURL,
    ):
        print("Error: demo agent command failed", file=sys.stderr)
        return 1
    print(result.render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
