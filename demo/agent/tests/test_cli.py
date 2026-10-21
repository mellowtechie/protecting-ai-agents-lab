from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import demo_agent.cli as cli
from demo_agent.web import execute_mode
from demo_agent.cli import Config, Result, default_factory, load_config, main, run


API_URL = "https://api.example.invalid/inventory"
SAAS_URL = "https://saas.example.invalid/ingest"
CLIENT_ID = "demo-client-id-never-output"
CLIENT_SECRET = "demo-client-secret-never-output"
PRIVATE_KEY_SENTINEL = "private-key-material-never-output"
CONTROLLED_ENDPOINT_TOKEN = "ce_" + "t" * 43
EXPECTED_RECORD = {
    "asset": "demo-laptop-042",
    "owner": "example-user",
    "classification": "ACME-SECRET-74291364",
}


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: object,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.json_calls = 0

    def json(self) -> object:
        self.json_calls += 1
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeClient:
    def __init__(
        self,
        calls: list[dict[str, object]],
        responses: list[FakeResponse],
        with_certificate: bool,
    ) -> None:
        self.calls = calls
        self.responses = responses
        self.with_certificate = with_certificate

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def get(self, url: str, headers: dict[str, str] | None = None):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "cert": self.with_certificate,
            }
        )
        return self.responses.pop(0)

    def post(
        self,
        url: str,
        json: dict[str, str],
        headers: dict[str, str] | None = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "json": json,
                "cert": self.with_certificate,
            }
        )
        return self.responses.pop(0)


class FakeFactory:
    def __init__(self, *responses: FakeResponse) -> None:
        self.calls: list[dict[str, object]] = []
        self.responses = list(responses)

    def __call__(self, with_certificate: bool, _: Config) -> FakeClient:
        return FakeClient(self.calls, self.responses, with_certificate)


def certificate_config(tmp_path: Path, common_names: list[str]) -> Config:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            *(
                x509.NameAttribute(NameOID.COMMON_NAME, common_name)
                for common_name in common_names
            ),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Lab"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(42)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
        .sign(private_key, hashes.SHA256())
    )
    certificate_path = tmp_path / "demo-agent.crt"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private_key_path = tmp_path / "demo-agent.key.fixture"
    private_key_path.write_text(PRIVATE_KEY_SENTINEL)
    return Config(
        api_url=API_URL,
        saas_url=SAAS_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        controlled_endpoint_token=CONTROLLED_ENDPOINT_TOKEN,
        certificate=certificate_path,
        private_key=private_key_path,
    )


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return certificate_config(tmp_path, ["demo-agent"])


def test_load_config_uses_exact_default_hosts_and_paths(monkeypatch) -> None:
    monkeypatch.setenv("CF_ACCESS_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("CONTROLLED_ENDPOINT_TOKEN", CONTROLLED_ENDPOINT_TOKEN)
    for name in ("DEMO_AGENT_API_URL", "DEMO_AGENT_SAAS_URL", "DEMO_AGENT_CERT", "DEMO_AGENT_KEY"):
        monkeypatch.delenv(name, raising=False)

    loaded = load_config()

    assert loaded == Config(
        api_url=API_URL,
        saas_url=SAAS_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        controlled_endpoint_token=CONTROLLED_ENDPOINT_TOKEN,
        certificate=Path("/etc/demo-agent/pki/demo-agent.crt"),
        private_key=Path("/etc/demo-agent/pki/demo-agent.key"),
    )


def test_load_config_requires_a_distinct_controlled_endpoint_token(monkeypatch) -> None:
    monkeypatch.setenv("CF_ACCESS_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("CONTROLLED_ENDPOINT_TOKEN", CONTROLLED_ENDPOINT_TOKEN)

    loaded = load_config()

    assert loaded.controlled_endpoint_token == CONTROLLED_ENDPOINT_TOKEN


def test_live_bridge_shows_real_status_and_ray_without_secrets(config) -> None:
    factory = FakeFactory(FakeResponse(200, EXPECTED_RECORD, {"cf-ray": "example-ray"}))

    payload = execute_mode("authorized", config, factory)
    encoded = str(payload)

    assert payload["result"]["http_result"] == "200"
    assert payload["exchanges"][0]["response"]["cf_ray"] == "example-ray"
    assert payload["exchanges"][0]["request"]["credentials"] == "service token and client certificate"
    assert payload["exchanges"][0]["response"]["body"]["classification"] == "[protected synthetic marker]"
    assert CLIENT_SECRET not in encoded
    assert EXPECTED_RECORD["classification"] not in encoded


def test_live_bridge_keeps_block_body_and_protected_post_redacted(config) -> None:
    factory = FakeFactory(
        FakeResponse(200, EXPECTED_RECORD),
        FakeResponse(302, "sensitive upstream body", {"location": "https://blocked.teams.cloudflare.com/"}),
    )

    payload = execute_mode("send-raw", config, factory)
    encoded = str(payload)

    assert len(payload["exchanges"]) == 2
    assert payload["exchanges"][1]["response"]["status"] == 302
    assert payload["exchanges"][1]["request"]["body"]["classification"] == "[protected synthetic marker]"
    assert "sensitive upstream body" not in encoded
    assert EXPECTED_RECORD["classification"] not in encoded


def test_identity_returns_certificate_metadata_without_network_or_key_material(config) -> None:
    factory = FakeFactory()
    certificate = x509.load_pem_x509_certificate(config.certificate.read_bytes())
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex(":")

    rendered = run("identity", config, factory).render()

    assert factory.calls == []
    assert rendered == "\n".join(
        (
            "Purpose: Show workload certificate metadata",
            "Policy expectation: No policy decision",
            "HTTP result: not sent",
            "Explanation: CN=demo-agent; "
            "issuer=O=Example Lab,CN=demo-agent; "
            f"SHA256={fingerprint}; expires=2027-01-01T00:00:00+00:00",
        )
    )
    assert "BEGIN CERTIFICATE" not in rendered
    assert str(config.certificate) not in rendered
    assert str(config.private_key) not in rendered
    assert PRIVATE_KEY_SENTINEL not in rendered


def test_no_auth_uses_neither_service_token_nor_certificate(config) -> None:
    response = FakeResponse(403, {"detail": CLIENT_SECRET})
    factory = FakeFactory(response)

    result = run("no-auth", config, factory)

    assert factory.calls == [
        {"method": "GET", "url": API_URL, "headers": {}, "cert": False}
    ]
    assert response.json_calls == 0
    assert result.render() == "\n".join(
        (
            "Purpose: Private API request in no-auth mode",
            "Policy expectation: Access denies missing token and certificate",
            "HTTP result: 403",
            "Explanation: Access evaluated machine credentials at the edge",
        )
    )


def test_token_only_uses_service_token_without_certificate(config) -> None:
    response = FakeResponse(403, {"detail": CLIENT_SECRET})
    factory = FakeFactory(response)

    result = run("token-only", config, factory)

    assert factory.calls == [
        {
            "method": "GET",
            "url": API_URL,
            "headers": {
                "CF-Access-Client-Id": CLIENT_ID,
                "CF-Access-Client-Secret": CLIENT_SECRET,
            },
            "cert": False,
        }
    ]
    assert response.json_calls == 0
    assert result.render() == "\n".join(
        (
            "Purpose: Private API request in token-only mode",
            "Policy expectation: Access denies missing certificate",
            "HTTP result: 403",
            "Explanation: Access evaluated machine credentials at the edge",
        )
    )


def test_authorized_uses_service_token_and_certificate(config) -> None:
    factory = FakeFactory(FakeResponse(200, EXPECTED_RECORD))

    result = run("authorized", config, factory)

    assert factory.calls == [
        {
            "method": "GET",
            "url": API_URL,
            "headers": {
                "CF-Access-Client-Id": CLIENT_ID,
                "CF-Access-Client-Secret": CLIENT_SECRET,
            },
            "cert": True,
        }
    ]
    assert result.render() == "\n".join(
        (
            "Purpose: Private API request in authorized mode",
            "Policy expectation: Access permits the exact token and demo-agent certificate",
            "HTTP result: 200",
            'Explanation: Private API returned {"asset": "demo-laptop-042", '
            '"classification": "ACME-SECRET-74291364", "owner": "example-user"}',
        )
    )


def test_send_safe_sanitizes_record_and_sends_only_controlled_endpoint_token(config) -> None:
    factory = FakeFactory(
        FakeResponse(200, EXPECTED_RECORD),
        FakeResponse(200, {"received": {"asset": "demo-laptop-042", "owner": "example-user"}}),
    )

    result = run("send-safe", config, factory)

    assert factory.calls == [
        {
            "method": "GET",
            "url": API_URL,
            "headers": {
                "CF-Access-Client-Id": CLIENT_ID,
                "CF-Access-Client-Secret": CLIENT_SECRET,
            },
            "cert": True,
        },
        {
            "method": "POST",
            "url": SAAS_URL,
            "headers": {"Authorization": f"Bearer {CONTROLLED_ENDPOINT_TOKEN}"},
            "json": {"asset": "demo-laptop-042", "owner": "example-user"},
            "cert": False,
        },
    ]
    assert result.render() == "\n".join(
        (
            "Purpose: Outbound send-safe POST",
            "Policy expectation: Gateway allows a sanitized POST",
            "HTTP result: 200",
            "Explanation: Controlled endpoint accepted the sanitized payload",
        )
    )
    assert "classification" not in result.render()
    assert "ACME-SECRET-74291364" not in result.render()


def test_main_send_safe_rejects_mismatched_success_json_without_leaking(
    config, monkeypatch, capsys
) -> None:
    response_content = "unexpected-response-content-never-output"
    factory = FakeFactory(
        FakeResponse(200, EXPECTED_RECORD),
        FakeResponse(
            200,
            {
                "received": {
                    "asset": "demo-laptop-042",
                    "owner": "example-user",
                },
                "unexpected": f"{response_content} {EXPECTED_RECORD['classification']}",
            },
        ),
    )
    real_run = cli.run
    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(
        cli, "run", lambda mode, loaded: real_run(mode, loaded, factory)
    )

    exit_code = main(["send-safe"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "Error: demo agent command failed\n"
    assert response_content not in captured.err
    assert EXPECTED_RECORD["classification"] not in captured.err


def test_main_send_safe_rejects_malformed_success_json_without_leaking(
    config, monkeypatch, capsys
) -> None:
    response_content = "malformed-response-content-never-output"
    factory = FakeFactory(
        FakeResponse(200, EXPECTED_RECORD),
        FakeResponse(
            200,
            ValueError(
                f"{response_content} {EXPECTED_RECORD['classification']}"
            ),
        ),
    )
    real_run = cli.run
    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(
        cli, "run", lambda mode, loaded: real_run(mode, loaded, factory)
    )

    exit_code = main(["send-safe"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "Error: demo agent command failed\n"
    assert response_content not in captured.err
    assert EXPECTED_RECORD["classification"] not in captured.err


def test_send_raw_preserves_marker_and_sends_only_controlled_endpoint_token(config) -> None:
    factory = FakeFactory(
        FakeResponse(200, EXPECTED_RECORD),
        FakeResponse(403, {"detail": CLIENT_SECRET}),
    )

    result = run("send-raw", config, factory)

    assert factory.calls[-1] == {
        "method": "POST",
        "url": SAAS_URL,
        "headers": {"Authorization": f"Bearer {CONTROLLED_ENDPOINT_TOKEN}"},
        "json": EXPECTED_RECORD,
        "cert": False,
    }
    assert result.render() == "\n".join(
        (
            "Purpose: Outbound send-raw POST",
            "Policy expectation: Gateway DLP blocks the protected marker",
            "HTTP result: 403",
            "Explanation: Gateway evaluated destination, method, and request-body DLP profile",
        )
    )


def test_send_raw_accepts_cloudflare_gateway_block_redirect(config) -> None:
    response = FakeResponse(
        302,
        {"detail": CLIENT_SECRET},
        {"location": "https://blocked.teams.cloudflare.com/"},
    )

    result = run(
        "send-raw",
        config,
        FakeFactory(FakeResponse(200, EXPECTED_RECORD), response),
    )

    assert response.json_calls == 0
    assert result.outcome == "302"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"location": "http://blocked.teams.cloudflare.com/"},
        {"location": "https://teams.cloudflare.com/block"},
        {"location": "https://blocked.teams.cloudflare.com.example/"},
    ],
)
def test_send_raw_rejects_untrusted_redirect(config, headers) -> None:
    with pytest.raises(RuntimeError, match="^unexpected policy outcome$"):
        run(
            "send-raw",
            config,
            FakeFactory(
                FakeResponse(200, EXPECTED_RECORD),
                FakeResponse(302, {"detail": CLIENT_SECRET}, headers),
            ),
        )


@pytest.mark.parametrize("mode", ["send-safe", "send-raw"])
def test_send_modes_require_controlled_endpoint_token_before_any_request(
    config, mode
) -> None:
    factory = FakeFactory(
        FakeResponse(200, EXPECTED_RECORD),
        FakeResponse(200, {"received": EXPECTED_RECORD}),
    )

    with pytest.raises(
        RuntimeError, match="^controlled endpoint authentication unavailable$"
    ):
        run(mode, replace(config, controlled_endpoint_token=""), factory)

    assert factory.calls == []


@pytest.mark.parametrize(
    ("mode", "responses"),
    [
        ("no-auth", (FakeResponse(401, {"detail": CLIENT_SECRET}),)),
        ("token-only", (FakeResponse(500, {"detail": CLIENT_SECRET}),)),
        ("authorized", (FakeResponse(503, {"detail": CLIENT_SECRET}),)),
        (
            "send-safe",
            (
                FakeResponse(200, EXPECTED_RECORD),
                FakeResponse(503, {"detail": CLIENT_SECRET}),
            ),
        ),
        (
            "send-raw",
            (
                FakeResponse(200, EXPECTED_RECORD),
                FakeResponse(200, {"received": EXPECTED_RECORD}),
            ),
        ),
    ],
)
def test_policy_modes_reject_every_unexpected_http_status_without_parsing_body(
    config, mode, responses
) -> None:
    factory = FakeFactory(*responses)

    with pytest.raises(RuntimeError, match="^unexpected policy outcome$") as error:
        run(mode, config, factory)

    assert responses[-1].json_calls == 0
    assert CLIENT_SECRET not in str(error.value)


@pytest.mark.parametrize("mode", ["send-safe", "send-raw"])
def test_send_modes_stop_when_private_api_returns_http_failure(config, mode) -> None:
    factory = FakeFactory(FakeResponse(502, {"detail": CLIENT_SECRET}))

    with pytest.raises(RuntimeError, match="^private API returned HTTP 502$"):
        run(mode, config, factory)

    assert len(factory.calls) == 1


@pytest.mark.parametrize(
    ("mode", "responses"),
    [
        ("no-auth", (FakeResponse(401, {"detail": CLIENT_SECRET}),)),
        ("token-only", (FakeResponse(200, {"detail": CLIENT_SECRET}),)),
        ("authorized", (FakeResponse(403, {"detail": CLIENT_SECRET}),)),
        (
            "send-safe",
            (
                FakeResponse(200, EXPECTED_RECORD),
                FakeResponse(403, {"detail": CLIENT_SECRET}),
            ),
        ),
        (
            "send-raw",
            (
                FakeResponse(200, EXPECTED_RECORD),
                FakeResponse(200, {"received": EXPECTED_RECORD}),
            ),
        ),
    ],
)
def test_main_returns_nonzero_without_rendering_an_unexpected_policy_outcome(
    config, mode, responses, monkeypatch, capsys
) -> None:
    factory = FakeFactory(*responses)
    real_run = cli.run
    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(
        cli, "run", lambda selected_mode, loaded: real_run(selected_mode, loaded, factory)
    )

    exit_code = main([mode])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "Error: demo agent command failed\n"
    assert CLIENT_SECRET not in captured.err


@pytest.mark.parametrize("mode", ["authorized", "send-safe", "send-raw"])
@pytest.mark.parametrize(
    "record",
    [
        [],
        {"asset": "demo-laptop-042", "owner": "example-user"},
        {**EXPECTED_RECORD, "extra": "unexpected"},
        {**EXPECTED_RECORD, "classification": "wrong"},
    ],
)
def test_successful_private_api_response_must_be_the_exact_demo_record(
    config, mode, record
) -> None:
    with pytest.raises(
        RuntimeError, match="^private API returned an unexpected record$"
    ):
        run(mode, config, FakeFactory(FakeResponse(200, record)))


@pytest.mark.parametrize("mode", ["authorized", "send-safe", "send-raw"])
def test_malformed_private_api_json_has_a_sanitized_error(config, mode) -> None:
    response = FakeResponse(200, ValueError(f"invalid JSON contains {CLIENT_SECRET}"))

    with pytest.raises(
        RuntimeError, match="^private API returned an unexpected record$"
    ) as error:
        run(mode, config, FakeFactory(response))

    assert CLIENT_SECRET not in str(error.value)


def mode_factory(mode: str) -> FakeFactory:
    if mode in {"no-auth", "token-only"}:
        return FakeFactory(FakeResponse(403, {"detail": CLIENT_SECRET}))
    if mode == "authorized":
        return FakeFactory(FakeResponse(200, EXPECTED_RECORD))
    if mode == "send-safe":
        return FakeFactory(
            FakeResponse(200, EXPECTED_RECORD),
            FakeResponse(
                200,
                {
                    "received": {
                        "asset": "demo-laptop-042",
                        "owner": "example-user",
                    }
                },
            ),
        )
    if mode == "send-raw":
        return FakeFactory(
            FakeResponse(200, EXPECTED_RECORD),
            FakeResponse(403, {"detail": f"{CLIENT_ID} {CLIENT_SECRET}"}),
        )
    return FakeFactory()


@pytest.mark.parametrize(
    "mode", ["identity", "no-auth", "token-only", "authorized", "send-safe", "send-raw"]
)
def test_rendered_output_never_contains_credentials_or_private_key_material(
    config, mode
) -> None:
    rendered = run(mode, config, mode_factory(mode)).render()

    assert CLIENT_ID not in rendered
    assert CLIENT_SECRET not in rendered
    assert CONTROLLED_ENDPOINT_TOKEN not in rendered
    assert PRIVATE_KEY_SENTINEL not in rendered
    assert str(config.private_key) not in rendered


def test_default_factory_loads_certificate_only_when_requested(config, monkeypatch) -> None:
    loaded_chains: list[tuple[Path, Path]] = []
    client_arguments: list[dict[str, object]] = []

    class FakeContext:
        def load_cert_chain(self, certificate: Path, private_key: Path) -> None:
            loaded_chains.append((certificate, private_key))

    def fake_client(**kwargs):
        client_arguments.append(kwargs)
        return object()

    context = FakeContext()
    monkeypatch.setattr(cli.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(cli.httpx, "Client", fake_client)

    default_factory(False, config)
    assert loaded_chains == []

    default_factory(True, config)
    assert loaded_chains == [(config.certificate, config.private_key)]
    assert client_arguments == [
        {"verify": context, "timeout": 15, "follow_redirects": False},
        {"verify": context, "timeout": 15, "follow_redirects": False},
    ]


def test_unknown_mode_fails_closed(config) -> None:
    with pytest.raises(ValueError, match="^unknown mode: send-everything$"):
        run("send-everything", config, FakeFactory())


def test_deployer_configured_hosts_are_used_and_redacted(config, monkeypatch) -> None:
    api_url = "https://private.example.org/inventory"
    saas_url = "https://receiver.example.org/ingest"
    monkeypatch.setenv("DEMO_AGENT_API_URL", api_url)
    monkeypatch.setenv("DEMO_AGENT_SAAS_URL", saas_url)
    configured = replace(config, api_url=api_url, saas_url=saas_url)
    result = execute_mode(
        "send-safe",
        configured,
        FakeFactory(
            FakeResponse(200, EXPECTED_RECORD),
            FakeResponse(200, {"received": {"asset": "demo-laptop-042", "owner": "example-user"}}),
        ),
    )
    assert [item["request"]["url"] for item in result["exchanges"]] == [api_url, saas_url]
    assert "ACME-SECRET" not in str(result)


@pytest.mark.parametrize(
    ("field", "unsafe_url", "mode"),
    [
        ("api_url", "http://api.example.invalid/inventory", "no-auth"),
        ("api_url", "https://alternate.example/inventory", "no-auth"),
        ("api_url", "https://api.example.invalid/other", "no-auth"),
        ("saas_url", "http://saas.example.invalid/ingest", "send-safe"),
        ("saas_url", "https://alternate.example/ingest", "send-safe"),
        ("saas_url", "https://saas.example.invalid/other", "send-safe"),
    ],
)
def test_run_rejects_noncanonical_endpoint_before_any_request(
    config, field, unsafe_url, mode
) -> None:
    unsafe_config = replace(config, **{field: unsafe_url})
    factory = FakeFactory(
        FakeResponse(200, EXPECTED_RECORD),
        FakeResponse(200, {"received": "ok"}),
    )

    with pytest.raises(ValueError, match="^invalid endpoint configuration$") as error:
        run(mode, unsafe_config, factory)

    assert factory.calls == []
    assert unsafe_url not in str(error.value)


def test_main_identity_prints_result_and_returns_zero(config, monkeypatch, capsys) -> None:
    monkeypatch.setenv("CF_ACCESS_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.delenv("CONTROLLED_ENDPOINT_TOKEN", raising=False)
    monkeypatch.setenv("DEMO_AGENT_CERT", str(config.certificate))
    monkeypatch.setenv("DEMO_AGENT_KEY", str(config.private_key))

    exit_code = main(["identity"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.startswith("Purpose: Show workload certificate metadata\n")
    assert captured.err == ""
    assert CLIENT_ID not in captured.out
    assert CLIENT_SECRET not in captured.out
    assert PRIVATE_KEY_SENTINEL not in captured.out


@pytest.mark.parametrize(
    "failure",
    [
        KeyError(CLIENT_SECRET),
        OSError(f"local failure contains {CLIENT_SECRET}"),
        RuntimeError(f"runtime failure contains {CLIENT_SECRET}"),
        ValueError(f"invalid value contains {CLIENT_SECRET}"),
        httpx.HTTPError(f"HTTP failure contains {CLIENT_SECRET}"),
        httpx.InvalidURL(f"invalid URL contains {CLIENT_SECRET}"),
    ],
    ids=["key", "os", "runtime", "value", "http", "invalid-url"],
)
def test_main_returns_one_with_sanitized_error_on_expected_failure(
    config, monkeypatch, capsys, failure
) -> None:
    monkeypatch.setattr(cli, "load_config", lambda: config)

    def fail_run(mode: str, loaded: Config) -> Result:
        raise failure

    monkeypatch.setattr(cli, "run", fail_run)

    exit_code = main(["authorized"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "Error: demo agent command failed\n"
    assert CLIENT_SECRET not in captured.err


def test_main_rejects_unknown_mode_with_exit_two(capsys) -> None:
    invalid_mode = "send-everything"

    with pytest.raises(SystemExit) as error:
        main([invalid_mode])

    captured = capsys.readouterr()
    assert error.value.code == 2
    assert captured.out == ""
    assert captured.err.endswith("demo-agent: error: invalid command line\n")
    assert invalid_mode not in captured.err
    assert CLIENT_ID not in captured.err
    assert CLIENT_SECRET not in captured.err


def test_main_sanitizes_credential_like_invalid_mode(capsys) -> None:
    credential_sentinel = "credential-like-invalid-mode-never-print"

    with pytest.raises(SystemExit) as error:
        main([credential_sentinel])

    captured = capsys.readouterr()
    assert error.value.code == 2
    assert captured.out == ""
    assert credential_sentinel not in captured.err
    assert captured.err.endswith("demo-agent: error: invalid command line\n")
    for mode in (
        "identity",
        "no-auth",
        "token-only",
        "authorized",
        "send-safe",
        "send-raw",
    ):
        assert mode in captured.err


@pytest.mark.parametrize(
    ("arguments", "credential_sentinel"),
    [
        (["identity", "extra-positional-credential-sentinel"], "extra-positional-credential-sentinel"),
        (["--malformed-option-credential-sentinel"], "malformed-option-credential-sentinel"),
    ],
    ids=["extra-positional", "malformed-option"],
)
def test_main_sanitizes_all_parser_errors(
    arguments, credential_sentinel, capsys
) -> None:
    with pytest.raises(SystemExit) as error:
        main(arguments)

    captured = capsys.readouterr()
    assert error.value.code == 2
    assert captured.out == ""
    assert captured.err.endswith("demo-agent: error: invalid command line\n")
    assert credential_sentinel not in captured.err


def test_main_help_lists_all_six_modes(capsys) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--help"])

    captured = capsys.readouterr()
    assert error.value.code == 0
    assert captured.err == ""
    for mode in (
        "identity",
        "no-auth",
        "token-only",
        "authorized",
        "send-safe",
        "send-raw",
    ):
        assert mode in captured.out


@pytest.mark.parametrize(
    "common_names",
    [
        [],
        ["wrong-cn-credential-sentinel"],
        ["demo-agent", "duplicate-cn-credential-sentinel"],
    ],
    ids=["missing", "wrong", "multiple"],
)
def test_main_rejects_invalid_certificate_identity_without_leaking(
    tmp_path, common_names, monkeypatch, capsys
) -> None:
    invalid_config = certificate_config(tmp_path, common_names)
    certificate_pem = invalid_config.certificate.read_text()
    monkeypatch.setattr(cli, "load_config", lambda: invalid_config)

    exit_code = main(["identity"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "Error: demo agent command failed\n"
    assert "Traceback" not in captured.err
    assert "BEGIN CERTIFICATE" not in captured.err
    assert certificate_pem not in captured.err
    for common_name in common_names:
        assert common_name not in captured.err
