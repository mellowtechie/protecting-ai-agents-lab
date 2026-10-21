import io
import json
import time
import urllib.request

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError, PyJWKSetError

import app
from app import AccessJWTVerifier, create_app, default_verifier


TEAM_DOMAIN = "https://demo.cloudflareaccess.com"
AUDIENCE = "demo-audience"


class FakeVerifier:
    def verify(self, token: str) -> dict[str, object]:
        if token != "valid.jwt.value":
            raise ValueError("invalid token")
        return {"aud": ["demo-audience"], "iss": "https://demo.cloudflareaccess.com"}


class FalseyVerifier(FakeVerifier):
    def __bool__(self) -> bool:
        return False


class RuntimeFailureVerifier:
    def verify(self, token: str) -> dict[str, object]:
        raise RuntimeError(f"unexpected verifier failure for {token}")


class JWKSConnectionFailureVerifier:
    def verify(self, token: str) -> dict[str, object]:
        raise PyJWKClientConnectionError("JWKS unavailable")


class MalformedJWKSVerifier:
    def verify(self, token: str) -> dict[str, object]:
        raise json.JSONDecodeError("Expecting value", "", 0)


class InvalidJWKSSetVerifier:
    def verify(self, token: str) -> dict[str, object]:
        raise PyJWKSetError("Invalid JWK Set value")


class MissingSigningKeyVerifier:
    def verify(self, token: str) -> dict[str, object]:
        raise PyJWKClientError("Unable to find a signing key that matches")


class StaticJWKClient:
    def __init__(self, public_key: rsa.RSAPublicKey) -> None:
        self.signing_key = jwt.PyJWK.from_json(
            jwt.algorithms.RSAAlgorithm.to_jwk(public_key)
        )

    def get_signing_key_from_jwt(self, token: str) -> jwt.PyJWK:
        return self.signing_key


@pytest.fixture(scope="module")
def signing_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPrivateKey]:
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


def access_claims() -> dict[str, object]:
    now = int(time.time())
    return {
        "aud": [AUDIENCE],
        "exp": now + 300,
        "iat": now,
        "iss": TEAM_DOMAIN,
    }


def access_verifier(public_key: rsa.RSAPublicKey) -> AccessJWTVerifier:
    verifier = AccessJWTVerifier(TEAM_DOMAIN, AUDIENCE)
    verifier.jwks = StaticJWKClient(public_key)
    return verifier


def encode_token(
    claims: dict[str, object], private_key: rsa.RSAPrivateKey
) -> str:
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "demo-key"},
    )


def patch_jwks_response(monkeypatch, response: object) -> None:
    encoded_response = json.dumps(response).encode()

    def fake_urlopen(request, *, timeout, context):
        return io.BytesIO(encoded_response)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


def public_jwk(
    public_key: rsa.RSAPublicKey,
    *,
    kid: str,
    use: str,
) -> dict[str, object]:
    key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    key.update({"kid": kid, "use": use})
    return key


client = TestClient(create_app(FakeVerifier()))


def test_health_is_unprotected() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_is_unprotected_without_access_configuration(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_TEAM_DOMAIN", raising=False)
    monkeypatch.delenv("ACCESS_AUDIENCE", raising=False)
    default_verifier.cache_clear()

    response = TestClient(create_app()).get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_succeeds_with_an_explicitly_injected_verifier(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_TEAM_DOMAIN", raising=False)
    monkeypatch.delenv("ACCESS_AUDIENCE", raising=False)
    default_verifier.cache_clear()

    response = TestClient(create_app(FalseyVerifier())).get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_ready_fails_closed_without_access_configuration(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_TEAM_DOMAIN", raising=False)
    monkeypatch.delenv("ACCESS_AUDIENCE", raising=False)
    default_verifier.cache_clear()

    response = TestClient(create_app(), raise_server_exceptions=False).get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


def test_ready_validates_configuration_without_requesting_jwks(monkeypatch) -> None:
    monkeypatch.setenv("ACCESS_TEAM_DOMAIN", TEAM_DOMAIN)
    monkeypatch.setenv("ACCESS_AUDIENCE", AUDIENCE)
    default_verifier.cache_clear()

    def reject_network(*args, **kwargs):
        pytest.fail("readiness must not request JWKS")

    monkeypatch.setattr(urllib.request, "urlopen", reject_network)
    try:
        response = TestClient(create_app()).get("/readyz")
    finally:
        default_verifier.cache_clear()

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_inventory_rejects_missing_assertion() -> None:
    response = client.get("/inventory")
    assert response.status_code == 401
    assert response.json() == {"detail": "Access assertion required"}


def test_inventory_rejects_invalid_assertion() -> None:
    response = client.get("/inventory", headers={"Cf-Access-Jwt-Assertion": "forged"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Access assertion invalid"}


def test_inventory_uses_falsey_injected_verifier(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_TEAM_DOMAIN", raising=False)
    monkeypatch.delenv("ACCESS_AUDIENCE", raising=False)
    default_verifier.cache_clear()
    falsey_client = TestClient(create_app(FalseyVerifier()))

    response = falsey_client.get(
        "/inventory",
        headers={"Cf-Access-Jwt-Assertion": "valid.jwt.value"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "asset": "demo-laptop-042",
        "owner": "example-user",
        "classification": "ACME-SECRET-74291364",
    }


def test_inventory_returns_503_without_access_configuration(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_TEAM_DOMAIN", raising=False)
    monkeypatch.delenv("ACCESS_AUDIENCE", raising=False)
    default_verifier.cache_clear()
    unconfigured_client = TestClient(create_app(), raise_server_exceptions=False)

    response = unconfigured_client.get(
        "/inventory",
        headers={"Cf-Access-Jwt-Assertion": "valid.jwt.value"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


@pytest.mark.parametrize(
    ("team_domain", "audience"),
    [
        ("", AUDIENCE),
        ("http://demo.cloudflareaccess.com", AUDIENCE),
        (TEAM_DOMAIN, ""),
    ],
)
def test_inventory_returns_503_for_invalid_access_configuration(
    monkeypatch,
    team_domain,
    audience,
) -> None:
    monkeypatch.setenv("ACCESS_TEAM_DOMAIN", team_domain)
    monkeypatch.setenv("ACCESS_AUDIENCE", audience)
    default_verifier.cache_clear()
    unconfigured_client = TestClient(create_app(), raise_server_exceptions=False)

    try:
        response = unconfigured_client.get(
            "/inventory",
            headers={"Cf-Access-Jwt-Assertion": "valid.jwt.value"},
        )
    finally:
        default_verifier.cache_clear()

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


def test_inventory_returns_503_when_jwks_is_unavailable() -> None:
    unavailable_client = TestClient(create_app(JWKSConnectionFailureVerifier()))

    response = unavailable_client.get(
        "/inventory",
        headers={"Cf-Access-Jwt-Assertion": "valid.jwt.value"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


def test_inventory_returns_503_when_jwks_json_is_malformed() -> None:
    malformed_client = TestClient(create_app(MalformedJWKSVerifier()))

    response = malformed_client.get(
        "/inventory",
        headers={"Cf-Access-Jwt-Assertion": "valid.jwt.value"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


def test_inventory_returns_503_when_jwks_set_is_invalid() -> None:
    invalid_set_client = TestClient(create_app(InvalidJWKSSetVerifier()))

    response = invalid_set_client.get(
        "/inventory",
        headers={"Cf-Access-Jwt-Assertion": "valid.jwt.value"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


def test_inventory_rejects_assertion_when_signing_key_is_missing() -> None:
    missing_key_client = TestClient(create_app(MissingSigningKeyVerifier()))

    response = missing_key_client.get(
        "/inventory",
        headers={"Cf-Access-Jwt-Assertion": "valid.jwt.value"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Access assertion invalid"}


def test_inventory_returns_controlled_500_for_unexpected_verifier_failure(
    caplog,
) -> None:
    assertion = "unexpected.internal.assertion"
    failing_client = TestClient(create_app(RuntimeFailureVerifier()))

    response = failing_client.get(
        "/inventory",
        headers={"Cf-Access-Jwt-Assertion": assertion},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "RuntimeError" in caplog.text
    assert assertion not in caplog.text


def test_inventory_returns_503_when_jwks_response_is_not_an_object(
    monkeypatch,
    signing_keys,
) -> None:
    private_key, _ = signing_keys
    patch_jwks_response(monkeypatch, [])
    verifier = AccessJWTVerifier(TEAM_DOMAIN, AUDIENCE)
    access_client = TestClient(create_app(verifier))

    response = access_client.get(
        "/inventory",
        headers={
            "Cf-Access-Jwt-Assertion": encode_token(access_claims(), private_key)
        },
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


def test_inventory_returns_503_when_jwks_encoding_is_invalid(
    monkeypatch,
    signing_keys,
) -> None:
    private_key, _ = signing_keys

    def fake_urlopen(request, *, timeout, context):
        return io.BytesIO(b"\xff")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    verifier = AccessJWTVerifier(TEAM_DOMAIN, AUDIENCE)
    access_client = TestClient(create_app(verifier))

    response = access_client.get(
        "/inventory",
        headers={
            "Cf-Access-Jwt-Assertion": encode_token(access_claims(), private_key)
        },
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


def test_inventory_returns_503_when_jwks_has_no_signing_keys(
    monkeypatch,
    signing_keys,
) -> None:
    private_key, _ = signing_keys
    patch_jwks_response(
        monkeypatch,
        {
            "keys": [
                public_jwk(
                    private_key.public_key(),
                    kid="demo-key",
                    use="enc",
                )
            ]
        },
    )
    verifier = AccessJWTVerifier(TEAM_DOMAIN, AUDIENCE)
    access_client = TestClient(create_app(verifier))

    response = access_client.get(
        "/inventory",
        headers={
            "Cf-Access-Jwt-Assertion": encode_token(access_claims(), private_key)
        },
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Access verification unavailable"}


def test_inventory_rejects_assertion_when_jwks_lacks_matching_kid(
    monkeypatch,
    signing_keys,
) -> None:
    private_key, _ = signing_keys
    patch_jwks_response(
        monkeypatch,
        {
            "keys": [
                public_jwk(
                    private_key.public_key(),
                    kid="other-key",
                    use="sig",
                )
            ]
        },
    )
    verifier = AccessJWTVerifier(TEAM_DOMAIN, AUDIENCE)
    access_client = TestClient(create_app(verifier))

    response = access_client.get(
        "/inventory",
        headers={
            "Cf-Access-Jwt-Assertion": encode_token(access_claims(), private_key)
        },
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Access assertion invalid"}


def test_inventory_returns_only_synthetic_record() -> None:
    response = client.get(
        "/inventory",
        headers={"Cf-Access-Jwt-Assertion": "valid.jwt.value"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "asset": "demo-laptop-042",
        "owner": "example-user",
        "classification": "ACME-SECRET-74291364",
    }


@pytest.mark.parametrize(
    "team_domain",
    [
        "",
        "demo.cloudflareaccess.com",
        "http://demo.cloudflareaccess.com",
        "https://",
        "https://user@demo.cloudflareaccess.com",
        "https://demo.cloudflareaccess.com:443",
        "https://example.com",
        "https://demo.cloudflareaccess.com/path",
        "https://demo.cloudflareaccess.com?query=value",
        "https://demo.cloudflareaccess.com#fragment",
        "https:\\demo.cloudflareaccess.com",
        "https://.cloudflareaccess.com",
        "https://demo..cloudflareaccess.com",
        "https://-demo.cloudflareaccess.com",
        "https://demo-.cloudflareaccess.com",
        "https://demo.other.cloudflareaccess.com",
        "HTTPS://demo.cloudflareaccess.com",
        "https://DEMO.cloudflareaccess.com",
    ],
)
def test_access_jwt_verifier_rejects_invalid_team_domain(team_domain) -> None:
    with pytest.raises(app.VerifierConfigurationError):
        AccessJWTVerifier(team_domain, AUDIENCE)


@pytest.mark.parametrize("audience", ["", "   ", " demo-audience", "demo-audience "])
def test_access_jwt_verifier_rejects_invalid_audience(audience) -> None:
    with pytest.raises(app.VerifierConfigurationError):
        AccessJWTVerifier(TEAM_DOMAIN, audience)


def test_access_jwt_verifier_normalizes_one_optional_trailing_slash() -> None:
    verifier = AccessJWTVerifier(f"{TEAM_DOMAIN}/", AUDIENCE)

    assert verifier.team_domain == TEAM_DOMAIN
    assert verifier.jwks.uri == f"{TEAM_DOMAIN}/cdn-cgi/access/certs"


def test_access_jwt_verifier_limits_jwks_requests_to_five_seconds(
    monkeypatch,
) -> None:
    observed_timeout = None

    def fake_urlopen(request, *, timeout, context):
        nonlocal observed_timeout
        observed_timeout = timeout
        return io.BytesIO(b'{"keys": []}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    verifier = AccessJWTVerifier(TEAM_DOMAIN, AUDIENCE)

    verifier.jwks.fetch_data()

    assert observed_timeout == 5


def test_access_jwt_verifier_accepts_valid_rs256_token(signing_keys) -> None:
    private_key, _ = signing_keys
    claims = access_claims()
    verifier = access_verifier(private_key.public_key())

    assert verifier.verify(encode_token(claims, private_key)) == claims


def test_access_jwt_verifier_rejects_wrong_signature(signing_keys) -> None:
    trusted_key, untrusted_key = signing_keys
    verifier = access_verifier(trusted_key.public_key())

    with pytest.raises(jwt.InvalidSignatureError):
        verifier.verify(encode_token(access_claims(), untrusted_key))


def test_access_jwt_verifier_rejects_wrong_issuer(signing_keys) -> None:
    private_key, _ = signing_keys
    claims = access_claims()
    claims["iss"] = "https://wrong.cloudflareaccess.com"
    verifier = access_verifier(private_key.public_key())

    with pytest.raises(jwt.InvalidIssuerError):
        verifier.verify(encode_token(claims, private_key))


def test_access_jwt_verifier_rejects_wrong_audience(signing_keys) -> None:
    private_key, _ = signing_keys
    claims = access_claims()
    claims["aud"] = ["wrong-audience"]
    verifier = access_verifier(private_key.public_key())

    with pytest.raises(jwt.InvalidAudienceError):
        verifier.verify(encode_token(claims, private_key))


def test_access_jwt_verifier_rejects_expired_token(signing_keys) -> None:
    private_key, _ = signing_keys
    claims = access_claims()
    claims["exp"] = int(time.time()) - 1
    verifier = access_verifier(private_key.public_key())

    with pytest.raises(jwt.ExpiredSignatureError):
        verifier.verify(encode_token(claims, private_key))


@pytest.mark.parametrize("required_claim", ["exp", "iat", "iss", "aud"])
def test_access_jwt_verifier_rejects_missing_required_claim(
    signing_keys, required_claim
) -> None:
    private_key, _ = signing_keys
    claims = access_claims()
    del claims[required_claim]
    verifier = access_verifier(private_key.public_key())

    with pytest.raises(jwt.MissingRequiredClaimError):
        verifier.verify(encode_token(claims, private_key))
