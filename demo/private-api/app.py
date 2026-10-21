import json
import logging
import os
import re
from functools import lru_cache
from typing import Protocol

import jwt
from fastapi import FastAPI, Header, HTTPException
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError, PyJWKSetError


LOGGER = logging.getLogger("demo-private-api")
SYNTHETIC_RECORD = {
    "asset": "demo-laptop-042",
    "owner": "example-user",
    "classification": "ACME-SECRET-74291364",
}
ACCESS_TEAM_DOMAIN_PATTERN = re.compile(
    r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com/?"
)


class TokenVerifier(Protocol):
    def verify(self, token: str) -> dict[str, object]: ...


class JWKSAvailabilityError(Exception):
    pass


class VerifierConfigurationError(Exception):
    pass


class AccessJWKClient(PyJWKClient):
    def get_jwk_set(self, refresh: bool = False) -> jwt.PyJWKSet:
        try:
            return super().get_jwk_set(refresh)
        except PyJWKClientConnectionError:
            raise
        except (UnicodeDecodeError, PyJWKClientError, PyJWKSetError) as error:
            raise JWKSAvailabilityError from error

    def get_signing_keys(self, refresh: bool = False) -> list[jwt.PyJWK]:
        try:
            return super().get_signing_keys(refresh)
        except PyJWKClientError as error:
            raise JWKSAvailabilityError from error


class AccessJWTVerifier:
    def __init__(self, team_domain: str, audience: str) -> None:
        if ACCESS_TEAM_DOMAIN_PATTERN.fullmatch(team_domain) is None:
            raise VerifierConfigurationError("invalid Access team domain")
        if not audience or audience != audience.strip():
            raise VerifierConfigurationError("invalid Access audience")

        self.team_domain = team_domain.removesuffix("/")
        self.audience = audience
        self.jwks = AccessJWKClient(
            f"{self.team_domain}/cdn-cgi/access/certs",
            timeout=5,
        )

    def verify(self, token: str) -> dict[str, object]:
        signing_key = self.jwks.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.team_domain,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )


@lru_cache(maxsize=1)
def default_verifier() -> AccessJWTVerifier:
    return AccessJWTVerifier(
        os.environ["ACCESS_TEAM_DOMAIN"],
        os.environ["ACCESS_AUDIENCE"],
    )


def create_app(verifier: TokenVerifier | None = None) -> FastAPI:
    app = FastAPI(title="Demo Agent Private API", docs_url=None, redoc_url=None)

    def configured_verifier() -> TokenVerifier:
        return verifier if verifier is not None else default_verifier()

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def ready() -> dict[str, str]:
        try:
            configured_verifier()
        except (KeyError, VerifierConfigurationError) as error:
            LOGGER.error(
                "access verifier configuration unavailable: %s",
                type(error).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail="Access verification unavailable",
            ) from error
        return {"status": "ready"}

    @app.get("/inventory")
    def inventory(
        cf_access_jwt_assertion: str | None = Header(default=None),
    ) -> dict[str, str]:
        if not cf_access_jwt_assertion:
            raise HTTPException(status_code=401, detail="Access assertion required")
        try:
            active_verifier = configured_verifier()
        except (KeyError, VerifierConfigurationError) as error:
            LOGGER.error(
                "access verifier configuration unavailable: %s",
                type(error).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail="Access verification unavailable",
            ) from error
        try:
            active_verifier.verify(cf_access_jwt_assertion)
        except (
            json.JSONDecodeError,
            JWKSAvailabilityError,
            PyJWKClientConnectionError,
            PyJWKSetError,
        ) as error:
            LOGGER.warning("access verifier unavailable: %s", type(error).__name__)
            raise HTTPException(
                status_code=503,
                detail="Access verification unavailable",
            ) from error
        except (jwt.PyJWTError, ValueError) as error:
            LOGGER.warning("access assertion rejected: %s", type(error).__name__)
            raise HTTPException(status_code=401, detail="Access assertion invalid") from error
        except Exception as error:
            LOGGER.error("access verifier internal error: %s", type(error).__name__)
            raise HTTPException(status_code=500, detail="Internal server error") from error
        LOGGER.info("authorized synthetic inventory request")
        return SYNTHETIC_RECORD.copy()

    return app


app = create_app()
