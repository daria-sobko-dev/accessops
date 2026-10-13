"""accessops-api: a tiny internal HTTP service, so n8n can run cleanup and drift on a schedule.

It runs in its own container with no published port: only containers in the same compose
network (n8n) can reach it, by name: http://accessops-api:8000.
Every endpoint except /health needs the header  Authorization: Bearer <ACCESSOPS_API_TOKEN>.

Run in the container: python -m accessops.api
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Protocol

import httpx
import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from accessops.clock import Clock, utcnow
from accessops.envfile import read_env, set_env_var
from accessops.errors import AccessOpsError, BusyError, ConfigError
from accessops.service import CleanupItem

TOKEN_VAR = "ACCESSOPS_API_TOKEN"
SSH_KEY_VAR = "ANSIBLE_SSH_PRIVATE_KEY_B64"
MIN_TOKEN_LENGTH = 32
PROBLEM_CATEGORIES = ("extra", "missing", "role_mismatch")

log = logging.getLogger("accessops.api")

# auto_error=False: we answer 401 ourselves, the same way for a missing and a wrong token.
_bearer = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]


class Jobs(Protocol):
    def cleanup(self) -> list[CleanupItem]: ...

    def drift(self) -> list[tuple[str, str, str, str, str]]: ...


def bootstrap_secrets(env_file: Path, service_key: Path, *, rotate: bool = False) -> list[str]:
    """Put the API token and the Ansible key (for the compose secret) into .env.

    The token is created once and kept (n8n stores a copy); --rotate makes a new one.
    The key is stored as one base64 line: .env values must stay on a single line.
    Nothing secret is returned: only what was done.
    """
    if not service_key.exists():
        raise ConfigError("Ansible service key is missing: run python -m accessops ssh-bootstrap.")
    steps = []
    current = read_env(env_file).get(TOKEN_VAR, "")
    if rotate or len(current) < MIN_TOKEN_LENGTH:
        set_env_var(env_file, TOKEN_VAR, secrets.token_urlsafe(32), "Token for accessops-api")
        steps.append(f"{'rotated' if current else 'created'} {TOKEN_VAR} in .env")
    else:
        steps.append(f"{TOKEN_VAR} already in .env (use --rotate for a new one)")
    encoded = base64.b64encode(service_key.read_bytes()).decode("ascii")
    set_env_var(
        env_file, SSH_KEY_VAR, encoded,
        "Ansible service key for accessops-api, passed as a compose secret (not in the image)",
    )  # fmt: skip
    steps.append(f"stored the Ansible service key in .env as {SSH_KEY_VAR} (base64)")
    return steps


# ---- response schemas (what n8n can rely on) ---------------------------------------


class RevokedGrant(BaseModel):
    subject: str
    system: str
    role: str
    expires_at: datetime | None


class FailedGrant(RevokedGrant):
    error: str


class CleanupResponse(BaseModel):
    status: Literal["ok", "failed"]
    checked_at: datetime
    revoked: list[RevokedGrant]
    errors: list[FailedGrant]


class DriftProblem(BaseModel):
    category: Literal["extra", "missing", "role_mismatch"]
    system: str
    subject: str
    expected_role: str
    actual_role: str


class ForeignAccount(BaseModel):
    system: str
    subject: str


class DriftResponse(BaseModel):
    checked_at: datetime
    problems: list[DriftProblem]
    foreign: list[ForeignAccount]


class StatusResponse(BaseModel):
    status: Literal["ok", "busy", "error"]
    detail: str = ""


# ---- app ------------------------------------------------------------------------------


def _safe_error(exc: Exception) -> str:
    # Known error types carry messages meant for people; anything else: only its type.
    if isinstance(exc, AccessOpsError | psycopg.Error | httpx.HTTPError):
        return f"{type(exc).__name__}: {exc}"[:300]
    return type(exc).__name__


def create_app(token: str, jobs: Jobs, *, clock: Clock = utcnow) -> FastAPI:
    if len(token) < MIN_TOKEN_LENGTH:
        raise ConfigError(f"{TOKEN_VAR} must be at least {MIN_TOKEN_LENGTH} characters.")
    expected = token.encode()

    def require_token(credentials: BearerCredentials) -> None:
        # compare_digest takes the same time for any wrong token: no guessing by timing.
        given = credentials.credentials.encode() if credentials else b""
        if not secrets.compare_digest(given, expected):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    app = FastAPI(title="accessops-api", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(Exception)
    async def failed(request: Request, exc: Exception) -> JSONResponse:
        log.exception("%s %s failed", request.method, request.url.path)
        body = StatusResponse(status="error", detail=_safe_error(exc))
        return JSONResponse(status_code=500, content=body.model_dump())

    @app.get("/health")
    def health() -> StatusResponse:
        return StatusResponse(status="ok")

    @app.post(
        "/cleanup",
        dependencies=[Depends(require_token)],
        response_model=CleanupResponse,
        responses={409: {"model": StatusResponse}},
    )
    def cleanup() -> CleanupResponse | JSONResponse:
        checked_at = clock()
        try:
            items = jobs.cleanup()
        except BusyError as exc:
            body = StatusResponse(status="busy", detail=str(exc))
            return JSONResponse(status_code=409, content=body.model_dump())
        revoked = [
            RevokedGrant(
                subject=i.grant.subject,
                system=i.grant.system,
                role=i.grant.role,
                expires_at=i.grant.expires_at,
            )
            for i in items
            if i.result == "revoked"
        ]
        errors = [
            FailedGrant(
                subject=i.grant.subject,
                system=i.grant.system,
                role=i.grant.role,
                expires_at=i.grant.expires_at,
                error="; ".join(i.steps) or "unknown error",
            )
            for i in items
            if i.result == "error"
        ]
        return CleanupResponse(
            status="failed" if errors else "ok",
            checked_at=checked_at,
            revoked=revoked,
            errors=errors,
        )

    @app.get("/drift", dependencies=[Depends(require_token)])
    def drift() -> DriftResponse:
        checked_at = clock()
        rows = jobs.drift()
        problems = [
            DriftProblem(
                category=category,
                system=system,
                subject=subject,
                expected_role=expected,
                actual_role=actual,
            )
            for category, system, subject, expected, actual in rows
            if category in PROBLEM_CATEGORIES
        ]
        foreign = [
            ForeignAccount(system=system, subject=subject)
            for category, system, subject, _, _ in rows
            if category == "foreign"
        ]
        return DriftResponse(checked_at=checked_at, problems=problems, foreign=foreign)

    return app


def main() -> None:
    import uvicorn

    from accessops.catalog import load_catalog
    from accessops.config import load_settings
    from accessops.wiring import LiveJobs

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # httpx logs every request URL at INFO; keep it quiet in case a URL ever holds a secret.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    settings = load_settings()
    catalog = load_catalog(settings.catalog_path)
    app = create_app(os.environ.get(TOKEN_VAR, ""), LiveJobs(settings, catalog))
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")


if __name__ == "__main__":
    main()
