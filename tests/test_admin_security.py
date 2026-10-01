"""Regression tests for fixed security findings.

SEC-fd39b1d585 (CWE-489): GET /api/v1/admin/debug returned the process
environment and cwd to any caller. The route was removed.
SEC-560bd48e8f (CWE-209): GET /api/v1/admin/reindex returned str(exc) plus a
full traceback to the caller. The failure is now logged server-side and the
caller gets a generic HTTP 500.
"""

import logging
import os

from app.db.session import get_db
from app.main import app

CANARY_NAME = "TICKETDESK_REGRESSION_CANARY"
CANARY_VALUE = "canary-4f1b9a27-do-not-disclose"

# Marker strings that must never leave the process through an HTTP response.
_INTERNAL_MARKERS = (
    "Traceback (most recent call last)",
    "traceback",
    "sqlalchemy",
    "app/api/v1/admin.py",
    r"app\\api\\v1\\admin.py",
)


def _openapi_paths(client) -> dict:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    return response.json()["paths"]


def _collect_get_paths(client) -> list[str]:
    """Every registered GET route that takes no path parameter."""
    return [
        path
        for path, operations in _openapi_paths(client).items()
        if "get" in operations and "{" not in path
    ]


def test_admin_debug_route_is_gone(client) -> None:
    """SEC-fd39b1d585: the debug endpoint must not exist."""
    response = client.get("/api/v1/admin/debug")

    assert response.status_code == 404, (
        f"debug endpoint still answers with HTTP {response.status_code}"
    )
    assert CANARY_NAME not in response.text, "debug endpoint disclosed an env var name"

    assert "/api/v1/admin/debug" not in _openapi_paths(client)


def test_no_endpoint_discloses_environment_variables(client, monkeypatch) -> None:
    """SEC-fd39b1d585: no response anywhere leaks an env var name or value."""
    monkeypatch.setenv(CANARY_NAME, CANARY_VALUE)

    # Sanity check: the canary really is in the process environment, so a leak
    # of dict(os.environ) would be observable.
    assert os.environ[CANARY_NAME] == CANARY_VALUE

    checked = 0
    for path in ["/openapi.json", *_collect_get_paths(client)]:
        try:
            response = client.get(path)
        except Exception:
            # Endpoint needs external resources; it cannot be reached here.
            continue
        checked += 1
        body = response.text
        # Booleans keep a leaking body out of the failure report.
        name_leaked = CANARY_NAME in body
        value_leaked = CANARY_VALUE in body
        cwd_leaked = os.getcwd() in body
        assert not name_leaked, f"{path} disclosed an env var name"
        assert not value_leaked, f"{path} disclosed an env var value"
        assert not cwd_leaked, f"{path} disclosed the process cwd"

    assert checked > 0, "no reachable GET endpoints were exercised"


def test_reindex_failure_returns_generic_error(client, caplog) -> None:
    """SEC-560bd48e8f: a db failure must not leak exception text or a traceback."""
    secret_text = (
        "OperationalError: FATAL: password authentication failed for user "
        "'ticketdesk' (postgresql://ticketdesk:s3cr3t@10.0.0.7:5432/ticketdesk)"
    )

    class ExplodingSession:
        def query(self, *args, **kwargs):
            raise RuntimeError(secret_text)

    def _override_get_db():
        yield ExplodingSession()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with caplog.at_level(logging.ERROR, logger="app.api.v1.admin"):
            response = client.get("/api/v1/admin/reindex")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 500, (
        f"reindex failure answered with HTTP {response.status_code}"
    )

    body = response.text
    for leak in (
        secret_text,
        "password authentication failed",
        "postgresql://",
        "s3cr3t",
        "RuntimeError",
        *_INTERNAL_MARKERS,
    ):
        leaked = leak.lower() in body.lower()
        assert not leaked, f"reindex response leaked {leak[:32]!r}"

    payload = response.json()
    assert "trace" not in payload
    detail = str(payload.get("detail", ""))
    assert detail == "Reindex failed"

    # The error must be recorded server-side, not swallowed.
    assert any(
        record.levelno >= logging.ERROR and record.exc_info is not None
        for record in caplog.records
    ), "reindex failure was not logged with its traceback"
