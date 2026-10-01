"""Regression tests for fixed security findings.

SEC-402dd344f6 / CWE-942: CORSMiddleware used allow_origins=["*"] together with
allow_credentials=True, so any site could make credentialed cross-origin calls
and read the responses.
"""

import contextlib
import importlib
import os

import pytest

from app.core import config as config_module
from app.core.config import Settings

ALLOWED_ORIGIN = "http://localhost:3000"
ALLOWED_ORIGINS = {"http://localhost:3000", "http://127.0.0.1:3000"}
HOSTILE_ORIGIN = "https://evil.example"


def test_disallowed_origin_gets_no_cors_grant(client):
    response = client.get("/health", headers={"Origin": HOSTILE_ORIGIN})
    allow_origin = response.headers.get("access-control-allow-origin")
    assert allow_origin != HOSTILE_ORIGIN
    assert allow_origin != "*"
    assert allow_origin is None


def test_disallowed_origin_preflight_is_refused(client):
    response = client.options(
        "/api/v1/tickets",
        headers={
            "Origin": HOSTILE_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    allow_origin = response.headers.get("access-control-allow-origin")
    assert allow_origin != HOSTILE_ORIGIN
    assert allow_origin != "*"


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"method": "GET", "url": "/health", "headers": {"Origin": ALLOWED_ORIGIN}},
        {"method": "GET", "url": "/health", "headers": {"Origin": HOSTILE_ORIGIN}},
        {
            "method": "OPTIONS",
            "url": "/api/v1/tickets",
            "headers": {
                "Origin": HOSTILE_ORIGIN,
                "Access-Control-Request-Method": "POST",
            },
        },
    ],
)
def test_credentials_never_granted_to_wildcard_or_unlisted_origin(client, request_kwargs):
    response = client.request(**request_kwargs)
    allow_origin = response.headers.get("access-control-allow-origin")
    allow_credentials = response.headers.get("access-control-allow-credentials")
    # "*" and credentials must never be emitted together.
    assert not (allow_origin == "*" and allow_credentials == "true")
    if allow_origin is not None and allow_credentials == "true":
        # A credentialed grant is only ever legitimate for an allow-listed origin.
        assert allow_origin in ALLOWED_ORIGINS


def test_allowed_origin_still_works(client):
    response = client.get("/health", headers={"Origin": ALLOWED_ORIGIN})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN

    preflight = client.options(
        "/api/v1/tickets",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    assert "POST" in preflight.headers.get("access-control-allow-methods", "")


def test_settings_never_allow_credentials_with_wildcard_or_empty_origins():
    assert "*" not in Settings().cors_origins
    assert Settings(cors_allowed_origins="*").cors_allow_credentials is False
    assert Settings(cors_allowed_origins="https://app.example,*").cors_allow_credentials is False
    assert Settings(cors_allowed_origins="").cors_allow_credentials is False
    assert Settings(cors_allowed_origins="https://app.example").cors_allow_credentials is True


@contextlib.contextmanager
def app_configured_with(cors_allowed_origins: str):
    """Rebuild the real app/main.py application with a given CORS_ALLOWED_ORIGINS value.

    get_settings is lru_cache'd and app.main binds the middleware at import time, so the
    cache has to be cleared and the module reloaded for the override to take effect.
    """
    import app.main

    previous = os.environ.get("CORS_ALLOWED_ORIGINS")
    os.environ["CORS_ALLOWED_ORIGINS"] = cors_allowed_origins
    config_module.get_settings.cache_clear()
    try:
        yield importlib.reload(app.main).app
    finally:
        if previous is None:
            os.environ.pop("CORS_ALLOWED_ORIGINS", None)
        else:
            os.environ["CORS_ALLOWED_ORIGINS"] = previous
        config_module.get_settings.cache_clear()
        importlib.reload(app.main)


@pytest.mark.parametrize(
    "cors_allowed_origins, expected_origins, expected_credentials",
    [
        ("*", [], False),
        (" * ", [], False),
        # A dropped entry also costs the surviving origins their credentialed grant.
        ("*,https://a.example", ["https://a.example"], False),
        ("https://a.example, * ", ["https://a.example"], False),
        ("*,*", [], False),
        # The opaque "null" origin (sandboxed iframes, file:// pages) is not allow-listable.
        ("null", [], False),
        ("NULL", [], False),
        ("https://a.example,null", ["https://a.example"], False),
        ("", [], False),
        ("https://a.example", ["https://a.example"], True),
    ],
)
def test_wildcard_and_null_entries_never_enter_the_allow_list(
    cors_allowed_origins, expected_origins, expected_credentials
):
    settings = Settings(cors_allowed_origins=cors_allowed_origins)
    assert settings.cors_origins == expected_origins
    assert "*" not in settings.cors_origins
    assert "null" not in settings.cors_origins
    assert settings.cors_allow_credentials is expected_credentials


@pytest.mark.parametrize("cors_allowed_origins", ["*", " * ", "*,https://a.example", "null"])
def test_wildcard_config_cannot_make_the_middleware_allow_all(cors_allowed_origins):
    """A wildcard in config must not reach CORSMiddleware: starlette would allow every origin."""
    from fastapi.testclient import TestClient

    with app_configured_with(cors_allowed_origins) as configured_app:
        with TestClient(configured_app) as wildcard_client:
            simple = wildcard_client.get("/health", headers={"Origin": HOSTILE_ORIGIN})
            assert simple.headers.get("access-control-allow-origin") != "*"
            assert simple.headers.get("access-control-allow-origin") != HOSTILE_ORIGIN
            assert simple.headers.get("access-control-allow-origin") is None

            opaque = wildcard_client.get("/health", headers={"Origin": "null"})
            assert opaque.headers.get("access-control-allow-origin") != "*"
            assert opaque.headers.get("access-control-allow-origin") != "null"

            preflight = wildcard_client.options(
                "/api/v1/tickets",
                headers={
                    "Origin": HOSTILE_ORIGIN,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
            )
            allow_origin = preflight.headers.get("access-control-allow-origin")
            assert allow_origin != "*"
            assert allow_origin != HOSTILE_ORIGIN


def test_wildcard_config_still_honours_the_concrete_origins_beside_it():
    """Dropping "*" must not drop the legitimate entries configured next to it."""
    from fastapi.testclient import TestClient

    with app_configured_with("*,https://a.example") as configured_app:
        with TestClient(configured_app) as mixed_client:
            response = mixed_client.get("/health", headers={"Origin": "https://a.example"})
            assert response.status_code == 200
            assert response.headers.get("access-control-allow-origin") == "https://a.example"
            assert response.headers.get("access-control-allow-credentials") != "true"

            hostile = mixed_client.get("/health", headers={"Origin": HOSTILE_ORIGIN})
            assert hostile.headers.get("access-control-allow-origin") is None
