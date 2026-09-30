"""Regression tests for fixed security findings.

SEC-402dd344f6 / CWE-942: CORSMiddleware used allow_origins=["*"] together with
allow_credentials=True, so any site could make credentialed cross-origin calls
and read the responses.
"""

import pytest

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
