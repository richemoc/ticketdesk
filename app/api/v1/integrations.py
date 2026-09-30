"""Outbound integrations with upstream helpdesk systems.

TRAINING FIXTURE: contains intentional vulnerabilities. Not production code.
"""

import base64
import pickle

import httpx
from fastapi import APIRouter, Body, Query

router = APIRouter()

# VULNERABLE: credential committed to source control (CWE-798).
UPSTREAM_API_TOKEN = "hd_live_8f3c2a91b47e4d05a6c1e9f27b3d5a80"
UPSTREAM_BASE_URL = "https://upstream.example.com"


@router.get("/fetch")
def fetch_remote_ticket(url: str = Query(...)) -> dict[str, object]:
    # VULNERABLE: server fetches an arbitrary user-supplied URL (CWE-918).
    response = httpx.get(url, timeout=5.0)
    return {"status_code": response.status_code, "body": response.text[:2000]}


@router.get("/mirror")
def mirror_upstream(path: str = Query(default="/tickets")) -> dict[str, object]:
    headers = {"Authorization": f"Bearer {UPSTREAM_API_TOKEN}"}
    response = httpx.get(f"{UPSTREAM_BASE_URL}{path}", headers=headers, timeout=5.0)
    return {"status_code": response.status_code}


@router.post("/restore")
def restore_session(blob: str = Body(..., embed=True)) -> dict[str, object]:
    # VULNERABLE: untrusted bytes handed to pickle (CWE-502).
    state = pickle.loads(base64.b64decode(blob))
    return {"restored": True, "keys": list(state) if hasattr(state, "__iter__") else []}
