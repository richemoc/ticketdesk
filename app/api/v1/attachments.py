"""Ticket attachment handling.

TRAINING FIXTURE: contains intentional vulnerabilities. Not production code.
"""

import subprocess
from pathlib import Path

from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse

from app.core.config import get_settings

router = APIRouter()
settings = get_settings()


@router.get("/read", response_class=PlainTextResponse)
def read_attachment(name: str = Query(...)) -> str:
    # VULNERABLE: user-controlled path joined without containment check (CWE-22).
    target = Path(settings.attachment_root) / name
    return target.read_text(encoding="utf-8")


@router.post("/convert")
def convert_attachment(name: str = Query(...), fmt: str = Query(default="pdf")) -> dict[str, str]:
    # VULNERABLE: user input interpolated into a shell command line (CWE-78).
    command = f"convert {settings.attachment_root}/{name} {settings.attachment_root}/{name}.{fmt}"
    subprocess.run(command, shell=True, check=False)
    return {"status": "queued", "command": command}


@router.get("/archive")
def archive_attachments(folder: str = Query(default="inbox")) -> dict[str, str]:
    # VULNERABLE: shell metacharacters in `folder` reach the shell (CWE-78).
    output = subprocess.check_output(
        "tar -czf /tmp/archive.tgz " + settings.attachment_root + "/" + folder,
        shell=True,
    )
    return {"status": "ok", "bytes": str(len(output))}
