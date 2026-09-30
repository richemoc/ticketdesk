"""Ticket attachment handling.

TRAINING FIXTURE: contains intentional vulnerabilities. Not production code.
"""

import shlex
import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from app.core.config import get_settings

router = APIRouter()
settings = get_settings()

# Output formats `convert` is allowed to produce. Anything else is rejected.
ALLOWED_CONVERT_FORMATS = frozenset({"pdf", "png", "jpg", "jpeg", "gif", "tiff", "webp"})


def resolve_within_attachment_root(name: str) -> Path:
    """Resolve a user-supplied name inside the attachment root.

    Returns the fully resolved path. Raises HTTP 400 when the name is empty or
    escapes the attachment root (``..`` segments, absolute paths and symlinks
    are all covered because both sides are resolved before being compared).
    """
    if not name or not name.strip():
        raise HTTPException(status_code=400, detail="Invalid attachment name.")

    root = Path(settings.attachment_root).resolve()
    try:
        candidate = (root / name).resolve()
    except (OSError, ValueError, RuntimeError) as exc:  # NUL bytes, loops, bad names
        raise HTTPException(status_code=400, detail="Invalid attachment name.") from exc

    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Invalid attachment name.")

    return candidate


@router.get("/read", response_class=PlainTextResponse)
def read_attachment(name: str = Query(...)) -> str:
    # `name` is confined to the attachment root before any file is opened (CWE-22).
    target = resolve_within_attachment_root(name)
    return target.read_text(encoding="utf-8")


@router.post("/convert")
def convert_attachment(name: str = Query(...), fmt: str = Query(default="pdf")) -> dict[str, str]:
    # No shell is involved: argv list only, `name` is root-confined and `fmt` allow-listed.
    if fmt not in ALLOWED_CONVERT_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported output format.")

    source = resolve_within_attachment_root(name)
    destination = source.with_name(f"{source.name}.{fmt}")
    command = ["convert", str(source), str(destination)]
    try:
        subprocess.run(command, check=False)
    except FileNotFoundError:
        # `convert` may not be installed; the previous shell form ignored that too.
        pass
    return {"status": "queued", "command": shlex.join(command)}


@router.get("/archive")
def archive_attachments(folder: str = Query(default="inbox")) -> dict[str, str]:
    # No shell is involved: argv list only, `folder` is confined to the attachment root.
    target = resolve_within_attachment_root(folder)
    output = subprocess.check_output(["tar", "-czf", "/tmp/archive.tgz", str(target)])
    return {"status": "ok", "bytes": str(len(output))}
