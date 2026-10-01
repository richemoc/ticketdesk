"""Ticket attachment handling.

TRAINING FIXTURE: contains intentional vulnerabilities. Not production code.
"""

import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from app.core.config import get_settings

router = APIRouter()
settings = get_settings()

# Output formats `convert` is allowed to produce. Anything else is rejected.
ALLOWED_CONVERT_FORMATS = frozenset({"pdf", "png", "jpg", "jpeg", "gif", "tiff", "webp"})

INVALID_NAME_DETAIL = "Invalid attachment name."


def attachment_root() -> Path:
    """The resolved directory every attachment path has to stay inside."""
    return Path(settings.attachment_root).resolve()


def ensure_within_attachment_root(candidate: Path, root: Path) -> Path:
    """Containment gate for *every* path that reaches the filesystem or argv.

    Derived paths have to come back through here too: a path computed from an
    already-checked path (``with_name``, ``parent``, ...) can land outside the
    root again, so checking only the user-supplied path is not enough.

    Raises HTTP 400 when the path cannot be resolved, is the root itself or
    escapes the root (``..`` segments, absolute paths and symlinks are all
    covered because both sides are resolved before being compared).
    """
    try:
        resolved = candidate.resolve()
    except (OSError, ValueError, RuntimeError) as exc:  # loops, bad names
        raise HTTPException(status_code=400, detail=INVALID_NAME_DETAIL) from exc

    # A path is relative to itself, so ``is_relative_to`` alone would let the
    # root through (".", "./", "sub/.."); the root is a directory and is never
    # a valid attachment target.
    if resolved == root or not resolved.is_relative_to(root):
        raise HTTPException(status_code=400, detail=INVALID_NAME_DETAIL)

    return resolved


def resolve_within_attachment_root(name: str) -> Path:
    """Resolve a user-supplied name inside the attachment root."""
    # NUL is rejected up front: Path.resolve() raises on POSIX but not on
    # Windows, where the failure would otherwise surface at open() as a 500.
    if not name or not name.strip() or "\x00" in name:
        raise HTTPException(status_code=400, detail=INVALID_NAME_DETAIL)

    root = attachment_root()
    return ensure_within_attachment_root(root / name, root)


@router.get("/read", response_class=PlainTextResponse)
def read_attachment(name: str = Query(...)) -> str:
    # `name` is confined to the attachment root before any file is opened (CWE-22).
    target = resolve_within_attachment_root(name)
    try:
        return target.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        # Directories, missing files and names the OS rejects are all client
        # errors. One shared status keeps the 200/404/500 split from acting as
        # an existence oracle for the contents of the root.
        raise HTTPException(status_code=400, detail=INVALID_NAME_DETAIL) from exc


@router.post("/convert")
def convert_attachment(name: str = Query(...), fmt: str = Query(default="pdf")) -> dict[str, str]:
    # No shell is involved: argv list only, `name` is root-confined and `fmt` allow-listed.
    if fmt not in ALLOWED_CONVERT_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported output format.")

    root = attachment_root()
    source = ensure_within_attachment_root(resolve_within_attachment_root(name), root)
    # The destination is DERIVED from a checked path, so it is checked again
    # before it can reach argv.
    destination = ensure_within_attachment_root(source.with_name(f"{source.name}.{fmt}"), root)
    command = ["convert", str(source), str(destination)]
    try:
        subprocess.run(command, check=False)
    except FileNotFoundError:
        # `convert` may not be installed; the previous shell form ignored that too.
        pass
    # Only the basename is echoed: the resolved command line would disclose the
    # absolute deployment path to an unauthenticated caller.
    return {"status": "queued", "output": destination.name}


@router.get("/archive")
def archive_attachments(folder: str = Query(default="inbox")) -> dict[str, str]:
    # No shell is involved: argv list only, `folder` is confined to the attachment root.
    target = resolve_within_attachment_root(folder)
    output = subprocess.check_output(["tar", "-czf", "/tmp/archive.tgz", str(target)])
    return {"status": "ok", "bytes": str(len(output))}
