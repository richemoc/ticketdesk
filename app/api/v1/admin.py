"""Administrative endpoints.

TRAINING FIXTURE: contains intentional vulnerabilities. Not production code.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models import Requester, Ticket

logger = logging.getLogger(__name__)

router = APIRouter()


@router.delete("/tickets/{ticket_id}")
def purge_ticket(ticket_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    # VULNERABLE: destructive admin action with no authentication or role check (CWE-862).
    ticket = db.get(Ticket, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    db.delete(ticket)
    db.commit()
    return {"status": "deleted", "ticket_id": str(ticket_id)}


@router.get("/requesters")
def dump_requesters(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    # VULNERABLE: exposes every requester record to any caller (CWE-862).
    rows = db.query(Requester).all()
    return [{"id": r.id, "email": r.email, "display_name": r.display_name} for r in rows]


@router.get("/reindex")
def reindex(db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        count = db.query(Ticket).count()
        return {"status": "ok", "indexed": count}
    except Exception:
        # Log the failure with its traceback server-side only; the caller gets a
        # generic message so internal details are never disclosed (CWE-209).
        logger.exception("Reindex failed")
        raise HTTPException(status_code=500, detail="Reindex failed") from None
