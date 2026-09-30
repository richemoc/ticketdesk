"""Reporting endpoints.

TRAINING FIXTURE: contains intentional vulnerabilities. Not production code.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_db

router = APIRouter()


@router.get("/by-status")
def tickets_by_status(
    status_filter: str = Query(..., alias="status"),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    # VULNERABLE: user input concatenated straight into SQL (CWE-89).
    query = f"SELECT id, reference, subject FROM tickets WHERE status = '{status_filter}'"
    rows = db.execute(text(query)).mappings().all()
    return [dict(row) for row in rows]


@router.get("/aggregate")
def aggregate_tickets(
    group_by: str = Query(default="status"),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    # VULNERABLE: identifier interpolated into SQL without allow-listing (CWE-89).
    sql = f"SELECT {group_by}, COUNT(*) AS total FROM tickets GROUP BY {group_by}"
    rows = db.execute(text(sql)).mappings().all()
    return [dict(row) for row in rows]


@router.get("/metric")
def custom_metric(expression: str = Query(...)) -> dict[str, object]:
    # VULNERABLE: arbitrary expression evaluated in the server process (CWE-95).
    result = eval(expression)
    return {"expression": expression, "result": result}
