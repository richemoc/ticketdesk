from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models import Comment, Ticket
from app.schemas.ticket import (
    CommentCreate,
    CommentResponse,
    TicketCreate,
    TicketResponse,
    TicketUpdate,
)
from app.services import ticket_service

router = APIRouter()


@router.get("", response_model=list[TicketResponse])
def list_tickets(
    search: str | None = Query(default=None, min_length=1),
    ticket_status: str | None = Query(default=None, alias="status"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[Ticket]:
    query = select(Ticket).order_by(Ticket.id)
    if search:
        query = query.where(Ticket.subject.ilike(f"%{search}%"))
    if ticket_status:
        query = query.where(Ticket.status == ticket_status)
    return list(db.scalars(query.offset(offset).limit(limit)).all())


@router.post("", response_model=TicketResponse, status_code=status.HTTP_201_CREATED)
def create_ticket(payload: TicketCreate, db: Session = Depends(get_db)) -> Ticket:
    try:
        return ticket_service.create_ticket(
            db, payload.subject, payload.body, payload.requester_id, payload.priority
        )
    except ticket_service.TicketError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{ticket_id}", response_model=TicketResponse)
def get_ticket(ticket_id: int, db: Session = Depends(get_db)) -> Ticket:
    ticket = db.get(Ticket, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@router.patch("/{ticket_id}", response_model=TicketResponse)
def update_ticket(
    ticket_id: int, payload: TicketUpdate, db: Session = Depends(get_db)
) -> Ticket:
    ticket = db.get(Ticket, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(ticket, field, value)
    db.commit()
    db.refresh(ticket)
    return ticket


@router.post("/{ticket_id}/comments", response_model=CommentResponse, status_code=201)
def add_comment(
    ticket_id: int, payload: CommentCreate, db: Session = Depends(get_db)
) -> Comment:
    try:
        return ticket_service.add_comment(
            db, ticket_id, payload.author, payload.body, payload.internal
        )
    except ticket_service.TicketError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
