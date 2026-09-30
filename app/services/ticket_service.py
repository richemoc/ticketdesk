import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Comment, Requester, Ticket


class TicketError(Exception):
    pass


def generate_reference() -> str:
    return f"TD-{secrets.token_hex(4).upper()}"


def create_ticket(
    db: Session, subject: str, body: str | None, requester_id: int, priority: int
) -> Ticket:
    if db.get(Requester, requester_id) is None:
        raise TicketError("Requester not found")
    ticket = Ticket(
        reference=generate_reference(),
        subject=subject,
        body=body,
        requester_id=requester_id,
        priority=priority,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


def add_comment(db: Session, ticket_id: int, author: str, body: str, internal: bool) -> Comment:
    if db.get(Ticket, ticket_id) is None:
        raise TicketError("Ticket not found")
    comment = Comment(ticket_id=ticket_id, author=author, body=body, internal=internal)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


def list_open_tickets(db: Session, limit: int = 50) -> list[Ticket]:
    query = (
        select(Ticket)
        .where(Ticket.status.in_(("open", "pending")))
        .order_by(Ticket.priority, Ticket.id)
        .limit(limit)
    )
    return list(db.scalars(query).all())
