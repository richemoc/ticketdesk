from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RequesterCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    display_name: str = Field(min_length=1, max_length=160)


class RequesterResponse(RequesterCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    active: bool
    created_at: datetime


class TicketCreate(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    body: str | None = None
    requester_id: int = Field(gt=0)
    priority: int = Field(default=3, ge=1, le=5)


class TicketUpdate(BaseModel):
    subject: str | None = Field(default=None, min_length=1, max_length=200)
    body: str | None = None
    status: str | None = Field(default=None, pattern="^(open|pending|resolved|closed)$")
    priority: int | None = Field(default=None, ge=1, le=5)


class TicketResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    reference: str
    subject: str
    body: str | None
    status: str
    priority: int
    requester_id: int
    created_at: datetime


class CommentCreate(BaseModel):
    author: str = Field(min_length=1, max_length=160)
    body: str = Field(min_length=1)
    internal: bool = False


class CommentResponse(CommentCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ticket_id: int
    created_at: datetime
