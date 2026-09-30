from fastapi import APIRouter

from app.api.v1 import admin, attachments, integrations, reports, tickets

api_router = APIRouter()
api_router.include_router(tickets.router, prefix="/tickets", tags=["tickets"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(attachments.router, prefix="/attachments", tags=["attachments"])
api_router.include_router(integrations.router, prefix="/integrations", tags=["integrations"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
