# Ticketdesk API

A FastAPI backend for support tickets, requesters, comments and attachments.

## Local setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[dev]"
copy .env.example .env
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`, docs at `/docs`.

## Tests

```powershell
pytest
```

Six tests cover the clean ticket CRUD paths only. They are the green baseline the
validator compares against — none of them exercise a vulnerable endpoint, so a
correct fix must leave all six passing.

## Layout

| Path | Contains |
|---|---|
| `app/api/v1/tickets.py` | clean CRUD — no planted findings |
| `app/services/ticket_service.py` | clean service layer — no planted findings |
| `app/api/v1/reports.py` | SQL injection, `eval` |
| `app/api/v1/attachments.py` | path traversal, command injection |
| `app/api/v1/integrations.py` | SSRF, hard-coded credential, unsafe deserialization |
| `app/api/v1/admin.py` | missing authorization, debug exposure, error disclosure |
| `app/core/security.py` | weak hash, predictable token |
| `app/main.py` | permissive CORS |
