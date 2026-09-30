# Ticketdesk API

A FastAPI backend for support tickets, requesters, comments and attachments.

> ## ⚠ SECURITY TRAINING FIXTURE — DO NOT DEPLOY
>
> This repository contains **intentional, unpatched vulnerabilities**. It exists to
> exercise the auto-remediation pipeline end to end: triage must find the planted
> findings genuinely present at the cited lines, the fixer must repair them, and the
> validation gates must prove the repair.
>
> Every vulnerable sink is marked with a `# VULNERABLE:` comment naming its CWE.
> Do not run this against a real network, and do not copy code out of
> `app/api/v1/reports.py`, `attachments.py`, `integrations.py`, `admin.py` or
> `app/core/security.py`.

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
