from app.db.session import SessionLocal
from app.models import Requester


def _make_requester() -> int:
    db = SessionLocal()
    try:
        requester = Requester(
            email=f"user{db.query(Requester).count() + 1}@example.com",
            display_name="Test User",
        )
        db.add(requester)
        db.commit()
        db.refresh(requester)
        return requester.id
    finally:
        db.close()


def test_create_and_fetch_ticket(client) -> None:
    requester_id = _make_requester()

    created = client.post(
        "/api/v1/tickets",
        json={"subject": "Printer offline", "body": "Floor 3", "requester_id": requester_id},
    )
    assert created.status_code == 201
    ticket = created.json()
    assert ticket["subject"] == "Printer offline"
    assert ticket["status"] == "open"
    assert ticket["reference"].startswith("TD-")

    fetched = client.get(f"/api/v1/tickets/{ticket['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == ticket["id"]


def test_create_ticket_unknown_requester(client) -> None:
    response = client.post(
        "/api/v1/tickets",
        json={"subject": "Orphan", "requester_id": 999999},
    )
    assert response.status_code == 404


def test_update_ticket_status(client) -> None:
    requester_id = _make_requester()
    created = client.post(
        "/api/v1/tickets",
        json={"subject": "Password reset", "requester_id": requester_id},
    )
    ticket_id = created.json()["id"]

    updated = client.patch(f"/api/v1/tickets/{ticket_id}", json={"status": "resolved"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "resolved"


def test_add_comment(client) -> None:
    requester_id = _make_requester()
    created = client.post(
        "/api/v1/tickets",
        json={"subject": "VPN drops", "requester_id": requester_id},
    )
    ticket_id = created.json()["id"]

    comment = client.post(
        f"/api/v1/tickets/{ticket_id}/comments",
        json={"author": "agent@example.com", "body": "Investigating", "internal": True},
    )
    assert comment.status_code == 201
    assert comment.json()["ticket_id"] == ticket_id


def test_list_tickets_filters_by_status(client) -> None:
    response = client.get("/api/v1/tickets", params={"status": "open"})
    assert response.status_code == 200
    assert all(t["status"] == "open" for t in response.json())
