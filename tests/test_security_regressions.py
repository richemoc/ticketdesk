"""Regression tests for the attachment endpoints.

SEC-f7f13d953a (CWE-22), SEC-79f9c8c625 (CWE-78), SEC-11e7e45aa1 (CWE-78).

These tests never invoke `convert` or `tar`; the external binaries do not have
to exist. `subprocess` is recorded instead so the tests can assert on how the
command is CONSTRUCTED (argv list, no shell) and on the input validation.
"""

import os
import subprocess
from pathlib import Path

import pytest

from app.api.v1 import attachments

# Names that resolve to the attachment root ITSELF. The root is not a valid
# attachment target: `is_relative_to` alone lets it through (a path is relative
# to itself) and /convert then derives a destination OUTSIDE the root.
ROOT_ITSELF_NAMES = [".", "./", "sub/..", ".."]

# A backslash is a path separator only on Windows; on POSIX it is an ordinary
# filename character, so the same payload has to be asserted differently.
WINDOWS_TRAVERSAL = r"..\secret.txt"

SHELL_PAYLOADS = [
    "note.txt; rm -rf /",
    "note.txt$(id)",
    "note.txt`id`",
    "note.txt && whoami",
    "note.txt | cat /etc/passwd",
]


@pytest.fixture
def attachment_root(tmp_path, monkeypatch):
    """Point the attachment root at an empty temp dir with a secret next to it."""
    root = tmp_path / "attachments"
    root.mkdir()
    (root / "note.txt").write_text("legitimate attachment", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("TOP-SECRET-OUTSIDE-ROOT", encoding="utf-8")
    monkeypatch.setattr(attachments.settings, "attachment_root", str(root))
    return root


@pytest.fixture
def recorded_calls(monkeypatch):
    """Capture subprocess invocations instead of executing them."""
    calls: list[tuple[object, dict]] = []

    def fake_run(args, *rest, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)

    def fake_check_output(args, *rest, **kwargs):
        calls.append((args, kwargs))
        return b""

    monkeypatch.setattr(attachments.subprocess, "run", fake_run)
    monkeypatch.setattr(attachments.subprocess, "check_output", fake_check_output)
    return calls


def assert_paths_confined(calls, root):
    """Every path argv entry must stay strictly inside the attachment root.

    Checked on the DESTINATION too, not just the source: the destination is
    derived from the source and can escape on its own.
    """
    root = Path(root).resolve()
    for args, _ in calls:
        for arg in args[1:]:
            if arg.startswith("-") or arg == "/tmp/archive.tgz":
                continue
            resolved = Path(arg).resolve()
            assert resolved != root, f"argv entry {arg!r} is the attachment root itself"
            assert resolved.is_relative_to(root), (
                f"argv entry {arg!r} escapes the attachment root {root}"
            )


def assert_no_shell(calls):
    """Every recorded call must be an argv list executed without a shell."""
    assert calls, "expected subprocess to be invoked"
    for args, kwargs in calls:
        assert kwargs.get("shell") in (None, False), "command was handed to a shell"
        assert isinstance(args, list), f"command must be an argv list, got {type(args).__name__}"
        assert all(isinstance(arg, str) for arg in args)


# --- SEC-f7f13d953a: path traversal (CWE-22) ---------------------------------


@pytest.mark.parametrize(
    "name",
    ["../secret.txt", "../../secret.txt", "sub/../../secret.txt"],
)
def test_read_rejects_relative_traversal(client, attachment_root, name):
    response = client.get("/api/v1/attachments/read", params={"name": name})

    assert response.status_code == 400
    assert "TOP-SECRET-OUTSIDE-ROOT" not in response.text


@pytest.mark.skipif(os.name != "nt", reason="backslash is a path separator only on Windows")
def test_read_rejects_windows_separator_traversal(client, attachment_root):
    response = client.get("/api/v1/attachments/read", params={"name": WINDOWS_TRAVERSAL})

    assert response.status_code == 400
    assert "TOP-SECRET-OUTSIDE-ROOT" not in response.text


@pytest.mark.skipif(os.name == "nt", reason="on POSIX a backslash is a literal filename character")
def test_read_contains_backslash_name_on_posix(client, attachment_root):
    # Not a traversal here: the name is one literal file inside the root, which
    # does not exist. It must still be a 4xx, never the secret and never a 500.
    response = client.get("/api/v1/attachments/read", params={"name": WINDOWS_TRAVERSAL})

    assert response.status_code == 400
    assert "TOP-SECRET-OUTSIDE-ROOT" not in response.text


@pytest.mark.parametrize("name", ROOT_ITSELF_NAMES)
def test_read_rejects_the_root_itself(client, attachment_root, name):
    response = client.get("/api/v1/attachments/read", params={"name": name})

    assert response.status_code == 400


def test_read_rejects_embedded_nul(client, attachment_root):
    # Path.resolve() does not raise on Windows, so without an explicit check the
    # NUL reaches open() and the endpoint 500s instead of rejecting the name.
    response = client.get("/api/v1/attachments/read", params={"name": "note.txt\x00.png"})

    assert response.status_code == 400


def test_read_rejects_absolute_path(client, attachment_root):
    outside = attachment_root.parent / "secret.txt"

    response = client.get("/api/v1/attachments/read", params={"name": str(outside)})

    assert response.status_code == 400
    assert "TOP-SECRET-OUTSIDE-ROOT" not in response.text


def test_read_rejects_posix_absolute_path(client, attachment_root):
    response = client.get("/api/v1/attachments/read", params={"name": "/etc/passwd"})

    assert response.status_code == 400


def test_read_allows_legitimate_attachment(client, attachment_root):
    response = client.get("/api/v1/attachments/read", params={"name": "note.txt"})

    assert response.status_code == 200
    assert response.text == "legitimate attachment"


# --- SEC-79f9c8c625: command injection in /convert (CWE-78) ------------------


@pytest.mark.parametrize("payload", SHELL_PAYLOADS)
def test_convert_never_reaches_a_shell(client, attachment_root, recorded_calls, payload):
    response = client.post(
        "/api/v1/attachments/convert", params={"name": payload, "fmt": "png"}
    )

    assert response.status_code in (200, 400)
    if response.status_code == 400:
        assert not recorded_calls
        return

    assert_no_shell(recorded_calls)
    args = recorded_calls[0][0]
    assert args[0] == "convert"
    # The metacharacters survive as inert characters inside single argv entries,
    # never as separate commands.
    assert not any(arg in {"rm", "id", "whoami", "cat", ";", "&&", "|"} for arg in args)


@pytest.mark.parametrize("payload", ["../secret.txt", "../../etc/passwd"])
def test_convert_rejects_traversal(client, attachment_root, recorded_calls, payload):
    response = client.post(
        "/api/v1/attachments/convert", params={"name": payload, "fmt": "png"}
    )

    assert response.status_code == 400
    assert not recorded_calls


@pytest.mark.parametrize(
    "fmt", ["pdf; rm -rf /", "png$(id)", "../../evil", "exe", "", "PDF ", "png|id"]
)
def test_convert_rejects_format_outside_allow_list(
    client, attachment_root, recorded_calls, fmt
):
    response = client.post(
        "/api/v1/attachments/convert", params={"name": "note.txt", "fmt": fmt}
    )

    assert response.status_code == 400
    assert not recorded_calls


@pytest.mark.parametrize("name", ROOT_ITSELF_NAMES)
def test_convert_rejects_the_root_itself(client, attachment_root, recorded_calls, name):
    """The root itself must not be convertible: the derived destination
    (``<root>.pdf``) is a SIBLING of the root, i.e. outside the boundary."""
    response = client.post(
        "/api/v1/attachments/convert", params={"name": name, "fmt": "pdf"}
    )

    # Fails loudly on the escape even if the request is somehow allowed.
    assert_paths_confined(recorded_calls, attachment_root)
    assert response.status_code == 400
    assert not recorded_calls


def test_convert_accepts_allow_listed_format(client, attachment_root, recorded_calls):
    response = client.post(
        "/api/v1/attachments/convert", params={"name": "note.txt", "fmt": "png"}
    )

    assert response.status_code == 200
    assert_no_shell(recorded_calls)
    args = recorded_calls[0][0]
    assert args[0] == "convert"
    assert args[1].endswith("note.txt")
    assert args[2].endswith("note.txt.png")
    # The destination itself has to be inside the root, not merely suffixed.
    assert_paths_confined(recorded_calls, attachment_root)


def test_convert_response_does_not_leak_absolute_paths(
    client, attachment_root, recorded_calls
):
    response = client.post(
        "/api/v1/attachments/convert", params={"name": "note.txt", "fmt": "png"}
    )

    assert response.status_code == 200
    root = Path(attachment_root).resolve()
    # Decode first: JSON escapes Windows separators, which would hide the leak.
    body = " ".join(str(value) for value in response.json().values())
    for leak in (str(root), root.as_posix(), str(attachment_root), str(root.parent)):
        assert leak not in body, "response discloses the absolute attachment root"
        assert leak not in response.text, "response discloses the absolute attachment root"


# --- SEC-11e7e45aa1: command injection in /archive (CWE-78) ------------------


@pytest.mark.parametrize("payload", SHELL_PAYLOADS)
def test_archive_never_reaches_a_shell(client, attachment_root, recorded_calls, payload):
    response = client.get("/api/v1/attachments/archive", params={"folder": payload})

    assert response.status_code in (200, 400)
    if response.status_code == 400:
        assert not recorded_calls
        return

    assert_no_shell(recorded_calls)
    args = recorded_calls[0][0]
    assert args[0] == "tar"
    assert not any(arg in {"rm", "id", "whoami", "cat", ";", "&&", "|"} for arg in args)


@pytest.mark.parametrize("payload", ["../../etc", "../secret.txt", "/etc"])
def test_archive_rejects_traversal(client, attachment_root, recorded_calls, payload):
    response = client.get("/api/v1/attachments/archive", params={"folder": payload})

    assert response.status_code == 400
    assert not recorded_calls


def test_archive_allows_default_folder(client, attachment_root, recorded_calls):
    response = client.get("/api/v1/attachments/archive")

    assert response.status_code == 200
    assert_no_shell(recorded_calls)
    args = recorded_calls[0][0]
    assert args[0] == "tar"
    assert args[-1].endswith("inbox")
