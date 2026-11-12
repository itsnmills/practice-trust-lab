"""Hostile-input and behaviour tests for the synthetic EHR (clinic-ehr/app.py).

The server is started on an ephemeral loopback port against a temporary data
directory, so the suite needs no Docker and never touches clinic-ehr/data.
"""

import http.client
import importlib.util
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlencode

import pytest

APP_PATH = Path(__file__).resolve().parent.parent / "clinic-ehr" / "app.py"


def _load_app():
    spec = importlib.util.spec_from_file_location("ehr_app_under_test", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


app = _load_app()


@pytest.fixture()
def ehr(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(app, "DB_PATH", str(tmp_path / "clinic.db"))
    monkeypatch.setattr(app, "LOG_PATH", str(tmp_path / "access.jsonl"))
    monkeypatch.setattr(app, "_last_reject_log", 0.0)
    original_timeout = app.Handler.timeout
    app.Handler.timeout = 2.0
    app.init_db()
    server = app.make_server(host="127.0.0.1", port=0, max_concurrency=16)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    port = server.server_address[1]
    yield app, port, tmp_path
    server.shutdown()
    server.server_close()
    thread.join(5)
    app.Handler.timeout = original_timeout


def call(port, method, path, body=None, headers=None, timeout=5):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        return response.status, data, dict(response.getheaders())
    finally:
        conn.close()


def form(fields):
    return urlencode(fields).encode(), {"Content-Type": "application/x-www-form-urlencoded"}


def valid_form(**overrides):
    fields = {
        "name": "Test Patient",
        "dob": "1980-01-02",
        "phone": "555-0100",
        "reason": "Synthetic check-up",
    }
    fields.update(overrides)
    return form(fields)


def read_audit(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_get_routes_and_healthz(ehr):
    _, port, tmp_path = ehr
    assert call(port, "GET", "/")[0] == 200
    assert call(port, "GET", "/intake")[0] == 200
    assert call(port, "GET", "/scribe")[0] == 200
    assert call(port, "GET", "/audit")[0] == 200
    status, body, _ = call(port, "GET", "/healthz")
    assert status == 200
    assert json.loads(body)["status"] == "ok"
    assert call(port, "GET", "/does-not-exist")[0] == 404
    events = {entry["event"] for entry in read_audit(tmp_path / "access.jsonl")}
    assert "page_view" in events


def test_head_matches_get_headers_but_has_no_body(ehr):
    _, port, _ = ehr
    get_status, get_body, get_headers = call(port, "GET", "/")
    head_status, head_body, head_headers = call(port, "HEAD", "/")
    assert get_status == head_status == 200
    assert head_body == b""
    assert head_headers["Content-Length"] == get_headers["Content-Length"]
    assert head_headers["X-Content-Type-Options"] == "nosniff"


def test_valid_intake_is_stored_and_redirects(ehr):
    module, port, tmp_path = ehr
    body, headers = valid_form(name="Ada Synthetic")
    status, _, response_headers = call(port, "POST", "/intake", body, headers)
    assert status == 303
    assert response_headers["Location"] == "/intake?ok=1"

    conn = module.db()
    rows = conn.execute("SELECT name, dob, phone FROM intakes").fetchall()
    conn.close()
    assert [tuple(row) for row in rows] == [("Ada Synthetic", "1980-01-02", "555-0100")]
    events = read_audit(tmp_path / "access.jsonl")
    assert any(e["event"] == "intake_submitted" and "Ada Synthetic" in e["detail"] for e in events)


def test_intake_success_banner_on_ok_query(ehr):
    _, port, _ = ehr
    status, body, _ = call(port, "GET", "/intake?ok=1")
    assert status == 200
    assert b"Intake recorded" in body


def test_dashboard_escapes_stored_patient_fields(ehr):
    module, port, _ = ehr
    payload = "<script>alert('xss')</script>"
    conn = module.db()
    conn.execute("UPDATE patients SET name = ? WHERE mrn = 'SYN-1001'", (payload,))
    conn.commit()
    conn.close()
    status, body, _ = call(port, "GET", "/")
    assert status == 200
    assert payload.encode() not in body
    assert b"&lt;script&gt;" in body


def test_audit_page_escapes_and_skips_malformed_lines(ehr):
    module, port, tmp_path = ehr
    module.audit("hostile", "<script>alert('audit')</script>")
    with open(tmp_path / "access.jsonl", "a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
    status, body, _ = call(port, "GET", "/audit")
    assert status == 200
    assert b"<script>alert('audit')</script>" not in body
    assert b"&lt;script&gt;" in body


def test_audit_newlines_cannot_break_json_lines(ehr):
    module, _, tmp_path = ehr
    module.audit("injected", 'first line\r\n{"event":"forged"}\nthird line')
    entries = read_audit(tmp_path / "access.jsonl")
    assert all("event" in entry for entry in entries)
    injected = [e for e in entries if e["event"] == "injected"]
    assert len(injected) == 1
    assert "\n" not in injected[0]["detail"] and "\r" not in injected[0]["detail"]
    assert injected[0]["detail"].startswith("first line")


def test_audit_detail_is_bounded(ehr):
    module, _, tmp_path = ehr
    module.audit("long", "A" * 5000)
    entry = [e for e in read_audit(tmp_path / "access.jsonl") if e["event"] == "long"][0]
    assert len(entry["detail"]) <= module.MAX_AUDIT_DETAIL


@pytest.mark.parametrize(
    "overrides, marker",
    [
        ({"name": ""}, b"required"),
        ({"name": "A" * 121}, b"too long"),
        ({"dob": "not-a-date"}, b"YYYY-MM-DD"),
        ({"dob": "2099-01-01"}, b"out of range"),
        ({"dob": "1800-01-01"}, b"out of range"),
        ({"phone": "123"}, b"7 digits"),
        ({"phone": "call me"}, b"7 digits"),
        ({"reason": ""}, b"required"),
        ({"reason": "my ssn is 123-45-6789"}, b"synthetic data"),
        ({"reason": "card 4111 1111 1111 1111"}, b"synthetic data"),
    ],
)
def test_intake_rejects_invalid_or_real_looking_data(ehr, overrides, marker):
    module, port, _ = ehr
    body, headers = valid_form(**overrides)
    status, response, _ = call(port, "POST", "/intake", body, headers)
    assert status == 400
    assert marker in response
    conn = module.db()
    assert conn.execute("SELECT COUNT(*) AS c FROM intakes").fetchone()["c"] == 0
    conn.close()


def test_intake_sql_injection_is_stored_as_text(ehr):
    module, port, _ = ehr
    payload = "Robert'); DROP TABLE intakes;--"
    body, headers = valid_form(name=payload)
    status, _, _ = call(port, "POST", "/intake", body, headers)
    assert status == 303
    conn = module.db()
    assert conn.execute("SELECT COUNT(*) AS c FROM intakes").fetchone()["c"] == 1
    assert conn.execute("SELECT name FROM intakes").fetchone()["name"] == payload
    conn.close()


def test_missing_content_length_returns_411(ehr):
    _, port, _ = ehr
    request = b"POST /intake HTTP/1.1\r\nHost: lab\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        response = sock.recv(4096)
    assert b" 411 " in response.splitlines()[0]


@pytest.mark.parametrize("raw_length", [b"abc", b"-1", b"1e9"])
def test_bad_content_length_returns_400(ehr, raw_length):
    _, port, _ = ehr
    request = (
        b"POST /intake HTTP/1.1\r\nHost: lab\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + raw_length + b"\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        response = sock.recv(4096)
    assert b" 400 " in response.splitlines()[0]


def test_huge_content_length_is_rejected_without_reading_body(ehr):
    _, port, _ = ehr
    request = (
        b"POST /intake HTTP/1.1\r\nHost: lab\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 999999999\r\n\r\n"
    )
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        response = sock.recv(4096)
    assert b" 413 " in response.splitlines()[0]
    assert time.monotonic() - started < 3


def test_truncated_body_returns_400(ehr):
    _, port, _ = ehr
    request = (
        b"POST /intake HTTP/1.1\r\nHost: lab\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 100\r\n\r\nname=x"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        response = sock.recv(4096)
    assert b" 400 " in response.splitlines()[0]


def test_duplicate_content_length_is_rejected(ehr):
    _, port, _ = ehr
    request = (
        b"POST /intake HTTP/1.1\r\nHost: lab\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nname=x"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        response = sock.recv(4096)
    assert b" 400 " in response.splitlines()[0]


def test_transfer_encoding_is_rejected(ehr):
    _, port, _ = ehr
    request = (
        b"POST /intake HTTP/1.1\r\nHost: lab\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        response = sock.recv(4096)
    assert b" 400 " in response.splitlines()[0]


def test_wrong_content_type_returns_415(ehr):
    _, port, _ = ehr
    status, _, _ = call(port, "POST", "/intake", b'{"name":"x"}', {"Content-Type": "application/json"})
    assert status == 415


def test_oversized_field_is_rejected(ehr):
    _, port, _ = ehr
    body, headers = valid_form(name="A" * 121)
    status, _, _ = call(port, "POST", "/intake", body, headers)
    assert status == 400


def test_slow_partial_request_times_out(ehr):
    module, port, _ = ehr
    module.Handler.timeout = 0.5
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: lab\r\n")
        sock.settimeout(5)
        try:
            data = sock.recv(4096)
        except ConnectionResetError:
            data = b""
    assert data == b""
    assert time.monotonic() - started < 4


def test_path_traversal_is_not_served(ehr):
    _, port, _ = ehr
    for path in ("/../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/data/clinic.db"):
        status, body, _ = call(port, "GET", path)
        assert status == 404
        assert b"root:" not in body
        assert b"SQLite" not in body


def test_crlf_in_path_cannot_inject_headers(ehr):
    _, port, _ = ehr
    status, _, headers = call(port, "GET", "/%0d%0aSet-Cookie:%20injected=1")
    assert status == 404
    assert "Set-Cookie" not in headers


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def test_unsupported_methods_are_405(ehr, method):
    _, port, _ = ehr
    status, _, headers = call(port, method, "/")
    assert status == 405
    assert headers["Allow"] == "GET, HEAD, POST"


def test_unknown_post_route_is_404(ehr):
    _, port, _ = ehr
    body, headers = valid_form()
    assert call(port, "POST", "/nothing", body, headers)[0] == 404


def test_scribe_run_records_five_transmissions(ehr):
    module, port, _ = ehr
    body, headers = form({"vendor": "scribe-a"})
    status, _, response_headers = call(port, "POST", "/scribe/run", body, headers)
    assert status == 303
    assert response_headers["Location"] == "/scribe"
    conn = module.db()
    rows = conn.execute("SELECT vendor, baa_status FROM transmissions").fetchall()
    conn.close()
    assert len(rows) == 5
    assert {row["vendor"] for row in rows} == {"ScribeCo"}
    assert {row["baa_status"] for row in rows} == {"unverified"}


def test_scribe_unknown_vendor_is_rejected(ehr):
    module, port, _ = ehr
    body, headers = form({"vendor": "evil-vendor"})
    status, _, _ = call(port, "POST", "/scribe/run", body, headers)
    assert status == 400
    conn = module.db()
    assert conn.execute("SELECT COUNT(*) AS c FROM transmissions").fetchone()["c"] == 0
    conn.close()


def test_concurrent_intakes_do_not_lock_the_database(ehr):
    module, port, _ = ehr

    def submit(index):
        body, headers = valid_form(name=f"Patient {index}", reason="concurrency check")
        return call(port, "POST", "/intake", body, headers)[0]

    with ThreadPoolExecutor(max_workers=12) as pool:
        statuses = list(pool.map(submit, range(30)))
    assert statuses == [303] * 30
    conn = module.db()
    count = conn.execute("SELECT COUNT(*) AS c FROM intakes").fetchone()["c"]
    conn.close()
    assert count == 30


def test_unhandled_error_does_not_leak_internals(ehr, tmp_path):
    module, port, _ = ehr
    module.DB_PATH = str(tmp_path / "missing-dir" / "clinic.db")
    status, body, _ = call(port, "GET", "/")
    assert status == 500
    lowered = body.lower()
    assert b"traceback" not in lowered
    assert b"sqlite" not in lowered
