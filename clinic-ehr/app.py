#!/usr/bin/env python3
"""MillsLab Clinic Portal - synthetic EHR + patient intake for the Velari practice lab.

Every record is synthetic. The point is a realistic EHR-shaped data source and
audit trail: patient records, a public intake form, and an "AI scribe" egress
path that shows patient-adjacent data leaving the EHR boundary.

This is a deliberately small, deliberately unauthenticated mock service. It is
hardened enough not to fall over on hostile input or corrupt its own audit log;
it is not a template for a real EHR. See docs/LAB-SECURITY.md for which
weaknesses are planted on purpose and which were accidental.
"""

import html
import json
import os
import re
import sqlite3
import threading
from collections import deque
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def _env_int(name, default):
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from exc
    if value < 0:
        raise SystemExit(f"{name} must be non-negative")
    return value


def _env_float(name, default):
    raw = os.environ.get(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise SystemExit(f"{name} must be positive")
    return value


DATA_DIR = os.environ.get("DATA_DIR", "/data")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = _env_int("PORT", 8095)
DB_PATH = os.path.join(DATA_DIR, "clinic.db")
LOG_PATH = os.path.join(DATA_DIR, "access.jsonl")

MAX_BODY_BYTES = _env_int("MAX_BODY_BYTES", 8192)
MAX_FORM_FIELDS = _env_int("MAX_FORM_FIELDS", 20)
READ_TIMEOUT = _env_float("READ_TIMEOUT", 10.0)
MAX_CONCURRENCY = _env_int("MAX_CONCURRENCY", 32)

MAX_NAME_LEN = 120
MAX_PHONE_LEN = 32
MAX_REASON_LEN = 2000
MAX_AUDIT_DETAIL = 300
MAX_USER_AGENT = 200
AUDIT_TAIL = 60

SYNTHETIC_PATIENTS = [
    ("SYN-1001", "Maria Alvarez", "1974-02-11", "Acme Health Plan"),
    ("SYN-1002", "James Chen", "1988-07-23", "Acme Health Plan"),
    ("SYN-1003", "Sarah Okafor", "1965-11-02", "Beacon Mutual"),
    ("SYN-1004", "Emily Tran", "1992-03-18", "Beacon Mutual"),
]

SCRIBE_VENDORS = [
    {
        "id": "scribe-a",
        "name": "ScribeCo",
        "status": "transmitting",
        "baa": "unverified",
        "subprocessors": "unknown",
        "note": "Two providers piloting; recordings leave the EHR to vendor cloud.",
    },
    {
        "id": "scribe-b",
        "name": "NoteGenie",
        "status": "evaluating",
        "baa": "requested",
        "subprocessors": "unknown",
        "note": "Free trial in use by front desk for one provider.",
    },
]

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")
_SSN_LIKE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_LIKE = re.compile(r"(?:\d[ -]?){13,19}")
_PHONE_OK = re.compile(r"^[0-9+()\-.\s]{7,32}$")
_DIGIT = re.compile(r"\d")

_write_lock = threading.Lock()
_audit_lock = threading.Lock()
_reject_lock = threading.Lock()
_last_reject_log = 0.0
REJECT_LOG_INTERVAL = 1.0


def _should_log_reject():
    global _last_reject_log
    with _reject_lock:
        now = datetime.now(timezone.utc).timestamp()
        if now - _last_reject_log < REJECT_LOG_INTERVAL:
            return False
        _last_reject_log = now
        return True


def _clean_text(value, limit, allow_newlines=False):
    text = str(value)
    if not allow_newlines:
        text = text.replace("\n", " ").replace("\r", " ")
    else:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL_CHARS.sub(" ", text).strip()[:limit]


def _looks_like_real_data(*values):
    for value in values:
        if _SSN_LIKE.search(value):
            return "SSN-like value"
        if _CARD_LIKE.search(value):
            return "card-like number"
    return None


def _validate_intake(form):
    raw_name = str(form.get("name", ""))
    raw_phone = str(form.get("phone", ""))
    raw_reason = str(form.get("reason", ""))
    if len(raw_name) > MAX_NAME_LEN:
        return None, "name is too long"
    if len(raw_phone) > MAX_PHONE_LEN:
        return None, "phone is too long"
    if len(raw_reason) > MAX_REASON_LEN:
        return None, "reason for visit is too long"

    name = _clean_text(raw_name, MAX_NAME_LEN)
    dob = _clean_text(form.get("dob", ""), 32)
    phone = _clean_text(raw_phone, MAX_PHONE_LEN)
    reason = _clean_text(raw_reason, MAX_REASON_LEN, allow_newlines=True)

    if not name:
        return None, "name is required"
    if not dob:
        return None, "date of birth is required"
    try:
        born = date.fromisoformat(dob)
    except ValueError:
        return None, "date of birth must be YYYY-MM-DD"
    if born < date(1900, 1, 1) or born > date.today():
        return None, "date of birth is out of range"
    if not phone:
        return None, "phone is required"
    if not _PHONE_OK.match(phone) or len(_DIGIT.findall(phone)) < 7:
        return None, "phone must contain at least 7 digits"
    if not reason:
        return None, "reason for visit is required"
    if len(reason) > MAX_REASON_LEN:
        return None, "reason for visit is too long"

    real = _looks_like_real_data(name, phone, reason)
    if real:
        return None, f"form rejected: {real}; this lab accepts only synthetic data"

    return {"name": name, "dob": dob, "phone": phone, "reason": reason}, None


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db():
    conn = db()
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS patients (
              mrn TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              dob TEXT NOT NULL,
              payer TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS intakes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              name TEXT NOT NULL,
              dob TEXT NOT NULL,
              phone TEXT NOT NULL,
              reason TEXT NOT NULL,
              remote TEXT NOT NULL,
              user_agent TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transmissions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              vendor TEXT NOT NULL,
              fields TEXT NOT NULL,
              destination TEXT NOT NULL,
              baa_status TEXT NOT NULL
            );
            """
        )
        count = conn.execute("SELECT COUNT(*) AS c FROM patients").fetchone()["c"]
        if count == 0:
            conn.executemany(
                "INSERT INTO patients (mrn, name, dob, payer) VALUES (?, ?, ?, ?)",
                SYNTHETIC_PATIENTS,
            )
        conn.commit()
    finally:
        conn.close()


def audit(event, detail, remote="", ua=""):
    line = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": _clean_text(event, 64),
        "detail": _clean_text(detail, MAX_AUDIT_DETAIL),
        "remote": _clean_text(remote, 64),
        "user_agent": _clean_text(ua, MAX_USER_AGENT),
    }
    payload = json.dumps(line, ensure_ascii=True) + "\n"
    with _audit_lock:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(payload)
        except OSError as exc:
            print(f"audit write failed: {exc.strerror}", flush=True)


def page(title, body):
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} - MillsLab Clinic (Synthetic)</title>
<style>
  :root {{ --ink:#1c1917; --mut:#57534e; --line:#e7e5e4; --bg:#faf9f7; --accent:#0f766e; --warn:#b45309; --bad:#b91c1c; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; color:var(--ink); background:var(--bg); }}
  header {{ border-bottom:1px solid var(--line); background:#fff; padding:14px 28px; display:flex; justify-content:space-between; align-items:baseline; }}
  header .brand {{ font-weight:650; letter-spacing:-0.01em; }}
  header .tag {{ font-size:12px; color:var(--warn); text-transform:uppercase; letter-spacing:.08em; }}
  main {{ max-width:900px; margin:36px auto; padding:0 24px; }}
  h1 {{ font-size:24px; letter-spacing:-0.02em; margin:0 0 6px; }}
  p.sub {{ color:var(--mut); margin:0 0 24px; }}
  nav a {{ color:var(--accent); text-decoration:none; margin-right:18px; font-weight:550; }}
  .card {{ background:#fff; border:1px solid var(--line); border-radius:10px; padding:20px; margin-bottom:16px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:16px; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--mut); font-weight:550; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }}
  .pill {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:12px; font-weight:600; }}
  .pill.ok {{ background:#ccfbf1; color:#115e59; }}
  .pill.warn {{ background:#fef3c7; color:var(--warn); }}
  .pill.bad {{ background:#fee2e2; color:var(--bad); }}
  input,textarea {{ width:100%; padding:9px 11px; border:1px solid var(--line); border-radius:8px; font:inherit; background:#fff; }}
  label {{ display:block; font-size:13px; font-weight:550; margin:12px 0 4px; }}
  button {{ background:var(--accent); color:#fff; border:0; border-radius:8px; padding:10px 18px; font:inherit; font-weight:600; cursor:pointer; margin-top:14px; }}
  .muted {{ color:var(--mut); font-size:13px; }}
  code {{ background:#f5f5f4; padding:1px 6px; border-radius:5px; font-size:13px; }}
</style></head>
<body>
<header><span class="brand">MillsLab Clinic</span><span class="tag">Synthetic lab - no real patients</span></header>
<main>
<nav><a href="/">Dashboard</a><a href="/intake">Patient intake</a><a href="/scribe">AI scribe</a><a href="/audit">Audit log</a><a href="/healthz">Health</a></nav>
<div style="height:20px"></div>
{body}
</main></body></html>"""


def error_page(message):
    return page(
        "Request rejected",
        f'<h1>Request rejected</h1><p class="sub">{html.escape(message)}</p>'
        '<div class="card"><p class="muted">This portal is a synthetic lab. Do not submit real '
        "patient information.</p></div>",
    )


def dashboard():
    conn = db()
    try:
        patients = conn.execute("SELECT * FROM patients ORDER BY mrn").fetchall()
        intakes = conn.execute("SELECT COUNT(*) AS c FROM intakes").fetchone()["c"]
        tx = conn.execute("SELECT COUNT(*) AS c FROM transmissions").fetchone()["c"]
    finally:
        conn.close()
    rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(p["mrn"])),
            html.escape(str(p["name"])),
            html.escape(str(p["dob"])),
            html.escape(str(p["payer"])),
        )
        for p in patients
    )
    body = f"""
<h1>Clinic dashboard</h1>
<p class="sub">Synthetic patient roster and data movement overview.</p>
<div class="grid">
  <div class="card"><div class="muted">Patients</div><div style="font-size:28px;font-weight:650">{len(patients)}</div></div>
  <div class="card"><div class="muted">Web intake submissions</div><div style="font-size:28px;font-weight:650">{intakes}</div></div>
  <div class="card"><div class="muted">Scribe transmissions</div><div style="font-size:28px;font-weight:650">{tx}</div>
    <span class="pill warn">BAA unverified</span></div>
</div>
<div class="card"><table><tr><th>MRN</th><th>Name</th><th>DOB</th><th>Payer</th></tr>{rows}</table></div>
<div class="card"><strong>What this lab demonstrates</strong>
<p class="muted">Patient-adjacent data leaves this EHR through a public web intake form and an AI scribe
integration. Velari's job in a real clinic: map those paths, verify vendor BAAs, and produce dated evidence.</p></div>"""
    return page("Dashboard", body)


def intake_form(success=False):
    banner = (
        '<div class="card"><span class="pill ok">Intake recorded</span> '
        '<span class="muted">Synthetic record stored. In this lab nothing is encrypted at rest '
        "and nothing is ever deleted.</span></div>"
        if success
        else ""
    )
    body = f"""
<h1>Patient intake</h1>
<p class="sub">Public-facing web form. In the lab this writes to the portal database and the access log.</p>
{banner}
<div class="card"><p class="muted"><strong>Synthetic data only.</strong> Use invented names and dates.
Submissions that look like real identifiers (SSN- or card-shaped numbers) are rejected.</p>
<form method="post" action="/intake">
<label>Full name</label><input name="name" maxlength="{MAX_NAME_LEN}" required>
<label>Date of birth</label><input name="dob" type="date" required>
<label>Phone</label><input name="phone" maxlength="{MAX_PHONE_LEN}" required>
<label>Reason for visit</label><textarea name="reason" rows="3" maxlength="{MAX_REASON_LEN}" required></textarea>
<button type="submit">Submit intake</button>
</form></div>"""
    return page("Patient intake", body)


def scribe_page():
    cards = ""
    for v in SCRIBE_VENDORS:
        baa = v["baa"]
        pill = "ok" if baa == "verified" else ("warn" if baa in ("requested", "unverified") else "bad")
        cards += f"""<div class="card"><strong>{html.escape(v["name"])}</strong>
        <span class="pill {pill}">BAA {html.escape(baa)}</span>
        <p class="muted">{html.escape(v["note"])}</p>
        <p class="muted">Status: <code>{html.escape(v["status"])}</code> - Subprocessors: <code>{html.escape(v["subprocessors"])}</code></p>
        <form method="post" action="/scribe/run"><input type="hidden" name="vendor" value="{html.escape(v["id"])}">
        <button type="submit">Simulate a week of encounters</button></form></div>"""
    body = f"""
<h1>AI scribe integrations</h1>
<p class="sub">Ambient scribe vendors receiving encounter audio/notes outside the EHR.</p>
{cards}
<div class="card"><strong>Evidence question for the practice</strong>
<p class="muted">Do we hold a signed BAA for each transmitting vendor, and can we show what data left,
when, and to where? The simulation writes exactly that metadata to the audit log.</p></div>"""
    return page("AI scribe", body)


def audit_page():
    events = deque(maxlen=AUDIT_TAIL)
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    events.append(entry)
    rows = "".join(
        f"<tr><td>{html.escape(str(e.get('ts', '')))}</td>"
        f"<td>{html.escape(str(e.get('event', '')))}</td>"
        f"<td>{html.escape(str(e.get('detail', '')))}</td>"
        f"<td>{html.escape(str(e.get('remote', '')))}</td></tr>"
        for e in reversed(events)
    )
    body = f"""
<h1>Access &amp; transmission log</h1>
<p class="sub">Newest first. This is the kind of metadata-only evidence Velari reviews - no patient content.</p>
<div class="card"><table><tr><th>Time (UTC)</th><th>Event</th><th>Detail</th><th>Remote</th></tr>
{rows or '<tr><td colspan="4" class="muted">No events yet.</td></tr>'}</table></div>"""
    return page("Audit log", body)


class Handler(BaseHTTPRequestHandler):
    server_version = "MillsLabClinic/0.1"
    sys_version = ""
    timeout = READ_TIMEOUT

    def version_string(self):
        return self.server_version

    def _send(self, code, content_type, payload, head=False, extra_headers=()):
        data = payload.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )
            for key, value in extra_headers:
                self.send_header(key, value)
            self.end_headers()
            if not head:
                self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _remote(self):
        return self.client_address[0]

    def _ua(self):
        return self.headers.get("User-Agent", "")[:MAX_USER_AGENT]

    def _path(self):
        return urlparse(self.path).path

    def _read_form(self):
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype and ctype != "application/x-www-form-urlencoded":
            return None, 415
        if self.headers.get("Transfer-Encoding"):
            return None, 400
        lengths = self.headers.get_all("Content-Length") or []
        if not lengths:
            return None, 411
        if len(lengths) != 1:
            return None, 400
        try:
            length = int(lengths[0].strip())
        except (TypeError, ValueError):
            return None, 400
        if length < 0:
            return None, 400
        if length > MAX_BODY_BYTES:
            return None, 413
        if length == 0:
            return {}, None
        try:
            raw = self.rfile.read(length)
        except TimeoutError:
            return None, 408
        if len(raw) != length:
            return None, 400
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, 400
        try:
            values = parse_qs(text, keep_blank_values=True, max_num_fields=MAX_FORM_FIELDS)
        except ValueError:
            return None, 400
        return {key: item[0] for key, item in values.items()}, None

    def _reject(self, code, message, head=False):
        reason = {
            400: "bad request",
            408: "request timeout",
            411: "length required",
            413: "payload too large",
            415: "unsupported media type",
        }.get(code, "request rejected")
        if _should_log_reject():
            audit("request_rejected", f"{code} {reason}", self._remote(), self._ua())
        self._send(code, "text/html; charset=utf-8", error_page(message), head=head)

    def _route_get(self, head=False):
        path = self._path()
        if path == "/":
            audit("page_view", "dashboard", self._remote(), self._ua())
            self._send(200, "text/html; charset=utf-8", dashboard(), head=head)
        elif path == "/intake":
            audit("page_view", "intake_form", self._remote(), self._ua())
            ok = parse_qs(urlparse(self.path).query).get("ok") == ["1"]
            self._send(200, "text/html; charset=utf-8", intake_form(success=ok), head=head)
        elif path == "/scribe":
            audit("page_view", "scribe_integrations", self._remote(), self._ua())
            self._send(200, "text/html; charset=utf-8", scribe_page(), head=head)
        elif path == "/audit":
            self._send(200, "text/html; charset=utf-8", audit_page(), head=head)
        elif path == "/healthz":
            self._send(200, "application/json", json.dumps({"status": "ok", "synthetic": True}), head=head)
        else:
            self._send(404, "text/plain; charset=utf-8", "not found\n", head=head)

    def do_GET(self):
        try:
            self._route_get()
        except OSError:
            self.close_connection = True
        except Exception as exc:
            self.log_error("GET failed: %s", type(exc).__name__)
            self._send(500, "text/plain; charset=utf-8", "internal error\n")

    def do_HEAD(self):
        try:
            self._route_get(head=True)
        except Exception as exc:
            self.log_error("HEAD failed: %s", type(exc).__name__)
            self.close_connection = True

    def _post_intake(self, form):
        record, error = _validate_intake(form)
        if error:
            if _should_log_reject():
                audit("intake_rejected", f"validation: {error.split(';')[0]}", self._remote(), self._ua())
            self._send(400, "text/html; charset=utf-8", error_page(error))
            return
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with _write_lock:
            conn = db()
            try:
                conn.execute(
                    "INSERT INTO intakes (ts, name, dob, phone, reason, remote, user_agent) VALUES (?,?,?,?,?,?,?)",
                    (
                        ts,
                        record["name"],
                        record["dob"],
                        record["phone"],
                        record["reason"],
                        self._remote()[:64],
                        self._ua(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        audit("intake_submitted", f"intake stored for {record['name']}", self._remote(), self._ua())
        self._send(303, "text/plain; charset=utf-8", "", extra_headers=[("Location", "/intake?ok=1")])

    def _post_scribe(self, form):
        vendor_id = form.get("vendor", "")
        vendor = next((v for v in SCRIBE_VENDORS if v["id"] == vendor_id), None)
        if vendor is None:
            self._send(400, "text/html; charset=utf-8", error_page("unknown scribe vendor"))
            return
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with _write_lock:
            conn = db()
            try:
                for _ in range(5):
                    conn.execute(
                        "INSERT INTO transmissions (ts, vendor, fields, destination, baa_status) VALUES (?,?,?,?,?)",
                        (
                            now,
                            vendor["name"],
                            "audio,transcript,patient_name,dob",
                            f"https://api.{vendor['id']}.example/v1/notes",
                            vendor["baa"],
                        ),
                    )
                conn.commit()
            finally:
                conn.close()
        audit(
            "scribe_transmission",
            f"5 encounters sent to {vendor['name']} (baa={vendor['baa']})",
            self._remote(),
            self._ua(),
        )
        self._send(303, "text/plain; charset=utf-8", "", extra_headers=[("Location", "/scribe")])

    def do_POST(self):
        path = self._path()
        if path not in ("/intake", "/scribe/run"):
            self._send(404, "text/plain; charset=utf-8", "not found\n")
            return
        try:
            form, error_code = self._read_form()
        except OSError:
            self.close_connection = True
            return
        if error_code is not None:
            self._reject(error_code, "Request body was missing, malformed, or too large.", head=False)
            return
        try:
            if path == "/intake":
                self._post_intake(form)
            else:
                self._post_scribe(form)
        except OSError:
            self.close_connection = True
        except Exception as exc:
            self.log_error("POST failed: %s", type(exc).__name__)
            self._send(500, "text/plain; charset=utf-8", "internal error\n")

    def _method_not_allowed(self):
        self._send(
            405,
            "text/plain; charset=utf-8",
            "method not allowed\n",
            extra_headers=[("Allow", "GET, HEAD, POST")],
        )

    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_OPTIONS = _method_not_allowed
    do_TRACE = _method_not_allowed

    def log_message(self, fmt, *args):
        pass


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, max_concurrency=MAX_CONCURRENCY):
        super().__init__(server_address, handler_class)
        self._slots = threading.BoundedSemaphore(max(1, max_concurrency))

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(1.0)
                body = b'{"status":"busy"}\n'
                head = (
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                request.sendall(head + body)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(host=None, port=None, max_concurrency=None):
    return BoundedThreadingHTTPServer(
        (HOST if host is None else host, PORT if port is None else port),
        Handler,
        max_concurrency=MAX_CONCURRENCY if max_concurrency is None else max_concurrency,
    )


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    init_db()
    audit("service_start", "clinic portal started")
    server = make_server()
    print(f"clinic portal on {HOST}:{PORT} data={DATA_DIR} (synthetic lab)", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
