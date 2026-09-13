#!/usr/bin/env python3
"""MillsLab Clinic Portal - synthetic EHR + patient intake for the Velari practice lab.

Every record is synthetic. The point is a realistic EHR-shaped data source and
audit trail: patient records, a public intake form, and an "AI scribe" egress
path that shows patient-adjacent data leaving the EHR boundary.
"""

import html
import json
import os
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DATA_DIR = os.environ.get("DATA_DIR", "/data")
PORT = int(os.environ.get("PORT", "8095"))
DB_PATH = os.path.join(DATA_DIR, "clinic.db")
LOG_PATH = os.path.join(DATA_DIR, "access.jsonl")

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


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
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
    conn.close()


def audit(event, detail, remote="", ua=""):
    line = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": event,
        "detail": detail,
        "remote": remote,
        "user_agent": ua,
    }
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(line) + "\n")


def page(title, body):
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - MillsLab Clinic (Synthetic)</title>
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


def dashboard():
    conn = db()
    patients = conn.execute("SELECT * FROM patients ORDER BY mrn").fetchall()
    intakes = conn.execute("SELECT COUNT(*) AS c FROM intakes").fetchone()["c"]
    tx = conn.execute("SELECT COUNT(*) AS c FROM transmissions").fetchone()["c"]
    conn.close()
    rows = "".join(
        f"<tr><td>{p['mrn']}</td><td>{p['name']}</td><td>{p['dob']}</td><td>{p['payer']}</td></tr>"
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


def intake_form():
    body = """
<h1>Patient intake</h1>
<p class="sub">Public-facing web form. In the lab this writes to the portal database and the access log.</p>
<div class="card"><form method="post" action="/intake">
<label>Full name</label><input name="name" required>
<label>Date of birth</label><input name="dob" type="date" required>
<label>Phone</label><input name="phone" required>
<label>Reason for visit</label><textarea name="reason" rows="3" required></textarea>
<button type="submit">Submit intake</button>
</form></div>"""
    return page("Patient intake", body)


def scribe_page():
    cards = ""
    for v in SCRIBE_VENDORS:
        baa = v["baa"]
        pill = "ok" if baa == "verified" else ("warn" if baa in ("requested", "unverified") else "bad")
        cards += f"""<div class="card"><strong>{v['name']}</strong>
        <span class="pill {pill}">BAA {baa}</span>
        <p class="muted">{v['note']}</p>
        <p class="muted">Status: <code>{v['status']}</code> - Subprocessors: <code>{v['subprocessors']}</code></p>
        <form method="post" action="/scribe/run"><input type="hidden" name="vendor" value="{v['id']}">
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
    events = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, encoding="utf-8") as fh:
            for line in fh:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    rows = "".join(
        f"<tr><td>{html.escape(str(e.get('ts', '')))}</td>"
        f"<td>{html.escape(str(e.get('event', '')))}</td>"
        f"<td>{html.escape(str(e.get('detail', '')))}</td>"
        f"<td>{html.escape(str(e.get('remote', '')))}</td></tr>"
        for e in events[-60:][::-1]
    )
    body = f"""
<h1>Access &amp; transmission log</h1>
<p class="sub">Newest first. This is the kind of metadata-only evidence Velari reviews - no patient content.</p>
<div class="card"><table><tr><th>Time (UTC)</th><th>Event</th><th>Detail</th><th>Remote</th></tr>
{rows or '<tr><td colspan="4" class="muted">No events yet.</td></tr>'}</table></div>"""
    return page("Audit log", body)


class Handler(BaseHTTPRequestHandler):
    server_version = "MillsLabClinic/0.1"

    def _send(self, code, content_type, payload):
        data = payload.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _remote(self):
        return self.client_address[0]

    def _ua(self):
        return self.headers.get("User-Agent", "")[:200]

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            audit("page_view", "dashboard", self._remote(), self._ua())
            self._send(200, "text/html; charset=utf-8", dashboard())
        elif path == "/intake":
            audit("page_view", "intake_form", self._remote(), self._ua())
            self._send(200, "text/html; charset=utf-8", intake_form())
        elif path == "/scribe":
            audit("page_view", "scribe_integrations", self._remote(), self._ua())
            self._send(200, "text/html; charset=utf-8", scribe_page())
        elif path == "/audit":
            self._send(200, "text/html; charset=utf-8", audit_page())
        elif path == "/healthz":
            self._send(200, "application/json", json.dumps({"status": "ok"}))
        else:
            self._send(404, "text/plain; charset=utf-8", "not found")

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        if path == "/intake":
            name = form.get("name", [""])[0]
            dob = form.get("dob", [""])[0]
            phone = form.get("phone", [""])[0]
            reason = form.get("reason", [""])[0]
            conn = db()
            conn.execute(
                "INSERT INTO intakes (ts, name, dob, phone, reason, remote, user_agent) VALUES (?,?,?,?,?,?,?)",
                (
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    name,
                    dob,
                    phone,
                    reason,
                    self._remote(),
                    self._ua(),
                ),
            )
            conn.commit()
            conn.close()
            audit("intake_submitted", f"intake stored for {name}", self._remote(), self._ua())
            self.send_response(303)
            self.send_header("Location", "/intake?ok=1")
            self.end_headers()
        elif path == "/scribe/run":
            vendor_id = form.get("vendor", [""])[0]
            vendor = next((v for v in SCRIBE_VENDORS if v["id"] == vendor_id), SCRIBE_VENDORS[0])
            conn = db()
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            for i in range(5):
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
            conn.close()
            audit(
                "scribe_transmission",
                f"5 encounters sent to {vendor['name']} (baa={vendor['baa']})",
                self._remote(),
                self._ua(),
            )
            self.send_response(303)
            self.send_header("Location", "/scribe")
            self.end_headers()
        else:
            self._send(404, "text/plain; charset=utf-8", "not found")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    init_db()
    audit("service_start", "clinic portal started")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"clinic portal on :{PORT} data={DATA_DIR}", flush=True)
    server.serve_forever()
