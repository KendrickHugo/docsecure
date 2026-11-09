"""DOC-SECURE development web application. Run with ``python main.py``."""
from __future__ import annotations

import base64
import hmac
import json
from io import BytesIO
import os
import secrets
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for
from werkzeug.utils import secure_filename

import database as store
from crypto_utils import ElGamal, QR_TTL_SECONDS, make_qr_png, request_payload

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = ROOT / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
app = Flask(__name__)
_session_key_file = ROOT / "instance" / "session.secret"
_session_key_file.parent.mkdir(parents=True, exist_ok=True)
if os.environ.get("DOCSECURE_SESSION_SECRET"):
    app.secret_key = os.environ["DOCSECURE_SESSION_SECRET"]
elif _session_key_file.exists():
    app.secret_key = _session_key_file.read_text(encoding="utf-8").strip()
else:
    app.secret_key = secrets.token_urlsafe(48)
    _session_key_file.write_text(app.secret_key, encoding="utf-8")
app.config.update(MAX_CONTENT_LENGTH=8 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.environ.get("DOCSECURE_HTTPS") == "1")
DOCS = {"TOR": "Transcript of Records", "GRADES": "Certificate of Grades", "COE": "Certificate of Enrollment", "COR": "Certificate of Registration"}
PRICE_PER_DOCUMENT = 100.00
DEMO_STUDENT_PASSWORD = os.environ.get("DOCSECURE_STUDENT_PASSWORD", "student-demo")
DEMO_REGISTRAR_PASSWORD = os.environ.get("DOCSECURE_REGISTRAR_PASSWORD", "registrar-demo")
DEMO_CASHIER_PASSWORD = os.environ.get("DOCSECURE_CASHIER_PASSWORD", "cashier-demo")
PAYMENT_URL = os.environ.get("DOCSECURE_PAYMENT_URL", "")
KEYS = ElGamal.generate()  # Replace with persisted, protected keys for a deployment.
store.initialize()
store.seed_demo_students()

def now() -> str: return datetime.now(timezone.utc).isoformat(timespec="seconds")
def staff_user(role: str | None = None):
    if session.get("role") not in ((role,) if role else ("student", "registrar", "cashier")): return None
    if role == "student": return session.get("student_id")
    return session.get("username")
def require_role(*roles):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                return redirect(url_for("login", role="student" if "student" in roles else "staff"))
            # Workstation inactivity timeout; touched only by authenticated requests.
            if time.time() - session.get("last_seen", time.time()) > 15 * 60:
                session.clear(); flash("Your session expired after inactivity. Please sign in again.", "error")
                return redirect(url_for("login", role="staff"))
            session["last_seen"] = time.time()
            return fn(*args, **kwargs)
        return wrapped
    return decorate

@app.get("/")
def home(): return redirect(url_for("login", role="student"))

@app.route("/login/<role>", methods=["GET", "POST"])
def login(role):
    if role not in ("student", "staff"): abort(404)
    error = None
    if request.method == "POST":
        if role == "student":
            sid = request.form.get("student_id", "").strip()
            if not (len(sid) == 10 and sid[:4].isdigit() and sid[4] == "-" and sid[5:].isdigit()): error = "Use the format YYYY-NNNNN."
            elif not hmac.compare_digest(DEMO_STUDENT_PASSWORD, request.form.get("password", "")): error = "Student ID or password was not accepted."
            else:
                with store.connect() as db: exists = db.execute("SELECT 1 FROM students WHERE student_id=?", (sid,)).fetchone()
                if not exists: error = "That ID is not in the demo student registry."
                else: session.clear(); session.update(role="student", student_id=sid, last_seen=time.time()); store.append_audit(sid, "Student login") ; return redirect(url_for("student_home"))
        else:
            username = request.form.get("username", "").strip().lower()
            passwords = {"registrar": DEMO_REGISTRAR_PASSWORD, "cashier": DEMO_CASHIER_PASSWORD}
            if username not in passwords or not hmac.compare_digest(passwords.get(username, "x"), request.form.get("password", "")): error = "Staff username or password was not accepted."
            else: session.clear(); session.update(role=username, username=username, last_seen=time.time()); store.append_audit(username, "Staff login"); return redirect(url_for("admin_home"))
    return render_template("login.html", role=role, error=error)

@app.get("/logout")
def logout():
    actor = staff_user() or "anonymous"
    store.append_audit(actor, "Logout")
    session.clear(); return redirect(url_for("login", role="student"))

@app.get("/student")
@require_role("student")
def student_home():
    with store.connect() as db:
        student = db.execute("SELECT * FROM students WHERE student_id=?", (session["student_id"],)).fetchone()
        rows = db.execute("SELECT * FROM requests WHERE student_id=? ORDER BY created_at DESC", (session["student_id"],)).fetchall()
    student = dict(student)
    student["holds"] = json.loads(student["holds_json"])
    return render_template("student.html", student=student, requests=[dict(r) for r in rows], docs=DOCS, payment_url=PAYMENT_URL, price_per_document=PRICE_PER_DOCUMENT)

@app.post("/student/requests")
@require_role("student")
def create_request():
    sid = session["student_id"]
    documents = list(dict.fromkeys(request.form.getlist("documents")))
    if not documents or any(code not in DOCS for code in documents): flash("Select at least one listed document.", "error"); return redirect(url_for("student_home"))
    copies = {}
    try:
        for code in documents:
            copies[code] = int(request.form.get(f"copies_{code}", "1"))
            if not 1 <= copies[code] <= 10:
                raise ValueError
    except ValueError:
        flash("Choose between 1 and 10 copies for each selected document.", "error")
        return redirect(url_for("student_home"))
    amount_due = sum(quantity * PRICE_PER_DOCUMENT for quantity in copies.values())
    with store.connect() as db: student = db.execute("SELECT * FROM students WHERE student_id=?", (sid,)).fetchone()
    holds = __import__("json").loads(student["holds_json"])
    signed = request.form.get("undertaking_signed") == "yes"
    if holds and not signed: flash("Sign the Digital Undertaking Agreement to continue.", "error"); return redirect(url_for("student_home"))
    file = request.files.get("receipt")
    if not file or not file.filename or Path(file.filename).suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp", ".pdf"}: flash("Upload a PNG, JPG, WebP or PDF receipt.", "error"); return redirect(url_for("student_home"))
    or_number = request.form.get("or_number", "").strip()
    if not or_number or len(or_number) > 80: flash("Enter the Official Receipt number.", "error"); return redirect(url_for("student_home"))
    request_id = "DS-" + secrets.token_hex(4).upper()
    filename = secrets.token_hex(12) + Path(secure_filename(file.filename)).suffix.lower()
    file.save(UPLOAD_DIR / filename)
    stamp = now()
    try:
        with store.connect() as db:
            db.execute("INSERT INTO requests(request_id,student_id,documents_json,copies_json,amount_due,undertaking_signed,undertaking_text,status,receipt_filename,or_number,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (request_id, sid, json.dumps(documents), json.dumps(copies, sort_keys=True), amount_due, int(signed), "I acknowledge the listed clearance hold(s) and agree to complete them." if signed else "", "Pending verification", filename, or_number, stamp, stamp))
        store.append_audit(sid, "Submitted request and payment proof", request_id, {"documents": documents, "copies": copies, "holds": holds, "or_number": or_number, "amount_due_php": amount_due})
    except Exception:
        (UPLOAD_DIR / filename).unlink(missing_ok=True); flash("This OR number may already be attached to another active request.", "error"); return redirect(url_for("student_home"))
    flash(f"Request {request_id} submitted for cashier verification.", "success"); return redirect(url_for("student_home"))

@app.get("/staff")
@require_role("registrar", "cashier")
def admin_home():
    role = session["role"]
    with store.connect() as db:
        rows = db.execute("SELECT r.*, s.name, s.course, s.year_level, s.holds_json FROM requests r JOIN students s USING(student_id) ORDER BY r.created_at DESC").fetchall()
        audit = db.execute("SELECT * FROM audit_log ORDER BY sequence DESC LIMIT 30").fetchall() if role == "registrar" else []
    return render_template("staff.html", role=role, rows=[dict(r) for r in rows], audit=[dict(r) for r in audit])

@app.get("/staff/receipt/<request_id>")
@require_role("registrar", "cashier")
def view_receipt(request_id):
    with store.connect() as db: row = db.execute("SELECT receipt_filename FROM requests WHERE request_id=?", (request_id,)).fetchone()
    if not row or not row["receipt_filename"]: abort(404)
    return send_from_directory(UPLOAD_DIR, row["receipt_filename"], as_attachment=False)

@app.post("/staff/decision/<request_id>")
@require_role("registrar", "cashier")
def decision(request_id):
    role = session["role"]
    if role != "registrar": abort(403)
    action = request.form.get("action"); note = request.form.get("note", "").strip(); or_number = request.form.get("or_number", "").strip()
    with store.connect() as db:
        row = db.execute("SELECT * FROM requests WHERE request_id=?", (request_id,)).fetchone()
        if not row: abort(404)
        if row["status"] not in ("Pending verification", "Rejected"): flash("This request has already moved forward.", "error"); return redirect(url_for("admin_home"))
        if action == "approve":
            bound_or = or_number or row["or_number"]
            try: db.execute("UPDATE requests SET status='Approved',or_number=?,rejection_note='',updated_at=? WHERE request_id=?", (bound_or, now(), request_id))
            except Exception: flash("That OR number is already bound to an active request.", "error"); return redirect(url_for("admin_home"))
            actor = session["username"]; store.append_audit(actor, "Approved and bound OR; QR generation unlocked", request_id, {"or_number": bound_or}, connection=db)
            flash("Approved. The student can now generate a single-use counter QR.", "success")
        elif action == "reject" and note:
            db.execute("UPDATE requests SET status='Rejected',rejection_note=?,updated_at=? WHERE request_id=?", (note, now(), request_id))
            store.append_audit(session["username"], "Rejected with correction notice", request_id, {"correction": note}, connection=db); flash("Correction notice sent to the student portal.", "success")
        else: flash("Choose approve or provide a correction note for rejection.", "error")
    return redirect(url_for("admin_home"))

@app.post("/student/qr/<request_id>")
@require_role("student")
def issue_qr(request_id):
    with store.connect() as db:
        row = db.execute("SELECT * FROM requests WHERE request_id=? AND student_id=?", (request_id, session["student_id"])).fetchone()
        if not row: abort(404)
        if row["status"] != "Approved" or row["qr_used"]: flash("Only approved requests with an unused QR can be presented.", "error"); return redirect(url_for("student_home"))
        with store.connect() as db2: student = db2.execute("SELECT * FROM students WHERE student_id=?", (row["student_id"],)).fetchone()
        payload = request_payload(request_id=request_id, student_id=row["student_id"], documents=json.loads(row["documents_json"]), copies=json.loads(row["copies_json"]), or_number=row["or_number"], undertaking_signed=bool(row["undertaking_signed"]), amount_due=row["amount_due"])
        token = KEYS.encrypt_payload(payload); image = make_qr_png(token)
        db.execute("UPDATE requests SET qr_nonce=?,qr_timestamp=?,updated_at=? WHERE request_id=?", (payload["nonce"], payload["timestamp"], now(), request_id))
    store.append_audit(session["student_id"], "Generated and downloaded encrypted counter QR", request_id, {"amount_due_php": row["amount_due"]})
    return send_file(BytesIO(image), mimetype="image/png", as_attachment=True,
                     download_name=f"DOC-SECURE-{request_id}.png", max_age=0)

@app.post("/staff/scan")
@require_role("registrar")
def scan_qr():
    token = request.form.get("payload", "").strip()
    if not token and request.files.get("qr_image"):
        try:
            import cv2
            import numpy as np
            raw = request.files["qr_image"].read()
            detector = cv2.QRCodeDetector()
            token, _, _ = detector.detectAndDecode(cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR))
        except ImportError: flash("Install opencv-python and numpy to scan uploaded QR images.", "error"); return redirect(url_for("admin_home"))
    try:
        payload = KEYS.decrypt_payload(token)
        age = int(time.time()) - int(payload["timestamp"])
        if age < 0 or age > QR_TTL_SECONDS: raise ValueError("QR expired. Ask the student to generate a fresh QR.")
        with store.connect() as db:
            row = db.execute("SELECT * FROM requests WHERE request_id=?", (payload["request_id"],)).fetchone()
            if not row or row["status"] != "Approved": raise ValueError("Request is not approved.")
            if row["qr_used"] or row["qr_nonce"] != payload["nonce"]: raise ValueError("QR was reused or replaced.")
            if (row["student_id"] != payload["student_id"] or row["or_number"] != payload["or_number"]
                    or json.loads(row["documents_json"]) != payload["document_ids"]
                    or json.loads(row["copies_json"]) != payload["document_copies"]
                    or round(float(row["amount_due"]), 2) != round(float(payload["amount_due_php"]), 2)
                    or bool(row["undertaking_signed"]) != (payload["undertaking_status"] == "signed")):
                raise ValueError("QR details do not match the live request.")
            db.execute("UPDATE requests SET qr_used=1,updated_at=? WHERE request_id=?", (now(), row["request_id"]))
        store.append_audit(session["username"], "QR passed decryption, integrity, expiry and replay checks", payload["request_id"], {"or_number": payload["or_number"]})
        session["scan_result"] = (True, f"PASS · {payload['request_id']} · {payload['student_id']} · OR {payload['or_number']}")
    except Exception as exc:
        session["scan_result"] = (False, f"FAIL · {exc}")
    return redirect(url_for("admin_home"))

@app.post("/staff/claim/<request_id>")
@require_role("registrar")
def mark_claimed(request_id):
    with store.connect() as db:
        changed = db.execute("UPDATE requests SET status='Claimed',updated_at=? WHERE request_id=? AND status='Approved' AND qr_used=1", (now(), request_id)).rowcount
    if not changed: flash("Validate an unused approved QR before releasing documents.", "error")
    else: store.append_audit(session["username"], "Documents released; marked Claimed", request_id); flash("Request marked Claimed and recorded in the audit trail.", "success")
    return redirect(url_for("admin_home"))

@app.get("/api/public-key")
def public_key(): return jsonify({"p": format(__import__("crypto_utils").P, "x"), "g": __import__("crypto_utils").G, "y": format(KEYS.public_y, "x")})

if __name__ == "__main__":
    # Local coursework demo only; use a production WSGI server and managed keys for deployment.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
