"""SQLite storage and append-only hash-chained audit events."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DOCSECURE_DB", ROOT / "instance" / "docsecure.sqlite3"))

class ClosingConnection(sqlite3.Connection):
    """Make ``with connect()`` commit and close to avoid per-request leaks."""
    def __exit__(self, exc_type, exc, traceback):
        try:
            return super().__exit__(exc_type, exc, traceback)
        finally:
            self.close()

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS students (
 student_id TEXT PRIMARY KEY, name TEXT NOT NULL, course TEXT NOT NULL,
 year_level TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', holds_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS staff (
 username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('registrar','cashier')),
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS requests (
 request_id TEXT PRIMARY KEY, student_id TEXT NOT NULL REFERENCES students(student_id),
 documents_json TEXT NOT NULL, copies_json TEXT NOT NULL DEFAULT '{}',
 amount_due REAL NOT NULL DEFAULT 0,
 undertaking_signed INTEGER NOT NULL DEFAULT 0,
 undertaking_text TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
 receipt_filename TEXT, or_number TEXT, rejection_note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 qr_nonce TEXT, qr_timestamp INTEGER, qr_used INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_live_or ON requests(or_number) WHERE or_number IS NOT NULL AND status NOT IN ('Rejected');
CREATE TABLE IF NOT EXISTS audit_log (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
 actor TEXT NOT NULL, action TEXT NOT NULL, request_id TEXT,
 metadata_json TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE
);
"""

def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10, factory=ClosingConnection)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA busy_timeout = 10000")
    return db

def initialize() -> None:
    with connect() as db:
        db.executescript(SCHEMA)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(requests)")}
        if "amount_due" not in columns:
            db.execute("ALTER TABLE requests ADD COLUMN amount_due REAL NOT NULL DEFAULT 0")
            # Backfill existing demo requests using the fixed per-document price.
            for row in db.execute("SELECT request_id, documents_json FROM requests WHERE amount_due=0"):
                amount = len(json.loads(row["documents_json"])) * 100.0
                db.execute("UPDATE requests SET amount_due=? WHERE request_id=?", (amount, row["request_id"]))
        if "copies_json" not in columns:
            db.execute("ALTER TABLE requests ADD COLUMN copies_json TEXT NOT NULL DEFAULT '{}'")
            for row in db.execute("SELECT request_id, documents_json FROM requests WHERE copies_json='{}'"):
                copies = {code: 1 for code in json.loads(row["documents_json"])}
                db.execute("UPDATE requests SET copies_json=? WHERE request_id=?",
                           (json.dumps(copies, sort_keys=True), row["request_id"]))

def seed_demo_students() -> None:
    """Add clearly synthetic records for local demonstration only."""
    with connect() as db:
        db.executemany("INSERT OR IGNORE INTO students(student_id,name,course,year_level,email,holds_json) VALUES(?,?,?,?,?,?)", [
            ("2023-00001", "Alex Rivera", "BS Computer Science", "3rd Year", "", "[]"),
            ("2023-00002", "Sam Santos", "BS Information Technology", "3rd Year", "", json.dumps(["Library clearance"])),
        ])

def append_audit(actor: str, action: str, request_id: str | None = None,
                 metadata: dict | None = None, connection: sqlite3.Connection | None = None) -> None:
    """Append a chained audit event, optionally in an existing transaction."""
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))
    def write_event(db: sqlite3.Connection) -> None:
        row = db.execute("SELECT entry_hash FROM audit_log ORDER BY sequence DESC LIMIT 1").fetchone()
        previous = row["entry_hash"] if row else "0" * 64
        content = "|".join((timestamp, actor, action, request_id or "", meta, previous))
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        db.execute("INSERT INTO audit_log(created_at,actor,action,request_id,metadata_json,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?)",
                   (timestamp, actor, action, request_id, meta, previous, digest))

    if connection is not None:
        write_event(connection)
    else:
        with connect() as db:
            write_event(db)
