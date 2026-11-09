# DOC-SECURE

Encrypted QR Code-Based Document Request System for a university registrar. This is a local coursework demo with separate student, cashier, and registrar views. Its UI follows the concept guide palette: white and black foundations, UA dark blue (#003366), gold highlights (#FFCC00), and red alerts (#CC0000).

## Project structure

```text
New-Doc/
├── main.py          # Flask routes, role views, upload, workflow
├── crypto_utils.py  # ElGamal/AES-GCM authenticated QR payload
├── database.py      # SQLite schema and hash-chained audit events
├── templates/       # Separate HTML views for student and staff portals
├── static/          # CSS, calculator JavaScript, and student payment QR image
├── requirements.txt
├── uploads/         # Local receipt proofs (ignored by Git)
└── instance/        # Local SQLite database (ignored by Git)
```

## Run locally

Python 3.11 or newer is recommended. In PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm install
npm run dev
```

`npm run dev` is a convenience launcher for `python main.py`; the application itself is Python/Flask. Install the Python requirements first. `npm install` has no JavaScript dependencies to download.

Open http://127.0.0.1:5000. Synthetic demo students are `2023-00001` and `2023-00002`; the second record has a sample library hold. Demo passwords: `student-demo`, `cashier-demo`, and `registrar-demo`. Set `DOCSECURE_STUDENT_PASSWORD`, `DOCSECURE_CASHIER_PASSWORD`, and `DOCSECURE_REGISTRAR_PASSWORD` before presenting the project. Do not use demo credentials with real records.

## Workflow

Students select a document, upload payment proof, enter an OR number, sign the undertaking when a hold exists, and track the request. Staff review proof and bind the validated OR on approval. Only the registrar can access the counter scan and audit views. Successful scan checks the ElGamal decryption, AES-GCM authentication, issuer signature, request fields, timestamp, and one-time nonce; the registrar can then mark it Claimed.

Each document copy costs PHP 100.00. Students choose 1–10 copies for each selected document. The form updates Total Amount Due as document selections and copy counts change; the server calculates and stores the same sum. The requested copy counts are included in the encrypted QR payload. Once approved, the student can download the encrypted QR image directly from the request row.

## Cryptographic and storage notes

`crypto_utils.ElGamal` uses a 2048-bit safe-prime group and fresh ephemeral exponent for ElGamal key encapsulation. The encrypted AES-256 key wraps an AES-GCM encrypted, Ed25519-signed JSON payload. The actual private exponent and signing key are generated at process start in this demo and are not persisted; restart invalidates existing QRs. A real deployment needs key custody/rotation and a client-side public-key implementation.

`database.py` defines students, staff, requests, unique active OR numbers, and an append-only SHA-256 hash-linked audit table. The audit chain makes edits detectable but SQLite alone is not tamper-proof against an administrator who can rewrite the whole file; production audit data should be replicated to a separately controlled append-only system.

The local session-signing secret is saved under the ignored `instance/` directory, so routine server restarts do not sign staff and student users out. Set `DOCSECURE_SESSION_SECRET` to override it in a deployment.

The camera upload route supports QR image decoding when `opencv-python` and `numpy` are additionally installed. The manual decoded-payload field works without them. For real use, add CSRF protection, server-side staff accounts and password hashing, rate limits, encrypted backups, a secure deployment configuration, privacy retention rules, and institution-approved payment instructions. This project is a student demo, not a production registrar service.
