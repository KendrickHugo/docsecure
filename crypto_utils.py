"""Hybrid ElGamal QR encryption helpers for DOC-SECURE.

ElGamal encrypts a random AES key; AES-GCM encrypts the JSON request. This
avoids trying to fit a long JSON document into a single group element. A
signature authenticates the issuer and the encrypted envelope is one-time.
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# RFC 3526 group 14. g=4 generates the prime-order quadratic-residue subgroup.
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22"
        "514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
Q = (P - 1) // 2
G = 4
AAD = b"DOC-SECURE|QR|v1"
QR_TTL_SECONDS = 600


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class ElGamal:
    """ElGamal key pair plus an Ed25519 signer for authenticated QR envelopes.

    Keep ``private_x`` and ``signing_key`` on the registrar server only. The
    public parameters may be distributed to the student client.
    """
    private_x: int
    signing_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "ElGamal":
        return cls(secrets.randbelow(Q - 3) + 2, Ed25519PrivateKey.generate())

    @property
    def public_y(self) -> int:
        return pow(G, self.private_x, P)

    @property
    def verify_key(self) -> Ed25519PublicKey:
        return self.signing_key.public_key()

    def encrypt_payload(self, payload: dict) -> str:
        """Return a compact JSON ciphertext suitable for QR encoding."""
        signed = {"payload": payload, "signature": base64.b64encode(self.signing_key.sign(_canonical(payload))).decode("ascii")}
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, _canonical(signed), AAD)
        k = secrets.randbelow(Q - 3) + 2
        c1 = pow(G, k, P)
        c2 = int.from_bytes(aes_key, "big") * pow(self.public_y, k, P) % P
        return json.dumps({"v": 1, "c1": format(c1, "x"), "c2": format(c2, "x"),
                           "nonce": base64.b64encode(nonce).decode("ascii"),
                           "ct": base64.b64encode(ciphertext).decode("ascii")}, separators=(",", ":"))

    def decrypt_payload(self, token: str) -> dict:
        """Decrypt and authenticate a QR. Raises ValueError for invalid input."""
        try:
            envelope = json.loads(token)
            if envelope.get("v") != 1:
                raise ValueError("Unsupported QR version.")
            c1, c2 = int(envelope["c1"], 16), int(envelope["c2"], 16)
            if not (1 < c1 < P - 1 and pow(c1, Q, P) == 1 and 0 < c2 < P):
                raise ValueError("Invalid ElGamal ciphertext.")
            shared = pow(c1, self.private_x, P)
            key_bytes = ((c2 * pow(shared, -1, P)) % P).to_bytes(32, "big")
            raw = AESGCM(key_bytes).decrypt(base64.b64decode(envelope["nonce"], validate=True),
                                             base64.b64decode(envelope["ct"], validate=True), AAD)
            signed = json.loads(raw)
            payload = signed["payload"]
            self.verify_key.verify(base64.b64decode(signed["signature"], validate=True), _canonical(payload))
            return payload
        except (KeyError, TypeError, ValueError, InvalidSignature, InvalidTag, json.JSONDecodeError) as exc:
            raise ValueError("QR is invalid, altered, or not issued by this registrar.") from exc


def request_payload(*, request_id: str, student_id: str, documents: list[str],
                    copies: dict[str, int], or_number: str,
                    undertaking_signed: bool, amount_due: float) -> dict:
    """Build the required Stage 5 message and attach replay-defense fields."""
    return {"request_id": request_id, "student_id": student_id,
            "document_ids": documents, "document_copies": copies,
            "or_number": or_number,
            "amount_due_php": round(float(amount_due), 2),
            "undertaking_status": "signed" if undertaking_signed else "not_required",
            "timestamp": int(time.time()), "nonce": secrets.token_urlsafe(24)}


def make_qr_png(token: str) -> bytes:
    """Render ciphertext as a PNG QR; imported lazily for easier module reuse."""
    import qrcode
    from io import BytesIO
    output = BytesIO()
    qrcode.make(token).save(output, format="PNG")
    return output.getvalue()
