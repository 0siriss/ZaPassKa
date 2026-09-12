"""
tools/make_vectors.py — regenerate docs/format/vectors.json.

The vectors pin the wire format so a second implementation can prove it
matches this one without talking to it. Everything here is deterministic:
nonces and salts are fixed constants, never random, so re-running the script
must reproduce the file byte for byte.

    python tools/make_vectors.py

The file is checked in; tests/test_format_vectors.py validates it.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # noqa: E402

import crypto    # noqa: E402
import sync      # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "format" / "vectors.json"


def fixed(tag: str, length: int) -> bytes:
    """A stable pseudo-random blob, so the file never depends on os.urandom."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"zapasska-vector-{tag}-{counter}".encode()).digest()
        counter += 1
    return out[:length]


def seal(key: bytes, nonce: bytes, plaintext: str) -> bytes:
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)


def build() -> dict:
    # ── Key derivation ────────────────────────────────────────────
    kdf_cases = []
    for tag, password in (("ad", "Passw0rd! доменный"), ("master", "correct horse battery staple")):
        salt = fixed(f"salt-{tag}", crypto._SALT_LEN)
        kdf_cases.append({
            "note":     f"scrypt for the {tag} unlock method",
            "password": password,
            "salt_hex": salt.hex(),
            "key_hex":  crypto.derive_kek(password, salt).hex(),
        })

    # ── Wrapped data key ──────────────────────────────────────────
    kek = bytes.fromhex(kdf_cases[1]["key_hex"])
    dek = fixed("dek", crypto._KEY_LEN)
    wrap_nonce = fixed("wrap-nonce", crypto._NONCE_LEN)
    wrapped = wrap_nonce + AESGCM(kek).encrypt(wrap_nonce, dek, None)

    # ── Field encryption ──────────────────────────────────────────
    field_cases = []
    for index, text in enumerate(["GitHub", "jdoe@corp.com", "пароль-Ω-🔐"]):
        nonce = fixed(f"field-nonce-{index}", crypto._NONCE_LEN)
        field_cases.append({
            "plaintext": text,
            "nonce_hex": nonce.hex(),
            "blob_hex":  seal(dek, nonce, text).hex(),
        })

    # ── A whole snapshot ──────────────────────────────────────────
    vault_id = "0f1b3c6e-7a2d-4f10-9c5b-2d8e4a6f1b30"
    entries_plain = [
        ("3f6a0d18-0f4c-4a2e-8a71-1c9b5d2e7f01", "GitHub", "jdoe@corp.com", "gh-pass", 0),
        ("7c2e9b44-51d3-4b8a-9f60-8e1a3c7d5b22", "VPN офиса", "j.doe", "vpn-pass", 0),
        ("b18d5f90-2c47-4e6b-83a1-6f0c9d4e2a13", "", "", "", 1),
    ]
    entries = []
    expected = []
    for index, (uuid, service, login, password, deleted) in enumerate(entries_plain):
        if deleted:
            entries.append({
                "uuid": uuid, "service": "", "login": "", "password": "",
                "updated_at": f"2026-02-0{index + 1}T10:00:00.000000Z",
                "deleted": 1,
            })
            continue
        blobs = [
            seal(dek, fixed(f"entry-{index}-{field}", crypto._NONCE_LEN), value)
            for field, value in (("s", service), ("l", login), ("p", password))
        ]
        entries.append({
            "uuid":       uuid,
            "service":    base64.b64encode(blobs[0]).decode(),
            "login":      base64.b64encode(blobs[1]).decode(),
            "password":   base64.b64encode(blobs[2]).decode(),
            "updated_at": f"2026-02-0{index + 1}T10:00:00.000000Z",
            "deleted":    0,
        })
        expected.append({"uuid": uuid, "service": service,
                         "login": login, "password": password})

    snapshot = {
        "format":     sync.SNAPSHOT_FORMAT,
        "vault_id":   vault_id,
        "updated_at": "2026-02-03T11:30:00.000000Z",
        "unlock_methods": [{
            "method":      "master",
            "identity":    "",
            "salt":        kdf_cases[1]["salt_hex"],
            "wrapped_dek": base64.b64encode(wrapped).decode(),
            "updated_at":  "2026-02-01T09:00:00.000000Z",
            "deleted":     0,
        }],
        "entries": entries,
    }

    return {
        "note": "Golden vectors for the ZaPassKa storage format. "
                "Regenerate with tools/make_vectors.py.",
        "scrypt": {
            "n": crypto._SCRYPT_N, "r": crypto._SCRYPT_R,
            "p": crypto._SCRYPT_P, "key_length": crypto._KEY_LEN,
        },
        "aead": {
            "algorithm": "AES-256-GCM",
            "nonce_length": crypto._NONCE_LEN,
            "tag_length": 16,
            "layout": "nonce || ciphertext || tag",
        },
        "key_derivation": kdf_cases,
        "key_wrapping": {
            "note": "The data key sealed under the master-password key above.",
            "kek_hex": kek.hex(),
            "data_key_hex": dek.hex(),
            "wrapped_hex": wrapped.hex(),
        },
        "field_encryption": {
            "note": "Fields sealed under the data key.",
            "data_key_hex": dek.hex(),
            "cases": field_cases,
        },
        "snapshot": {
            "note": "A complete vault snapshot, as stored in Google Drive. "
                    "Unwrap the data key with the master password, then read "
                    "the entries; the third one is a tombstone and must not "
                    "appear in the list.",
            "master_password": kdf_cases[1]["password"],
            "data_key_hex": dek.hex(),
            "digest": sync.snapshot_digest(snapshot),
            "document": snapshot,
            "expected_entries": expected,
        },
    }


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", "utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
