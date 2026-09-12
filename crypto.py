"""
crypto.py — Key derivation & encryption

Key derivation : scrypt (N=2^17, r=8, p=1) — memory-hard
Encryption     : AES-256-GCM (AEAD)

Blob format    : nonce(12) + ciphertext + tag(16)

Verifier       : AES-GCM encrypt of known constant with derived key.
                 Used to detect AD password change without storing the password.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

_SCRYPT_N   = 2 ** 17
_SCRYPT_R   = 8
_SCRYPT_P   = 1
_KEY_LEN    = 32       # 256 bits
_NONCE_LEN  = 12       # 96 bits

# Known plaintext used to verify a key is correct.
# Changing this constant will invalidate all existing verifiers.
_VERIFIER_MAGIC = b"ZaymerPassKeeker_V1"


# ── Key derivation ────────────────────────────────────────────────

def _scrypt(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=_KEY_LEN,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def derive_key(username: str, password: str) -> tuple[bytes, bool]:
    """
    Derive encryption key for username+password.

    Flow:
      1. Look up salt + verifier in DB.
      2a. First login (no record): generate salt, derive key, create verifier → save.
      2b. Normal login: derive key, verify → return key.
      2c. Password changed: verifier mismatch → return (None, False).
           Caller must show migration dialog.

    Returns:
      (key, True)   — key is valid, proceed normally
      (None, False) — verifier mismatch, AD password was changed
    """
    import database

    record = database.get_kdf_record(username)

    if record is None:
        # First login — bootstrap
        salt = os.urandom(32)
        key  = _scrypt(password, salt)
        verifier = _make_verifier(key)
        database.save_kdf_record(username, salt.hex(), verifier)
        return key, True

    salt     = bytes.fromhex(record["salt"])
    verifier = record["verifier"]
    key      = _scrypt(password, salt)

    if verifier is None:
        # Existing user from old schema without verifier — adopt key
        database.save_kdf_record(username, salt.hex(), _make_verifier(key))
        return key, True

    if _check_verifier(key, bytes(verifier)):
        return key, True

    # Verifier mismatch — password changed in AD
    return None, False


def reencrypt_all(username: str, old_password: str, new_password: str) -> bool:
    """
    Re-encrypt all password rows with new key.
    Called after AD password change is detected.

    Returns True on success, False if old_password is wrong.
    """
    import database

    record = database.get_kdf_record(username)
    if record is None:
        return False

    salt    = bytes.fromhex(record["salt"])
    old_key = _scrypt(old_password, salt)

    # Verify old key is actually correct
    if not _check_verifier(old_key, bytes(record["verifier"])):
        return False

    # Decrypt all rows with old key
    db_rows = database.get_all_passwords()
    try:
        plain_rows = [decrypt_row(old_key, r) for r in db_rows]
    except InvalidTag:
        return False

    # Re-encrypt with new key
    new_key = _scrypt(new_password, salt)
    new_rows = []
    for r in plain_rows:
        enc = encrypt_row(new_key, r["service"], r["login"], r["password"])
        new_rows.append((
            r["id"],
            enc["service_enc"],
            enc["login_enc"],
            enc["password_enc"],
        ))

    # Atomically replace all rows + update verifier
    database.update_all_passwords(new_rows)
    database.save_kdf_record(username, salt.hex(), _make_verifier(new_key))
    return True


# ── Verifier ──────────────────────────────────────────────────────

def _make_verifier(key: bytes) -> bytes:
    """Encrypt magic constant with key → store result as verifier."""
    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(key).encrypt(nonce, _VERIFIER_MAGIC, None)
    return nonce + ct


def _check_verifier(key: bytes, verifier: bytes) -> bool:
    """Return True if key correctly decrypts the verifier blob."""
    try:
        nonce = verifier[:_NONCE_LEN]
        ct    = verifier[_NONCE_LEN:]
        AESGCM(key).decrypt(nonce, ct, None)
        return True
    except InvalidTag:
        return False


# ── Encrypt / Decrypt ─────────────────────────────────────────────

def encrypt(key: bytes, plaintext: str) -> bytes:
    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct


def decrypt(key: bytes, blob: bytes) -> str:
    nonce = blob[:_NONCE_LEN]
    ct    = blob[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def encrypt_row(key: bytes, service: str, login: str, password: str) -> dict:
    return {
        "service_enc":  encrypt(key, service),
        "login_enc":    encrypt(key, login),
        "password_enc": encrypt(key, password),
    }


def decrypt_row(key: bytes, row) -> dict:
    return {
        "id":       row["id"],
        "service":  decrypt(key, bytes(row["service"])),
        "login":    decrypt(key, bytes(row["login"])),
        "password": decrypt(key, bytes(row["password"])),
    }