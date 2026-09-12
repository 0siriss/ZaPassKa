"""
crypto.py — key management & encryption.

Key hierarchy
-------------
Every vault owns a random 256-bit **data key (DEK)**. Entries are encrypted
with the DEK and nothing else.

Each way of unlocking the vault — Active Directory credentials or a master
password — derives a **key-encryption key (KEK)** from its own secret with
scrypt and its own random salt, and stores the DEK wrapped under that KEK.

    AD password ──scrypt(salt_ad)──► KEK_ad ──► wrap(DEK)
    master pw   ──scrypt(salt_mp)──► KEK_mp ──► wrap(DEK)
                                                  │
                                     entries ◄────┘ AES-256-GCM

Consequences:
  * Both unlock methods open the same entries.
  * Switching between them, or changing either secret, only rewraps the DEK —
    entries are never re-encrypted and can never be lost in the process.
  * A failed unwrap (InvalidTag) is itself the wrong-secret check, so no
    password or verifier needs to be stored.

Blob format everywhere: nonce(12) + ciphertext + tag(16).
"""

import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import database
from database import METHOD_AD, METHOD_MASTER

_SCRYPT_N  = 2 ** 17      # ~1 s, 128 MB
_SCRYPT_R  = 8
_SCRYPT_P  = 1
_KEY_LEN   = 32           # 256 bits
_NONCE_LEN = 12           # 96 bits
_SALT_LEN  = 32

# Legacy (pre-vault) schema constant — see migrate_legacy_user.
_VERIFIER_MAGIC = b"ZaymerPassKeeker_V1"

# Unlock outcomes
OK           = "ok"
NO_METHOD    = "no_method"      # nothing stored for this identity yet
WRONG_SECRET = "wrong_secret"   # secret does not unwrap the data key


@dataclass
class VaultSession:
    """An unlocked vault. `dek` lives only in memory, for this session."""
    vault_id: str
    dek: bytes
    method: str
    identity: str
    display_name: str = ""

    def close(self):
        self.dek = b""


# ── Key derivation & wrapping ─────────────────────────────────────

def derive_kek(secret: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt, length=_KEY_LEN,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(secret.encode("utf-8"))


def wrap_dek(kek: bytes, dek: bytes) -> bytes:
    nonce = os.urandom(_NONCE_LEN)
    return nonce + AESGCM(kek).encrypt(nonce, dek, None)


def unwrap_dek(kek: bytes, wrapped: bytes) -> bytes | None:
    """Return the data key, or None when the secret is wrong."""
    try:
        return AESGCM(kek).decrypt(wrapped[:_NONCE_LEN], wrapped[_NONCE_LEN:], None)
    except InvalidTag:
        return None


# ── Field encryption ──────────────────────────────────────────────

def encrypt(dek: bytes, plaintext: str) -> bytes:
    nonce = os.urandom(_NONCE_LEN)
    return nonce + AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), None)


def decrypt(dek: bytes, blob: bytes) -> str:
    return AESGCM(dek).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], None).decode("utf-8")


def encrypt_row(dek: bytes, service: str, login: str, password: str) -> dict:
    return {
        "service_enc":  encrypt(dek, service),
        "login_enc":    encrypt(dek, login),
        "password_enc": encrypt(dek, password),
    }


def decrypt_row(dek: bytes, row) -> dict:
    return {
        "uuid":     row["uuid"],
        "service":  decrypt(dek, bytes(row["service"])),
        "login":    decrypt(dek, bytes(row["login"])),
        "password": decrypt(dek, bytes(row["password"])),
    }


# ── Creating & unlocking vaults ───────────────────────────────────

def create_vault(method: str, identity: str, secret: str,
                 display_name: str = "") -> VaultSession:
    """New vault with a random data key, unlockable by the given secret."""
    vault_id = database.create_vault()
    dek      = os.urandom(_KEY_LEN)
    _store_method(vault_id, method, identity, secret, dek)
    return VaultSession(vault_id, dek, method, identity, display_name)


def _store_method(vault_id: str, method: str, identity: str,
                  secret: str, dek: bytes, exclusive: bool = False):
    """
    Wrap the data key under a key derived from `secret`.
    With exclusive=True this becomes the vault's only way in.
    """
    salt    = os.urandom(_SALT_LEN)
    kek     = derive_kek(secret, salt)
    wrapped = wrap_dek(kek, dek)
    if exclusive:
        database.replace_unlock_method(vault_id, method, identity, salt.hex(), wrapped)
    else:
        database.save_unlock_method(vault_id, method, identity, salt.hex(), wrapped)


def _try_unlock(rows, secret: str, method: str) -> VaultSession | None:
    """
    Open the vault this secret unwraps.

    One secret is meant to open one vault, but two machines can each start a
    vault for the same account before they ever meet through the cloud: an old
    database migrated separately on both, say. Once they do meet, the secret
    opens two, and picking either one would hide half the user's passwords.
    So every match is opened and the duplicates are folded into one.
    """
    sessions = []
    for row in rows:
        kek = derive_kek(secret, bytes.fromhex(row["salt"]))
        dek = unwrap_dek(kek, bytes(row["wrapped_dek"]))
        if dek is not None:
            sessions.append(
                VaultSession(row["vault_id"], dek, method, row["identity"]))

    if not sessions:
        return None
    if len(sessions) == 1:
        return sessions[0]
    return _absorb_duplicates(sessions)


def _absorb_duplicates(sessions: list[VaultSession]) -> VaultSession:
    """
    Fold several vaults opened by one secret into a single one.

    The survivor is chosen by the lowest vault id, which every machine agrees
    on without talking to the others. Entries are copied first and only then
    retired from the vault they came from, so an interruption duplicates an
    entry rather than losing it.
    """
    survivor = min(sessions, key=lambda session: session.vault_id)

    for other in sessions:
        if other.vault_id == survivor.vault_id:
            continue
        for row in database.get_entries(other.vault_id):
            plain = decrypt_row(other.dek, row)
            enc = encrypt_row(survivor.dek, plain["service"],
                              plain["login"], plain["password"])
            database.insert_entry(
                survivor.vault_id, enc["service_enc"], enc["login_enc"],
                enc["password_enc"],
                entry_uuid=database.derived_uuid(survivor.vault_id, row["uuid"])
            )
            database.delete_entry(row["uuid"])
        database.delete_unlock_method(other.vault_id, other.method, other.identity)

    return survivor


def unlock_with_ad(username: str, password: str) -> tuple[VaultSession | None, str]:
    """
    Open the vault tied to an AD account. Call only after AD accepted the
    password — then a failed unwrap means the AD password has changed since
    the vault was wrapped, not that the user mistyped.
    """
    identity = database.hash_identity(username)
    rows     = database.find_unlock_methods(METHOD_AD, identity)

    if not rows:
        migrated = migrate_legacy_user(username, password)
        if migrated is not None:
            return migrated, OK
        return None, NO_METHOD

    session = _try_unlock(rows, password, METHOD_AD)
    if session is None:
        return None, WRONG_SECRET
    session.display_name = username
    return session, OK


def unlock_with_master(password: str) -> tuple[VaultSession | None, str]:
    """Open whichever vault this master password unwraps."""
    rows = database.find_unlock_methods(METHOD_MASTER)
    if not rows:
        return None, NO_METHOD

    session = _try_unlock(rows, password, METHOD_MASTER)
    if session is None:
        return None, WRONG_SECRET
    session.display_name = "master password"
    return session, OK


def rewrap_method(vault_id: str, method: str, identity: str,
                  old_secret: str, new_secret: str) -> bool:
    """
    Re-wrap the data key under a new secret, e.g. after an AD password change.
    Entries are untouched. Returns False if old_secret is wrong.
    """
    row = database.get_unlock_method(vault_id, method, identity)
    if row is None:
        return False

    kek = derive_kek(old_secret, bytes.fromhex(row["salt"]))
    dek = unwrap_dek(kek, bytes(row["wrapped_dek"]))
    if dek is None:
        return False

    _store_method(vault_id, method, identity, new_secret, dek)
    return True


def recover_with_old_ad_password(username: str, old_password: str,
                                 new_password: str) -> VaultSession | None:
    """
    AD password changed: unwrap with the previous password, rewrap with the
    current one. Returns the opened session, or None if old_password is wrong.
    """
    identity = database.hash_identity(username)
    rows     = database.find_unlock_methods(METHOD_AD, identity)

    session = _try_unlock(rows, old_password, METHOD_AD)
    if session is None:
        return None

    _store_method(session.vault_id, METHOD_AD, identity, new_password, session.dek)
    session.display_name = username
    return session


# ── Switching the unlock method of an open vault ──────────────────
#
# A vault has exactly one way in. Switching rewraps the data key under the
# new secret and retires the old wrapping; the entries are never touched, so
# nothing can be lost in the move.

def switch_to_master(session: VaultSession, master_password: str):
    """Make a master password the only way into this vault."""
    _store_method(session.vault_id, METHOD_MASTER, "", master_password,
                  session.dek, exclusive=True)
    session.method   = METHOD_MASTER
    session.identity = ""


def verify_master_password(session: VaultSession, password: str) -> bool:
    """
    True when `password` is the vault's current master password.

    Asked before changing it, so that walking up to an unlocked session is not
    enough to re-key someone else's vault.
    """
    row = database.get_unlock_method(session.vault_id, METHOD_MASTER, "")
    if row is None:
        return False

    kek = derive_kek(password, bytes.fromhex(row["salt"]))
    dek = unwrap_dek(kek, bytes(row["wrapped_dek"]))
    return dek is not None and hmac.compare_digest(dek, session.dek)


def switch_to_ad(session: VaultSession, username: str, ad_password: str):
    """Make an AD account the only way into this vault."""
    identity = database.hash_identity(username)
    _store_method(session.vault_id, METHOD_AD, identity, ad_password,
                  session.dek, exclusive=True)
    session.method       = METHOD_AD
    session.identity     = identity
    session.display_name = username


def current_method(vault_id: str):
    """The vault's active unlock method, or None if it somehow has none."""
    rows = database.list_unlock_methods(vault_id)
    return rows[0] if rows else None


# ── Migration from the pre-vault schema ───────────────────────────

def migrate_legacy_user(username: str, password: str) -> VaultSession | None:
    """
    Convert an old-format database (kdf_salts + passwords, everything encrypted
    straight from the AD password) into a vault with a data key.

    Only the rows this user's key can actually decrypt are moved, so several
    users sharing one machine migrate independently. Returns None when the
    user has no legacy data or the password does not fit it.
    """
    record = database.legacy_kdf_record(username)
    if record is None:
        return None

    legacy_key = derive_kek(password, bytes.fromhex(record["salt"]))

    if record["verifier"] is not None and not _check_legacy_verifier(
            legacy_key, bytes(record["verifier"])):
        return None

    moved, row_ids = [], []
    for row in database.legacy_passwords():
        try:
            moved.append((
                decrypt(legacy_key, bytes(row["service"])),
                decrypt(legacy_key, bytes(row["login"])),
                decrypt(legacy_key, bytes(row["password"])),
            ))
            row_ids.append(row["id"])
        except (InvalidTag, UnicodeDecodeError, ValueError):
            continue      # belongs to another user of this machine

    if record["verifier"] is None and not moved:
        # The oldest databases stored no verifier. Without one, a key that
        # decrypts nothing is indistinguishable from a wrong password, so
        # refuse rather than retire a vault that might still be readable.
        return None

    session = create_vault(METHOD_AD, database.hash_identity(username),
                           password, display_name=username)
    for service, login, secret in moved:
        enc = encrypt_row(session.dek, service, login, secret)
        database.insert_entry(session.vault_id, enc["service_enc"],
                              enc["login_enc"], enc["password_enc"])

    database.legacy_drop_user(username, row_ids)
    return session


def _check_legacy_verifier(key: bytes, verifier: bytes) -> bool:
    try:
        AESGCM(key).decrypt(verifier[:_NONCE_LEN], verifier[_NONCE_LEN:], None)
        return True
    except InvalidTag:
        return False
