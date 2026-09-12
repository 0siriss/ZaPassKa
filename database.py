"""
database.py — SQLite layer
Tables:
  settings  : unencrypted key-value (ad_server, ad_domain, kdf salts)
  passwords : encrypted blobs — nonce is prepended inside each blob
"""
import hashlib
import os
import sqlite3
import sys
from pathlib import Path


def get_db_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
        db_dir = base / "ZaPassKa"
    else:
        db_dir = Path.home() / ".zapasska"

    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "tp.sec"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(get_db_path()))
    conn.row_factory = sqlite3.Row
    return conn


def _hash_username(username: str) -> str:
    """SHA-256 of lowercased username — one-way deterministic lookup key."""
    return hashlib.sha256(username.lower().encode()).hexdigest()


def init_db():
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS kdf_salts (
                username_hash TEXT PRIMARY KEY,
                salt          TEXT NOT NULL,
                verifier      BLOB
            );

            CREATE TABLE IF NOT EXISTS passwords (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                service  BLOB NOT NULL,
                login    BLOB NOT NULL,
                password BLOB NOT NULL
            );
        """)
        _migrate(conn)


def _migrate(conn: sqlite3.Connection):
    """
    Handles all migrations from older DB schemas.
    Safe to call on every startup — checks existence before acting.
    """
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    # Migration 1: old 'settings' table → kdf_salts
    if "settings" in tables:
        rows = conn.execute(
            "SELECT key, value FROM settings WHERE key LIKE 'kdf_salt_%'"
        ).fetchall()
        for row in rows:
            username = row["key"][len("kdf_salt_"):]
            conn.execute(
                "INSERT INTO kdf_salts(username_hash, salt) VALUES(?,?) "
                "ON CONFLICT(username_hash) DO NOTHING",
                (_hash_username(username), row["value"])
            )
        conn.execute("DROP TABLE settings")

    # Migration 2: passwords table — drop created_at / updated_at if present
    if "passwords" in tables:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(passwords)").fetchall()}
        if "created_at" in cols or "updated_at" in cols:
            conn.executescript("""
                ALTER TABLE passwords RENAME TO passwords_old;

                CREATE TABLE passwords (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    service  BLOB NOT NULL,
                    login    BLOB NOT NULL,
                    password BLOB NOT NULL
                );

                INSERT INTO passwords (id, service, login, password)
                SELECT id, service, login, password FROM passwords_old;

                DROP TABLE passwords_old;
            """)

    # Migration 3: add verifier column to kdf_salts if missing
    if "kdf_salts" in tables:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(kdf_salts)").fetchall()}
        if "verifier" not in cols:
            conn.execute("ALTER TABLE kdf_salts ADD COLUMN verifier BLOB")

    conn.commit()


# ── KDF salt & verifier ───────────────────────────────────────────

def get_kdf_record(username: str) -> sqlite3.Row | None:
    """Returns full row (salt, verifier) or None if user not seen before."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT salt, verifier FROM kdf_salts WHERE username_hash = ?",
            (_hash_username(username),)
        ).fetchone()


def save_kdf_record(username: str, salt_hex: str, verifier: bytes):
    """Upsert salt + verifier for username."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO kdf_salts(username_hash, salt, verifier)
               VALUES(?,?,?)
               ON CONFLICT(username_hash)
               DO UPDATE SET salt=excluded.salt, verifier=excluded.verifier""",
            (_hash_username(username), salt_hex, verifier)
        )


# ── Passwords ─────────────────────────────────────────────────────

def insert_password(service_enc: bytes, login_enc: bytes, password_enc: bytes):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO passwords (service, login, password) VALUES (?,?,?)",
            (service_enc, login_enc, password_enc)
        )


def get_all_passwords() -> list:
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, service, login, password FROM passwords ORDER BY id"
        ).fetchall()


def update_all_passwords(rows: list[tuple]):
    """Replace all password rows atomically. Used during re-encryption."""
    with get_connection() as conn:
        conn.execute("DELETE FROM passwords")
        conn.executemany(
            "INSERT INTO passwords (id, service, login, password) VALUES (?,?,?,?)",
            rows
        )


def delete_password(row_id: int):
    with get_connection() as conn:
        conn.execute("DELETE FROM passwords WHERE id = ?", (row_id,))


def update_password(row_id: int, service_enc: bytes, login_enc: bytes, password_enc: bytes):
    with get_connection() as conn:
        conn.execute(
            "UPDATE passwords SET service=?, login=?, password=? WHERE id=?",
            (service_enc, login_enc, password_enc, row_id)
        )