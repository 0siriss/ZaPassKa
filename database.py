"""
database.py — SQLite layer.

Schema
------
vaults          : one row per vault (a set of entries sharing one data key)
unlock_methods  : how a vault can be unlocked — AD credentials or master
                  password. Each row stores the vault data key wrapped with a
                  key derived from that method's secret.
entries         : encrypted entries with sync metadata (uuid, updated_at,
                  tombstone flag).

Legacy tables (kdf_salts, passwords) are kept until the owning user signs in
once; see crypto.migrate_legacy_user.
"""
import hashlib
import os
import sqlite3
import sys
import uuid as _uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

METHOD_AD     = "ad"
METHOD_MASTER = "master"


# ── Paths & connections ───────────────────────────────────────────

def get_app_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
        app_dir = base / "ZaPassKa"
    else:
        app_dir = Path.home() / ".zapasska"
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir


def get_db_path() -> Path:
    override = os.environ.get("ZAPASSKA_DB")
    if override:
        path = Path(override)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    return get_app_dir() / "tp.sec"


@contextmanager
def get_connection():
    """Connection that commits on success, rolls back on error, always closes."""
    conn = sqlite3.connect(str(get_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def utcnow() -> str:
    """ISO-8601 UTC timestamp. Sorts lexicographically — used for sync merges."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_uuid() -> str:
    return str(_uuid.uuid4())


def hash_identity(username: str) -> str:
    """SHA-256 of the lowercased username — one-way deterministic lookup key."""
    return hashlib.sha256(username.lower().encode()).hexdigest()


# ── Schema ────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vaults (
    id         TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS unlock_methods (
    vault_id    TEXT NOT NULL,
    method      TEXT NOT NULL,
    identity    TEXT NOT NULL,
    salt        TEXT NOT NULL,
    wrapped_dek BLOB NOT NULL,
    updated_at  TEXT NOT NULL,
    deleted     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (vault_id, method, identity)
);

CREATE TABLE IF NOT EXISTS entries (
    uuid       TEXT PRIMARY KEY,
    vault_id   TEXT NOT NULL,
    service    BLOB NOT NULL,
    login      BLOB NOT NULL,
    password   BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    deleted    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_entries_vault ON entries(vault_id, deleted);
"""


def init_db():
    with get_connection() as conn:
        conn.executescript(_SCHEMA)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


# ── Vaults ────────────────────────────────────────────────────────

def create_vault() -> str:
    vault_id = new_uuid()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO vaults (id, created_at) VALUES (?,?)",
            (vault_id, utcnow())
        )
    return vault_id


def vault_exists(vault_id: str) -> bool:
    with get_connection() as conn:
        return conn.execute(
            "SELECT 1 FROM vaults WHERE id=?", (vault_id,)
        ).fetchone() is not None


def ensure_vault(vault_id: str):
    """Create the vault row if a sync pulled entries for an unknown vault."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO vaults (id, created_at) VALUES (?,?) "
            "ON CONFLICT(id) DO NOTHING",
            (vault_id, utcnow())
        )


def list_vaults() -> list[str]:
    with get_connection() as conn:
        return [r["id"] for r in conn.execute("SELECT id FROM vaults ORDER BY created_at")]


# ── Unlock methods ────────────────────────────────────────────────

def get_unlock_method(vault_id: str, method: str, identity: str) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM unlock_methods "
            " WHERE vault_id=? AND method=? AND identity=? AND deleted=0",
            (vault_id, method, identity)
        ).fetchone()


def find_unlock_methods(method: str, identity: str | None = None) -> list[sqlite3.Row]:
    """All live unlock methods of a kind, newest first — candidates for unlocking."""
    sql = "SELECT * FROM unlock_methods WHERE method=? AND deleted=0"
    params: list = [method]
    if identity is not None:
        sql += " AND identity=?"
        params.append(identity)
    sql += " ORDER BY updated_at DESC"
    with get_connection() as conn:
        return conn.execute(sql, params).fetchall()


def list_unlock_methods(vault_id: str, include_deleted: bool = False) -> list[sqlite3.Row]:
    sql = "SELECT * FROM unlock_methods WHERE vault_id=?"
    if not include_deleted:
        sql += " AND deleted=0"
    sql += " ORDER BY method, identity"
    with get_connection() as conn:
        return conn.execute(sql, (vault_id,)).fetchall()


def save_unlock_method(vault_id: str, method: str, identity: str,
                       salt_hex: str, wrapped_dek: bytes):
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO unlock_methods
                   (vault_id, method, identity, salt, wrapped_dek, updated_at, deleted)
               VALUES (?,?,?,?,?,?,0)
               ON CONFLICT(vault_id, method, identity) DO UPDATE SET
                   salt        = excluded.salt,
                   wrapped_dek = excluded.wrapped_dek,
                   updated_at  = excluded.updated_at,
                   deleted     = 0""",
            (vault_id, method, identity, salt_hex, wrapped_dek, utcnow())
        )


def delete_unlock_method(vault_id: str, method: str, identity: str):
    """Soft delete, so the removal reaches the other machines through sync."""
    with get_connection() as conn:
        conn.execute(
            """UPDATE unlock_methods
                  SET deleted=1, updated_at=?, salt='', wrapped_dek=X''
                WHERE vault_id=? AND method=? AND identity=?""",
            (utcnow(), vault_id, method, identity)
        )


def upsert_unlock_method_raw(row: dict):
    """Write an unlock method verbatim (used by sync — keeps incoming updated_at)."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO unlock_methods
                   (vault_id, method, identity, salt, wrapped_dek, updated_at, deleted)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(vault_id, method, identity) DO UPDATE SET
                   salt        = excluded.salt,
                   wrapped_dek = excluded.wrapped_dek,
                   updated_at  = excluded.updated_at,
                   deleted     = excluded.deleted""",
            (row["vault_id"], row["method"], row["identity"], row["salt"],
             row["wrapped_dek"], row["updated_at"], int(row["deleted"]))
        )


def count_unlock_methods(vault_id: str) -> int:
    with get_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM unlock_methods WHERE vault_id=? AND deleted=0",
            (vault_id,)
        ).fetchone()["n"]


def has_method(method: str) -> bool:
    with get_connection() as conn:
        return conn.execute(
            "SELECT 1 FROM unlock_methods WHERE method=? AND deleted=0 LIMIT 1",
            (method,)
        ).fetchone() is not None


# ── Entries ───────────────────────────────────────────────────────

def get_entries(vault_id: str, include_deleted: bool = False) -> list[sqlite3.Row]:
    sql = "SELECT * FROM entries WHERE vault_id=?"
    if not include_deleted:
        sql += " AND deleted=0"
    sql += " ORDER BY updated_at"
    with get_connection() as conn:
        return conn.execute(sql, (vault_id,)).fetchall()


def insert_entry(vault_id: str, service_enc: bytes, login_enc: bytes,
                 password_enc: bytes) -> str:
    entry_uuid = new_uuid()
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO entries
                   (uuid, vault_id, service, login, password, updated_at, deleted)
               VALUES (?,?,?,?,?,?,0)""",
            (entry_uuid, vault_id, service_enc, login_enc, password_enc, utcnow())
        )
    return entry_uuid


def update_entry(entry_uuid: str, service_enc: bytes, login_enc: bytes,
                 password_enc: bytes):
    with get_connection() as conn:
        conn.execute(
            """UPDATE entries
                  SET service=?, login=?, password=?, updated_at=?, deleted=0
                WHERE uuid=?""",
            (service_enc, login_enc, password_enc, utcnow(), entry_uuid)
        )


def delete_entry(entry_uuid: str):
    """Soft delete — the tombstone is what propagates the deletion to other PCs."""
    with get_connection() as conn:
        conn.execute(
            """UPDATE entries
                  SET deleted=1, updated_at=?,
                      service=X'', login=X'', password=X''
                WHERE uuid=?""",
            (utcnow(), entry_uuid)
        )


def upsert_entry_raw(row: dict):
    """Write an entry verbatim (used by sync — keeps the incoming updated_at)."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO entries
                   (uuid, vault_id, service, login, password, updated_at, deleted)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(uuid) DO UPDATE SET
                   vault_id   = excluded.vault_id,
                   service    = excluded.service,
                   login      = excluded.login,
                   password   = excluded.password,
                   updated_at = excluded.updated_at,
                   deleted    = excluded.deleted""",
            (row["uuid"], row["vault_id"], row["service"], row["login"],
             row["password"], row["updated_at"], int(row["deleted"]))
        )


def purge_tombstones(older_than: str):
    """Drop tombstones older than the given timestamp, entries and methods alike."""
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM entries WHERE deleted=1 AND updated_at < ?", (older_than,)
        )
        conn.execute(
            "DELETE FROM unlock_methods WHERE deleted=1 AND updated_at < ?", (older_than,)
        )


# ── Legacy schema (pre-vault) ─────────────────────────────────────

def legacy_kdf_record(username: str) -> sqlite3.Row | None:
    with get_connection() as conn:
        if not _table_exists(conn, "kdf_salts"):
            return None
        return conn.execute(
            "SELECT salt, verifier FROM kdf_salts WHERE username_hash=?",
            (hash_identity(username),)
        ).fetchone()


def legacy_passwords() -> list[sqlite3.Row]:
    with get_connection() as conn:
        if not _table_exists(conn, "passwords"):
            return []
        return conn.execute(
            "SELECT id, service, login, password FROM passwords ORDER BY id"
        ).fetchall()


def legacy_has_data() -> bool:
    with get_connection() as conn:
        return _table_exists(conn, "kdf_salts") and conn.execute(
            "SELECT 1 FROM kdf_salts LIMIT 1"
        ).fetchone() is not None


def legacy_drop_user(username: str, row_ids: list[int]):
    """Remove a migrated user's salt and the rows that moved to the new schema."""
    with get_connection() as conn:
        if _table_exists(conn, "kdf_salts"):
            conn.execute(
                "DELETE FROM kdf_salts WHERE username_hash=?",
                (hash_identity(username),)
            )
        if _table_exists(conn, "passwords") and row_ids:
            conn.executemany(
                "DELETE FROM passwords WHERE id=?", [(i,) for i in row_ids]
            )
        # Once nothing is left behind, the old tables go away for good.
        if _table_exists(conn, "kdf_salts") and _table_exists(conn, "passwords"):
            salts_left = conn.execute("SELECT 1 FROM kdf_salts LIMIT 1").fetchone()
            rows_left  = conn.execute("SELECT 1 FROM passwords LIMIT 1").fetchone()
            if not salts_left and not rows_left:
                conn.execute("DROP TABLE kdf_salts")
                conn.execute("DROP TABLE passwords")
