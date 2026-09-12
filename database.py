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
        _tombstone(conn, vault_id, "AND method=? AND identity=?", (method, identity))


def _tombstone(conn: sqlite3.Connection, vault_id: str, extra: str, params: tuple):
    conn.execute(
        f"""UPDATE unlock_methods
               SET deleted=1, updated_at=?, salt='', wrapped_dek=X''
             WHERE vault_id=? AND deleted=0 {extra}""",
        (utcnow(), vault_id, *params)
    )


def replace_unlock_method(vault_id: str, method: str, identity: str,
                          salt_hex: str, wrapped_dek: bytes):
    """
    Make this the vault's only way in, in one transaction.

    The new method is written before the old ones are tombstoned, so a crash
    halfway through leaves the vault openable by both rather than by neither.
    """
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
        _tombstone(conn, vault_id, "AND NOT (method=? AND identity=?)",
                   (method, identity))


def enforce_single_method(vault_id: str) -> int:
    """
    Keep only the newest unlock method of a vault, tombstoning the rest.

    A vault is meant to have exactly one. Two machines can still each switch
    method while apart, and the merge would then bring both back to life.
    Resolving by updated_at leaves every machine with the same survivor.
    Returns how many were dropped.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT method, identity FROM unlock_methods
                WHERE vault_id=? AND deleted=0
                ORDER BY updated_at DESC, method, identity""",
            (vault_id,)
        ).fetchall()
        if len(rows) <= 1:
            return 0

        keep = rows[0]
        _tombstone(conn, vault_id, "AND NOT (method=? AND identity=?)",
                   (keep["method"], keep["identity"]))
        return len(rows) - 1


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
#
# Three shapes have existed and all of them may still be on disk:
#   1. settings(key='kdf_salt_<user>') + passwords with nonce_s/nonce_l/nonce_p
#   2. kdf_salts without a verifier column
#   3. kdf_salts with a verifier, blobs carrying their own nonce
# Everything here normalises them to one shape so the migration sees no
# difference, because guessing wrong means a user loses their passwords.

_LEGACY_SALT_PREFIX = "kdf_salt_"


def _columns(conn: sqlite3.Connection, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def legacy_kdf_record(username: str) -> dict | None:
    """The user's salt and verifier from whichever old table holds them."""
    with get_connection() as conn:
        if _table_exists(conn, "kdf_salts"):
            columns = _columns(conn, "kdf_salts")
            verifier = "verifier" if "verifier" in columns else "NULL AS verifier"
            row = conn.execute(
                f"SELECT salt, {verifier} FROM kdf_salts WHERE username_hash=?",
                (hash_identity(username),)
            ).fetchone()
            if row is not None:
                return {"salt": row["salt"], "verifier": row["verifier"]}

        # The first release kept salts in a settings table, keyed by name.
        if _table_exists(conn, "settings"):
            rows = conn.execute(
                "SELECT key, value FROM settings WHERE key LIKE ?",
                (_LEGACY_SALT_PREFIX + "%",)
            ).fetchall()
            for row in rows:
                if row["key"][len(_LEGACY_SALT_PREFIX):].lower() == username.lower():
                    return {"salt": row["value"], "verifier": None}

        return None


def legacy_passwords() -> list[dict]:
    """
    Old rows with each field as one blob of nonce + ciphertext.

    The first schema kept the nonce in its own column, so it is put back in
    front of the ciphertext here. An unrecognised table yields nothing, which
    stops the migration rather than letting it discard rows it cannot read.
    """
    with get_connection() as conn:
        if not _table_exists(conn, "passwords"):
            return []

        columns = _columns(conn, "passwords")
        if not {"id", "service", "login", "password"} <= columns:
            return []

        split_nonce = {"nonce_s", "nonce_l", "nonce_p"} <= columns
        if split_nonce:
            rows = conn.execute(
                "SELECT id, service, login, password, nonce_s, nonce_l, nonce_p "
                "  FROM passwords ORDER BY id"
            ).fetchall()
            return [
                {
                    "id":       row["id"],
                    "service":  bytes(row["nonce_s"]) + bytes(row["service"]),
                    "login":    bytes(row["nonce_l"]) + bytes(row["login"]),
                    "password": bytes(row["nonce_p"]) + bytes(row["password"]),
                }
                for row in rows
            ]

        rows = conn.execute(
            "SELECT id, service, login, password FROM passwords ORDER BY id"
        ).fetchall()
        return [
            {
                "id":       row["id"],
                "service":  bytes(row["service"]),
                "login":    bytes(row["login"]),
                "password": bytes(row["password"]),
            }
            for row in rows
        ]


def legacy_has_data() -> bool:
    with get_connection() as conn:
        for table, sql in (("kdf_salts", "SELECT 1 FROM kdf_salts LIMIT 1"),
                           ("settings",
                            "SELECT 1 FROM settings WHERE key LIKE 'kdf_salt_%' LIMIT 1")):
            if _table_exists(conn, table) and conn.execute(sql).fetchone():
                return True
        return False


def legacy_has_user(username: str) -> bool:
    """Whether an old database holds a vault for this account."""
    return legacy_kdf_record(username) is not None


def legacy_drop_user(username: str, row_ids: list[int]):
    """Remove a migrated user's salt and the rows that moved to the new schema."""
    with get_connection() as conn:
        if _table_exists(conn, "kdf_salts"):
            conn.execute("DELETE FROM kdf_salts WHERE username_hash=?",
                         (hash_identity(username),))

        if _table_exists(conn, "settings"):
            rows = conn.execute(
                "SELECT key FROM settings WHERE key LIKE ?",
                (_LEGACY_SALT_PREFIX + "%",)
            ).fetchall()
            for row in rows:
                if row["key"][len(_LEGACY_SALT_PREFIX):].lower() == username.lower():
                    conn.execute("DELETE FROM settings WHERE key=?", (row["key"],))

        if _table_exists(conn, "passwords") and row_ids:
            conn.executemany("DELETE FROM passwords WHERE id=?",
                             [(i,) for i in row_ids])

        _drop_empty_legacy_tables(conn)


def _drop_empty_legacy_tables(conn: sqlite3.Connection):
    """Retire the old tables once the last user has moved off them."""
    salts_left = (
        _table_exists(conn, "kdf_salts")
        and conn.execute("SELECT 1 FROM kdf_salts LIMIT 1").fetchone() is not None
    ) or (
        _table_exists(conn, "settings")
        and conn.execute(
            "SELECT 1 FROM settings WHERE key LIKE 'kdf_salt_%' LIMIT 1"
        ).fetchone() is not None
    )
    rows_left = (
        _table_exists(conn, "passwords")
        and conn.execute("SELECT 1 FROM passwords LIMIT 1").fetchone() is not None
    )
    if salts_left or rows_left:
        return

    for table in ("kdf_salts", "passwords"):
        if _table_exists(conn, table):
            conn.execute(f"DROP TABLE {table}")
