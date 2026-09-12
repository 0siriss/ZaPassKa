"""
sync.py — vault snapshots and two-way merge.

A snapshot is the whole vault as JSON: its unlock methods and its entries,
with the ciphertext base64-encoded. Everything inside is either public (salts,
timestamps) or encrypted (wrapped data keys, entry fields), so a snapshot is
safe to keep in cloud storage — the data key never leaves the machine that
derived it.

Merging is last-write-wins per record, keyed by entry uuid and by
(method, identity) for unlock methods. Deletions travel as tombstones, so a
row removed on one machine does not come back from another one.
"""
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import database

SNAPSHOT_FORMAT    = 1
TOMBSTONE_TTL_DAYS = 90


def snapshot_name(vault_id: str) -> str:
    return f"zapasska-{vault_id}.json"


def _b64(blob) -> str:
    return base64.b64encode(bytes(blob)).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# ── Build ─────────────────────────────────────────────────────────

def build_snapshot(vault_id: str) -> dict:
    methods = [
        {
            "method":      r["method"],
            "identity":    r["identity"],
            "salt":        r["salt"],
            "wrapped_dek": _b64(r["wrapped_dek"]),
            "updated_at":  r["updated_at"],
            "deleted":     int(r["deleted"]),
        }
        for r in database.list_unlock_methods(vault_id, include_deleted=True)
    ]
    entries = [
        {
            "uuid":       r["uuid"],
            "service":    _b64(r["service"]),
            "login":      _b64(r["login"]),
            "password":   _b64(r["password"]),
            "updated_at": r["updated_at"],
            "deleted":    int(r["deleted"]),
        }
        for r in database.get_entries(vault_id, include_deleted=True)
    ]
    return {
        "format":         SNAPSHOT_FORMAT,
        "vault_id":       vault_id,
        "updated_at":     database.utcnow(),
        "unlock_methods": methods,
        "entries":        entries,
    }


def snapshot_digest(snapshot: dict) -> str:
    """
    Content fingerprint that ignores the snapshot's own timestamp, so an
    unchanged vault is not uploaded again on every sync.
    """
    payload = {
        "vault_id":       snapshot["vault_id"],
        "unlock_methods": sorted(snapshot.get("unlock_methods", []),
                                 key=lambda m: (m["method"], m["identity"])),
        "entries":        sorted(snapshot.get("entries", []),
                                 key=lambda e: e["uuid"]),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def dumps(snapshot: dict) -> bytes:
    return json.dumps(snapshot, separators=(",", ":")).encode("utf-8")


def loads(blob: bytes) -> dict:
    snapshot = json.loads(blob.decode("utf-8"))
    if not isinstance(snapshot, dict) or "vault_id" not in snapshot:
        raise ValueError("not a ZaPassKa snapshot")
    if int(snapshot.get("format", 0)) > SNAPSHOT_FORMAT:
        raise ValueError(
            f"snapshot format {snapshot['format']} is newer than this build "
            f"supports ({SNAPSHOT_FORMAT}) — update ZaPassKa"
        )
    return snapshot


# ── Merge ─────────────────────────────────────────────────────────

class MergeResult:
    def __init__(self):
        self.entries_applied = 0
        self.methods_applied = 0

    @property
    def changed(self) -> bool:
        return bool(self.entries_applied or self.methods_applied)

    def __repr__(self):
        return (f"MergeResult(entries={self.entries_applied}, "
                f"methods={self.methods_applied})")


def merge_snapshot(remote: dict) -> MergeResult:
    """
    Apply a remote snapshot on top of the local database.
    A remote record wins only when its updated_at is strictly newer, so a tie
    keeps whatever is already local.
    """
    result   = MergeResult()
    vault_id = remote["vault_id"]
    database.ensure_vault(vault_id)

    local_methods = {
        (r["method"], r["identity"]): r["updated_at"]
        for r in database.list_unlock_methods(vault_id, include_deleted=True)
    }
    for m in remote.get("unlock_methods", []):
        local_ts = local_methods.get((m["method"], m["identity"]))
        if local_ts is not None and m["updated_at"] <= local_ts:
            continue
        database.upsert_unlock_method_raw({
            "vault_id":    vault_id,
            "method":      m["method"],
            "identity":    m["identity"],
            "salt":        m["salt"],
            "wrapped_dek": _unb64(m["wrapped_dek"]),
            "updated_at":  m["updated_at"],
            "deleted":     int(m.get("deleted", 0)),
        })
        result.methods_applied += 1

    local_entries = {
        r["uuid"]: r["updated_at"]
        for r in database.get_entries(vault_id, include_deleted=True)
    }
    for e in remote.get("entries", []):
        local_ts = local_entries.get(e["uuid"])
        if local_ts is not None and e["updated_at"] <= local_ts:
            continue
        database.upsert_entry_raw({
            "uuid":       e["uuid"],
            "vault_id":   vault_id,
            "service":    _unb64(e["service"]),
            "login":      _unb64(e["login"]),
            "password":   _unb64(e["password"]),
            "updated_at": e["updated_at"],
            "deleted":    int(e.get("deleted", 0)),
        })
        result.entries_applied += 1

    # Two machines apart can each switch method, and the merge would then
    # bring both back. A vault has exactly one way in, so settle on the newest.
    if database.enforce_single_method(vault_id):
        result.methods_applied += 1

    return result


def purge_old_tombstones():
    """
    Forget deletions older than the TTL. A machine offline for longer than
    that can resurrect an entry it never learned was deleted.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=TOMBSTONE_TTL_DAYS)
    database.purge_tombstones(cutoff.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
