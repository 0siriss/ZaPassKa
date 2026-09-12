"""
cloud_sync.py — ties the snapshot merge to Google Drive storage.

One Drive file per vault, in the app's private appDataFolder. A sync is
pull → merge → push: the remote snapshot is merged into the local database
first, then the merged result is written back, so both machines end up with
the union of the changes.
"""
from dataclasses import dataclass

import gdrive
import sync
from i18n import tr


@dataclass
class SyncOutcome:
    pulled_entries: int = 0
    pulled_methods: int = 0
    pushed: bool = False
    created: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.pulled_entries or self.pulled_methods or self.pushed)

    def summary(self) -> str:
        if self.created:
            return tr("Vault backed up to Google Drive")
        if self.pulled_entries and self.pushed:
            return tr("Synced · {count} entries pulled, changes pushed",
                      count=self.pulled_entries)
        if self.pulled_entries:
            return tr("Synced · {count} entries pulled", count=self.pulled_entries)
        if self.pushed:
            return tr("Synced · changes pushed")
        return tr("Synced · already up to date")


def available() -> bool:
    return gdrive.is_connected()


def sync_vault(vault_id: str) -> SyncOutcome:
    """
    Pull the remote snapshot, merge it in, push the result back.
    Raises gdrive.DriveError when Drive cannot be reached — callers treat that
    as "work offline and try again later".
    """
    outcome = SyncOutcome()
    sync.purge_old_tombstones()

    name        = sync.snapshot_name(vault_id)
    remote_file = gdrive.find_file(name)
    remote_digest = None

    if remote_file:
        remote = sync.loads(gdrive.download(remote_file["id"]))
        if remote.get("vault_id") == vault_id:
            merged = sync.merge_snapshot(remote)
            outcome.pulled_entries = merged.entries_applied
            outcome.pulled_methods = merged.methods_applied
            remote_digest = sync.snapshot_digest(remote)

    local = sync.build_snapshot(vault_id)
    if sync.snapshot_digest(local) != remote_digest:
        gdrive.upload(name, sync.dumps(local),
                      remote_file["id"] if remote_file else None)
        outcome.pushed  = True
        outcome.created = remote_file is None

    return outcome


def pull_all_snapshots() -> tuple[int, int]:
    """
    Import every snapshot stored in Drive into the local database.

    This is what makes a second machine work: the snapshots carry the wrapped
    data keys and the encrypted entries, so after pulling them the user can
    sign in exactly as on the first machine. Nothing is decrypted here.

    Returns (vaults seen, entries applied).
    """
    vaults = entries = 0
    for meta in gdrive.list_snapshots():
        try:
            remote = sync.loads(gdrive.download(meta["id"]))
        except (ValueError, gdrive.DriveError):
            continue          # not ours, or damaged — skip it
        result = sync.merge_snapshot(remote)
        vaults  += 1
        entries += result.entries_applied
    return vaults, entries
