"""Two-way snapshot merge, exercised as two machines sharing one vault."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crypto        # noqa: E402
import database      # noqa: E402
import sync          # noqa: E402
from database import METHOD_AD, METHOD_MASTER   # noqa: E402


class TwoMachineTestCase(unittest.TestCase):
    """
    Machine A and machine B each have their own database file. Switching
    `ZAPASSKA_DB` is what the app sees as running on the other PC; the Drive
    file is the snapshot handed between them.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._db = {
            "A": str(Path(self._tmp.name) / "a.sec"),
            "B": str(Path(self._tmp.name) / "b.sec"),
        }
        self._real_n = crypto._SCRYPT_N
        crypto._SCRYPT_N = 2 ** 10
        for name in self._db:
            self.on(name)
            database.init_db()

    def tearDown(self):
        crypto._SCRYPT_N = self._real_n
        os.environ.pop("ZAPASSKA_DB", None)
        self._tmp.cleanup()

    def on(self, machine: str):
        os.environ["ZAPASSKA_DB"] = self._db[machine]

    def add_entry(self, session, service, login, password) -> str:
        enc = crypto.encrypt_row(session.dek, service, login, password)
        return database.insert_entry(session.vault_id, enc["service_enc"],
                                     enc["login_enc"], enc["password_enc"])

    def services(self, session) -> set:
        return {crypto.decrypt_row(session.dek, r)["service"]
                for r in database.get_entries(session.vault_id)}


class TestSnapshotTransfer(TwoMachineTestCase):

    def test_second_machine_opens_the_vault_from_a_snapshot(self):
        """The whole point of the backup: same master password, other PC."""
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        self.add_entry(session, "GitHub", "jdoe", "gh-pass")
        snapshot = sync.build_snapshot(session.vault_id)

        self.on("B")
        self.assertEqual(crypto.unlock_with_master("master pw")[1], crypto.NO_METHOD)

        sync.merge_snapshot(sync.loads(sync.dumps(snapshot)))
        opened, status = crypto.unlock_with_master("master pw")

        self.assertEqual(status, crypto.OK)
        self.assertEqual(opened.vault_id, session.vault_id)
        self.assertEqual(self.services(opened), {"GitHub"})

    def test_snapshot_carries_no_plaintext(self):
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        self.add_entry(session, "GitHub", "jdoe@corp.com", "sup3r-s3cret")

        blob = sync.dumps(sync.build_snapshot(session.vault_id))

        for secret in (b"sup3r-s3cret", b"jdoe@corp.com", b"GitHub", b"master pw"):
            self.assertNotIn(secret, blob)

    def test_edits_flow_in_both_directions(self):
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        self.add_entry(session, "GitHub", "jdoe", "gh-pass")
        to_b = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(to_b)
        on_b, _ = crypto.unlock_with_master("master pw")
        self.add_entry(on_b, "Jira", "jdoe", "jira-pass")
        to_a = sync.build_snapshot(on_b.vault_id)

        self.on("A")
        result = sync.merge_snapshot(to_a)

        self.assertEqual(result.entries_applied, 1)
        self.assertEqual(self.services(session), {"GitHub", "Jira"})

    def test_newer_edit_wins(self):
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        uuid = self.add_entry(session, "GitHub", "jdoe", "old-pass")
        to_b = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(to_b)
        on_b, _ = crypto.unlock_with_master("master pw")
        enc = crypto.encrypt_row(on_b.dek, "GitHub", "jdoe", "new-pass")
        database.update_entry(uuid, enc["service_enc"], enc["login_enc"],
                              enc["password_enc"])
        to_a = sync.build_snapshot(on_b.vault_id)

        self.on("A")
        sync.merge_snapshot(to_a)
        rows = database.get_entries(session.vault_id)

        self.assertEqual(len(rows), 1)
        self.assertEqual(crypto.decrypt_row(session.dek, rows[0])["password"],
                         "new-pass")

    def test_an_older_snapshot_does_not_overwrite_newer_local_data(self):
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        uuid = self.add_entry(session, "GitHub", "jdoe", "old-pass")
        stale = sync.build_snapshot(session.vault_id)

        enc = crypto.encrypt_row(session.dek, "GitHub", "jdoe", "newer-pass")
        database.update_entry(uuid, enc["service_enc"], enc["login_enc"],
                              enc["password_enc"])

        result = sync.merge_snapshot(stale)

        self.assertEqual(result.entries_applied, 0)
        self.assertEqual(
            crypto.decrypt_row(session.dek, database.get_entries(session.vault_id)[0])
            ["password"], "newer-pass")

    def test_deletion_propagates_and_stays_deleted(self):
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        uuid = self.add_entry(session, "GitHub", "jdoe", "gh-pass")
        to_b = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(to_b)
        on_b, _ = crypto.unlock_with_master("master pw")
        self.assertEqual(self.services(on_b), {"GitHub"})

        self.on("A")
        database.delete_entry(uuid)
        to_b_again = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(to_b_again)
        self.assertEqual(self.services(on_b), set())

        # B pushes back what it has; the entry must not come back to A.
        back_to_a = sync.build_snapshot(on_b.vault_id)
        self.on("A")
        sync.merge_snapshot(back_to_a)
        self.assertEqual(self.services(session), set())


class TestUnlockMethodSync(TwoMachineTestCase):

    def test_a_switch_on_one_machine_reaches_the_other(self):
        self.on("A")
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")
        self.add_entry(session, "VPN", "jdoe", "vpn-pass")

        crypto.switch_to_master(session, "master pw")
        snapshot = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(snapshot)
        opened, status = crypto.unlock_with_master("master pw")

        self.assertEqual(status, crypto.OK)
        self.assertEqual(self.services(opened), {"VPN"})
        self.assertEqual(crypto.unlock_with_ad("jdoe", "ad-pw")[1], crypto.NO_METHOD)

    def test_a_retired_unlock_method_does_not_come_back(self):
        self.on("A")
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")
        to_b = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(to_b)
        self.assertIsNotNone(crypto.unlock_with_ad("jdoe", "ad-pw")[0])

        self.on("A")
        crypto.switch_to_master(session, "master pw")
        to_b_again = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(to_b_again)
        self.assertIsNone(crypto.unlock_with_ad("jdoe", "ad-pw")[0])

        # B's own snapshot must not revive the domain account on A.
        back_to_a = sync.build_snapshot(session.vault_id)
        self.on("A")
        sync.merge_snapshot(back_to_a)
        self.assertIsNone(crypto.unlock_with_ad("jdoe", "ad-pw")[0])

    def test_the_same_switch_on_both_machines_keeps_the_later_one(self):
        """Both moved to a master password: one key, so newest wins."""
        self.on("A")
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")
        self.add_entry(session, "VPN", "jdoe", "vpn-pass")
        shared = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(shared)
        on_b, _ = crypto.unlock_with_ad("jdoe", "ad-pw")
        crypto.switch_to_master(on_b, "b master pw")
        from_b = sync.build_snapshot(on_b.vault_id)

        self.on("A")
        crypto.switch_to_master(session, "a master pw")     # later than B's
        sync.merge_snapshot(from_b)

        self.assertEqual(database.count_unlock_methods(session.vault_id), 1)
        opened, status = crypto.unlock_with_master("a master pw")
        self.assertEqual(status, crypto.OK)
        self.assertEqual(self.services(opened), {"VPN"})

    def test_different_switches_on_both_machines_settle_on_one_method(self):
        """
        A went to a master password while B went to the domain. The merge sees
        two live methods on different keys, and the vault must end up with one.
        """
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "orig pw")
        self.add_entry(session, "VPN", "jdoe", "vpn-pass")
        shared = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(shared)
        on_b, _ = crypto.unlock_with_master("orig pw")
        crypto.switch_to_ad(on_b, "jdoe", "ad-pw")
        from_b = sync.build_snapshot(on_b.vault_id)

        self.on("A")
        crypto.switch_to_master(session, "a master pw")     # later than B's switch
        result = sync.merge_snapshot(from_b)

        self.assertTrue(result.methods_applied)
        self.assertEqual(database.count_unlock_methods(session.vault_id), 1)
        self.assertEqual(crypto.unlock_with_master("a master pw")[1], crypto.OK)
        self.assertEqual(crypto.unlock_with_ad("jdoe", "ad-pw")[1], crypto.NO_METHOD)

    def test_both_machines_reach_the_same_surviving_method(self):
        """Whichever order they sync in, A and B must agree on the way in."""
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "orig pw")
        shared = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(shared)
        on_b, _ = crypto.unlock_with_master("orig pw")
        crypto.switch_to_ad(on_b, "jdoe", "ad-pw")
        from_b = sync.build_snapshot(on_b.vault_id)

        self.on("A")
        crypto.switch_to_master(session, "a master pw")
        sync.merge_snapshot(from_b)
        from_a = sync.build_snapshot(session.vault_id)

        self.on("B")
        sync.merge_snapshot(from_a)

        self.assertEqual(database.count_unlock_methods(session.vault_id), 1)
        self.assertEqual(crypto.unlock_with_master("a master pw")[1], crypto.OK)
        self.assertEqual(crypto.unlock_with_ad("jdoe", "ad-pw")[1], crypto.NO_METHOD)


class TestSnapshotFormat(TwoMachineTestCase):

    def test_digest_ignores_the_snapshot_timestamp(self):
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        self.add_entry(session, "GitHub", "jdoe", "gh-pass")

        first  = sync.build_snapshot(session.vault_id)
        second = sync.build_snapshot(session.vault_id)

        self.assertNotEqual(first["updated_at"], second["updated_at"])
        self.assertEqual(sync.snapshot_digest(first), sync.snapshot_digest(second))

    def test_digest_changes_when_an_entry_changes(self):
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        before = sync.snapshot_digest(sync.build_snapshot(session.vault_id))

        self.add_entry(session, "GitHub", "jdoe", "gh-pass")

        self.assertNotEqual(
            before, sync.snapshot_digest(sync.build_snapshot(session.vault_id)))

    def test_a_newer_snapshot_format_is_refused(self):
        self.on("A")
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")
        snapshot = sync.build_snapshot(session.vault_id)
        snapshot["format"] = sync.SNAPSHOT_FORMAT + 1

        with self.assertRaises(ValueError):
            sync.loads(sync.dumps(snapshot))

    def test_garbage_is_refused(self):
        with self.assertRaises(ValueError):
            sync.loads(b'{"hello": "world"}')


if __name__ == "__main__":
    unittest.main()
