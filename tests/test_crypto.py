"""Key wrapping, unlock methods and legacy migration."""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crypto                      # noqa: E402
import database                    # noqa: E402
from database import METHOD_AD, METHOD_MASTER   # noqa: E402


class VaultTestCase(unittest.TestCase):
    """Each test gets its own database file and cheap scrypt parameters."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["ZAPASSKA_DB"] = str(Path(self._tmp.name) / "test.sec")
        self._real_n = crypto._SCRYPT_N
        crypto._SCRYPT_N = 2 ** 10          # keep the suite fast
        database.init_db()

    def tearDown(self):
        crypto._SCRYPT_N = self._real_n
        os.environ.pop("ZAPASSKA_DB", None)
        self._tmp.cleanup()


class TestUnlockMethods(VaultTestCase):

    def test_master_password_round_trip(self):
        session = crypto.create_vault(METHOD_MASTER, "", "correct horse")
        opened, status = crypto.unlock_with_master("correct horse")

        self.assertEqual(status, crypto.OK)
        self.assertEqual(opened.vault_id, session.vault_id)
        self.assertEqual(opened.dek, session.dek)

    def test_wrong_master_password_is_rejected(self):
        crypto.create_vault(METHOD_MASTER, "", "correct horse")
        opened, status = crypto.unlock_with_master("wrong horse")

        self.assertIsNone(opened)
        self.assertEqual(status, crypto.WRONG_SECRET)

    def test_no_master_password_configured(self):
        opened, status = crypto.unlock_with_master("anything")

        self.assertIsNone(opened)
        self.assertEqual(status, crypto.NO_METHOD)

    def test_switching_replaces_the_way_in_and_keeps_the_entries(self):
        """One vault, one way in: the new method works, the old one stops."""
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")
        enc = crypto.encrypt_row(session.dek, "GitHub", "jdoe@corp", "s3cret")
        database.insert_entry(session.vault_id, enc["service_enc"],
                              enc["login_enc"], enc["password_enc"])

        crypto.switch_to_master(session, "my master pw")

        via_master, status = crypto.unlock_with_master("my master pw")
        self.assertEqual(status, crypto.OK)
        self.assertEqual(via_master.vault_id, session.vault_id)
        self.assertEqual(crypto.unlock_with_ad("jdoe", "ad-pw")[1], crypto.NO_METHOD)

        entry = crypto.decrypt_row(
            via_master.dek, database.get_entries(via_master.vault_id)[0])
        self.assertEqual(entry["password"], "s3cret")

    def test_a_vault_never_has_two_ways_in(self):
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")

        crypto.switch_to_master(session, "my master pw")
        self.assertEqual(database.count_unlock_methods(session.vault_id), 1)

        crypto.switch_to_ad(session, "jdoe", "ad-pw")
        self.assertEqual(database.count_unlock_methods(session.vault_id), 1)

    def test_the_session_follows_the_switch(self):
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")

        crypto.switch_to_master(session, "my master pw")

        self.assertEqual(session.method, METHOD_MASTER)
        self.assertEqual(crypto.current_method(session.vault_id)["method"],
                         METHOD_MASTER)

    def test_the_master_password_can_be_changed(self):
        session = crypto.create_vault(METHOD_MASTER, "", "old master pw")
        enc = crypto.encrypt_row(session.dek, "GitHub", "jdoe", "gh-pass")
        database.insert_entry(session.vault_id, enc["service_enc"],
                              enc["login_enc"], enc["password_enc"])

        crypto.switch_to_master(session, "new master pw")

        self.assertEqual(crypto.unlock_with_master("old master pw")[1],
                         crypto.WRONG_SECRET)
        opened, status = crypto.unlock_with_master("new master pw")
        self.assertEqual(status, crypto.OK)
        self.assertEqual(database.count_unlock_methods(session.vault_id), 1)

        entry = crypto.decrypt_row(opened.dek,
                                   database.get_entries(opened.vault_id)[0])
        self.assertEqual(entry["password"], "gh-pass")

    def test_the_current_master_password_can_be_checked(self):
        session = crypto.create_vault(METHOD_MASTER, "", "master pw")

        self.assertTrue(crypto.verify_master_password(session, "master pw"))
        self.assertFalse(crypto.verify_master_password(session, "wrong pw"))

    def test_an_ad_vault_has_no_master_password_to_check(self):
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")

        self.assertFalse(crypto.verify_master_password(session, "anything"))

    def test_switching_there_and_back_keeps_the_entries(self):
        """Leaving AD for a master password and returning loses nothing."""
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")
        enc = crypto.encrypt_row(session.dek, "Jira", "jdoe", "hunter2")
        database.insert_entry(session.vault_id, enc["service_enc"],
                              enc["login_enc"], enc["password_enc"])

        crypto.switch_to_master(session, "master pw")
        via_master, _ = crypto.unlock_with_master("master pw")
        self.assertIsNotNone(via_master)
        self.assertIsNone(crypto.unlock_with_ad("jdoe", "ad-pw")[0])

        crypto.switch_to_ad(via_master, "jdoe", "ad-pw")
        back, status = crypto.unlock_with_ad("jdoe", "ad-pw")

        self.assertEqual(status, crypto.OK)
        self.assertEqual(crypto.unlock_with_master("master pw")[1], crypto.NO_METHOD)
        entry = crypto.decrypt_row(back.dek, database.get_entries(back.vault_id)[0])
        self.assertEqual(entry["password"], "hunter2")

    def test_changed_ad_password_recovers_with_the_old_one(self):
        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "old-pw", "jdoe")
        enc = crypto.encrypt_row(session.dek, "VPN", "jdoe", "vpn-pass")
        database.insert_entry(session.vault_id, enc["service_enc"],
                              enc["login_enc"], enc["password_enc"])

        opened, status = crypto.unlock_with_ad("jdoe", "new-pw")
        self.assertIsNone(opened)
        self.assertEqual(status, crypto.WRONG_SECRET)

        recovered = crypto.recover_with_old_ad_password("jdoe", "old-pw", "new-pw")
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.vault_id, session.vault_id)

        again, status = crypto.unlock_with_ad("jdoe", "new-pw")
        self.assertEqual(status, crypto.OK)
        entry = crypto.decrypt_row(again.dek, database.get_entries(again.vault_id)[0])
        self.assertEqual(entry["password"], "vpn-pass")

    def test_recovery_rejects_a_wrong_old_password(self):
        crypto.create_vault(METHOD_AD, database.hash_identity("jdoe"), "old-pw")

        self.assertIsNone(
            crypto.recover_with_old_ad_password("jdoe", "not-it", "new-pw"))

    def test_two_users_keep_separate_vaults(self):
        alice = crypto.create_vault(METHOD_AD, database.hash_identity("alice"), "pw-a")
        bob   = crypto.create_vault(METHOD_AD, database.hash_identity("bob"), "pw-b")
        enc = crypto.encrypt_row(alice.dek, "Mail", "alice", "a-pass")
        database.insert_entry(alice.vault_id, enc["service_enc"],
                              enc["login_enc"], enc["password_enc"])

        self.assertNotEqual(alice.vault_id, bob.vault_id)
        self.assertEqual(len(database.get_entries(bob.vault_id)), 0)


class TestLegacyMigration(VaultTestCase):
    """The pre-vault schema encrypted entries straight from the AD password."""

    def _write_legacy_db(self, users: dict):
        """users: {username: (password, [(service, login, password), ...])}"""
        conn = sqlite3.connect(os.environ["ZAPASSKA_DB"])
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS kdf_salts (
                username_hash TEXT PRIMARY KEY, salt TEXT NOT NULL, verifier BLOB);
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service BLOB NOT NULL, login BLOB NOT NULL, password BLOB NOT NULL);
        """)
        for username, (password, rows) in users.items():
            salt = os.urandom(32)
            key  = crypto.derive_kek(password, salt)
            verifier = crypto.wrap_dek(key, crypto._VERIFIER_MAGIC)
            conn.execute(
                "INSERT INTO kdf_salts(username_hash, salt, verifier) VALUES (?,?,?)",
                (database.hash_identity(username), salt.hex(), verifier))
            for service, login, secret in rows:
                conn.execute(
                    "INSERT INTO passwords(service, login, password) VALUES (?,?,?)",
                    (crypto.encrypt(key, service), crypto.encrypt(key, login),
                     crypto.encrypt(key, secret)))
        conn.commit()
        conn.close()

    def test_legacy_entries_move_into_a_vault_on_first_login(self):
        self._write_legacy_db({
            "jdoe": ("ad-pw", [("GitHub", "jdoe", "gh-pass"),
                               ("Jira",   "jdoe", "jira-pass")])
        })

        session, status = crypto.unlock_with_ad("jdoe", "ad-pw")

        self.assertEqual(status, crypto.OK)
        entries = [crypto.decrypt_row(session.dek, r)
                   for r in database.get_entries(session.vault_id)]
        self.assertEqual({e["service"] for e in entries}, {"GitHub", "Jira"})
        self.assertEqual({e["password"] for e in entries}, {"gh-pass", "jira-pass"})

    def test_migrated_vault_reopens_without_the_legacy_tables(self):
        self._write_legacy_db({"jdoe": ("ad-pw", [("VPN", "jdoe", "vpn-pass")])})
        crypto.unlock_with_ad("jdoe", "ad-pw")

        self.assertFalse(database.legacy_has_data())

        session, status = crypto.unlock_with_ad("jdoe", "ad-pw")
        self.assertEqual(status, crypto.OK)
        entry = crypto.decrypt_row(
            session.dek, database.get_entries(session.vault_id)[0])
        self.assertEqual(entry["service"], "VPN")

    def test_each_user_migrates_only_their_own_rows(self):
        """Old databases mixed every user's rows in one table."""
        self._write_legacy_db({
            "alice": ("pw-a", [("Mail", "alice", "a-pass")]),
            "bob":   ("pw-b", [("Wiki", "bob",   "b-pass")]),
        })

        alice, _ = crypto.unlock_with_ad("alice", "pw-a")
        alice_entries = [crypto.decrypt_row(alice.dek, r)
                         for r in database.get_entries(alice.vault_id)]
        self.assertEqual([e["service"] for e in alice_entries], ["Mail"])

        bob, _ = crypto.unlock_with_ad("bob", "pw-b")
        bob_entries = [crypto.decrypt_row(bob.dek, r)
                       for r in database.get_entries(bob.vault_id)]
        self.assertEqual([e["service"] for e in bob_entries], ["Wiki"])

    def test_legacy_migration_refuses_a_wrong_password(self):
        self._write_legacy_db({"jdoe": ("ad-pw", [("VPN", "jdoe", "vpn-pass")])})

        self.assertIsNone(crypto.migrate_legacy_user("jdoe", "wrong-pw"))
        self.assertTrue(database.legacy_has_data())


class TestOlderLegacyShapes(VaultTestCase):
    """
    Databases from every earlier release must still open. Getting this wrong
    means a user upgrades and finds their passwords gone.
    """

    def _connect(self):
        conn = sqlite3.connect(os.environ["ZAPASSKA_DB"])
        conn.row_factory = sqlite3.Row
        return conn

    def test_the_first_schema_with_separate_nonce_columns(self):
        """settings table for the salt, nonce kept in its own column."""
        password = "ad-pw"
        salt = os.urandom(32)
        key = crypto.derive_kek(password, salt)

        conn = self._connect()
        conn.executescript("""
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service BLOB, login BLOB, password BLOB,
                nonce_s BLOB, nonce_l BLOB, nonce_p BLOB,
                created_at TEXT, updated_at TEXT);
        """)
        conn.execute("INSERT INTO settings VALUES ('kdf_salt_jdoe', ?)", (salt.hex(),))

        blobs = [crypto.encrypt(key, text) for text in ("GitHub", "jdoe", "gh-pass")]
        conn.execute(
            "INSERT INTO passwords (service, login, password, nonce_s, nonce_l, "
            "nonce_p, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (blobs[0][12:], blobs[1][12:], blobs[2][12:],
             blobs[0][:12], blobs[1][:12], blobs[2][:12], "now", "now"))
        conn.commit()
        conn.close()

        session, status = crypto.unlock_with_ad("jdoe", password)

        self.assertEqual(status, crypto.OK)
        entry = crypto.decrypt_row(session.dek,
                                   database.get_entries(session.vault_id)[0])
        self.assertEqual((entry["service"], entry["login"], entry["password"]),
                         ("GitHub", "jdoe", "gh-pass"))

    def test_a_kdf_salts_table_without_a_verifier_column(self):
        password = "ad-pw"
        salt = os.urandom(32)
        key = crypto.derive_kek(password, salt)

        conn = self._connect()
        conn.executescript("""
            CREATE TABLE kdf_salts (username_hash TEXT PRIMARY KEY, salt TEXT NOT NULL);
            CREATE TABLE passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service BLOB NOT NULL, login BLOB NOT NULL, password BLOB NOT NULL);
        """)
        conn.execute("INSERT INTO kdf_salts VALUES (?,?)",
                     (database.hash_identity("jdoe"), salt.hex()))
        conn.execute("INSERT INTO passwords (service, login, password) VALUES (?,?,?)",
                     (crypto.encrypt(key, "VPN"), crypto.encrypt(key, "jdoe"),
                      crypto.encrypt(key, "vpn-pass")))
        conn.commit()
        conn.close()

        session, status = crypto.unlock_with_ad("jdoe", password)

        self.assertEqual(status, crypto.OK)
        entry = crypto.decrypt_row(session.dek,
                                   database.get_entries(session.vault_id)[0])
        self.assertEqual(entry["password"], "vpn-pass")

    def test_without_a_verifier_a_wrong_password_leaves_the_old_data_alone(self):
        salt = os.urandom(32)
        key = crypto.derive_kek("real-pw", salt)

        conn = self._connect()
        conn.executescript("""
            CREATE TABLE kdf_salts (username_hash TEXT PRIMARY KEY, salt TEXT NOT NULL);
            CREATE TABLE passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service BLOB NOT NULL, login BLOB NOT NULL, password BLOB NOT NULL);
        """)
        conn.execute("INSERT INTO kdf_salts VALUES (?,?)",
                     (database.hash_identity("jdoe"), salt.hex()))
        conn.execute("INSERT INTO passwords (service, login, password) VALUES (?,?,?)",
                     (crypto.encrypt(key, "VPN"), crypto.encrypt(key, "jdoe"),
                      crypto.encrypt(key, "vpn-pass")))
        conn.commit()
        conn.close()

        self.assertIsNone(crypto.migrate_legacy_user("jdoe", "wrong-pw"))
        self.assertTrue(database.legacy_has_user("jdoe"),
                        "the old vault must survive a wrong password")

        session, status = crypto.unlock_with_ad("jdoe", "real-pw")
        self.assertEqual(status, crypto.OK)
        entry = crypto.decrypt_row(session.dek,
                                   database.get_entries(session.vault_id)[0])
        self.assertEqual(entry["password"], "vpn-pass")

    def test_an_unreadable_passwords_table_stops_the_migration(self):
        """A shape we do not recognise must not be quietly thrown away."""
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE kdf_salts (username_hash TEXT PRIMARY KEY, salt TEXT NOT NULL);
            CREATE TABLE passwords (id INTEGER PRIMARY KEY, blob BLOB);
        """)
        conn.execute("INSERT INTO kdf_salts VALUES (?,?)",
                     (database.hash_identity("jdoe"), os.urandom(32).hex()))
        conn.execute("INSERT INTO passwords VALUES (1, X'00')")
        conn.commit()
        conn.close()

        self.assertEqual(database.legacy_passwords(), [])
        self.assertIsNone(crypto.migrate_legacy_user("jdoe", "ad-pw"))
        self.assertTrue(database.legacy_has_user("jdoe"))


class TestFieldEncryption(VaultTestCase):

    def test_round_trip_with_unicode(self):
        dek = os.urandom(32)
        text = "пароль-Ω-🔐"

        self.assertEqual(crypto.decrypt(dek, crypto.encrypt(dek, text)), text)

    def test_same_plaintext_encrypts_differently(self):
        dek = os.urandom(32)

        self.assertNotEqual(crypto.encrypt(dek, "same"), crypto.encrypt(dek, "same"))


if __name__ == "__main__":
    unittest.main()
