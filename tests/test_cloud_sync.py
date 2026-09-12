"""
What happens to a change when Google Drive cannot be reached.

The rule the app relies on: the entry is written to SQLite first, the sync is
attempted afterwards, and a failed sync is reported but never fatal.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cloud_sync    # noqa: E402
import crypto        # noqa: E402
import database      # noqa: E402
import gdrive        # noqa: E402
import sync          # noqa: E402
from database import METHOD_MASTER      # noqa: E402


class OfflineTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["ZAPASSKA_DB"] = str(Path(self._tmp.name) / "offline.sec")
        self._real_n = crypto._SCRYPT_N
        crypto._SCRYPT_N = 2 ** 10
        database.init_db()
        self.session = crypto.create_vault(METHOD_MASTER, "", "master password")

    def tearDown(self):
        crypto._SCRYPT_N = self._real_n
        os.environ.pop("ZAPASSKA_DB", None)
        self._tmp.cleanup()

    def add_entry(self, service="GitHub"):
        enc = crypto.encrypt_row(self.session.dek, service, "jdoe", "gh-pass")
        return database.insert_entry(self.session.vault_id, enc["service_enc"],
                                     enc["login_enc"], enc["password_enc"])


class TestNoNetwork(OfflineTestCase):

    def test_sync_reports_a_drive_error_instead_of_crashing(self):
        self.add_entry()

        with mock.patch.object(gdrive, "find_file",
                               side_effect=gdrive.DriveError("no route to host")):
            with self.assertRaises(gdrive.DriveError):
                cloud_sync.sync_vault(self.session.vault_id)

    def test_the_entry_survives_a_failed_sync(self):
        self.add_entry()

        with mock.patch.object(gdrive, "find_file",
                               side_effect=gdrive.DriveError("no route to host")):
            with self.assertRaises(gdrive.DriveError):
                cloud_sync.sync_vault(self.session.vault_id)

        rows = database.get_entries(self.session.vault_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(crypto.decrypt_row(self.session.dek, rows[0])["service"],
                         "GitHub")

    def test_a_missed_change_is_pushed_by_the_next_successful_sync(self):
        self.add_entry("GitHub")

        with mock.patch.object(gdrive, "find_file",
                               side_effect=gdrive.DriveError("offline")):
            with self.assertRaises(gdrive.DriveError):
                cloud_sync.sync_vault(self.session.vault_id)

        uploaded = {}

        def fake_upload(name, content, file_id=None):
            uploaded["name"], uploaded["content"] = name, content
            return "file-id"

        with mock.patch.object(gdrive, "find_file", return_value=None), \
             mock.patch.object(gdrive, "upload", side_effect=fake_upload):
            outcome = cloud_sync.sync_vault(self.session.vault_id)

        self.assertTrue(outcome.pushed)
        snapshot = sync.loads(uploaded["content"])
        self.assertEqual(len(snapshot["entries"]), 1)

    def test_an_unconfigured_drive_makes_no_network_call(self):
        with mock.patch.object(gdrive, "_load_token", return_value=None):
            self.assertFalse(cloud_sync.available())

    def test_a_token_that_google_refuses_is_a_drive_error(self):
        with mock.patch.object(gdrive, "_load_token",
                               return_value={"refresh_token": "stale"}), \
             mock.patch.object(gdrive, "client_config", return_value=("id", "secret")), \
             mock.patch.object(gdrive, "_post_form", return_value={"error": "invalid_grant"}):
            with self.assertRaises(gdrive.DriveError):
                gdrive._access_token()


class TestVaultWindowOffline(OfflineTestCase):
    """The UI must degrade to a status line, not to a traceback."""

    def setUp(self):
        super().setUp()
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        try:
            from PyQt6.QtWidgets import QApplication
            self._app = QApplication.instance() or QApplication(sys.argv[:1])
        except Exception as exc:                    # noqa: BLE001
            self.skipTest(f"Qt unavailable: {exc}")

    def test_a_failed_sync_only_updates_the_status_line(self):
        from vault_window import VaultWindow

        self.add_entry()
        window = VaultWindow(self.session)
        self.addCleanup(window.close)

        window._on_sync_failed("Google Drive unreachable: timed out")

        self.assertIn("offline", window._sync_status.text())
        self.assertEqual(window.table.rowCount(), 1)

    def test_adding_an_entry_without_drive_keeps_the_vault_usable(self):
        from vault_window import VaultWindow

        window = VaultWindow(self.session)
        self.addCleanup(window.close)

        with mock.patch.object(gdrive, "_load_token", return_value=None):
            self.add_entry("Jira")
            window._after_change()

        self.assertEqual(window.table.rowCount(), 1)
        self.assertIn("not connected", window._sync_status.text())


if __name__ == "__main__":
    unittest.main()
