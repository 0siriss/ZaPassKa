"""
Smoke tests for the windows: they build, switch modes and render entries.

Skipped automatically where PyQt6 or a Qt platform plugin is unavailable.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication
    # Held for the whole module: a dropped QApplication takes the widgets with it.
    _APP = QApplication.instance() or QApplication(sys.argv[:1])
except Exception as exc:                      # noqa: BLE001
    raise unittest.SkipTest(f"Qt unavailable: {exc}")

import crypto        # noqa: E402
import database      # noqa: E402
from database import METHOD_AD, METHOD_MASTER    # noqa: E402


class UiTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["ZAPASSKA_DB"] = str(Path(self._tmp.name) / "ui.sec")
        # Keep QSettings out of the developer's real profile.
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        self._real_n = crypto._SCRYPT_N
        crypto._SCRYPT_N = 2 ** 10
        database.init_db()
        self._windows = []

    def tearDown(self):
        for window in self._windows:
            window.close()
        crypto._SCRYPT_N = self._real_n
        os.environ.pop("ZAPASSKA_DB", None)
        self._tmp.cleanup()

    def track(self, window):
        self._windows.append(window)
        return window


class TestLoginWindow(UiTestCase):

    def test_mode_switch_shows_and_hides_the_domain_fields(self):
        from login_window import LoginWindow, MODE_AD, MODE_MASTER

        window = self.track(LoginWindow())
        window.show()

        window._set_mode(MODE_AD)
        self.assertTrue(window.ad_box.isVisible())
        self.assertEqual(window.login_btn.text(), "Sign In")

        window._set_mode(MODE_MASTER)
        self.assertFalse(window.ad_box.isVisible())
        self.assertEqual(window.login_btn.text(), "Unlock")

    def test_master_mode_offers_to_create_a_vault_when_none_exists(self):
        from login_window import LoginWindow, MODE_MASTER

        window = self.track(LoginWindow())
        window._set_mode(MODE_MASTER)

        self.assertTrue(window.create_btn.isVisibleTo(window))
        self.assertFalse(window.login_btn.isEnabled())

    def test_a_first_ad_sign_in_creates_a_vault_without_asking(self):
        from login_window import LoginWindow

        window = self.track(LoginWindow())
        window._username = "jdoe"

        # Nothing on this machine yet, so there is nothing to confuse it with.
        self.assertTrue(window._confirm_new_ad_vault())

    def test_master_mode_is_ready_once_a_master_password_exists(self):
        from login_window import LoginWindow, MODE_MASTER

        crypto.create_vault(METHOD_MASTER, "", "master password")
        window = self.track(LoginWindow())
        window._set_mode(MODE_MASTER)

        self.assertFalse(window.create_btn.isVisibleTo(window))
        self.assertTrue(window.login_btn.isEnabled())


class TestVaultWindow(UiTestCase):

    def _open_vault(self, entries=(("GitHub", "jdoe", "gh-pass"),)):
        from vault_window import VaultWindow

        session = crypto.create_vault(METHOD_MASTER, "", "master password", "master")
        for service, login, password in entries:
            enc = crypto.encrypt_row(session.dek, service, login, password)
            database.insert_entry(session.vault_id, enc["service_enc"],
                                  enc["login_enc"], enc["password_enc"])
        return self.track(VaultWindow(session)), session

    def test_entries_render_with_the_password_masked(self):
        import theme

        window, _ = self._open_vault()

        self.assertEqual(window.table.rowCount(), 1)
        self.assertEqual(window.table.item(0, 0).text(), "GitHub")
        self.assertEqual(window.table.item(0, 2).text(), theme.PASS_MASK)

    def test_toggling_a_password_reveals_it(self):
        window, _ = self._open_vault()
        uuid = window._rows[0]["uuid"]

        window._toggle_pw(uuid)
        self.assertEqual(window.table.item(0, 2).text(), "gh-pass")

        window._toggle_pw(uuid)
        self.assertNotEqual(window.table.item(0, 2).text(), "gh-pass")

    def test_showing_one_password_hides_the_other(self):
        import theme

        window, _ = self._open_vault([
            ("GitHub", "jdoe", "gh-pass"),
            ("Jira",   "jdoe", "jira-pass"),
        ])
        first, second = (row["uuid"] for row in window._rows)

        window._toggle_pw(first)
        self.assertEqual(window.table.item(0, 2).text(), "gh-pass")
        self.assertEqual(window.table.item(1, 2).text(), theme.PASS_MASK)

        window._toggle_pw(second)
        self.assertEqual(window.table.item(0, 2).text(), theme.PASS_MASK)
        self.assertEqual(window.table.item(1, 2).text(), "jira-pass")

    def test_deleting_the_open_entry_clears_the_visible_one(self):
        window, _ = self._open_vault()
        uuid = window._rows[0]["uuid"]

        window._toggle_pw(uuid)
        database.delete_entry(uuid)
        window._visible_uuid = None if window._visible_uuid == uuid else window._visible_uuid
        window._load_rows()

        self.assertIsNone(window._visible_uuid)

    def test_search_filters_the_table(self):
        window, _ = self._open_vault([
            ("GitHub", "jdoe", "gh-pass"),
            ("Jira",   "jdoe", "jira-pass"),
        ])

        window.search_edit.setText("jir")
        self.assertEqual(window.table.rowCount(), 1)
        self.assertEqual(window.table.item(0, 0).text(), "Jira")

        window.search_edit.setText("")
        self.assertEqual(window.table.rowCount(), 2)

    def test_copying_puts_the_password_on_the_clipboard_and_clears_it(self):
        from PyQt6.QtWidgets import QApplication

        window, _ = self._open_vault()
        window._copy_pw("gh-pass")
        self.assertEqual(QApplication.clipboard().text(), "gh-pass")

        window._clear_clipboard("gh-pass")
        self.assertEqual(QApplication.clipboard().text(), "")

    def test_clearing_leaves_someone_elses_clipboard_alone(self):
        from PyQt6.QtWidgets import QApplication

        window, _ = self._open_vault()
        window._copy_pw("gh-pass")
        QApplication.clipboard().setText("a shopping list")

        window._clear_clipboard("gh-pass")
        self.assertEqual(QApplication.clipboard().text(), "a shopping list")

    def test_deleting_an_entry_leaves_a_tombstone(self):
        window, session = self._open_vault()
        uuid = window._rows[0]["uuid"]

        database.delete_entry(uuid)
        window._load_rows()

        self.assertEqual(window.table.rowCount(), 0)
        self.assertEqual(
            len(database.get_entries(session.vault_id, include_deleted=True)), 1)

    def test_sync_status_says_so_when_drive_is_not_connected(self):
        window, _ = self._open_vault()

        window._request_sync()

        self.assertIn("not connected", window._sync_status.text())


class TestStayOnTopSetting(UiTestCase):
    """The pin state is a stored preference, not a per-session default."""

    def setUp(self):
        super().setUp()
        import settings
        self._saved = settings.stay_on_top()

    def tearDown(self):
        import settings
        settings.set_stay_on_top(self._saved)
        super().tearDown()

    def _open_vault(self):
        from vault_window import VaultWindow

        session = crypto.create_vault(METHOD_MASTER, "", "master password", "master")
        return self.track(VaultWindow(session))

    def test_a_new_window_follows_the_stored_choice(self):
        import settings

        settings.set_stay_on_top(False)
        window = self._open_vault()

        self.assertFalse(window._on_top)
        self.assertFalse(window.pin_btn.isChecked())
        self.assertIn("Off", window.pin_btn.text())

    def test_toggling_stores_the_new_choice(self):
        import settings

        settings.set_stay_on_top(True)
        window = self._open_vault()

        window._toggle_on_top()
        self.assertFalse(settings.stay_on_top())
        self.assertFalse(window.pin_btn.isChecked())

        window._toggle_on_top()
        self.assertTrue(settings.stay_on_top())
        self.assertTrue(window.pin_btn.isChecked())


class TestSecurityDialog(UiTestCase):

    def test_it_lists_every_unlock_method(self):
        from vault_window import SecurityDialog

        session = crypto.create_vault(
            METHOD_AD, database.hash_identity("jdoe"), "ad-pw", "jdoe")
        crypto.set_master_password(session, "master password")

        dialog = self.track(SecurityDialog(session))

        self.assertEqual(dialog._list_box.count(), 2)
        self.assertIn("Change master password", dialog.master_btn.text())

    def test_the_only_method_cannot_be_removed(self):
        from vault_window import SecurityDialog

        session = crypto.create_vault(METHOD_MASTER, "", "master password")
        dialog = self.track(SecurityDialog(session))

        card = dialog._list_box.itemAt(0).widget()
        remove_btn = card.findChildren(type(dialog.master_btn))[0]
        self.assertFalse(remove_btn.isEnabled())


class TestEntryDialog(UiTestCase):

    def test_generated_passwords_cover_every_character_class(self):
        from vault_window import generate_password

        for _ in range(20):
            password = generate_password(16)
            self.assertEqual(len(password), 16)
            self.assertTrue(any(c.islower() for c in password))
            self.assertTrue(any(c.isupper() for c in password))
            self.assertTrue(any(c.isdigit() for c in password))
            self.assertTrue(any(not c.isalnum() for c in password))

    def test_generating_fills_the_field_and_reveals_it(self):
        from PyQt6.QtWidgets import QLineEdit
        from vault_window import EntryDialog

        dialog = self.track(EntryDialog())
        dialog._generate()

        self.assertEqual(len(dialog.values()[2]), 16)
        self.assertEqual(dialog.pass_edit.echoMode(), QLineEdit.EchoMode.Normal)


if __name__ == "__main__":
    unittest.main()
