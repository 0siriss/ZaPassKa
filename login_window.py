"""
login_window.py — unlock screen.

Two ways in, chosen with the switch at the top of the panel:

  Active Directory — the domain checks the password, then the stored data key
                     is unwrapped with it.
  Master password  — no domain involved; the data key is unwrapped with a
                     password kept only in the user's head.

Both open the same vault. Which one was used last is remembered in QSettings
(registry on Windows, an ini file elsewhere).
"""

import os

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPushButton, QVBoxLayout, QWidget
)

import ad_auth
import crypto
import database
import gdrive
import i18n
import theme
from i18n import tr
from database import METHOD_AD, METHOD_MASTER
from settings import KEY_AD_SERVER, KEY_AUTH_MODE, app_settings

MODE_AD     = "ad"
MODE_MASTER = "master"

MIN_MASTER_LENGTH = 8


def _connected_text() -> str:
    email = gdrive.account_email()
    return tr("Connected as {email}.", email=email) if email else tr("Connected.")


def pull_snapshots():
    """Import every vault backed up in Drive. Imported lazily: no Drive, no cost."""
    import cloud_sync
    return cloud_sync.pull_all_snapshots()


# ── Worker threads ────────────────────────────────────────────────

class CallWorker(QThread):
    """
    Runs one callable off the UI thread. Everything here is slow by design:
    scrypt takes about a second, LDAP and Drive wait on the network.
    """
    done   = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, fn, *args):
        super().__init__()
        self._fn   = fn
        self._args = args

    def run(self):
        try:
            self.done.emit(self._fn(*self._args))
        except Exception as exc:                      # noqa: BLE001 — reported to the user
            self.failed.emit(str(exc))


class PingWorker(QThread):
    result = pyqtSignal(bool)

    def __init__(self, server: str):
        super().__init__()
        self.server = server

    def run(self):
        self.result.emit(ad_auth.check_dc_reachable(self.server))


# ── Dialogs ───────────────────────────────────────────────────────

class MasterPasswordDialog(QDialog):
    """Asks for a new master password twice."""

    def __init__(self, parent=None, title=None, intro=""):
        super().__init__(parent)
        self.setWindowTitle(title or tr("Set Master Password"))
        self.setFixedWidth(440)
        self.setStyleSheet(theme.DIALOG_STYLE)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(28, 24, 28, 24)

        if intro:
            info = QLabel(intro)
            info.setObjectName("info")
            info.setWordWrap(True)
            lay.addWidget(info)

        lay.addWidget(QLabel(tr("MASTER PASSWORD")))
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText(theme.PASS_MASK)
        lay.addWidget(self.pass_edit)

        lay.addWidget(QLabel(tr("REPEAT PASSWORD")))
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_edit.setPlaceholderText(theme.PASS_MASK)
        lay.addWidget(self.confirm_edit)

        warn = QLabel(tr(
            "There is no way to recover a forgotten master password — it is "
            "never stored, only used to unwrap the vault key."
        ))
        warn.setWordWrap(True)
        lay.addWidget(warn)

        self.error_lbl = QLabel()
        self.error_lbl.setObjectName("error")
        self.error_lbl.hide()
        lay.addWidget(self.error_lbl)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _validate(self):
        password, confirm = self.pass_edit.text(), self.confirm_edit.text()
        if len(password) < MIN_MASTER_LENGTH:
            self._error(tr("Use at least {count} characters.",
                           count=MIN_MASTER_LENGTH))
        elif password != confirm:
            self._error(tr("The two passwords do not match."))
        else:
            self.accept()

    def _error(self, msg: str):
        self.error_lbl.setText(msg)
        self.error_lbl.show()

    def password(self) -> str:
        return self.pass_edit.text()


class OldPasswordDialog(QDialog):
    """
    Shown when AD accepted the password but it no longer unwraps the vault —
    which means the domain password was changed since the last sign-in.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("AD Password Changed"))
        self.setFixedWidth(440)
        self.setStyleSheet(theme.DIALOG_STYLE)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(28, 24, 28, 24)

        info = QLabel(tr(
            "Your Active Directory password has changed since this vault was "
            "last opened.\n\nEnter the previous password once — the vault key "
            "is simply re-wrapped with the new one. Your entries are not "
            "re-encrypted and cannot be lost in the process."
        ))
        info.setObjectName("info")
        info.setWordWrap(True)
        lay.addWidget(info)

        lay.addWidget(QLabel(tr("PREVIOUS AD PASSWORD")))
        self.old_pass = QLineEdit()
        self.old_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.old_pass.setPlaceholderText(theme.PASS_MASK)
        lay.addWidget(self.old_pass)

        self.error_lbl = QLabel()
        self.error_lbl.setObjectName("error")
        self.error_lbl.hide()
        lay.addWidget(self.error_lbl)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def old_password(self) -> str:
        return self.old_pass.text()

    def show_error(self, msg: str):
        self.error_lbl.setText(msg)
        self.error_lbl.show()


class GoogleClientDialog(QDialog):
    """Collects a Google OAuth desktop client when the build ships without one."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Google OAuth Client"))
        self.setFixedWidth(500)
        self.setStyleSheet(theme.DIALOG_STYLE)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(28, 24, 28, 24)

        info = QLabel(tr(
            "This build has no Google client baked in, so ZaPassKa needs one "
            "of yours.\n\nIn Google Cloud Console: enable the Drive API, then "
            "create an OAuth client of type “Desktop app” and paste its ID "
            "and secret here. They are stored locally and identify the "
            "application only — never your account."
        ))
        info.setObjectName("info")
        info.setWordWrap(True)
        lay.addWidget(info)

        lay.addWidget(QLabel(tr("CLIENT ID")))
        self.id_edit = QLineEdit()
        self.id_edit.setPlaceholderText("1234567890-abc.apps.googleusercontent.com")
        lay.addWidget(self.id_edit)

        lay.addWidget(QLabel(tr("CLIENT SECRET")))
        self.secret_edit = QLineEdit()
        self.secret_edit.setPlaceholderText("GOCSPX-…")
        lay.addWidget(self.secret_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def values(self) -> tuple[str, str]:
        return self.id_edit.text().strip(), self.secret_edit.text().strip()


class GoogleDriveDialog(QDialog):
    """
    Connects the machine to the user's own Google account and pulls whatever
    vaults are already backed up there.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Google Drive Backup"))
        self.setFixedWidth(480)
        self.setStyleSheet(theme.DIALOG_STYLE)
        self._worker = None

        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(28, 24, 28, 24)

        info = QLabel(tr(
            "Vaults are backed up to a private folder of your own Google "
            "Drive, visible to this app alone. Everything stored there is "
            "already encrypted — the key stays on your machines."
        ))
        info.setObjectName("info")
        info.setWordWrap(True)
        lay.addWidget(info)

        self.status_lbl = QLabel()
        self.status_lbl.setObjectName("info")
        self.status_lbl.setWordWrap(True)
        lay.addWidget(self.status_lbl)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.connect_btn = QPushButton()
        self.connect_btn.setObjectName("rowBtn")
        self.connect_btn.clicked.connect(self._toggle_connection)
        row.addWidget(self.connect_btn)

        self.pull_btn = QPushButton(tr("Download vaults now"))
        self.pull_btn.setObjectName("rowBtn")
        self.pull_btn.clicked.connect(self._pull)
        row.addWidget(self.pull_btn)
        row.addStretch()
        lay.addLayout(row)

        self.client_btn = QPushButton(tr("Configure OAuth client…"))
        self.client_btn.setObjectName("rowBtn")
        self.client_btn.clicked.connect(self._configure_client)
        lay.addWidget(self.client_btn)

        self.result_lbl = QLabel()
        self.result_lbl.setObjectName("ok")
        self.result_lbl.setWordWrap(True)
        self.result_lbl.hide()
        lay.addWidget(self.result_lbl)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        lay.addWidget(buttons)

        self._refresh()

    def _refresh(self):
        connected = gdrive.is_connected()
        if connected:
            self.status_lbl.setText(_connected_text())
            self.connect_btn.setText(tr("Disconnect"))
        else:
            self.status_lbl.setText(tr("Not connected — backups are disabled."))
            self.connect_btn.setText(tr("Connect Google Drive"))
        self.pull_btn.setEnabled(connected)
        self.client_btn.setVisible(not gdrive.has_client_config())

    def _busy(self, msg: str | None):
        for btn in (self.connect_btn, self.pull_btn, self.client_btn):
            btn.setEnabled(msg is None)
        if msg:
            self.status_lbl.setText(msg)
        else:
            self._refresh()

    def _toggle_connection(self):
        if gdrive.is_connected():
            gdrive.disconnect()
            self._refresh()
            return

        if not gdrive.has_client_config():
            self._configure_client()
            if not gdrive.has_client_config():
                return

        self._busy(tr("Waiting for the browser… finish signing in to Google."))
        self._run(gdrive.authorize, self._on_authorized)

    def _on_authorized(self, _email):
        self._busy(None)
        self._show_result(_connected_text(), ok=True)
        self._pull()

    def _pull(self):
        self._busy(tr("Downloading vaults from Google Drive…"))
        self._run(pull_snapshots, self._on_pulled)

    def _on_pulled(self, counts):
        vaults, entries = counts
        self._busy(None)
        if vaults:
            self._show_result(tr(
                "{vaults} vault(s) downloaded, {entries} entries applied. "
                "Sign in as usual.", vaults=vaults, entries=entries), ok=True)
        else:
            self._show_result(tr("Nothing backed up on this account yet."), ok=True)

    def _configure_client(self):
        dlg = GoogleClientDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        client_id, client_secret = dlg.values()
        if client_id:
            gdrive.save_client_config(client_id, client_secret)
        self._refresh()

    def _run(self, fn, on_done):
        self._worker = CallWorker(fn)
        self._worker.done.connect(on_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_failed(self, message: str):
        self._busy(None)
        self._show_result(message, ok=False)

    def _show_result(self, text: str, ok: bool):
        self.result_lbl.setObjectName("ok" if ok else "error")
        self.result_lbl.setStyleSheet(
            f"color: {theme.SUCCESS if ok else theme.DANGER}; "
            f"font-size: 11px; font-weight: 400;")
        self.result_lbl.setText(text)
        self.result_lbl.show()


# ── Login window ──────────────────────────────────────────────────

class LoginWindow(QWidget):

    def __init__(self):
        super().__init__()
        database.init_db()
        self._mode          = MODE_AD
        self._username      = ""
        self._ping_worker   = None
        self._worker        = None
        self._ping_timer    = None
        self._repeat_timer  = None
        self._pending_password = ""

        self.setWindowTitle(tr("ZaPassKa — Login"))
        self.setStyleSheet(theme.BASE_STYLE)

        self._build_ui()
        # Let the translated text decide the size instead of hardcoded numbers.
        hint = self.sizeHint()
        self.setMinimumSize(max(480, hint.width()), max(520, hint.height()))
        self.resize(self.minimumSize())
        self._load_settings()
        self._schedule_ping()
        self._startup_drive_pull()

    # ── Build UI ──────────────────────────────────────────────────

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.setContentsMargins(30, 30, 30, 30)

        panel = QFrame()
        panel.setObjectName("panel")
        outer.addWidget(panel)

        lay = QVBoxLayout(panel)
        lay.setSpacing(12)
        lay.setContentsMargins(36, 32, 36, 28)

        # Title
        title_row = QHBoxLayout()
        icon = QLabel("🔐")
        icon.setStyleSheet("font-size: 30px;")
        col = QVBoxLayout()
        col.setSpacing(2)
        title = QLabel(tr("Password Vault"))
        title.setObjectName("title")
        subtitle = QLabel(tr("AES-256-GCM encrypted password manager"))
        subtitle.setObjectName("subtitle")
        col.addWidget(title)
        col.addWidget(subtitle)
        title_row.addWidget(icon)
        title_row.addSpacing(10)
        title_row.addLayout(col)
        title_row.addStretch()
        lay.addLayout(title_row)
        lay.addSpacing(4)

        # Unlock mode switch
        lay.addWidget(self._lbl(tr("UNLOCK WITH")))
        mode_row = QHBoxLayout()
        mode_row.setSpacing(8)
        self.ad_mode_btn = QPushButton(tr("🏢  Active Directory"))
        self.master_mode_btn = QPushButton(tr("🔑  Master password"))
        for btn, mode in ((self.ad_mode_btn, MODE_AD),
                          (self.master_mode_btn, MODE_MASTER)):
            btn.setObjectName("modeBtn")
            btn.setCheckable(True)
            btn.setFixedHeight(38)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, m=mode: self._set_mode(m))
            mode_row.addWidget(btn)
        lay.addLayout(mode_row)

        # AD-only fields
        self.ad_box = QWidget()
        ad_lay = QVBoxLayout(self.ad_box)
        ad_lay.setContentsMargins(0, 0, 0, 0)
        ad_lay.setSpacing(12)

        ad_lay.addWidget(self._lbl(tr("AD SERVER (LDAP URL)")))
        srv_row = QHBoxLayout()
        srv_row.setSpacing(8)
        self.server_edit = QLineEdit()
        self.server_edit.setPlaceholderText("domain.com")
        self.server_edit.textChanged.connect(self._on_server_changed)
        srv_row.addWidget(self.server_edit)

        self.dc_dot = QLabel("●")
        self.dc_dot.setFixedWidth(22)
        self.dc_dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.dc_dot.setStyleSheet("font-size: 18px; color: #484f58;")
        self.dc_dot.setToolTip(tr("DC connection status"))
        srv_row.addWidget(self.dc_dot)
        ad_lay.addLayout(srv_row)

        ad_lay.addWidget(self._lbl(tr("USERNAME")))
        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText(os.environ.get("USERNAME", "username"))
        self.user_edit.setText(os.environ.get("USERNAME", ""))
        ad_lay.addWidget(self.user_edit)
        lay.addWidget(self.ad_box)

        # Password
        self.pass_label = self._lbl(tr("PASSWORD"))
        lay.addWidget(self.pass_label)
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText(theme.PASS_MASK)
        self.pass_edit.returnPressed.connect(self._do_login)
        lay.addWidget(self.pass_edit)

        # Messages
        self.error_lbl = QLabel()
        self.error_lbl.setObjectName("errorLbl")
        self.error_lbl.setWordWrap(True)
        self.error_lbl.hide()
        lay.addWidget(self.error_lbl)

        self.info_lbl = QLabel()
        self.info_lbl.setObjectName("infoLbl")
        self.info_lbl.setWordWrap(True)
        self.info_lbl.hide()
        lay.addWidget(self.info_lbl)

        lay.addSpacing(2)

        self.login_btn = QPushButton(tr("Sign In"))
        self.login_btn.setObjectName("loginBtn")
        self.login_btn.setFixedHeight(46)
        self.login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_btn.clicked.connect(self._do_login)
        lay.addWidget(self.login_btn)

        self.create_btn = QPushButton(tr("Create a vault with a master password"))
        self.create_btn.setObjectName("linkBtn")
        self.create_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.create_btn.clicked.connect(self._create_master_vault)
        self.create_btn.hide()
        lay.addWidget(self.create_btn)

        lay.addStretch()

        drive_row = QHBoxLayout()
        self.drive_btn = QPushButton(tr("☁  Google Drive backup…"))
        self.drive_btn.setObjectName("linkBtn")
        self.drive_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.drive_btn.clicked.connect(self._open_drive_dialog)
        drive_row.addWidget(self.drive_btn)
        drive_row.addStretch()

        self.lang_btn = QPushButton(i18n.LANGUAGE_NAMES[i18n.other_language()])
        self.lang_btn.setObjectName("langBtn")
        self.lang_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.lang_btn.setToolTip(tr("Switch interface language"))
        self.lang_btn.clicked.connect(self._switch_language)
        drive_row.addWidget(self.lang_btn)
        drive_row.addSpacing(8)

        self.drive_status = QLabel()
        self.drive_status.setObjectName("hint")
        drive_row.addWidget(self.drive_status)
        lay.addLayout(drive_row)

    def _lbl(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("fieldLabel")
        return label

    # ── Mode ──────────────────────────────────────────────────────

    def _set_mode(self, mode: str):
        self._mode = mode
        self.ad_mode_btn.setChecked(mode == MODE_AD)
        self.master_mode_btn.setChecked(mode == MODE_MASTER)
        self.ad_box.setVisible(mode == MODE_AD)
        self.error_lbl.hide()
        self.info_lbl.hide()
        self.pass_edit.clear()

        if mode == MODE_AD:
            self.pass_label.setText(tr("PASSWORD"))
            self.login_btn.setText(tr("Sign In"))
            self.create_btn.hide()
            self._do_ping()
        else:
            self.pass_label.setText(tr("MASTER PASSWORD"))
            self.login_btn.setText(tr("Unlock"))
            has_master = database.has_method(METHOD_MASTER)
            self.create_btn.setVisible(not has_master)
            self.pass_edit.setEnabled(has_master)
            self.login_btn.setEnabled(has_master)
            if not has_master:
                self._show_info(tr(
                    "No master password on this machine yet. Sign in with "
                    "Active Directory and enable one under Security, or "
                    "create a new empty vault below."
                ))

        app_settings().setValue(KEY_AUTH_MODE, mode)

    # ── Settings ──────────────────────────────────────────────────

    def _load_settings(self):
        settings = app_settings()
        server = settings.value(KEY_AD_SERVER, "")
        if server:
            self.server_edit.setText(server)

        mode = settings.value(KEY_AUTH_MODE, MODE_AD)
        if mode not in (MODE_AD, MODE_MASTER):
            mode = MODE_AD
        # Land on the mode this machine can actually use.
        if mode == MODE_MASTER and not database.has_method(METHOD_MASTER):
            mode = MODE_AD
        elif (mode == MODE_AD and not database.has_method(METHOD_AD)
              and database.has_method(METHOD_MASTER)):
            mode = MODE_MASTER
        self._set_mode(mode)

    def _save_settings(self):
        settings = app_settings()
        settings.setValue(KEY_AD_SERVER, self.server_edit.text().strip())
        settings.sync()

    # ── DC ping ───────────────────────────────────────────────────

    def _on_server_changed(self):
        self.dc_dot.setStyleSheet("font-size: 18px; color: #484f58;")
        if self._ping_timer:
            self._ping_timer.stop()
        self._ping_timer = QTimer(self)
        self._ping_timer.setSingleShot(True)
        self._ping_timer.timeout.connect(self._do_ping)
        self._ping_timer.start(800)

    def _schedule_ping(self):
        QTimer.singleShot(400, self._do_ping)
        self._repeat_timer = QTimer(self)
        self._repeat_timer.timeout.connect(self._do_ping)
        self._repeat_timer.start(15000)

    def _do_ping(self):
        if self._mode != MODE_AD:
            return
        server = self.server_edit.text().strip()
        if not server:
            self.dc_dot.setStyleSheet("font-size: 18px; color: #484f58;")
            self.dc_dot.setToolTip(tr("No server configured"))
            return
        if self._ping_worker and self._ping_worker.isRunning():
            return
        self._ping_worker = PingWorker(server)
        self._ping_worker.result.connect(self._on_ping_result)
        self._ping_worker.start()

    def _on_ping_result(self, ok: bool):
        color = theme.SUCCESS if ok else theme.DANGER
        self.dc_dot.setStyleSheet(f"font-size: 18px; color: {color};")
        self.dc_dot.setToolTip(tr("Domain controller reachable ✓") if ok
                               else tr("Domain controller unreachable ✗"))

    # ── Google Drive ──────────────────────────────────────────────

    def _startup_drive_pull(self):
        """Pick up vaults backed up from another machine before the user signs in."""
        if not gdrive.is_connected():
            self.drive_status.setText(tr("Drive: off"))
            return
        self.drive_status.setText(tr("Drive: syncing…"))
        self._drive_worker = CallWorker(pull_snapshots)
        self._drive_worker.done.connect(self._on_startup_pull)
        self._drive_worker.failed.connect(
            lambda _msg: self.drive_status.setText(tr("Drive: offline")))
        self._drive_worker.start()

    def _on_startup_pull(self, counts):
        vaults, _entries = counts
        self.drive_status.setText(
            tr("Drive: {count} vault(s)", count=vaults) if vaults else tr("Drive: on"))
        if self._mode == MODE_MASTER and not self.login_btn.isEnabled():
            self._set_mode(MODE_MASTER)      # a pulled vault brought a master password

    def _open_drive_dialog(self):
        GoogleDriveDialog(self).exec()
        self.drive_status.setText(
            tr("Drive: on") if gdrive.is_connected() else tr("Drive: off"))
        self._set_mode(self._mode)

    # ── Sign in ───────────────────────────────────────────────────

    def _do_login(self):
        password = self.pass_edit.text()
        if not password:
            self._show_error(tr("Enter your password."))
            return

        self.error_lbl.hide()
        self.info_lbl.hide()
        self._pending_password = password

        if self._mode == MODE_MASTER:
            self._set_busy(tr("Unlocking…"))
            self._run(crypto.unlock_with_master, self._on_unlocked, password)
            return

        server   = self.server_edit.text().strip()
        username = self.user_edit.text().strip()
        if not server or not username:
            self._show_error(tr("Please fill in all fields."))
            return

        self._save_settings()
        self._username = username
        self._set_busy(tr("Authenticating…"))
        self._run(ad_auth.authenticate, self._on_ad_auth_done,
                  server, username, password)

    def _on_ad_auth_done(self, success: bool):
        if not success:
            self._set_busy(None)
            self._show_error(
                tr("Authentication failed. Check credentials or server address."))
            self.pass_edit.clear()
            return

        self._set_busy(tr("Opening vault…"))
        self._run(crypto.unlock_with_ad, self._on_unlocked,
                  self._username, self._pending_password)

    def _on_unlocked(self, result):
        session, status = result
        self._set_busy(None)

        if status == crypto.OK:
            self._open_vault(session)
            return

        if status == crypto.WRONG_SECRET:
            if self._mode == MODE_MASTER:
                self._show_error(tr("Wrong master password."))
                self.pass_edit.clear()
            else:
                self._recover_changed_ad_password()
            return

        # NO_METHOD
        if self._mode == MODE_MASTER:
            self._show_error(tr("No vault is protected by this master password."))
        elif self._confirm_new_ad_vault():
            self._set_busy(tr("Creating vault…"))
            self._run(crypto.create_vault, self._on_vault_created,
                      METHOD_AD, database.hash_identity(self._username),
                      self._pending_password, self._username)

    def _confirm_new_ad_vault(self) -> bool:
        """
        First sign-in for this AD account. If the machine already holds other
        vaults, say so — the user probably wants to add AD unlock to one of
        them rather than start an empty second vault.
        """
        if not database.list_vaults():
            return True

        reply = QMessageBox.question(
            self, tr("New Vault"),
            tr("No vault on this machine is linked to <b>{user}</b>.<br><br>"
               "Create a new, empty one?<br><br>"
               "If your passwords are in an existing vault, cancel, unlock it "
               "the way you usually do, and add this account under Security.",
               user=self._username),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if reply == QMessageBox.StandardButton.Yes:
            return True

        self._show_info(tr(
            "No vault opened. Unlock your existing vault and add this account "
            "under Security to sign in with Active Directory next time."))
        return False

    def _on_vault_created(self, session):
        self._set_busy(None)
        self._open_vault(session)

    def _recover_changed_ad_password(self):
        dlg = OldPasswordDialog(self)
        while dlg.exec() == QDialog.DialogCode.Accepted:
            old_password = dlg.old_password()
            if not old_password:
                dlg.show_error(tr("Enter your previous password."))
                continue

            self._set_busy(tr("Re-wrapping vault key…"))
            QApplication.processEvents()
            session = crypto.recover_with_old_ad_password(
                self._username, old_password, self._pending_password)
            self._set_busy(None)

            if session is not None:
                self._open_vault(session)
                return
            dlg.show_error(tr("That is not the previous password. Try again."))

        self._show_error(tr(
            "Vault not opened. It is still encrypted with your previous AD "
            "password, and only that password can unwrap it."
        ))

    def _create_master_vault(self):
        dlg = MasterPasswordDialog(
            self, title=tr("Create Vault"),
            intro=tr("This creates a new, empty vault unlocked by a master "
                     "password alone. To put an existing vault behind a master "
                     "password instead, sign in with Active Directory and use "
                     "Security in the vault window.")
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._set_busy(tr("Creating vault…"))
        self._run(crypto.create_vault, self._on_vault_created,
                  METHOD_MASTER, "", dlg.password(), "master password")

    def _open_vault(self, session):
        from vault_window import VaultWindow
        self._pending_password = ""
        self.pass_edit.clear()
        if self._repeat_timer:
            self._repeat_timer.stop()
        self._vault = VaultWindow(session)
        self._vault.show()
        self.close()

    # ── Helpers ───────────────────────────────────────────────────

    def _run(self, fn, on_done, *args):
        self._worker = CallWorker(fn, *args)
        self._worker.done.connect(on_done)
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.start()

    def _on_worker_failed(self, message: str):
        self._set_busy(None)
        self._show_error(message)

    def _set_busy(self, msg: str | None):
        if msg:
            self.login_btn.setEnabled(False)
            self.login_btn.setText(msg)
        else:
            self.login_btn.setEnabled(True)
            self.login_btn.setText(
                tr("Sign In") if self._mode == MODE_AD else tr("Unlock"))

    def _show_error(self, msg: str):
        self.info_lbl.hide()
        self.error_lbl.setText(msg)
        self.error_lbl.show()

    def _show_info(self, msg: str):
        self.error_lbl.hide()
        self.info_lbl.setText(msg)
        self.info_lbl.show()

    def _switch_language(self):
        """Rebuild the window: every label was translated when it was created."""
        i18n.set_language(i18n.other_language())
        if self._repeat_timer:
            self._repeat_timer.stop()
        self._replacement = LoginWindow()
        self._replacement.move(self.pos())
        self._replacement.show()
        self.close()

    def closeEvent(self, event):
        if self._repeat_timer:
            self._repeat_timer.stop()
        if self._ping_timer:
            self._ping_timer.stop()
        super().closeEvent(event)
