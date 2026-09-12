"""
login_window.py — Login UI with AD password change detection & migration dialog.

QSettings storage:
  Windows → HKCU/Software/ADPasswordManager  (registry)
  Linux   → ~/.config/ADPasswordManager/ADPasswordManager.ini
  macOS   → ~/Library/Preferences/ADPasswordManager.plist
"""

import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QDialog,
    QDialogButtonBox, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings

import database
import ad_auth

# ── Palette ───────────────────────────────────────────────────────
DARK_BG  = "#0d1117"
PANEL_BG = "#161b22"
BORDER   = "#30363d"
ACCENT   = "#58a6ff"
ACCENT2  = "#1f6feb"
TEXT     = "#e6edf3"
TEXT_DIM = "#8b949e"
SUCCESS  = "#3fb950"
DANGER   = "#f85149"
INPUT_BG = "#0d1117"

BASE_STYLE = f"""
QWidget {{
    background: {DARK_BG};
    font-family: 'Segoe UI', sans-serif;
}}
QFrame#panel {{
    background: {PANEL_BG};
    border: 1px solid {BORDER};
    border-radius: 16px;
}}
QLabel#title {{
    color: {TEXT};
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 1px;
}}
QLabel#subtitle {{
    color: {TEXT_DIM};
    font-size: 12px;
}}
QLabel#fieldLabel {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
}}
QLineEdit {{
    background: {INPUT_BG};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13px;
    selection-background-color: {ACCENT2};
}}
QLineEdit:focus {{ border: 1px solid {ACCENT}; }}
QLineEdit:hover {{ border: 1px solid #484f58; }}
QPushButton#loginBtn {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {ACCENT2}, stop:1 {ACCENT});
    color: white;
    border: none;
    border-radius: 8px;
    padding: 12px;
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 0.5px;
}}
QPushButton#loginBtn:hover {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #388bfd, stop:1 #79c0ff);
}}
QPushButton#loginBtn:pressed {{ background: {ACCENT2}; }}
QPushButton#loginBtn:disabled {{ background: #30363d; color: {TEXT_DIM}; }}
QLabel#errorLbl {{
    color: {DANGER};
    font-size: 12px;
    padding: 6px 12px;
    background: rgba(248,81,73,0.1);
    border: 1px solid rgba(248,81,73,0.3);
    border-radius: 6px;
}}
QLabel#warnLbl {{
    color: #d29922;
    font-size: 12px;
    padding: 6px 12px;
    background: rgba(210,153,34,0.1);
    border: 1px solid rgba(210,153,34,0.3);
    border-radius: 6px;
}}
QLabel#hint {{ color: {TEXT_DIM}; font-size: 10px; }}
"""

DIALOG_STYLE = f"""
QDialog {{
    background: {PANEL_BG};
    font-family: 'Segoe UI', sans-serif;
}}
QLabel {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 600;
}}
QLabel#info {{
    color: {TEXT};
    font-size: 12px;
    font-weight: 400;
    padding: 8px 0;
}}
QLineEdit {{
    background: {INPUT_BG};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13px;
}}
QLineEdit:focus {{ border: 1px solid {ACCENT}; }}
QDialogButtonBox QPushButton {{
    background: {ACCENT2};
    color: white;
    border: none;
    border-radius: 7px;
    padding: 8px 20px;
    font-size: 13px;
    font-weight: 600;
    min-width: 80px;
}}
QDialogButtonBox QPushButton:hover {{ background: {ACCENT}; }}
QDialogButtonBox QPushButton[text="Cancel"] {{
    background: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
}}
"""

ORG_NAME = "ZaPassKa"
APP_NAME = "ZaPassKa"


def app_settings() -> QSettings:
    return QSettings(ORG_NAME, APP_NAME)


# ── Worker threads ────────────────────────────────────────────────

class PingWorker(QThread):
    result = pyqtSignal(bool)

    def __init__(self, server: str):
        super().__init__()
        self.server = server

    def run(self):
        self.result.emit(ad_auth.check_dc_reachable(self.server))


class AuthWorker(QThread):
    done = pyqtSignal(bool)

    def __init__(self, server: str, username: str, password: str):
        super().__init__()
        self.server   = server
        self.username = username
        self.password = password

    def run(self):
        self.done.emit(
            ad_auth.authenticate(self.server, self.username, self.password)
        )


class ReencryptWorker(QThread):
    done = pyqtSignal(bool)

    def __init__(self, username: str, old_password: str, new_password: str):
        super().__init__()
        self.username     = username
        self.old_password = old_password
        self.new_password = new_password

    def run(self):
        import crypto
        self.done.emit(
            crypto.reencrypt_all(self.username, self.old_password, self.new_password)
        )


# ── Password change migration dialog ─────────────────────────────

class MigrationDialog(QDialog):
    """
    Shown when AD password change is detected.
    Asks user for their OLD password to re-encrypt all stored entries.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AD Password Changed — Data Migration")
        self.setFixedWidth(440)
        self.setStyleSheet(DIALOG_STYLE)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(28, 24, 28, 24)

        info = QLabel(
            "Your Active Directory password has changed.\n\n"
            "To keep your saved passwords accessible, enter your "
            "previous AD password below. All entries will be "
            "re-encrypted with your new password."
        )
        info.setObjectName("info")
        info.setWordWrap(True)
        lay.addWidget(info)

        lay.addWidget(self._lbl("PREVIOUS AD PASSWORD"))
        self.old_pass = QLineEdit()
        self.old_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.old_pass.setPlaceholderText("••••••••••••")
        lay.addWidget(self.old_pass)

        self.error_lbl = QLabel()
        self.error_lbl.setStyleSheet(
            f"color: {DANGER}; font-size: 11px; font-weight: 400;"
        )
        self.error_lbl.hide()
        lay.addWidget(self.error_lbl)

        lay.addSpacing(8)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _lbl(self, text: str) -> QLabel:
        l = QLabel(text)
        return l

    def old_password(self) -> str:
        return self.old_pass.text()

    def show_error(self, msg: str):
        self.error_lbl.setText(msg)
        self.error_lbl.show()


# ── Login Window ──────────────────────────────────────────────────

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        database.init_db()
        self._ping_worker     = None
        self._auth_worker     = None
        self._reencrypt_worker = None
        self._ping_timer      = None
        self._pending_username = None
        self._pending_password = None

        self.setWindowTitle("ZaPassKa — Login")
        self.setFixedSize(460, 520)
        self.setStyleSheet(BASE_STYLE)
        self._build_ui()
        self._load_settings()
        self._schedule_ping()

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
        lay.setContentsMargins(36, 36, 36, 36)

        # Title
        title_row = QHBoxLayout()
        icon = QLabel("🔐")
        icon.setStyleSheet("font-size: 30px;")
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel("Password Vault")
        t.setObjectName("title")
        s = QLabel("AD-authenticated password manager")
        s.setObjectName("subtitle")
        col.addWidget(t)
        col.addWidget(s)
        title_row.addWidget(icon)
        title_row.addSpacing(10)
        title_row.addLayout(col)
        title_row.addStretch()
        lay.addLayout(title_row)
        lay.addSpacing(6)

        # AD Server + DC indicator
        lay.addWidget(self._lbl("AD SERVER (LDAP URL)"))
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
        self.dc_dot.setToolTip("DC connection status")
        srv_row.addWidget(self.dc_dot)
        lay.addLayout(srv_row)

        # Username
        lay.addWidget(self._lbl("USERNAME"))
        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText(os.environ.get("USERNAME", "username"))
        self.user_edit.setText(os.environ.get("USERNAME", ""))
        lay.addWidget(self.user_edit)

        # Password
        lay.addWidget(self._lbl("PASSWORD"))
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("••••••••••••")
        self.pass_edit.returnPressed.connect(self._do_login)
        lay.addWidget(self.pass_edit)

        # Error label
        self.error_lbl = QLabel()
        self.error_lbl.setObjectName("errorLbl")
        self.error_lbl.setWordWrap(True)
        self.error_lbl.hide()
        lay.addWidget(self.error_lbl)

        lay.addSpacing(4)

        # Login button
        self.login_btn = QPushButton("Sign In")
        self.login_btn.setObjectName("loginBtn")
        self.login_btn.setFixedHeight(46)
        self.login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_btn.clicked.connect(self._do_login)
        lay.addWidget(self.login_btn)

        lay.addStretch()

        hint = QLabel("AES-256-GCM + scrypt")
        hint.setObjectName("hint")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(hint)

    def _lbl(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setObjectName("fieldLabel")
        return l

    # ── Settings ──────────────────────────────────────────────────

    def _load_settings(self):
        s = app_settings()
        server = s.value("ad_server", "")
        if server:
            self.server_edit.setText(server)

    def _save_settings(self):
        s = app_settings()
        s.setValue("ad_server", self.server_edit.text().strip())
        s.sync()

    # ── DC Ping ───────────────────────────────────────────────────

    def _on_server_changed(self):
        self.dc_dot.setStyleSheet("font-size: 18px; color: #484f58;")
        if self._ping_timer:
            self._ping_timer.stop()
        self._ping_timer = QTimer()
        self._ping_timer.setSingleShot(True)
        self._ping_timer.timeout.connect(self._do_ping)
        self._ping_timer.start(800)

    def _schedule_ping(self):
        QTimer.singleShot(400, self._do_ping)
        self._repeat = QTimer()
        self._repeat.timeout.connect(self._do_ping)
        self._repeat.start(15000)

    def _do_ping(self):
        server = self.server_edit.text().strip()
        if not server:
            self.dc_dot.setStyleSheet("font-size: 18px; color: #484f58;")
            self.dc_dot.setToolTip("No server configured")
            return
        if self._ping_worker and self._ping_worker.isRunning():
            return
        self._ping_worker = PingWorker(server)
        self._ping_worker.result.connect(self._on_ping_result)
        self._ping_worker.start()

    def _on_ping_result(self, ok: bool):
        if ok:
            self.dc_dot.setStyleSheet(f"font-size: 18px; color: {SUCCESS};")
            self.dc_dot.setToolTip("Domain controller reachable ✓")
        else:
            self.dc_dot.setStyleSheet(f"font-size: 18px; color: {DANGER};")
            self.dc_dot.setToolTip("Domain controller unreachable ✗")

    # ── Auth ──────────────────────────────────────────────────────

    def _do_login(self):
        server   = self.server_edit.text().strip()
        username = self.user_edit.text().strip()
        password = self.pass_edit.text()

        if not all([server, username, password]):
            self._show_error("Please fill in all fields.")
            return

        self._save_settings()
        self.error_lbl.hide()
        self._set_busy("Authenticating…")

        self._auth_worker = AuthWorker(server, username, password)
        self._auth_worker.done.connect(
            lambda ok: self._on_ad_auth_done(ok, username, password)
        )
        self._auth_worker.start()

    def _on_ad_auth_done(self, success: bool, username: str, password: str):
        self._set_busy(None)

        if not success:
            self._show_error("Authentication failed. Check credentials or server address.")
            self.pass_edit.clear()
            return

        # AD accepted — now verify encryption key
        import crypto
        key, ok = crypto.derive_key(username, password)

        if ok:
            self._open_vault(key, username)
        else:
            # Password changed — start migration flow
            self._pending_username = username
            self._pending_password = password
            self._show_migration_dialog()

    def _show_migration_dialog(self):
        dlg = MigrationDialog(self)
        while True:
            result = dlg.exec()
            if result != QDialog.DialogCode.Accepted:
                # User cancelled — can't open vault
                self._show_error(
                    "Migration cancelled. Cannot open vault with changed password."
                )
                return

            old_pw = dlg.old_password()
            if not old_pw:
                dlg.show_error("Please enter your previous password.")
                continue

            self._set_busy("Re-encrypting data…")
            import crypto
            ok = crypto.reencrypt_all(
                self._pending_username, old_pw, self._pending_password
            )
            self._set_busy(None)

            if ok:
                # Re-encryption done — derive key with new password and open vault
                key, valid = crypto.derive_key(
                    self._pending_username, self._pending_password
                )
                if valid:
                    self._open_vault(key, self._pending_username)
                    return
            else:
                dlg.show_error("Incorrect previous password. Please try again.")

    def _open_vault(self, key: bytes, username: str):
        from vault_window import VaultWindow
        self._vault = VaultWindow(key, username)
        self._vault.show()
        self.close()

    # ── Helpers ───────────────────────────────────────────────────

    def _set_busy(self, msg: str | None):
        if msg:
            self.login_btn.setEnabled(False)
            self.login_btn.setText(msg)
        else:
            self.login_btn.setEnabled(True)
            self.login_btn.setText("Sign In")

    def _show_error(self, msg: str):
        self.error_lbl.setText(msg)
        self.error_lbl.show()