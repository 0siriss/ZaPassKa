"""
vault_window.py — the vault itself: entries, unlock methods, Drive sync.
"""

import secrets
import string

from cryptography.exceptions import InvalidTag
from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QDialogButtonBox, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget
)

import ad_auth
import cloud_sync
import crypto
import database
import gdrive
import settings
import theme
from database import METHOD_MASTER

CLIPBOARD_CLEAR_MS = 30_000

# How long closing waits for a sync already in flight. Dropping a running
# thread aborts the process, and the entry is safe in SQLite either way.
SYNC_SHUTDOWN_WAIT_MS = 5_000

COL_SERVICE  = 0
COL_LOGIN    = 1
COL_PASSWORD = 2
COL_ACTIONS  = 3


# ── Password generator ────────────────────────────────────────────

def generate_password(length: int = 16) -> str:
    """Cryptographically secure password with all character classes."""
    lower   = string.ascii_lowercase
    upper   = string.ascii_uppercase
    digits  = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    alphabet = lower + upper + digits + symbols
    mandatory = [secrets.choice(group) for group in (lower, upper, digits, symbols)]
    rest = [secrets.choice(alphabet) for _ in range(max(0, length - len(mandatory)))]
    pool = mandatory + rest
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)


# ── Workers ───────────────────────────────────────────────────────

class SyncWorker(QThread):
    """One pull-merge-push cycle against Google Drive."""
    done   = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, vault_id: str):
        super().__init__()
        self._vault_id = vault_id

    def run(self):
        try:
            self.done.emit(cloud_sync.sync_vault(self._vault_id))
        except gdrive.DriveError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:                       # noqa: BLE001
            self.failed.emit(f"Sync failed: {exc}")


class TaskWorker(QThread):
    """Runs a slow local task (scrypt, LDAP bind) off the UI thread."""
    done   = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, fn, *args):
        super().__init__()
        self._fn, self._args = fn, args

    def run(self):
        try:
            self.done.emit(self._fn(*self._args))
        except Exception as exc:                       # noqa: BLE001
            self.failed.emit(str(exc))


# ── Add / edit entry ──────────────────────────────────────────────

class EntryDialog(QDialog):
    def __init__(self, parent=None, service="", login="", password="",
                 title="Add Entry"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedWidth(420)
        self.setStyleSheet(theme.DIALOG_STYLE)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(28, 24, 28, 24)

        btn_style = f"""
            QPushButton {{
                background: {theme.INPUT_BG};
                border: 1px solid {theme.BORDER};
                border-radius: 8px;
                color: {theme.TEXT_DIM};
                font-size: 16px;
                min-width: 38px;
            }}
            QPushButton:hover {{ color: {theme.ACCENT}; border-color: {theme.ACCENT}; }}
            QPushButton:checked {{ color: {theme.ACCENT}; border-color: {theme.ACCENT}; }}
        """

        lay.addWidget(QLabel("SERVICE / WEBSITE"))
        self.service_edit = QLineEdit(service)
        self.service_edit.setPlaceholderText("e.g. GitHub")
        lay.addWidget(self.service_edit)

        lay.addWidget(QLabel("LOGIN / EMAIL"))
        self.login_edit = QLineEdit(login)
        self.login_edit.setPlaceholderText("e.g. user@company.com")
        lay.addWidget(self.login_edit)

        lay.addWidget(QLabel("PASSWORD"))
        pw_row = QHBoxLayout()
        pw_row.setSpacing(6)

        self.pass_edit = QLineEdit(password)
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("••••••••••")
        pw_row.addWidget(self.pass_edit)

        self.toggle_btn = QPushButton("👁")
        self.toggle_btn.setFixedSize(38, 38)
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setToolTip("Show / hide password")
        self.toggle_btn.setStyleSheet(btn_style)
        self.toggle_btn.toggled.connect(
            lambda shown: self.pass_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password
            )
        )
        pw_row.addWidget(self.toggle_btn)

        gen_btn = QPushButton("↔")
        gen_btn.setFixedSize(38, 38)
        gen_btn.setToolTip("Generate secure 16-char password")
        gen_btn.setStyleSheet(btn_style)
        gen_btn.clicked.connect(self._generate)
        pw_row.addWidget(gen_btn)

        lay.addLayout(pw_row)
        lay.addSpacing(8)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _generate(self):
        self.pass_edit.setText(generate_password(16))
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        self.toggle_btn.setChecked(True)

    def values(self) -> tuple:
        return (
            self.service_edit.text().strip(),
            self.login_edit.text().strip(),
            self.pass_edit.text(),
        )


# ── Attach AD unlock ──────────────────────────────────────────────

class AdUnlockDialog(QDialog):
    """Collects the domain credentials that should be able to open this vault."""

    def __init__(self, parent=None, server="", username=""):
        super().__init__(parent)
        self.setWindowTitle("Add Active Directory Unlock")
        self.setFixedWidth(440)
        self.setStyleSheet(theme.DIALOG_STYLE)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(28, 24, 28, 24)

        info = QLabel(
            "The domain password is checked against the DC first, then used "
            "to wrap this vault's key. Your entries stay as they are."
        )
        info.setObjectName("info")
        info.setWordWrap(True)
        lay.addWidget(info)

        lay.addWidget(QLabel("AD SERVER (LDAP URL)"))
        self.server_edit = QLineEdit(server)
        self.server_edit.setPlaceholderText("domain.com")
        lay.addWidget(self.server_edit)

        lay.addWidget(QLabel("USERNAME"))
        self.user_edit = QLineEdit(username)
        lay.addWidget(self.user_edit)

        lay.addWidget(QLabel("PASSWORD"))
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText(theme.PASS_MASK)
        lay.addWidget(self.pass_edit)

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
        if all(self.values()):
            self.accept()
        else:
            self.error_lbl.setText("Fill in every field.")
            self.error_lbl.show()

    def values(self) -> tuple[str, str, str]:
        return (self.server_edit.text().strip(),
                self.user_edit.text().strip(),
                self.pass_edit.text())

    def show_error(self, msg: str):
        self.error_lbl.setText(msg)
        self.error_lbl.show()


# ── Security (unlock methods) ─────────────────────────────────────

class SecurityDialog(QDialog):
    """
    Shows the one way into this vault and switches it to the other one.

    A switch rewraps the data key under the new secret and retires the old
    wrapping. Entries are never re-encrypted, so the move cannot lose them.
    """

    def __init__(self, session, parent=None):
        super().__init__(parent)
        self._session = session
        self._worker  = None
        self.changed  = False

        self.setWindowTitle("Vault Security")
        self.setMinimumWidth(520)
        self.setStyleSheet(theme.DIALOG_STYLE)

        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(28, 24, 28, 24)

        intro = QLabel(
            "This vault has exactly one way in. Switching replaces it; your "
            "entries stay as they are."
        )
        intro.setObjectName("info")
        intro.setWordWrap(True)
        lay.addWidget(intro)

        self.card = QFrame()
        self.card.setObjectName("card")
        card_lay = QVBoxLayout(self.card)
        card_lay.setContentsMargins(14, 12, 14, 12)
        card_lay.setSpacing(2)
        self.method_lbl = QLabel()
        self.method_lbl.setStyleSheet(
            f"color: {theme.TEXT}; font-size: 13px; font-weight: 600;")
        self.detail_lbl = QLabel()
        self.detail_lbl.setStyleSheet(
            f"color: {theme.TEXT_DIM}; font-size: 11px; font-weight: 400;")
        self.detail_lbl.setWordWrap(True)
        card_lay.addWidget(self.method_lbl)
        card_lay.addWidget(self.detail_lbl)
        lay.addWidget(self.card)

        self.switch_btn = QPushButton()
        self.switch_btn.setObjectName("rowBtn")
        self.switch_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.switch_btn.clicked.connect(self._switch)
        lay.addWidget(self.switch_btn)

        self.caution_lbl = QLabel()
        self.caution_lbl.setWordWrap(True)
        lay.addWidget(self.caution_lbl)

        self.status_lbl = QLabel()
        self.status_lbl.setWordWrap(True)
        self.status_lbl.hide()
        lay.addWidget(self.status_lbl)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.accept)
        lay.addWidget(buttons)

        self._refresh()

    # ── State ─────────────────────────────────────────────────────

    def _current(self) -> str:
        row = crypto.current_method(self._session.vault_id)
        return row["method"] if row else self._session.method

    def _refresh(self):
        row = crypto.current_method(self._session.vault_id)
        current = row["method"] if row else self._session.method
        since = f" · set {row['updated_at'][:10]}" if row else ""

        if current == METHOD_MASTER:
            self.method_lbl.setText("🔑  Master password")
            self.detail_lbl.setText("Opens the vault without the domain" + since)
            self.switch_btn.setText("Switch to Active Directory…")
            self.caution_lbl.setText(
                "After switching, the domain password is the only way in. "
                "If it changes you will be asked for the previous one once; "
                "forget it and the vault cannot be opened."
            )
            self.caution_lbl.setStyleSheet(
                f"color: {theme.WARNING}; font-size: 11px; font-weight: 400;")
        else:
            who = self._session.display_name or "domain account"
            self.method_lbl.setText("🏢  Active Directory")
            self.detail_lbl.setText(f"Opens with the password of {who}" + since)
            self.switch_btn.setText("Switch to a master password…")
            self.caution_lbl.setText(
                "After switching, the domain is no longer involved. A "
                "forgotten master password cannot be recovered."
            )
            self.caution_lbl.setStyleSheet(
                f"color: {theme.TEXT_DIM}; font-size: 11px; font-weight: 400;")

    # ── Switching ─────────────────────────────────────────────────

    def _switch(self):
        if self._current() == METHOD_MASTER:
            self._switch_to_ad()
        else:
            self._switch_to_master()

    def _switch_to_master(self):
        from login_window import MasterPasswordDialog

        dlg = MasterPasswordDialog(
            self, title="Switch to Master Password",
            intro="From now on this password alone opens the vault, and the "
                  "domain account stops working for it. The entries you see "
                  "now stay exactly as they are."
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._busy("Rewrapping the vault key…")
        self._run(crypto.switch_to_master, self._on_switched,
                  self._session, dlg.password())

    def _switch_to_ad(self):
        store = settings.app_settings()
        dlg = AdUnlockDialog(self, server=store.value(settings.KEY_AD_SERVER, ""),
                             username=self._session.display_name)
        while dlg.exec() == QDialog.DialogCode.Accepted:
            server, username, password = dlg.values()
            self._busy("Checking the domain…")
            QApplication.processEvents()

            if not ad_auth.authenticate(server, username, password):
                self._busy(None)
                dlg.show_error("The domain rejected those credentials.")
                continue

            self._busy("Rewrapping the vault key…")
            QApplication.processEvents()
            crypto.switch_to_ad(self._session, username, password)
            store.setValue(settings.KEY_AD_SERVER, server)
            store.sync()

            self._busy(None)
            self._finish(f"{username} is now the only way into this vault.")
            return

    def _on_switched(self, _result):
        self._busy(None)
        self._finish("The master password is now the only way into this vault.")

    def _finish(self, message: str):
        self.changed = True
        self._status(message, ok=True)
        self._refresh()

    # ── Helpers ───────────────────────────────────────────────────

    def _run(self, fn, on_done, *args):
        self._worker = TaskWorker(fn, *args)
        self._worker.done.connect(on_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_failed(self, message: str):
        self._busy(None)
        self._status(message, ok=False)

    def _busy(self, msg: str | None):
        self.switch_btn.setEnabled(msg is None)
        if msg:
            self._status(msg, ok=True)

    def _status(self, text: str, ok: bool):
        self.status_lbl.setStyleSheet(
            f"color: {theme.SUCCESS if ok else theme.DANGER}; "
            f"font-size: 11px; font-weight: 400;")
        self.status_lbl.setText(text)
        self.status_lbl.show()


# ── Vault window ──────────────────────────────────────────────────

class VaultWindow(QWidget):

    def __init__(self, session):
        super().__init__()
        self._session = session
        self._rows: list[dict] = []
        self._visible_uuid: str | None = None   # at most one password in clear text
        self._on_top = settings.stay_on_top()
        self._sync_worker  = None
        self._sync_running = False
        self._sync_pending = False
        self._clip_timer = None

        self.setWindowTitle("ZaPassKa (password manager)")
        self.setMinimumSize(940, 560)
        self.resize(1040, 640)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, self._on_top)
        self.setStyleSheet(theme.VAULT_STYLE)

        self._build_ui()
        self._load_rows()
        self._request_sync()

    # ── UI ────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        top = QHBoxLayout()
        icon = QLabel("🔐")
        icon.setStyleSheet("font-size: 22px;")
        top.addWidget(icon)

        col = QVBoxLayout()
        col.setSpacing(0)
        header = QLabel("Password Vault")
        header.setObjectName("header")
        user = QLabel(f"Unlocked with  {self._session.display_name}")
        user.setObjectName("userInfo")
        col.addWidget(header)
        col.addWidget(user)
        top.addLayout(col)
        top.addStretch()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍  Search…")
        self.search_edit.setFixedWidth(190)
        self.search_edit.textChanged.connect(self._filter)
        top.addWidget(self.search_edit)

        add_btn = QPushButton("＋  Add Entry")
        add_btn.setObjectName("addBtn")
        add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        add_btn.clicked.connect(self._add_entry)
        top.addWidget(add_btn)

        self.sync_btn = QPushButton("☁ Sync")
        self.sync_btn.setObjectName("toolBtn")
        self.sync_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.sync_btn.setToolTip("Back up to Google Drive and pull other machines' changes")
        self.sync_btn.clicked.connect(lambda: self._request_sync(manual=True))
        top.addWidget(self.sync_btn)

        security_btn = QPushButton("🛡 Security")
        security_btn.setObjectName("toolBtn")
        security_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        security_btn.setToolTip("Master password and Active Directory unlock")
        security_btn.clicked.connect(self._open_security)
        top.addWidget(security_btn)

        self.pin_btn = QPushButton()
        self.pin_btn.setObjectName("pinBtn")
        self.pin_btn.setCheckable(True)
        self.pin_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.pin_btn.setToolTip("Toggle always-on-top, remembered between sessions")
        self.pin_btn.clicked.connect(self._toggle_on_top)
        self._update_pin_button()
        top.addWidget(self.pin_btn)

        logout_btn = QPushButton("Sign out")
        logout_btn.setObjectName("logoutBtn")
        logout_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        logout_btn.clicked.connect(self._logout)
        top.addWidget(logout_btn)

        root.addLayout(top)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet(f"color: {theme.BORDER};")
        root.addWidget(divider)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Service", "Login", "Password", "Actions"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        hdr = self.table.horizontalHeader()
        for column in (COL_SERVICE, COL_LOGIN, COL_PASSWORD):
            hdr.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(COL_ACTIONS, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(COL_ACTIONS, 290)
        self.table.verticalHeader().setDefaultSectionSize(52)
        root.addWidget(self.table)

        bottom = QHBoxLayout()
        self._status = QLabel("")
        self._status.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 11px;")
        bottom.addWidget(self._status)
        bottom.addStretch()
        self._sync_status = QLabel("")
        self._sync_status.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 11px;")
        bottom.addWidget(self._sync_status)
        root.addLayout(bottom)

    # ── Data ──────────────────────────────────────────────────────

    def _load_rows(self):
        self._rows = []
        failed = 0
        for row in database.get_entries(self._session.vault_id):
            try:
                self._rows.append(crypto.decrypt_row(self._session.dek, row))
            except (InvalidTag, ValueError):
                failed += 1
        if failed:
            QMessageBox.warning(
                self, "Decryption Warning",
                f"{failed} entr(ies) could not be decrypted. They were written "
                "with a different key — most likely a damaged sync."
            )
        self._filter(self.search_edit.text())

    def _render(self, rows: list[dict]):
        self.table.setRowCount(0)
        for row_data in rows:
            index = self.table.rowCount()
            self.table.insertRow(index)
            self._fill_row(index, row_data)
        self._update_status()

    def _fill_row(self, index: int, row_data: dict):
        entry_uuid = row_data["uuid"]
        shown      = entry_uuid == self._visible_uuid

        for column, text in ((COL_SERVICE, row_data["service"]),
                             (COL_LOGIN, row_data["login"])):
            item = QTableWidgetItem(text)
            item.setTextAlignment(
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.table.setItem(index, column, item)

        item = QTableWidgetItem(row_data["password"] if shown else theme.PASS_MASK)
        item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        if not shown:
            item.setForeground(QColor(theme.TEXT_DIM))
        self.table.setItem(index, COL_PASSWORD, item)

        cell = QWidget()
        cell.setStyleSheet("background: transparent;")
        actions = QHBoxLayout(cell)
        actions.setContentsMargins(8, 4, 8, 4)
        actions.setSpacing(6)

        def button(label, tip, handler, name="iconBtn"):
            btn = QPushButton(label)
            btn.setObjectName(name)
            btn.setToolTip(tip)
            btn.setFixedHeight(30)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(handler)
            return btn

        actions.addWidget(button(
            "🙈 Hide" if shown else "👁 Show", "Toggle password visibility",
            lambda _, u=entry_uuid: self._toggle_pw(u)))
        actions.addWidget(button(
            "📋 Copy", f"Copy password (cleared after {CLIPBOARD_CLEAR_MS // 1000}s)",
            lambda _, pw=row_data["password"]: self._copy_pw(pw)))
        actions.addWidget(button(
            "✎ Edit", "Edit this entry",
            lambda _, d=row_data: self._edit_entry(d)))
        actions.addStretch()

        delete_btn = button("🗑", "Delete entry",
                            lambda _, d=row_data: self._delete_entry(d), "dangerBtn")
        delete_btn.setFixedSize(32, 30)
        actions.addWidget(delete_btn)

        self.table.setCellWidget(index, COL_ACTIONS, cell)

    def _update_status(self):
        shown, total = self.table.rowCount(), len(self._rows)
        if shown == total:
            self._status.setText(f"{total} entries · AES-256-GCM encrypted")
        else:
            self._status.setText(f"Showing {shown} of {total} entries")

    # ── Entry actions ─────────────────────────────────────────────

    def _filter(self, text: str):
        text = text.lower()
        rows = self._rows if not text else [
            r for r in self._rows
            if text in r["service"].lower() or text in r["login"].lower()
        ]
        self._render(rows)

    def _toggle_pw(self, entry_uuid: str):
        """Only one password is ever readable — opening one closes the other."""
        self._visible_uuid = None if entry_uuid == self._visible_uuid else entry_uuid
        self._filter(self.search_edit.text())

    def _copy_pw(self, password: str):
        QApplication.clipboard().setText(password)
        self._status.setText(
            f"✓ Copied — clipboard clears in {CLIPBOARD_CLEAR_MS // 1000}s")
        if self._clip_timer:
            self._clip_timer.stop()
        self._clip_timer = QTimer(self)
        self._clip_timer.setSingleShot(True)
        self._clip_timer.timeout.connect(lambda: self._clear_clipboard(password))
        self._clip_timer.start(CLIPBOARD_CLEAR_MS)

    def _clear_clipboard(self, password: str):
        """Only wipe what we put there — never someone else's copy."""
        clipboard = QApplication.clipboard()
        if clipboard.text() == password:
            clipboard.clear()
        self._update_status()

    def _add_entry(self):
        dlg = EntryDialog(self, title="Add New Entry")
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        service, login, password = dlg.values()
        if not service or not login or not password:
            QMessageBox.warning(self, "Validation", "All fields are required.")
            return
        enc = crypto.encrypt_row(self._session.dek, service, login, password)
        database.insert_entry(self._session.vault_id, enc["service_enc"],
                              enc["login_enc"], enc["password_enc"])
        self._after_change()

    def _edit_entry(self, row_data: dict):
        dlg = EntryDialog(self, service=row_data["service"], login=row_data["login"],
                          password=row_data["password"], title="Edit Entry")
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        service, login, password = dlg.values()
        if not service or not login or not password:
            QMessageBox.warning(self, "Validation", "All fields are required.")
            return
        enc = crypto.encrypt_row(self._session.dek, service, login, password)
        database.update_entry(row_data["uuid"], enc["service_enc"],
                              enc["login_enc"], enc["password_enc"])
        self._after_change()

    def _delete_entry(self, row_data: dict):
        reply = QMessageBox.question(
            self, "Delete Entry",
            f"Delete entry for <b>{row_data['service']}</b>?<br>This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        database.delete_entry(row_data["uuid"])
        if self._visible_uuid == row_data["uuid"]:
            self._visible_uuid = None
        self._after_change()

    def _after_change(self):
        self._load_rows()
        self._request_sync()

    # ── Security ──────────────────────────────────────────────────

    def _open_security(self):
        dlg = SecurityDialog(self._session, self)
        dlg.exec()
        if dlg.changed:
            self._request_sync()

    # ── Google Drive sync ─────────────────────────────────────────

    def _request_sync(self, manual: bool = False):
        """
        Back up after every change. Without a Drive connection this is a no-op,
        so the vault keeps working offline.
        """
        if not cloud_sync.available():
            self._sync_status.setText("☁ Drive: not connected")
            self.sync_btn.setEnabled(True)
            return

        if self._sync_running:
            self._sync_pending = True        # coalesce: one more run after this one
            return

        self._sync_running = True
        self.sync_btn.setEnabled(False)
        self._sync_status.setText("☁ Syncing…")

        self._sync_worker = SyncWorker(self._session.vault_id)
        self._sync_worker.done.connect(self._on_sync_done)
        self._sync_worker.failed.connect(self._on_sync_failed)
        self._sync_worker.finished.connect(self._on_sync_finished)
        self._sync_worker.start()

    def _on_sync_done(self, outcome):
        self._sync_status.setText(f"☁ {outcome.summary()}")
        if outcome.pulled_entries or outcome.pulled_methods:
            self._load_rows()

    def _on_sync_failed(self, message: str):
        self._sync_status.setText("☁ Drive unavailable — working offline")
        self._sync_status.setToolTip(message)

    def _on_sync_finished(self):
        self._sync_running = False
        self.sync_btn.setEnabled(True)
        if self._sync_pending:
            self._sync_pending = False
            QTimer.singleShot(0, self._request_sync)

    # ── Window ────────────────────────────────────────────────────

    def _toggle_on_top(self):
        self._on_top = not self._on_top
        settings.set_stay_on_top(self._on_top)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, self._on_top)
        self.show()                          # required to apply the flag change
        self._update_pin_button()

    def _update_pin_button(self):
        self.pin_btn.setChecked(self._on_top)
        self.pin_btn.setText("📌 On Top" if self._on_top else "📌 Off")

    def _logout(self):
        from login_window import LoginWindow
        self._session.close()
        self._visible_uuid = None
        self._rows = []
        self._login_win = LoginWindow()
        self._login_win.show()
        self.close()

    def closeEvent(self, event):
        if self._clip_timer:
            self._clip_timer.stop()
        if self._sync_worker and self._sync_worker.isRunning():
            self._sync_pending = False
            self._sync_worker.wait(SYNC_SHUTDOWN_WAIT_MS)
        super().closeEvent(event)
