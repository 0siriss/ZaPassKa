"""
vault_window.py — Main vault UI
"""

import secrets
import string

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
    QDialog, QDialogButtonBox, QMessageBox, QFrame,
    QApplication, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor

import database
import crypto
from cryptography.exceptions import InvalidTag

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

PASS_MASK = "••••••••••••"

VAULT_STYLE = f"""
QWidget {{
    background: {DARK_BG};
    color: {TEXT};
    font-family: 'Segoe UI', sans-serif;
}}
QLabel#header {{
    font-size: 20px;
    font-weight: 700;
    color: {TEXT};
}}
QLabel#userInfo {{
    font-size: 12px;
    color: {TEXT_DIM};
}}
QTableWidget {{
    background: {PANEL_BG};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 10px;
    outline: none;
    font-size: 13px;
    color: {TEXT};
}}
QTableWidget::item {{
    padding: 6px 12px;
    border: none;
}}
QTableWidget::item:selected {{
    background: rgba(88,166,255,0.15);
    color: {TEXT};
}}
QHeaderView::section {{
    background: #1c2128;
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 600;
    padding: 10px 12px;
    border: none;
    border-bottom: 1px solid {BORDER};
    letter-spacing: 0.5px;
}}
QLineEdit {{
    background: {PANEL_BG};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 9px 14px;
    font-size: 13px;
}}
QLineEdit:focus {{
    border: 1px solid {ACCENT};
}}
QPushButton#addBtn {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {ACCENT2}, stop:1 {ACCENT});
    color: white;
    border: none;
    border-radius: 8px;
    padding: 10px 22px;
    font-size: 13px;
    font-weight: 600;
}}
QPushButton#addBtn:hover {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #388bfd, stop:1 #79c0ff);
}}
QPushButton#iconBtn {{
    background: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 12px;
}}
QPushButton#iconBtn:hover {{
    background: rgba(88,166,255,0.1);
    color: {ACCENT};
    border-color: {ACCENT};
}}
QPushButton#dangerBtn {{
    background: transparent;
    color: {DANGER};
    border: 1px solid rgba(248,81,73,0.4);
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 12px;
}}
QPushButton#dangerBtn:hover {{
    background: rgba(248,81,73,0.1);
}}
QPushButton#logoutBtn {{
    background: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-radius: 7px;
    padding: 7px 16px;
    font-size: 12px;
}}
QPushButton#logoutBtn:hover {{
    color: {DANGER};
    border-color: {DANGER};
}}
QPushButton#pinBtn {{
    background: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-radius: 7px;
    padding: 7px 14px;
    font-size: 12px;
}}
QPushButton#pinBtn:hover {{
    color: {ACCENT};
    border-color: {ACCENT};
}}
QPushButton#pinBtn:checked {{
    background: rgba(88,166,255,0.12);
    color: {ACCENT};
    border-color: {ACCENT};
}}
QScrollBar:vertical {{
    background: {DARK_BG};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: #30363d;
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {ACCENT};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
"""

DIALOG_STYLE = f"""
QDialog {{
    background: {PANEL_BG};
    color: {TEXT};
    font-family: 'Segoe UI', sans-serif;
}}
QLabel {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 600;
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
QDialogButtonBox QPushButton[text="Cancel"]:hover {{
    background: rgba(255,255,255,0.05);
}}
"""


# ── Password generator ────────────────────────────────────────────

def generate_password(length: int = 16) -> str:
    """Cryptographically secure password with all character classes."""
    lower   = string.ascii_lowercase
    upper   = string.ascii_uppercase
    digits  = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    alphabet = lower + upper + digits + symbols
    # Guarantee at least one from each group
    mandatory = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    rest = [secrets.choice(alphabet) for _ in range(length - len(mandatory))]
    pool = mandatory + rest
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)


# ── Add / Edit dialog ─────────────────────────────────────────────

class EntryDialog(QDialog):
    def __init__(self, parent=None, service="", login="", password="", title="Add Entry"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedWidth(420)
        self.setStyleSheet(DIALOG_STYLE)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(28, 24, 28, 24)

        btn_style = f"""
            QPushButton {{
                background: {INPUT_BG};
                border: 1px solid {BORDER};
                border-radius: 8px;
                color: {TEXT_DIM};
                font-size: 16px;
                min-width: 38px;
            }}
            QPushButton:hover {{
                color: {ACCENT};
                border-color: {ACCENT};
            }}
            QPushButton:checked {{
                color: {ACCENT};
                border-color: {ACCENT};
            }}
        """

        # Service
        lay.addWidget(QLabel("SERVICE / WEBSITE"))
        self.service_edit = QLineEdit(service)
        self.service_edit.setPlaceholderText("e.g. GitHub")
        lay.addWidget(self.service_edit)

        # Login
        lay.addWidget(QLabel("LOGIN / EMAIL"))
        self.login_edit = QLineEdit(login)
        self.login_edit.setPlaceholderText("e.g. user@company.com")
        lay.addWidget(self.login_edit)

        # Password row
        lay.addWidget(QLabel("PASSWORD"))
        pw_row = QHBoxLayout()
        pw_row.setSpacing(6)

        self.pass_edit = QLineEdit(password)
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("••••••••••")
        pw_row.addWidget(self.pass_edit)

        # Show/hide toggle
        self.toggle_btn = QPushButton("👁")
        self.toggle_btn.setFixedSize(38, 38)
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setToolTip("Show / hide password")
        self.toggle_btn.setStyleSheet(btn_style)
        self.toggle_btn.toggled.connect(
            lambda v: self.pass_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password
            )
        )
        pw_row.addWidget(self.toggle_btn)

        # Generate button
        gen_btn = QPushButton("↔")
        gen_btn.setFixedSize(38, 38)
        gen_btn.setToolTip("Generate secure 16-char password")
        gen_btn.setStyleSheet(btn_style)
        gen_btn.clicked.connect(self._generate)
        pw_row.addWidget(gen_btn)

        lay.addLayout(pw_row)
        lay.addSpacing(8)

        # OK / Cancel
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _generate(self):
        pwd = generate_password(16)
        self.pass_edit.setText(pwd)
        # Show the generated password so user can see it
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        self.toggle_btn.setChecked(True)

    def values(self) -> tuple:
        return (
            self.service_edit.text().strip(),
            self.login_edit.text().strip(),
            self.pass_edit.text(),
        )


# ── Vault Window ──────────────────────────────────────────────────

COL_SERVICE  = 0
COL_LOGIN    = 1
COL_PASSWORD = 2
COL_ACTIONS  = 3


class VaultWindow(QWidget):
    def __init__(self, key: bytes, username: str):
        super().__init__()
        self._key      = key
        self._username = username
        self._rows: list[dict] = []
        self._visible: set[int] = set()   # row IDs with visible password
        self._on_top   = True

        self.setWindowTitle("ZaPassKa (password manager)")
        self.setMinimumSize(860, 560)
        self.resize(980, 640)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        self.setStyleSheet(VAULT_STYLE)

        self._build_ui()
        self._load_rows()

    # ── UI ────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        # Top bar
        top = QHBoxLayout()

        icon = QLabel("🔐")
        icon.setStyleSheet("font-size: 22px;")
        top.addWidget(icon)

        col = QVBoxLayout()
        col.setSpacing(0)
        h = QLabel("Password Vault")
        h.setObjectName("header")
        u = QLabel(f"Signed in as  {self._username}")
        u.setObjectName("userInfo")
        col.addWidget(h)
        col.addWidget(u)
        top.addLayout(col)
        top.addStretch()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍  Search…")
        self.search_edit.setFixedWidth(200)
        self.search_edit.textChanged.connect(self._filter)
        top.addWidget(self.search_edit)

        add_btn = QPushButton("＋  Add Entry")
        add_btn.setObjectName("addBtn")
        add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        add_btn.clicked.connect(self._add_entry)
        top.addWidget(add_btn)

        self.pin_btn = QPushButton("📌 On Top")
        self.pin_btn.setObjectName("pinBtn")
        self.pin_btn.setCheckable(True)
        self.pin_btn.setChecked(True)
        self.pin_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.pin_btn.setToolTip("Toggle always-on-top")
        self.pin_btn.clicked.connect(self._toggle_on_top)
        top.addWidget(self.pin_btn)

        logout_btn = QPushButton("Sign out")
        logout_btn.setObjectName("logoutBtn")
        logout_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        logout_btn.clicked.connect(self._logout)
        top.addWidget(logout_btn)

        root.addLayout(top)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"color: {BORDER};")
        root.addWidget(div)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Service", "Login", "Password", "Actions"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(3, 220)
        self.table.verticalHeader().setDefaultSectionSize(52)

        root.addWidget(self.table)

        # Status bar
        self._status = QLabel("")
        self._status.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        root.addWidget(self._status)

    # ── Data ──────────────────────────────────────────────────────

    def _load_rows(self):
        db_rows = database.get_all_passwords()
        self._rows = []
        failed = 0
        for r in db_rows:
            try:
                self._rows.append(crypto.decrypt_row(self._key, r))
            except (InvalidTag, Exception):
                failed += 1
        if failed:
            QMessageBox.warning(
                self, "Decryption Warning",
                f"{failed} row(s) could not be decrypted (wrong key or corrupt data)."
            )
        self._render(self._rows)

    def _render(self, rows: list[dict]):
        self.table.setRowCount(0)
        for row_data in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self._fill_row(r, row_data)
        self._update_status()

    def _fill_row(self, r: int, row_data: dict):
        row_id   = row_data["id"]
        pw_shown = row_id in self._visible

        # Service
        item_s = QTableWidgetItem(row_data["service"])
        item_s.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        self.table.setItem(r, COL_SERVICE, item_s)

        # Login
        item_l = QTableWidgetItem(row_data["login"])
        item_l.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        self.table.setItem(r, COL_LOGIN, item_l)

        # Password
        pw_text = row_data["password"] if pw_shown else PASS_MASK
        item_p = QTableWidgetItem(pw_text)
        item_p.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        if not pw_shown:
            item_p.setForeground(QColor(TEXT_DIM))
        self.table.setItem(r, COL_PASSWORD, item_p)

        # Actions widget
        cell = QWidget()
        cell.setStyleSheet("background: transparent;")
        al = QHBoxLayout(cell)
        al.setContentsMargins(8, 4, 8, 4)
        al.setSpacing(6)

        def btn(label, tip, handler):
            b = QPushButton(label)
            b.setObjectName("iconBtn")
            b.setToolTip(tip)
            b.setFixedHeight(30)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(handler)
            return b

        eye_label = "🙈 Hide" if pw_shown else "👁 Show"
        show_btn = btn(eye_label, "Toggle password visibility",
                       lambda _, rid=row_id: self._toggle_pw(rid))
        copy_btn = btn("📋 Copy", "Copy password to clipboard",
                       lambda _, pw=row_data["password"]: self._copy_pw(pw))

        del_btn = QPushButton("🗑")
        del_btn.setObjectName("dangerBtn")
        del_btn.setToolTip("Delete entry")
        del_btn.setFixedSize(32, 30)
        del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        del_btn.clicked.connect(lambda _, rid=row_id: self._delete_entry(rid))

        al.addWidget(show_btn)
        al.addWidget(copy_btn)
        al.addStretch()
        al.addWidget(del_btn)

        self.table.setCellWidget(r, COL_ACTIONS, cell)

    def _update_status(self):
        shown = self.table.rowCount()
        total = len(self._rows)
        if shown == total:
            self._status.setText(f"{total} entries · AES-256-GCM encrypted")
        else:
            self._status.setText(f"Showing {shown} of {total} entries")

    # ── Actions ───────────────────────────────────────────────────

    def _filter(self, text: str):
        text = text.lower()
        filtered = self._rows if not text else [
            r for r in self._rows
            if text in r["service"].lower() or text in r["login"].lower()
        ]
        self._render(filtered)

    def _toggle_pw(self, row_id: int):
        if row_id in self._visible:
            self._visible.discard(row_id)
        else:
            self._visible.add(row_id)
        self._filter(self.search_edit.text())

    def _copy_pw(self, password: str):
        QApplication.clipboard().setText(password)
        self._status.setText("✓ Password copied to clipboard")
        QTimer.singleShot(3000, self._update_status)

    def _add_entry(self):
        dlg = EntryDialog(self, title="Add New Entry")
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        service, login, password = dlg.values()
        if not service or not login or not password:
            QMessageBox.warning(self, "Validation", "All fields are required.")
            return
        enc = crypto.encrypt_row(self._key, service, login, password)
        database.insert_password(enc["service_enc"], enc["login_enc"], enc["password_enc"])
        self._load_rows()

    def _delete_entry(self, row_id: int):
        row_data = next((r for r in self._rows if r["id"] == row_id), None)
        if not row_data:
            return
        reply = QMessageBox.question(
            self, "Delete Entry",
            f"Delete entry for <b>{row_data['service']}</b>?<br>This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if reply == QMessageBox.StandardButton.Yes:
            database.delete_password(row_id)
            self._visible.discard(row_id)
            self._load_rows()

    def _toggle_on_top(self):
        self._on_top = not self._on_top
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, self._on_top)
        self.show()  # required to apply flag change
        if self._on_top:
            self.pin_btn.setText("📌 On Top")
        else:
            self.pin_btn.setText("📌 Off")

    def _logout(self):
        self._key = None
        from login_window import LoginWindow
        self._login_win = LoginWindow()
        self._login_win.show()
        self.close()