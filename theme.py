"""
theme.py — palette and stylesheets shared by the windows.
"""

DARK_BG  = "#0d1117"
PANEL_BG = "#161b22"
BORDER   = "#30363d"
ACCENT   = "#58a6ff"
ACCENT2  = "#1f6feb"
TEXT     = "#e6edf3"
TEXT_DIM = "#8b949e"
SUCCESS  = "#3fb950"
WARNING  = "#d29922"
DANGER   = "#f85149"
INPUT_BG = "#0d1117"

PASS_MASK = "••••••••••••"

_INPUTS = f"""
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
QLineEdit:disabled {{ color: {TEXT_DIM}; background: #11161d; }}
"""

_DIALOG_BUTTONS = f"""
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
QDialogButtonBox QPushButton[text="Cancel"]:hover {{ background: rgba(255,255,255,0.05); }}
"""

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
QLabel#subtitle {{ color: {TEXT_DIM}; font-size: 12px; }}
QLabel#fieldLabel {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
}}
{_INPUTS}
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
QPushButton#modeBtn {{
    background: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 8px 10px;
    font-size: 12px;
    font-weight: 600;
}}
QPushButton#modeBtn:hover {{ color: {TEXT}; border-color: #484f58; }}
QPushButton#modeBtn:checked {{
    background: rgba(88,166,255,0.12);
    color: {ACCENT};
    border-color: {ACCENT};
}}
QPushButton#linkBtn {{
    background: transparent;
    color: {TEXT_DIM};
    border: none;
    font-size: 11px;
    text-align: left;
}}
QPushButton#linkBtn:hover {{ color: {ACCENT}; }}
QLabel#errorLbl {{
    color: {DANGER};
    font-size: 12px;
    padding: 6px 12px;
    background: rgba(248,81,73,0.1);
    border: 1px solid rgba(248,81,73,0.3);
    border-radius: 6px;
}}
QLabel#infoLbl {{
    color: {ACCENT};
    font-size: 12px;
    padding: 6px 12px;
    background: rgba(88,166,255,0.08);
    border: 1px solid rgba(88,166,255,0.25);
    border-radius: 6px;
}}
QLabel#hint {{ color: {TEXT_DIM}; font-size: 10px; }}
"""

DIALOG_STYLE = f"""
QDialog {{
    background: {PANEL_BG};
    color: {TEXT};
    font-family: 'Segoe UI', sans-serif;
}}
QLabel {{ color: {TEXT_DIM}; font-size: 11px; font-weight: 600; }}
QLabel#info {{
    color: {TEXT};
    font-size: 12px;
    font-weight: 400;
    padding: 4px 0;
}}
QLabel#error {{ color: {DANGER}; font-size: 11px; font-weight: 400; }}
QLabel#ok {{ color: {SUCCESS}; font-size: 11px; font-weight: 400; }}
{_INPUTS}
QPushButton#rowBtn {{
    background: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 12px;
}}
QPushButton#rowBtn:hover {{ color: {ACCENT}; border-color: {ACCENT}; }}
QPushButton#rowDangerBtn {{
    background: transparent;
    color: {DANGER};
    border: 1px solid rgba(248,81,73,0.4);
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 12px;
}}
QPushButton#rowDangerBtn:hover {{ background: rgba(248,81,73,0.1); }}
QFrame#card {{
    background: {DARK_BG};
    border: 1px solid {BORDER};
    border-radius: 10px;
}}
{_DIALOG_BUTTONS}
"""

VAULT_STYLE = f"""
QWidget {{
    background: {DARK_BG};
    color: {TEXT};
    font-family: 'Segoe UI', sans-serif;
}}
QLabel#header {{ font-size: 20px; font-weight: 700; color: {TEXT}; }}
QLabel#userInfo {{ font-size: 12px; color: {TEXT_DIM}; }}
QTableWidget {{
    background: {PANEL_BG};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 10px;
    outline: none;
    font-size: 13px;
    color: {TEXT};
}}
QTableWidget::item {{ padding: 6px 12px; border: none; }}
QTableWidget::item:selected {{ background: rgba(88,166,255,0.15); color: {TEXT}; }}
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
QLineEdit:focus {{ border: 1px solid {ACCENT}; }}
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
QPushButton#dangerBtn:hover {{ background: rgba(248,81,73,0.1); }}
QPushButton#logoutBtn, QPushButton#toolBtn {{
    background: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-radius: 7px;
    padding: 7px 16px;
    font-size: 12px;
}}
QPushButton#logoutBtn:hover {{ color: {DANGER}; border-color: {DANGER}; }}
QPushButton#toolBtn:hover {{ color: {ACCENT}; border-color: {ACCENT}; }}
QPushButton#pinBtn {{
    background: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-radius: 7px;
    padding: 7px 14px;
    font-size: 12px;
}}
QPushButton#pinBtn:hover {{ color: {ACCENT}; border-color: {ACCENT}; }}
QPushButton#pinBtn:checked {{
    background: rgba(88,166,255,0.12);
    color: {ACCENT};
    border-color: {ACCENT};
}}
QScrollBar:vertical {{ background: {DARK_BG}; width: 8px; border-radius: 4px; }}
QScrollBar::handle:vertical {{
    background: #30363d;
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
"""
