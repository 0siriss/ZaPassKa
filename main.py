"""
ZaPassKa — password manager
===========================
PyQt6 + SQLite + AES-256-GCM + scrypt
"""

import sys

from PyQt6.QtWidgets import QApplication

import resources
from login_window import LoginWindow

APP_NAME = "ZaPassKa"


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    # Lets Wayland and GNOME tie the window to the installed .desktop entry.
    app.setDesktopFileName(APP_NAME)
    app.setWindowIcon(resources.app_icon())
    app.setStyle("Fusion")

    window = LoginWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
