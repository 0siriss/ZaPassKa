"""
AD Password Manager
===================
PyQt6 + SQLite + AES-256-GCM + scrypt
"""

import sys
from PyQt6.QtWidgets import QApplication
from login_window import LoginWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("ZaPassKa")
    app.setStyle("Fusion")
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
