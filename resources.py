"""
resources.py — locating files that ship next to the code.

PyInstaller unpacks bundled data into a temporary directory and points
sys._MEIPASS at it. Running from a checkout there is no such directory and
the files sit beside this module.
"""
import sys
from pathlib import Path

# PNG first: Linux panels and desktop entries handle it best, and Windows
# takes its executable icon from the .exe resource anyway.
ICON_NAMES = ("icon.png", "icon.ico")


def resource_path(name: str) -> Path:
    base = getattr(sys, "_MEIPASS", None)
    return Path(base if base else Path(__file__).resolve().parent) / name


def app_icon():
    """
    The application icon, or an empty one when the file is missing.

    Windows executables carry the icon as a resource, but an ELF binary has
    nowhere to put one, so on Linux this is the only thing that gives the
    window and the taskbar an icon at all.
    """
    from PyQt6.QtGui import QIcon

    icon = QIcon()
    for name in ICON_NAMES:
        path = resource_path(name)
        if path.exists():
            icon.addFile(str(path))
    return icon
