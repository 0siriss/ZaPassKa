"""
settings.py — user preferences that are not secrets.

Stored by Qt in the platform's own place: the registry on Windows, an ini
file under ~/.config elsewhere. Nothing sensitive goes here, only the AD
server address and window preferences.
"""
from PyQt6.QtCore import QSettings

ORG_NAME = "ZaPassKa"
APP_NAME = "ZaPassKa"

KEY_AD_SERVER   = "ad_server"
KEY_AUTH_MODE   = "auth_mode"
KEY_STAY_ON_TOP = "stay_on_top"


def app_settings() -> QSettings:
    return QSettings(ORG_NAME, APP_NAME)


def stay_on_top() -> bool:
    return app_settings().value(KEY_STAY_ON_TOP, True, type=bool)


def set_stay_on_top(value: bool):
    store = app_settings()
    store.setValue(KEY_STAY_ON_TOP, value)
    store.sync()
