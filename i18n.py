"""
i18n.py — interface language.

Source strings are English and double as the lookup key, so an untranslated
string falls back to English instead of showing a placeholder. The chosen
language lives with the other preferences and survives restarts.
"""
import settings

EN = "en"
RU = "ru"
LANGUAGES = (EN, RU)

LANGUAGE_NAMES = {EN: "EN", RU: "RU"}

_current = EN

_RU = {
    # ── Login window ──────────────────────────────────────────────
    "ZaPassKa — Login": "ZaPassKa — вход",
    "Password Vault": "Хранилище паролей",
    "AES-256-GCM encrypted password manager": "Менеджер паролей с шифрованием AES-256-GCM",
    "UNLOCK WITH": "СПОСОБ ВХОДА",
    "🏢  Active Directory": "🏢  Домен",
    "🔑  Master password": "🔑  Мастер-пароль",
    "AD SERVER (LDAP URL)": "СЕРВЕР AD (LDAP)",
    "USERNAME": "ЛОГИН",
    "PASSWORD": "ПАРОЛЬ",
    "MASTER PASSWORD": "МАСТЕР-ПАРОЛЬ",
    "REPEAT PASSWORD": "ПОВТОРИТЕ ПАРОЛЬ",
    "PREVIOUS AD PASSWORD": "ПРЕДЫДУЩИЙ ПАРОЛЬ ДОМЕНА",
    "Sign In": "Войти",
    "Unlock": "Открыть",
    "Create a vault with a master password": "Создать хранилище с мастер-паролем",
    "☁  Google Drive backup…": "☁  Резервная копия на Google Диске…",
    "DC connection status": "Состояние связи с контроллером домена",
    "No server configured": "Сервер не указан",
    "Domain controller reachable ✓": "Контроллер домена доступен ✓",
    "Domain controller unreachable ✗": "Контроллер домена недоступен ✗",
    "Switch interface language": "Сменить язык интерфейса",

    # Login statuses
    "Authenticating…": "Проверка в домене…",
    "Opening vault…": "Открываю хранилище…",
    "Creating vault…": "Создаю хранилище…",
    "Unlocking…": "Открываю…",
    "Re-wrapping vault key…": "Перезаворачиваю ключ…",
    "Enter your password.": "Введите пароль.",
    "Please fill in all fields.": "Заполните все поля.",
    "Authentication failed. Check credentials or server address.":
        "Вход не выполнен. Проверьте учётные данные и адрес сервера.",
    "Wrong master password.": "Неверный мастер-пароль.",
    "No vault is protected by this master password.":
        "Этим мастер-паролем не открывается ни одно хранилище.",
    "No master password on this machine yet. Sign in with Active Directory "
    "and enable one under Security, or create a new empty vault below.":
        "На этом компьютере мастер-пароль ещё не задан. Войдите через домен и "
        "переключитесь на него в разделе «Безопасность», либо создайте новое "
        "пустое хранилище ниже.",
    "Vault not opened. It is still encrypted with your previous AD password, "
    "and only that password can unwrap it.":
        "Хранилище не открыто. Оно зашифровано прежним паролем домена, и "
        "развернуть ключ можно только им.",
    "Enter your previous password.": "Введите предыдущий пароль.",
    "That is not the previous password. Try again.":
        "Это не предыдущий пароль. Попробуйте ещё раз.",
    "No vault opened. Unlock your existing vault and add this account under "
    "Security to sign in with Active Directory next time.":
        "Хранилище не открыто. Откройте существующее хранилище и переключите "
        "его на эту учётную запись в разделе «Безопасность».",

    # Dialogs
    "Set Master Password": "Задать мастер-пароль",
    "Change Master Password": "Смена мастер-пароля",
    "Change master password…": "Сменить мастер-пароль…",
    "CURRENT MASTER PASSWORD": "ТЕКУЩИЙ МАСТЕР-ПАРОЛЬ",
    "NEW MASTER PASSWORD": "НОВЫЙ МАСТЕР-ПАРОЛЬ",
    "Enter your current master password.": "Введите текущий мастер-пароль.",
    "That is not your current master password.":
        "Это не текущий мастер-пароль.",
    "Checking the current password…": "Проверяю текущий пароль…",
    "The master password has been changed.": "Мастер-пароль изменён.",
    "The vault key is re-wrapped with the new password. Your entries are not "
    "re-encrypted and stay exactly as they are.":
        "Ключ хранилища заворачивается в новый пароль. Записи не "
        "перешифровываются и остаются ровно такими же.",
    "Create Vault": "Создать хранилище",
    "AD Password Changed": "Пароль домена изменился",
    "New Vault": "Новое хранилище",
    "There is no way to recover a forgotten master password — it is never "
    "stored, only used to unwrap the vault key.":
        "Забытый мастер-пароль восстановить нельзя: он нигде не хранится и "
        "нужен только для разворачивания ключа хранилища.",
    "Use at least {count} characters.": "Минимум {count} символов.",
    "The two passwords do not match.": "Пароли не совпадают.",
    "Your Active Directory password has changed since this vault was last "
    "opened.\n\nEnter the previous password once — the vault key is simply "
    "re-wrapped with the new one. Your entries are not re-encrypted and "
    "cannot be lost in the process.":
        "Пароль домена изменился с прошлого открытия хранилища.\n\nВведите "
        "предыдущий пароль один раз. Ключ хранилища просто завернётся в новый "
        "пароль, записи не перешифровываются и потеряться не могут.",
    "This creates a new, empty vault unlocked by a master password alone. To "
    "put an existing vault behind a master password instead, sign in with "
    "Active Directory and use Security in the vault window.":
        "Будет создано новое пустое хранилище, открываемое только "
        "мастер-паролем. Чтобы перевести на мастер-пароль существующее "
        "хранилище, войдите через домен и откройте раздел «Безопасность».",
    "No vault on this machine is linked to <b>{user}</b>.<br><br>Create a "
    "new, empty one?<br><br>If your passwords are in an existing vault, "
    "cancel, unlock it the way you usually do, and add this account under "
    "Security.":
        "Ни одно хранилище на этом компьютере не связано с <b>{user}</b>."
        "<br><br>Создать новое пустое?<br><br>Если пароли лежат в "
        "существующем хранилище, отмените, откройте его привычным способом и "
        "переключите на эту учётную запись в разделе «Безопасность».",

    # ── Google Drive ──────────────────────────────────────────────
    "Google Drive Backup": "Резервная копия на Google Диске",
    "Google OAuth Client": "Клиент Google OAuth",
    "CLIENT ID": "CLIENT ID",
    "CLIENT SECRET": "CLIENT SECRET",
    "Vaults are backed up to a private folder of your own Google Drive, "
    "visible to this app alone. Everything stored there is already "
    "encrypted — the key stays on your machines.":
        "Хранилища копируются в приватную папку вашего Google Диска, видимую "
        "только этому приложению. Всё, что туда попадает, уже зашифровано, "
        "ключ остаётся на ваших компьютерах.",
    "This build has no Google client baked in, so ZaPassKa needs one of "
    "yours.\n\nIn Google Cloud Console: enable the Drive API, then create an "
    "OAuth client of type “Desktop app” and paste its ID and secret here. "
    "They are stored locally and identify the application only — never your "
    "account.":
        "В эту сборку клиент Google не вшит, поэтому нужен ваш собственный."
        "\n\nВ Google Cloud Console включите Drive API, создайте OAuth-клиент "
        "типа «Desktop app» и вставьте его ID и secret сюда. Они хранятся "
        "локально и опознают приложение, а не вашу учётную запись.",
    "Connect Google Drive": "Подключить Google Диск",
    "Disconnect": "Отключить",
    "Download vaults now": "Скачать хранилища",
    "Configure OAuth client…": "Настроить OAuth-клиент…",
    "Connected.": "Подключено.",
    "Connected as {email}.": "Подключено как {email}.",
    "Not connected — backups are disabled.":
        "Не подключено, резервное копирование выключено.",
    "Waiting for the browser… finish signing in to Google.":
        "Жду браузер, завершите вход в Google.",
    "Downloading vaults from Google Drive…": "Скачиваю хранилища с Google Диска…",
    "{vaults} vault(s) downloaded, {entries} entries applied. Sign in as usual.":
        "Скачано хранилищ: {vaults}, применено записей: {entries}. "
        "Входите обычным способом.",
    "Nothing backed up on this account yet.":
        "На этом аккаунте пока нет резервных копий.",
    "Drive: off": "Диск: выкл",
    "Drive: on": "Диск: вкл",
    "Drive: offline": "Диск: нет сети",
    "Drive: syncing…": "Диск: синхронизация…",
    "Drive: {count} vault(s)": "Диск: хранилищ {count}",

    # ── Vault window ──────────────────────────────────────────────
    "ZaPassKa (password manager)": "ZaPassKa (менеджер паролей)",
    "Unlocked with  {name}": "Вход: {name}",
    "master password": "мастер-пароль",
    "🔍  Search…": "🔍  Поиск…",
    "＋  Add Entry": "＋  Добавить",
    "☁ Sync": "☁ Синхрон.",
    "🛡 Security": "🛡 Защита",
    "📌 On Top": "📌 Поверх",
    "📌 Off": "📌 Обычно",
    "Sign out": "Выйти",
    "Service": "Сервис",
    "Login": "Логин",
    "Password": "Пароль",
    "Actions": "Действия",
    "Back up to Google Drive and pull other machines' changes":
        "Выгрузить на Google Диск и забрать изменения с других компьютеров",
    "Master password and Active Directory unlock":
        "Мастер-пароль и вход через домен",
    "Toggle always-on-top, remembered between sessions":
        "Держать окно поверх остальных, выбор запоминается",
    "👁 Show": "👁 Показать",
    "🙈 Hide": "🙈 Скрыть",
    "📋 Copy": "📋 Копировать",
    "✎ Edit": "✎ Изменить",
    "Toggle password visibility": "Показать или скрыть пароль",
    "Copy password (cleared after {seconds}s)":
        "Скопировать пароль, буфер очистится через {seconds} с",
    "Edit this entry": "Изменить запись",
    "Delete entry": "Удалить запись",
    "✓ Copied — clipboard clears in {seconds}s":
        "✓ Скопировано, буфер очистится через {seconds} с",
    "{count} entries · AES-256-GCM encrypted":
        "Записей: {count} · шифрование AES-256-GCM",
    "Showing {shown} of {total} entries": "Показано {shown} из {total}",
    "Decryption Warning": "Ошибка расшифровки",
    "{count} entr(ies) could not be decrypted. They were written with a "
    "different key — most likely a damaged sync.":
        "Не удалось расшифровать записей: {count}. Они записаны другим ключом, "
        "скорее всего из-за повреждённой синхронизации.",
    "Validation": "Проверка",
    "All fields are required.": "Заполните все поля.",
    "Delete Entry": "Удаление записи",
    "Delete entry for <b>{service}</b>?<br>This cannot be undone.":
        "Удалить запись «<b>{service}</b>»?<br>Отменить это будет нельзя.",
    "☁ Drive: not connected": "☁ Диск: не подключён",
    "☁ Syncing…": "☁ Синхронизация…",
    "☁ Drive unavailable — working offline": "☁ Диск недоступен, работаю офлайн",

    # Entry dialog
    "Add Entry": "Добавить запись",
    "Add New Entry": "Новая запись",
    "Edit Entry": "Изменить запись",
    "SERVICE / WEBSITE": "СЕРВИС ИЛИ САЙТ",
    "LOGIN / EMAIL": "ЛОГИН ИЛИ ПОЧТА",
    "e.g. GitHub": "например GitHub",
    "e.g. user@company.com": "например user@company.com",
    "Show / hide password": "Показать или скрыть пароль",
    "Generate secure 16-char password": "Сгенерировать пароль из 16 символов",

    # Security dialog
    "Vault Security": "Безопасность хранилища",
    "This vault has exactly one way in. Switching replaces it; your entries "
    "stay as they are.":
        "В хранилище ровно один способ входа. Переключение заменяет его, "
        "записи остаются на месте.",
    "Opens the vault without the domain": "Открывает хранилище без домена",
    "Opens with the password of {who}": "Открывается паролем: {who}",
    "domain account": "учётная запись домена",
    " · set {date}": " · задан {date}",
    "Switch to Active Directory…": "Переключить на домен…",
    "Switch to a master password…": "Переключить на мастер-пароль…",
    "After switching, the domain password is the only way in. If it changes "
    "you will be asked for the previous one once; forget it and the vault "
    "cannot be opened.":
        "После переключения пароль домена станет единственным входом. При его "
        "смене приложение один раз спросит предыдущий пароль; если он забыт, "
        "хранилище открыть не получится.",
    "After switching, the domain is no longer involved. A forgotten master "
    "password cannot be recovered.":
        "После переключения домен больше не участвует. Забытый мастер-пароль "
        "восстановить нельзя.",
    "Switch to Master Password": "Переход на мастер-пароль",
    "From now on this password alone opens the vault, and the domain account "
    "stops working for it. The entries you see now stay exactly as they are.":
        "Дальше хранилище открывает только этот пароль, учётная запись домена "
        "для него перестаёт работать. Записи остаются ровно такими же.",
    "Rewrapping the vault key…": "Перезаворачиваю ключ хранилища…",
    "Checking the domain…": "Проверяю в домене…",
    "The master password is now the only way into this vault.":
        "Теперь в хранилище пускает только мастер-пароль.",
    "{user} is now the only way into this vault.":
        "Теперь в хранилище пускает только учётная запись {user}.",

    # AD unlock dialog
    "Add Active Directory Unlock": "Вход через домен",
    "The domain password is checked against the DC first, then used to wrap "
    "this vault's key. Your entries stay as they are.":
        "Пароль сначала проверяется на контроллере домена, затем им "
        "заворачивается ключ хранилища. Записи остаются на месте.",
    "Fill in every field.": "Заполните все поля.",
    "The domain rejected those credentials.":
        "Домен отклонил эти учётные данные.",

    # Sync outcomes
    "Vault backed up to Google Drive": "Хранилище выгружено на Google Диск",
    "Synced · {count} entries pulled, changes pushed":
        "Синхронизировано · получено записей: {count}, изменения выгружены",
    "Synced · {count} entries pulled": "Синхронизировано · получено записей: {count}",
    "Synced · changes pushed": "Синхронизировано · изменения выгружены",
    "Synced · already up to date": "Синхронизировано · всё актуально",
}

_TRANSLATIONS = {EN: {}, RU: _RU}


def init():
    """Load the stored language. Call once, after QApplication exists."""
    global _current
    stored = settings.language()
    _current = stored if stored in LANGUAGES else EN


def current() -> str:
    return _current


def set_language(language: str):
    global _current
    if language not in LANGUAGES:
        return
    _current = language
    settings.set_language(language)


def other_language() -> str:
    """The language the toggle button switches to."""
    return RU if _current == EN else EN


def tr(text: str, **fmt) -> str:
    """Translate a source string, then fill in any placeholders."""
    translated = _TRANSLATIONS.get(_current, {}).get(text, text)
    return translated.format(**fmt) if fmt else translated
