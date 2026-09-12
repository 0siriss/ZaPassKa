# 🔐 AD Password Manager

Менеджер паролей с аутентификацией через Active Directory.

## Стек
- **UI**: PyQt6
- **БД**: SQLite (встроенная, файл `passmanager.db`)
- **Шифрование**: AES-256-GCM (AEAD) + ключ через **scrypt** из AD-кредов
- **Аутентификация**: LDAP NTLM через `ldap3`

---

## Установка

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
PyQt6>=6.4.0
ldap3>=2.9.1
cryptography>=41.0.0
```

---

## Запуск

```bash
python main.py
```

---

## Архитектура

```
main.py           — точка входа, запуск QApplication
login_window.py   — окно входа (AD server, домен, логин, пароль, индикатор DC)
vault_window.py   — главное окно хранилища паролей
database.py       — SQLite: таблицы settings + passwords
crypto.py         — derive_key (scrypt) + encrypt/decrypt (AES-256-GCM)
ad_auth.py        — проверка доступности DC + NTLM-аутентификация
```

---

## Как работает шифрование

```
AD login + AD password
        │
        ▼
    scrypt KDF
    (N=2^17, r=8, p=1)       ← ~1 сек, 128 МБ памяти
        │
        ▼
   256-bit key
        │
        ├──► encrypt(service)  → AES-256-GCM + random nonce
        ├──► encrypt(login)    → AES-256-GCM + random nonce
        └──► encrypt(password) → AES-256-GCM + random nonce
```

- Каждое поле шифруется **отдельно** своим random nonce (12 байт)
- GCM обеспечивает **аутентификацию** — при неверном ключе сразу `InvalidTag`
- Пароль AD **нигде не хранится**; только производный ключ живёт в памяти
- При выходе ключ уничтожается

---

## Схема БД

```sql
-- Настройки (без шифрования)
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Пароли (всё зашифровано)
CREATE TABLE passwords (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service    BLOB,   -- зашифровано
    login      BLOB,   -- зашифровано
    password   BLOB,   -- зашифровано
    nonce_s    BLOB,   -- nonce для service
    nonce_l    BLOB,   -- nonce для login
    nonce_p    BLOB,   -- nonce для password
    created_at TEXT,
    updated_at TEXT
);
```

---

## Окно входа

| Элемент | Описание |
|---|---|
| AD Server | URL вида `ldap://dc01.company.local` — сохраняется в БД |
| Domain | NetBIOS-имя домена, напр. `COMPANY` |
| Username | Авто-заполняется из `%USERNAME%` |
| Password | Не хранится нигде |
| **●** зелёная точка | DC доступен (TCP-проба порта 389/636) |
| **●** красная точка | DC недоступен |

---

## Главное окно

- Таблица: Сервис / Логин / Пароль (скрыт `••••••••`)
- **👁 Show** — показать/скрыть пароль в строке
- **📋 Copy** — скопировать пароль в буфер (очищается через 3 сек в статусе)
- **🗑** — удалить запись с подтверждением
- **＋ Add Entry** — добавить новую запись
- **Поиск** — фильтр по сервису и логину в реальном времени
- **Sign out** — выйти, вернуться к окну входа (ключ уничтожается)

---

## Безопасность

- ✅ Пароль AD никогда не записывается на диск
- ✅ Все три поля каждой записи зашифрованы независимо
- ✅ AES-256-GCM — аутентифицированное шифрование (tamper-evident)
- ✅ scrypt с высокими параметрами защищает от брутфорса мастер-ключа
- ✅ Неверный ключ детектируется мгновенно (`InvalidTag`)
- ⚠️  Файл `passmanager.db` следует хранить в защищённом месте
- ⚠️  Для продакшена — добавить per-user соль из отдельного защищённого хранилища
