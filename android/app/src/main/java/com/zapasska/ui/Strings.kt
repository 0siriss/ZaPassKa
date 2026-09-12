package com.zapasska.ui

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * Interface language, the same scheme the desktop client uses: the English
 * text is the lookup key, so anything untranslated still reads as English
 * rather than as a missing placeholder.
 */
object Strings {

    const val EN = "en"
    const val RU = "ru"

    private const val PREFS = "ui"
    private const val KEY = "language"

    /** Compose observes this, so switching redraws every screen at once. */
    var language by mutableStateOf(EN)
        private set

    fun load(context: Context) {
        language = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, EN) ?: EN
    }

    fun toggle(context: Context) {
        language = if (language == RU) EN else RU
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY, language).apply()
    }

    /** The language the button switches to. */
    fun other(): String = if (language == RU) "EN" else "RU"

    fun tr(text: String): String =
        if (language == RU) ru[text] ?: text else text

    fun tr(text: String, vararg args: Any): String = tr(text).format(*args)

    private val ru = mapOf(
        // Login
        "Password Vault" to "Хранилище паролей",
        "AES-256-GCM encrypted" to "Шифрование AES-256-GCM",
        "Master password" to "Мастер-пароль",
        "New master password" to "Новый мастер-пароль",
        "Repeat password" to "Повторите пароль",
        "Unlock" to "Открыть",
        "Create vault" to "Создать хранилище",
        "I already have a vault" to "У меня уже есть хранилище",
        "Create a new vault" to "Создать новое хранилище",
        "A forgotten master password cannot be recovered: it is never stored, "
            + "it only unwraps the vault key." to
            "Забытый мастер-пароль восстановить нельзя: он нигде не хранится и "
            + "нужен только для разворачивания ключа.",
        "Enter your master password." to "Введите мастер-пароль.",
        "Wrong master password." to "Неверный мастер-пароль.",
        "No vault on this phone yet. Create one, or connect Google Drive to "
            + "download it." to
            "На этом телефоне ещё нет хранилища. Создайте его или подключите "
            + "Google Диск, чтобы скачать.",
        "At least %d characters." to "Минимум %d символов.",
        "The passwords do not match." to "Пароли не совпадают.",
        "Opening…" to "Открываю…",
        "Creating the vault…" to "Создаю хранилище…",
        "Connecting Drive…" to "Подключаю Диск…",
        "Downloading vaults…" to "Скачиваю хранилища…",
        "This build has no Google client inside." to
            "В эту сборку не встроен клиент Google.",

        // Drive
        "Connect Google Drive" to "Подключить Google Диск",
        "Drive connected" to "Диск подключён",
        "Drive not connected" to "Диск не подключён",
        "Downloaded %d vault(s), %d entries" to "Скачано хранилищ: %d, записей: %d",
        "Syncing…" to "Синхронизация…",
        "Up to date" to "Всё актуально",
        "Backed up to Drive" to "Выгружено на Диск",
        "Pulled %d entries" to "Получено записей: %d",
        "Changes pushed" to "Изменения выгружены",
        "Drive unavailable, working offline" to "Диск недоступен, работаю офлайн",
        "Sync" to "Синхронизировать",

        // Vault
        "Vault" to "Хранилище",
        "Search" to "Поиск",
        "Lock" to "Запереть",
        "Nothing here yet. Add the first entry with the button below." to
            "Пока пусто. Добавьте первую запись кнопкой ниже.",
        "Nothing found" to "Ничего не найдено",
        "%d entries" to "Записей: %d",
        "Show" to "Показать",
        "Hide" to "Скрыть",
        "Copy" to "Копировать",
        "Edit" to "Изменить",
        "Delete" to "Удалить",
        "Add" to "Добавить",
        "Password copied" to "Пароль скопирован",
        "New entry" to "Новая запись",
        "Edit entry" to "Изменить запись",
        "Service" to "Сервис",
        "Login" to "Логин",
        "Password" to "Пароль",
        "Generate" to "Сгенерировать",
        "Save" to "Сохранить",
        "Cancel" to "Отмена",
        "Delete entry “%s”? This cannot be undone." to
            "Удалить запись «%s»? Это необратимо.",
        "Switch language" to "Сменить язык",
    )
}
