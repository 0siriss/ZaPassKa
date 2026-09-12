package com.zapasska

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import com.zapasska.core.Crypto
import com.zapasska.core.UnlockResult
import com.zapasska.core.Vault
import com.zapasska.data.Database
import com.zapasska.data.Entry
import com.zapasska.data.VaultSession
import com.zapasska.sync.Drive
import com.zapasska.sync.GoogleAuth
import com.zapasska.ui.ConfirmDialog
import com.zapasska.ui.EntryDialog
import com.zapasska.ui.LoginScreen
import com.zapasska.ui.VaultScreen
import com.zapasska.ui.ZaPassKaTheme
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val MIN_MASTER_LENGTH = 8

class MainActivity : ComponentActivity() {

    private lateinit var db: Database
    private lateinit var vault: Vault

    private var session by mutableStateOf<VaultSession?>(null)
    private var entries by mutableStateOf<List<Entry>>(emptyList())

    private var password by mutableStateOf("")
    private var confirm by mutableStateOf("")
    private var creating by mutableStateOf(false)
    private var busy by mutableStateOf<String?>(null)
    private var message by mutableStateOf<String?>(null)

    private var query by mutableStateOf("")
    private var revealed by mutableStateOf<String?>(null)
    private var syncStatus by mutableStateOf("")

    private var editing by mutableStateOf<Entry?>(null)
    private var showEditor by mutableStateOf(false)
    private var formService by mutableStateOf("")
    private var formLogin by mutableStateOf("")
    private var formPassword by mutableStateOf("")
    private var deleting by mutableStateOf<Entry?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = Database(applicationContext)
        vault = Vault(db)
        syncStatus = driveStatus()

        setContent {
            ZaPassKaTheme {
                val current = session
                if (current == null) {
                    LoginScreen(
                        password = password,
                        onPasswordChange = { password = it; message = null },
                        confirm = confirm,
                        onConfirmChange = { confirm = it },
                        creating = creating || !vault.hasMasterVault(),
                        hasVault = vault.hasMasterVault(),
                        busy = busy,
                        message = message,
                        driveConnected = GoogleAuth.isConnected(this),
                        onUnlock = ::unlock,
                        onCreate = ::createVault,
                        onToggleCreate = { creating = !creating; message = null },
                        onConnectDrive = ::connectDrive,
                    )
                } else {
                    VaultScreen(
                        entries = visibleEntries(),
                        query = query,
                        onQueryChange = { query = it },
                        revealed = revealed,
                        syncStatus = syncStatus,
                        onToggleReveal = { uuid ->
                            revealed = if (revealed == uuid) null else uuid
                        },
                        onCopy = ::copyPassword,
                        onEdit = ::openEditor,
                        onDelete = { deleting = it },
                        onAdd = { openEditor(null) },
                        onSync = ::syncNow,
                        onLock = ::lock,
                    )

                    if (showEditor) {
                        EntryDialog(
                            title = if (editing == null) "Новая запись" else "Изменить запись",
                            service = formService,
                            login = formLogin,
                            password = formPassword,
                            onServiceChange = { formService = it },
                            onLoginChange = { formLogin = it },
                            onPasswordChange = { formPassword = it },
                            onGenerate = { formPassword = generatePassword() },
                            onConfirm = ::saveEntry,
                            onDismiss = { showEditor = false },
                        )
                    }
                    deleting?.let { entry ->
                        ConfirmDialog(
                            text = "Удалить запись «${entry.service}»? Это необратимо.",
                            onConfirm = {
                                vault.deleteEntry(entry.uuid)
                                deleting = null
                                reload()
                                syncNow()
                            },
                            onDismiss = { deleting = null },
                        )
                    }
                }
            }
        }
    }

    /** The browser sends the authorization code back to this activity. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val redirect: Uri = intent.data ?: return
        if (redirect.scheme != BuildConfig.OAUTH_REDIRECT_SCHEME) return

        busy = "Подключаю Диск…"
        lifecycleScope.launch {
            val outcome = runCatching {
                withContext(Dispatchers.IO) {
                    GoogleAuth.completeAuthorization(this@MainActivity, redirect)
                    Drive.pullAll(this@MainActivity, db)
                }
            }
            busy = null
            outcome
                .onSuccess { (vaults, applied) ->
                    syncStatus = if (vaults > 0)
                        "☁ Скачано хранилищ: $vaults, записей: $applied"
                    else "☁ Диск подключён"
                    message = null
                    reload()
                }
                .onFailure { message = it.message }
        }
    }

    // ── Login ─────────────────────────────────────────────────────

    private fun unlock() {
        if (password.isEmpty()) {
            message = "Введите мастер-пароль."
            return
        }
        busy = "Открываю…"
        lifecycleScope.launch {
            val unlocked = withContext(Dispatchers.IO) { vault.unlock(password) }
            busy = null
            when (unlocked.result) {
                UnlockResult.OK -> open(unlocked.session!!)
                UnlockResult.WRONG_SECRET -> message = "Неверный мастер-пароль."
                UnlockResult.NO_VAULT ->
                    message = "На этом телефоне нет хранилища. Создайте его или " +
                        "подключите Google Диск, чтобы скачать."
            }
        }
    }

    private fun createVault() {
        if (password.length < MIN_MASTER_LENGTH) {
            message = "Минимум $MIN_MASTER_LENGTH символов."
            return
        }
        if (password != confirm) {
            message = "Пароли не совпадают."
            return
        }
        busy = "Создаю хранилище…"
        lifecycleScope.launch {
            val created = withContext(Dispatchers.IO) { vault.create(password) }
            busy = null
            creating = false
            open(created)
        }
    }

    private fun open(opened: VaultSession) {
        session = opened
        password = ""
        confirm = ""
        message = null
        reload()
        syncNow()
    }

    private fun lock() {
        session = null
        entries = emptyList()
        revealed = null
        query = ""
        syncStatus = driveStatus()
    }

    // ── Entries ───────────────────────────────────────────────────

    private fun reload() {
        session?.let { entries = vault.entries(it) }
    }

    private fun visibleEntries(): List<Entry> {
        val needle = query.trim().lowercase()
        if (needle.isEmpty()) return entries
        return entries.filter {
            it.service.lowercase().contains(needle) || it.login.lowercase().contains(needle)
        }
    }

    private fun openEditor(entry: Entry?) {
        editing = entry
        formService = entry?.service.orEmpty()
        formLogin = entry?.login.orEmpty()
        formPassword = entry?.password.orEmpty()
        showEditor = true
    }

    private fun saveEntry() {
        val current = session ?: return
        if (formService.isBlank() || formLogin.isBlank() || formPassword.isEmpty()) {
            return
        }
        val existing = editing
        if (existing == null) {
            vault.addEntry(current, formService.trim(), formLogin.trim(), formPassword)
        } else {
            vault.updateEntry(current, existing.uuid,
                              formService.trim(), formLogin.trim(), formPassword)
        }
        showEditor = false
        reload()
        syncNow()
    }

    private fun copyPassword(entry: Entry) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("password", entry.password)
        clipboard.setPrimaryClip(clip)
        syncStatus = "Пароль скопирован"
    }

    private fun generatePassword(): String {
        val lower = "abcdefghijklmnopqrstuvwxyz"
        val upper = lower.uppercase()
        val digits = "0123456789"
        val symbols = "!@#\$%^&*()-_=+[]{}|;:,.<>?"
        val random = SecureRandom()
        val alphabet = lower + upper + digits + symbols
        val mandatory = listOf(lower, upper, digits, symbols)
            .map { it[random.nextInt(it.length)] }
        val rest = (1..12).map { alphabet[random.nextInt(alphabet.length)] }
        return (mandatory + rest).shuffled(random).joinToString("")
    }

    // ── Google Drive ──────────────────────────────────────────────

    private fun driveStatus(): String =
        if (GoogleAuth.isConnected(this)) "☁ Диск подключён" else "☁ Диск не подключён"

    private fun connectDrive() {
        if (!GoogleAuth.isConfigured()) {
            message = "В эту сборку не встроен клиент Google."
            return
        }
        if (GoogleAuth.isConnected(this)) {
            busy = "Скачиваю хранилища…"
            lifecycleScope.launch {
                val outcome = runCatching {
                    withContext(Dispatchers.IO) { Drive.pullAll(this@MainActivity, db) }
                }
                busy = null
                outcome
                    .onSuccess { (vaults, applied) ->
                        syncStatus = "☁ Скачано хранилищ: $vaults, записей: $applied"
                        reload()
                    }
                    .onFailure { message = it.message }
            }
            return
        }
        runCatching { startActivity(Intent(Intent.ACTION_VIEW,
                                           GoogleAuth.authorizationUrl(this))) }
            .onFailure { message = it.message }
    }

    private fun syncNow() {
        val current = session ?: return
        if (!Drive.isConnected(this)) {
            syncStatus = "☁ Диск не подключён"
            return
        }
        syncStatus = "☁ Синхронизация…"
        lifecycleScope.launch {
            val outcome = runCatching {
                withContext(Dispatchers.IO) { Drive.syncVault(this@MainActivity, db, current.vaultId) }
            }
            outcome
                .onSuccess { result ->
                    syncStatus = when {
                        result.created -> "☁ Хранилище выгружено на Диск"
                        result.pulledEntries > 0 && result.pushed ->
                            "☁ Получено записей: ${result.pulledEntries}, изменения выгружены"
                        result.pulledEntries > 0 -> "☁ Получено записей: ${result.pulledEntries}"
                        result.pushed -> "☁ Изменения выгружены"
                        else -> "☁ Всё актуально"
                    }
                    if (result.pulledEntries > 0) reload()
                }
                .onFailure { syncStatus = "☁ Диск недоступен, работаю офлайн" }
        }
    }
}
