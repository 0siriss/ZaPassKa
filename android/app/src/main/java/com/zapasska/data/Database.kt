package com.zapasska.data

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

/**
 * The same tables the desktop client keeps, so the sync rules can be applied
 * against identical data. See docs/FORMAT.md.
 */
class Database(context: Context) : SQLiteOpenHelper(context, NAME, null, VERSION) {

    companion object {
        private const val NAME = "tp.sec"
        private const val VERSION = 1

        /** docs/FORMAT.md section 5: strict UTC, compared as text. */
        fun now(): String {
            val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS", Locale.US)
            format.timeZone = TimeZone.getTimeZone("UTC")
            return format.format(java.util.Date()) + "000Z"
        }

        fun newUuid(): String = UUID.randomUUID().toString()

        /** uuid5 of the surviving vault and the source entry, as the spec requires. */
        fun derivedUuid(vaultId: String, sourceUuid: String): String =
            uuidV5(UUID.fromString(vaultId), sourceUuid)

        private fun uuidV5(namespace: UUID, name: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-1")
            digest.update(uuidToBytes(namespace))
            digest.update(name.toByteArray(Charsets.UTF_8))
            val hash = digest.digest().copyOf(16)
            hash[6] = ((hash[6].toInt() and 0x0f) or 0x50).toByte()
            hash[8] = ((hash[8].toInt() and 0x3f) or 0x80).toByte()
            return bytesToUuid(hash).toString()
        }

        private fun uuidToBytes(uuid: UUID): ByteArray {
            val bytes = ByteArray(16)
            var most = uuid.mostSignificantBits
            var least = uuid.leastSignificantBits
            for (index in 7 downTo 0) {
                bytes[index] = (most and 0xff).toByte(); most = most ushr 8
                bytes[index + 8] = (least and 0xff).toByte(); least = least ushr 8
            }
            return bytes
        }

        private fun bytesToUuid(bytes: ByteArray): UUID {
            var most = 0L
            var least = 0L
            for (index in 0..7) most = (most shl 8) or (bytes[index].toLong() and 0xff)
            for (index in 8..15) least = (least shl 8) or (bytes[index].toLong() and 0xff)
            return UUID(most, least)
        }
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS vaults (
                id         TEXT PRIMARY KEY,
                created_at TEXT NOT NULL)
        """.trimIndent())
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS unlock_methods (
                vault_id    TEXT NOT NULL,
                method      TEXT NOT NULL,
                identity    TEXT NOT NULL,
                salt        TEXT NOT NULL,
                wrapped_dek BLOB NOT NULL,
                updated_at  TEXT NOT NULL,
                deleted     INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (vault_id, method, identity))
        """.trimIndent())
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS entries (
                uuid       TEXT PRIMARY KEY,
                vault_id   TEXT NOT NULL,
                service    BLOB NOT NULL,
                login      BLOB NOT NULL,
                password   BLOB NOT NULL,
                updated_at TEXT NOT NULL,
                deleted    INTEGER NOT NULL DEFAULT 0)
        """.trimIndent())
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_entries_vault ON entries(vault_id, deleted)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    // ── Vaults ────────────────────────────────────────────────────

    fun createVault(): String {
        val id = newUuid()
        ensureVault(id)
        return id
    }

    fun ensureVault(vaultId: String) {
        writableDatabase.execSQL(
            "INSERT INTO vaults (id, created_at) VALUES (?,?) ON CONFLICT(id) DO NOTHING",
            arrayOf(vaultId, now()))
    }

    // ── Unlock methods ────────────────────────────────────────────

    fun liveMethods(method: String? = null): List<UnlockMethod> {
        val sql = StringBuilder("SELECT * FROM unlock_methods WHERE deleted = 0")
        val args = mutableListOf<String>()
        if (method != null) {
            sql.append(" AND method = ?")
            args.add(method)
        }
        sql.append(" ORDER BY updated_at DESC")
        return readableDatabase.rawQuery(sql.toString(), args.toTypedArray())
            .use { it.readMethods() }
    }

    fun methodsOf(vaultId: String, includeDeleted: Boolean = false): List<UnlockMethod> {
        val sql = "SELECT * FROM unlock_methods WHERE vault_id = ?" +
            (if (includeDeleted) "" else " AND deleted = 0")
        return readableDatabase.rawQuery(sql, arrayOf(vaultId)).use { it.readMethods() }
    }

    fun saveMethod(vaultId: String, method: String, identity: String,
                   salt: String, wrapped: ByteArray, updatedAt: String = now(),
                   deleted: Boolean = false) {
        val values = ContentValues().apply {
            put("vault_id", vaultId)
            put("method", method)
            put("identity", identity)
            put("salt", salt)
            put("wrapped_dek", wrapped)
            put("updated_at", updatedAt)
            put("deleted", if (deleted) 1 else 0)
        }
        writableDatabase.insertWithOnConflict(
            "unlock_methods", null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    /** Makes this the vault's only way in, as docs/FORMAT.md section 2 requires. */
    fun replaceMethod(vaultId: String, method: String, identity: String,
                      salt: String, wrapped: ByteArray) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            saveMethod(vaultId, method, identity, salt, wrapped)
            db.execSQL(
                """UPDATE unlock_methods
                      SET deleted = 1, updated_at = ?, salt = '', wrapped_dek = X''
                    WHERE vault_id = ? AND deleted = 0
                      AND NOT (method = ? AND identity = ?)""",
                arrayOf(now(), vaultId, method, identity))
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun retireMethod(vaultId: String, method: String, identity: String) {
        writableDatabase.execSQL(
            """UPDATE unlock_methods
                  SET deleted = 1, updated_at = ?, salt = '', wrapped_dek = X''
                WHERE vault_id = ? AND method = ? AND identity = ?""",
            arrayOf(now(), vaultId, method, identity))
    }

    /** Keeps only the newest method of a vault; see docs/FORMAT.md section 6. */
    fun enforceSingleMethod(vaultId: String): Int {
        val live = readableDatabase.rawQuery(
            """SELECT method, identity FROM unlock_methods
                WHERE vault_id = ? AND deleted = 0
                ORDER BY updated_at DESC, method, identity""",
            arrayOf(vaultId)).use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(cursor.getString(0) to cursor.getString(1))
            }
        }
        if (live.size <= 1) return 0

        val (method, identity) = live.first()
        writableDatabase.execSQL(
            """UPDATE unlock_methods
                  SET deleted = 1, updated_at = ?, salt = '', wrapped_dek = X''
                WHERE vault_id = ? AND deleted = 0
                  AND NOT (method = ? AND identity = ?)""",
            arrayOf(now(), vaultId, method, identity))
        return live.size - 1
    }

    // ── Entries ───────────────────────────────────────────────────

    fun entriesOf(vaultId: String, includeDeleted: Boolean = false): List<StoredEntry> {
        val sql = "SELECT * FROM entries WHERE vault_id = ?" +
            (if (includeDeleted) "" else " AND deleted = 0") + " ORDER BY updated_at"
        return readableDatabase.rawQuery(sql, arrayOf(vaultId)).use { it.readEntries() }
    }

    fun putEntry(vaultId: String, uuid: String, service: ByteArray,
                 login: ByteArray, password: ByteArray,
                 updatedAt: String = now(), deleted: Boolean = false) {
        val values = ContentValues().apply {
            put("uuid", uuid)
            put("vault_id", vaultId)
            put("service", service)
            put("login", login)
            put("password", password)
            put("updated_at", updatedAt)
            put("deleted", if (deleted) 1 else 0)
        }
        writableDatabase.insertWithOnConflict(
            "entries", null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    /** Soft delete, so the removal reaches the other machines through sync. */
    fun deleteEntry(uuid: String) {
        writableDatabase.execSQL(
            """UPDATE entries
                  SET deleted = 1, updated_at = ?, service = X'', login = X'', password = X''
                WHERE uuid = ?""",
            arrayOf(now(), uuid))
    }

    fun purgeTombstones(olderThan: String) {
        writableDatabase.execSQL(
            "DELETE FROM entries WHERE deleted = 1 AND updated_at < ?", arrayOf(olderThan))
        writableDatabase.execSQL(
            "DELETE FROM unlock_methods WHERE deleted = 1 AND updated_at < ?",
            arrayOf(olderThan))
    }

    // ── Cursors ───────────────────────────────────────────────────

    private fun Cursor.readMethods(): List<UnlockMethod> = buildList {
        while (moveToNext()) {
            add(UnlockMethod(
                vaultId = getString(getColumnIndexOrThrow("vault_id")),
                method = getString(getColumnIndexOrThrow("method")),
                identity = getString(getColumnIndexOrThrow("identity")),
                salt = getString(getColumnIndexOrThrow("salt")),
                wrappedDataKey = getBlob(getColumnIndexOrThrow("wrapped_dek")),
                updatedAt = getString(getColumnIndexOrThrow("updated_at")),
                deleted = getInt(getColumnIndexOrThrow("deleted")) != 0))
        }
    }

    private fun Cursor.readEntries(): List<StoredEntry> = buildList {
        while (moveToNext()) {
            add(StoredEntry(
                uuid = getString(getColumnIndexOrThrow("uuid")),
                vaultId = getString(getColumnIndexOrThrow("vault_id")),
                service = getBlob(getColumnIndexOrThrow("service")),
                login = getBlob(getColumnIndexOrThrow("login")),
                password = getBlob(getColumnIndexOrThrow("password")),
                updatedAt = getString(getColumnIndexOrThrow("updated_at")),
                deleted = getInt(getColumnIndexOrThrow("deleted")) != 0))
        }
    }
}
