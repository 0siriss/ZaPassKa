package com.zapasska.sync

import android.util.Base64
import com.zapasska.data.Database
import com.zapasska.data.StoredEntry
import com.zapasska.data.UnlockMethod
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

/**
 * Reading and writing the snapshot document of docs/FORMAT.md section 4, and
 * merging one into the local database by the rules of section 6.
 */
object Snapshot {

    const val FORMAT = 1
    private const val TOMBSTONE_TTL_DAYS = 90L

    class UnsupportedSnapshot(message: String) : Exception(message)

    fun fileName(vaultId: String) = "zapasska-$vaultId.json"

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(text: String): ByteArray = Base64.decode(text, Base64.DEFAULT)

    // ── Build ─────────────────────────────────────────────────────

    fun build(db: Database, vaultId: String): JSONObject {
        val methods = JSONArray()
        for (method in db.methodsOf(vaultId, includeDeleted = true)) {
            methods.put(JSONObject().apply {
                put("method", method.method)
                put("identity", method.identity)
                put("salt", method.salt)
                put("wrapped_dek", encode(method.wrappedDataKey))
                put("updated_at", method.updatedAt)
                put("deleted", if (method.deleted) 1 else 0)
            })
        }

        val entries = JSONArray()
        for (entry in db.entriesOf(vaultId, includeDeleted = true)) {
            entries.put(JSONObject().apply {
                put("uuid", entry.uuid)
                put("service", encode(entry.service))
                put("login", encode(entry.login))
                put("password", encode(entry.password))
                put("updated_at", entry.updatedAt)
                put("deleted", if (entry.deleted) 1 else 0)
            })
        }

        return JSONObject().apply {
            put("format", FORMAT)
            put("vault_id", vaultId)
            put("updated_at", Database.now())
            put("unlock_methods", methods)
            put("entries", entries)
        }
    }

    fun parse(bytes: ByteArray): JSONObject {
        val document = JSONObject(String(bytes, Charsets.UTF_8))
        if (!document.has("vault_id")) throw UnsupportedSnapshot("not a ZaPassKa snapshot")
        val format = document.optInt("format", 0)
        if (format > FORMAT) {
            throw UnsupportedSnapshot(
                "snapshot format $format is newer than this build supports")
        }
        return document
    }

    /**
     * A fingerprint that ignores the snapshot's own timestamp, so an unchanged
     * vault is not uploaded again on every sync.
     */
    fun digest(document: JSONObject): String {
        val methods = document.optJSONArray("unlock_methods") ?: JSONArray()
        val entries = document.optJSONArray("entries") ?: JSONArray()

        val methodLines = (0 until methods.length())
            .map { methods.getJSONObject(it) }
            .sortedWith(compareBy({ it.getString("method") }, { it.getString("identity") }))
            .map { canonicalMethod(it) }
        val entryLines = (0 until entries.length())
            .map { entries.getJSONObject(it) }
            .sortedBy { it.getString("uuid") }
            .map { canonicalEntry(it) }

        val payload = buildString {
            append("{\"entries\":[").append(entryLines.joinToString(","))
            append("],\"unlock_methods\":[").append(methodLines.joinToString(","))
            append("],\"vault_id\":").append(quote(document.getString("vault_id")))
            append("}")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(payload.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    private fun canonicalMethod(method: JSONObject) = buildString {
        append("{\"deleted\":").append(method.optInt("deleted", 0))
        append(",\"identity\":").append(quote(method.getString("identity")))
        append(",\"method\":").append(quote(method.getString("method")))
        append(",\"salt\":").append(quote(method.getString("salt")))
        append(",\"updated_at\":").append(quote(method.getString("updated_at")))
        append(",\"wrapped_dek\":").append(quote(method.getString("wrapped_dek")))
        append("}")
    }

    private fun canonicalEntry(entry: JSONObject) = buildString {
        append("{\"deleted\":").append(entry.optInt("deleted", 0))
        append(",\"login\":").append(quote(entry.getString("login")))
        append(",\"password\":").append(quote(entry.getString("password")))
        append(",\"service\":").append(quote(entry.getString("service")))
        append(",\"updated_at\":").append(quote(entry.getString("updated_at")))
        append(",\"uuid\":").append(quote(entry.getString("uuid")))
        append("}")
    }

    /** Matches Python's json.dumps for the characters these fields can hold. */
    private fun quote(value: String) = buildString {
        append('"')
        for (character in value) {
            when {
                character == '"' -> append("\\\"")
                character == '\\' -> append("\\\\")
                character.code < 0x20 -> append("\\u%04x".format(character.code))
                character.code > 0x7e -> append("\\u%04x".format(character.code))
                else -> append(character)
            }
        }
        append('"')
    }

    // ── Merge ─────────────────────────────────────────────────────

    data class MergeResult(val entries: Int, val methods: Int) {
        val changed: Boolean get() = entries > 0 || methods > 0
    }

    fun merge(db: Database, remote: JSONObject): MergeResult {
        val vaultId = remote.getString("vault_id")
        db.ensureVault(vaultId)

        var methodsApplied = 0
        val localMethods = db.methodsOf(vaultId, includeDeleted = true)
            .associateBy { it.method to it.identity }
        val methods = remote.optJSONArray("unlock_methods") ?: JSONArray()
        for (index in 0 until methods.length()) {
            val incoming = methods.getJSONObject(index)
            val key = incoming.getString("method") to incoming.getString("identity")
            val localStamp = localMethods[key]?.updatedAt
            val stamp = incoming.getString("updated_at")
            if (localStamp != null && stamp <= localStamp) continue

            db.saveMethod(vaultId, key.first, key.second,
                          incoming.getString("salt"),
                          decode(incoming.getString("wrapped_dek")),
                          stamp,
                          incoming.optInt("deleted", 0) != 0)
            methodsApplied++
        }

        var entriesApplied = 0
        val localEntries: Map<String, StoredEntry> =
            db.entriesOf(vaultId, includeDeleted = true).associateBy { it.uuid }
        val entries = remote.optJSONArray("entries") ?: JSONArray()
        for (index in 0 until entries.length()) {
            val incoming = entries.getJSONObject(index)
            val uuid = incoming.getString("uuid")
            val stamp = incoming.getString("updated_at")
            val localStamp = localEntries[uuid]?.updatedAt
            if (localStamp != null && stamp <= localStamp) continue

            db.putEntry(vaultId, uuid,
                        decode(incoming.getString("service")),
                        decode(incoming.getString("login")),
                        decode(incoming.getString("password")),
                        stamp,
                        incoming.optInt("deleted", 0) != 0)
            entriesApplied++
        }

        if (db.enforceSingleMethod(vaultId) > 0) methodsApplied++
        return MergeResult(entriesApplied, methodsApplied)
    }

    fun purgeOldTombstones(db: Database) {
        val cutoff = System.currentTimeMillis() - TOMBSTONE_TTL_DAYS * 24 * 3600 * 1000
        val format = java.text.SimpleDateFormat(
            "yyyy-MM-dd'T'HH:mm:ss.SSS", java.util.Locale.US)
        format.timeZone = java.util.TimeZone.getTimeZone("UTC")
        db.purgeTombstones(format.format(java.util.Date(cutoff)) + "000Z")
    }
}
