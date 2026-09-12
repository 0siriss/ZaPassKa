package com.zapasska.sync

import android.content.Context
import com.zapasska.data.Database
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import org.json.JSONObject

/**
 * Snapshots in the private appDataFolder of the user's own Drive, exactly as
 * docs/FORMAT.md section 7 lays out. Only ciphertext ever goes there.
 */
object Drive {

    private const val FILES = "https://www.googleapis.com/drive/v3/files"
    private const val UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"

    class DriveError(message: String) : IOException(message)

    data class Outcome(val pulledEntries: Int, val pushed: Boolean, val created: Boolean)

    fun isConnected(context: Context): Boolean = GoogleAuth.isConnected(context)

    /** Pull, merge, push, the whole cycle for one vault. */
    fun syncVault(context: Context, db: Database, vaultId: String): Outcome {
        Snapshot.purgeOldTombstones(db)

        val name = Snapshot.fileName(vaultId)
        val remoteFile = findFile(context, name)
        var pulled = 0
        var remoteDigest: String? = null

        if (remoteFile != null) {
            val remote = Snapshot.parse(download(context, remoteFile))
            if (remote.getString("vault_id") == vaultId) {
                pulled = Snapshot.merge(db, remote).entries
                remoteDigest = Snapshot.digest(remote)
            }
        }

        val local = Snapshot.build(db, vaultId)
        if (Snapshot.digest(local) != remoteDigest) {
            upload(context, name, local.toString().toByteArray(Charsets.UTF_8), remoteFile)
            return Outcome(pulled, pushed = true, created = remoteFile == null)
        }
        return Outcome(pulled, pushed = false, created = false)
    }

    /**
     * Import every snapshot the account holds. This is what makes a new phone
     * work: the snapshots carry the wrapped keys, so after pulling them the
     * usual master password opens the vault. Nothing is decrypted here.
     */
    fun pullAll(context: Context, db: Database): Pair<Int, Int> {
        var vaults = 0
        var entries = 0
        for (id in listSnapshots(context)) {
            val remote = try {
                Snapshot.parse(download(context, id))
            } catch (error: Exception) {
                continue        // not ours, or damaged
            }
            entries += Snapshot.merge(db, remote).entries
            vaults++
        }
        return vaults to entries
    }

    // ── REST ──────────────────────────────────────────────────────

    private fun listSnapshots(context: Context): List<String> {
        val query = params(mapOf(
            "spaces" to "appDataFolder",
            "fields" to "files(id,name)",
            "pageSize" to "100",
            "q" to "name contains 'zapasska-' and trashed = false",
        ))
        val payload = JSONObject(request(context, "$FILES?$query", "GET").toString(Charsets.UTF_8))
        val files = payload.optJSONArray("files") ?: return emptyList()
        return (0 until files.length()).map { files.getJSONObject(it).getString("id") }
    }

    private fun findFile(context: Context, name: String): String? {
        val escaped = name.replace("'", "\\'")
        val query = params(mapOf(
            "spaces" to "appDataFolder",
            "fields" to "files(id,name)",
            "q" to "name = '$escaped' and trashed = false",
        ))
        val payload = JSONObject(request(context, "$FILES?$query", "GET").toString(Charsets.UTF_8))
        val files = payload.optJSONArray("files") ?: return null
        return if (files.length() == 0) null else files.getJSONObject(0).getString("id")
    }

    private fun download(context: Context, fileId: String): ByteArray =
        request(context, "$FILES/$fileId?alt=media", "GET")

    private fun upload(context: Context, name: String, content: ByteArray, fileId: String?) {
        if (fileId != null) {
            request(context, "$UPLOAD/$fileId?uploadType=media", "PATCH",
                    content, "application/json")
            return
        }
        val boundary = "zpk" + System.nanoTime().toString(16)
        val metadata = JSONObject()
            .put("name", name)
            .put("parents", org.json.JSONArray().put("appDataFolder"))
        val body = ("--$boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" +
            "$metadata\r\n--$boundary\r\nContent-Type: application/json\r\n\r\n")
            .toByteArray(Charsets.UTF_8) + content +
            "\r\n--$boundary--\r\n".toByteArray(Charsets.UTF_8)

        request(context, "$UPLOAD?uploadType=multipart", "POST", body,
                "multipart/related; boundary=$boundary")
    }

    private fun request(context: Context, url: String, method: String,
                        body: ByteArray? = null, contentType: String? = null): ByteArray {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 20_000
            readTimeout = 20_000
            setRequestProperty("Authorization", "Bearer ${GoogleAuth.accessToken(context)}")
            if (contentType != null) setRequestProperty("Content-Type", contentType)
            if (body != null) doOutput = true
        }
        body?.let { payload -> connection.outputStream.use { it.write(payload) } }

        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val bytes = stream?.readBytes() ?: ByteArray(0)
        connection.disconnect()

        if (code !in 200..299) {
            throw DriveError("Google Drive returned $code: " +
                String(bytes, Charsets.UTF_8).take(300))
        }
        return bytes
    }

    private fun params(values: Map<String, String>) =
        values.entries.joinToString("&") {
            "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}"
        }
}
