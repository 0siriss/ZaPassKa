package com.zapasska

import com.zapasska.core.Crypto
import com.zapasska.sync.Snapshot
import java.io.File
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Android client and the desktop client must agree on the storage format
 * byte for byte. Both are checked against the same file, docs/format/vectors.json,
 * so a divergence fails here rather than in somebody's vault.
 *
 * A failure is never fixed by regenerating the vectors: it means the change
 * breaks every vault that already exists.
 */
class FormatVectorsTest {

    private val vectors: JSONObject by lazy {
        val candidates = listOf(
            "../../docs/format/vectors.json",   // unit tests run in android/app
            "../docs/format/vectors.json",
            "docs/format/vectors.json",
        )
        val file = candidates.map(::File).firstOrNull { it.exists() }
            ?: error("vectors.json not found from ${File(".").absolutePath}")
        JSONObject(file.readText(Charsets.UTF_8))
    }

    private fun b64(text: String): ByteArray = Base64.getDecoder().decode(text)

    @Test
    fun `scrypt parameters match the specification`() {
        val scrypt = vectors.getJSONObject("scrypt")

        assertEquals(scrypt.getInt("n"), Crypto.SCRYPT_N)
        assertEquals(scrypt.getInt("r"), Crypto.SCRYPT_R)
        assertEquals(scrypt.getInt("p"), Crypto.SCRYPT_P)
        assertEquals(scrypt.getInt("key_length"), Crypto.KEY_LENGTH)
    }

    @Test
    fun `aead parameters match the specification`() {
        val aead = vectors.getJSONObject("aead")

        assertEquals("AES-256-GCM", aead.getString("algorithm"))
        assertEquals(aead.getInt("nonce_length"), Crypto.NONCE_LENGTH)
    }

    @Test
    fun `key derivation reproduces every recorded key`() {
        val cases = vectors.getJSONArray("key_derivation")

        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            val key = Crypto.deriveKek(case.getString("password"),
                                       Crypto.fromHex(case.getString("salt_hex")))
            assertEquals(case.getString("note"),
                         case.getString("key_hex"), Crypto.toHex(key))
        }
    }

    @Test
    fun `the recorded blob unwraps to the recorded data key`() {
        val case = vectors.getJSONObject("key_wrapping")

        val dataKey = Crypto.unwrapDataKey(Crypto.fromHex(case.getString("kek_hex")),
                                           Crypto.fromHex(case.getString("wrapped_hex")))

        assertEquals(case.getString("data_key_hex"), Crypto.toHex(dataKey!!))
    }

    @Test
    fun `a wrong key unwraps to nothing`() {
        val case = vectors.getJSONObject("key_wrapping")

        assertNull(Crypto.unwrapDataKey(ByteArray(32),
                                        Crypto.fromHex(case.getString("wrapped_hex"))))
    }

    @Test
    fun `every recorded field decrypts to its plaintext`() {
        val section = vectors.getJSONObject("field_encryption")
        val dataKey = Crypto.fromHex(section.getString("data_key_hex"))
        val cases = section.getJSONArray("cases")

        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            assertEquals(case.getString("plaintext"),
                         Crypto.openText(dataKey, Crypto.fromHex(case.getString("blob_hex"))))
        }
    }

    @Test
    fun `sealing with the recorded nonce reproduces the recorded blob`() {
        val section = vectors.getJSONObject("field_encryption")
        val dataKey = Crypto.fromHex(section.getString("data_key_hex"))
        val cases = section.getJSONArray("cases")

        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            val sealed = Crypto.seal(dataKey,
                                     case.getString("plaintext").toByteArray(Charsets.UTF_8),
                                     Crypto.fromHex(case.getString("nonce_hex")))
            assertEquals(case.getString("blob_hex"), Crypto.toHex(sealed))
        }
    }

    @Test
    fun `the snapshot is accepted and its digest matches the desktop client`() {
        val section = vectors.getJSONObject("snapshot")
        val document = section.getJSONObject("document")

        val parsed = Snapshot.parse(document.toString().toByteArray(Charsets.UTF_8))

        assertEquals(document.getString("vault_id"), parsed.getString("vault_id"))
        assertEquals(section.getString("digest"), Snapshot.digest(parsed))
    }

    @Test
    fun `a newer snapshot format is refused`() {
        val document = JSONObject(
            vectors.getJSONObject("snapshot").getJSONObject("document").toString())
        document.put("format", Snapshot.FORMAT + 1)

        val failure = runCatching {
            Snapshot.parse(document.toString().toByteArray(Charsets.UTF_8))
        }.exceptionOrNull()

        assertTrue("expected the reader to refuse a newer format",
                   failure is Snapshot.UnsupportedSnapshot)
    }

    @Test
    fun `the master password opens the snapshot and reads its entries`() {
        val section = vectors.getJSONObject("snapshot")
        val document = section.getJSONObject("document")
        val method = document.getJSONArray("unlock_methods").getJSONObject(0)

        val kek = Crypto.deriveKek(section.getString("master_password"),
                                   Crypto.fromHex(method.getString("salt")))
        val dataKey = Crypto.unwrapDataKey(kek, b64(method.getString("wrapped_dek")))!!
        assertEquals(section.getString("data_key_hex"), Crypto.toHex(dataKey))

        val expected = section.getJSONArray("expected_entries")
        val entries = document.getJSONArray("entries")
        var live = 0
        for (index in 0 until entries.length()) {
            val entry = entries.getJSONObject(index)
            if (entry.getInt("deleted") != 0) continue

            val want = expected.getJSONObject(live)
            assertEquals(want.getString("uuid"), entry.getString("uuid"))
            assertEquals(want.getString("service"),
                         Crypto.openText(dataKey, b64(entry.getString("service"))))
            assertEquals(want.getString("login"),
                         Crypto.openText(dataKey, b64(entry.getString("login"))))
            assertEquals(want.getString("password"),
                         Crypto.openText(dataKey, b64(entry.getString("password"))))
            live++
        }
        assertEquals(expected.length(), live)
    }
}
