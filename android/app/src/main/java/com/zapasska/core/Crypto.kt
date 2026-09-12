package com.zapasska.core

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.generators.SCrypt

/**
 * The storage format, implemented exactly as docs/FORMAT.md describes it.
 *
 * Every constant here is part of the format. Changing one makes existing
 * vaults unreadable, so FormatVectorsTest pins them against the shared
 * golden vectors.
 */
object Crypto {

    const val SCRYPT_N = 1 shl 17
    const val SCRYPT_R = 8
    const val SCRYPT_P = 1
    const val KEY_LENGTH = 32
    const val SALT_LENGTH = 32
    const val NONCE_LENGTH = 12
    private const val TAG_BITS = 128

    private val random = SecureRandom()

    fun randomBytes(length: Int): ByteArray =
        ByteArray(length).also { random.nextBytes(it) }

    /** scrypt over the secret, giving the key that wraps the data key. */
    fun deriveKek(secret: String, salt: ByteArray): ByteArray =
        SCrypt.generate(secret.toByteArray(Charsets.UTF_8), salt,
                        SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LENGTH)

    /** Seals [plaintext] as nonce || ciphertext || tag. */
    fun seal(key: ByteArray, plaintext: ByteArray,
             nonce: ByteArray = randomBytes(NONCE_LENGTH)): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"),
                    GCMParameterSpec(TAG_BITS, nonce))
        return nonce + cipher.doFinal(plaintext)
    }

    /** Opens a blob, or returns null when the key is wrong or it was tampered with. */
    fun open(key: ByteArray, blob: ByteArray): ByteArray? {
        if (blob.size <= NONCE_LENGTH) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"),
                        GCMParameterSpec(TAG_BITS, blob, 0, NONCE_LENGTH))
            cipher.doFinal(blob, NONCE_LENGTH, blob.size - NONCE_LENGTH)
        } catch (error: GeneralSecurityException) {
            // A wrong key fails the tag check; that is the wrong-secret signal.
            null
        }
    }

    fun sealText(key: ByteArray, text: String): ByteArray =
        seal(key, text.toByteArray(Charsets.UTF_8))

    fun openText(key: ByteArray, blob: ByteArray): String? =
        open(key, blob)?.toString(Charsets.UTF_8)

    fun wrapDataKey(kek: ByteArray, dataKey: ByteArray): ByteArray = seal(kek, dataKey)

    fun unwrapDataKey(kek: ByteArray, wrapped: ByteArray): ByteArray? = open(kek, wrapped)

    fun toHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    fun fromHex(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** sha256 of the lowercased name, the identity of an AD unlock method. */
    fun identityOf(username: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return toHex(digest.digest(username.lowercase().toByteArray(Charsets.UTF_8)))
    }
}
