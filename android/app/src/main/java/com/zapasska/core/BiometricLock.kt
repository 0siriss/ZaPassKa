package com.zapasska.core

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import com.zapasska.data.VaultSession
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Opening the vault with a fingerprint.
 *
 * The master password is never stored, here or anywhere. What is stored is the
 * vault's data key, sealed under a key that lives in the Android Keystore and
 * is only released after the device authenticates the user. The password
 * remains the only thing that can derive that data key from scratch, so
 * turning the fingerprint off, or having it invalidated, loses nothing.
 *
 * Enrolling a new fingerprint invalidates the Keystore key by design: whoever
 * added it should not inherit access, and the vault falls back to the password.
 */
object BiometricLock {

    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "zapasska.vault.dek"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val TAG_BITS = 128

    private const val PREFS = "biometric"
    private const val KEY_VAULT = "vault_id"
    private const val KEY_IV = "iv"
    private const val KEY_BLOB = "blob"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Whether this device has a usable fingerprint or face enrolled. */
    fun available(context: Context): Boolean =
        BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS

    fun isEnabled(context: Context): Boolean =
        prefs(context).contains(KEY_BLOB) && vaultId(context) != null

    fun vaultId(context: Context): String? = prefs(context).getString(KEY_VAULT, null)

    fun disable(context: Context) {
        prefs(context).edit().clear().apply()
        runCatching {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)
        }
    }

    // ── Ciphers for the prompt ────────────────────────────────────
    //
    // The prompt authenticates a specific Cipher, so it is built first and
    // only used after the user has been recognised.

    /** A cipher that will seal the data key once the user is recognised. */
    fun cipherForEnrolling(): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, newKey()) }

    /**
     * A cipher that will open the stored data key, or null when the Keystore
     * key is gone: the fingerprint set changed, or the screen lock was removed.
     */
    fun cipherForUnlocking(context: Context): Cipher? {
        val iv = prefs(context).getString(KEY_IV, null) ?: return null
        val key = existingKey() ?: return null
        return try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key,
                     GCMParameterSpec(TAG_BITS, Base64.decode(iv, Base64.NO_WRAP)))
            }
        } catch (invalidated: KeyPermanentlyInvalidatedException) {
            disable(context)
            null
        }
    }

    /** Called after the prompt succeeds: seals the data key of the open vault. */
    fun store(context: Context, session: VaultSession, cipher: Cipher) {
        val sealed = cipher.doFinal(session.dataKey)
        prefs(context).edit()
            .putString(KEY_VAULT, session.vaultId)
            .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .putString(KEY_BLOB, Base64.encodeToString(sealed, Base64.NO_WRAP))
            .apply()
    }

    /** Called after the prompt succeeds: returns the vault the key belongs to. */
    fun open(context: Context, cipher: Cipher): VaultSession? {
        val vaultId = vaultId(context) ?: return null
        val blob = prefs(context).getString(KEY_BLOB, null) ?: return null
        return try {
            VaultSession(vaultId, cipher.doFinal(Base64.decode(blob, Base64.NO_WRAP)))
        } catch (failure: Exception) {          // tampered storage, nothing to open
            disable(context)
            null
        }
    }

    // ── Keystore ──────────────────────────────────────────────────

    private fun existingKey(): SecretKey? {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return store.getKey(ALIAS, null) as? SecretKey
    }

    private fun newKey(): SecretKey {
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)

        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setUserAuthenticationRequired(true)
            setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // 0 seconds: every use needs a fresh authentication.
                setUserAuthenticationParameters(
                    0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
        }.build()

        generator.init(spec)
        return generator.generateKey()
    }
}
