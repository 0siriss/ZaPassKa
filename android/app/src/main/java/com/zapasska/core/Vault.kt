package com.zapasska.core

import com.zapasska.data.Database
import com.zapasska.data.Entry
import com.zapasska.data.UnlockMethod
import com.zapasska.data.VaultSession

/** What happened when the user tried to open a vault. */
enum class UnlockResult { OK, WRONG_SECRET, NO_VAULT }

data class Unlocked(val result: UnlockResult, val session: VaultSession? = null)

/**
 * Opening vaults and keeping their entries, following docs/FORMAT.md.
 *
 * Android only ever uses the master password: a phone is rarely on the
 * corporate network, so a vault wrapped under a domain account cannot be
 * opened here at all.
 */
class Vault(private val db: Database) {

    fun hasMasterVault(): Boolean = db.liveMethods(UnlockMethod.MASTER).isNotEmpty()

    fun create(masterPassword: String): VaultSession {
        val vaultId = db.createVault()
        val dataKey = Crypto.randomBytes(Crypto.KEY_LENGTH)
        storeMaster(vaultId, masterPassword, dataKey)
        return VaultSession(vaultId, dataKey)
    }

    fun unlock(masterPassword: String): Unlocked {
        val methods = db.liveMethods(UnlockMethod.MASTER)
        if (methods.isEmpty()) return Unlocked(UnlockResult.NO_VAULT)

        val opened = methods.mapNotNull { method ->
            val kek = Crypto.deriveKek(masterPassword, Crypto.fromHex(method.salt))
            Crypto.unwrapDataKey(kek, method.wrappedDataKey)
                ?.let { VaultSession(method.vaultId, it) }
        }
        if (opened.isEmpty()) return Unlocked(UnlockResult.WRONG_SECRET)

        val session = if (opened.size == 1) opened.first() else absorbDuplicates(opened)
        return Unlocked(UnlockResult.OK, session)
    }

    /**
     * One secret is meant to open one vault. Two devices can still each start
     * one before they meet through Drive, and showing either alone would hide
     * half the user's passwords. docs/FORMAT.md section 6 fixes the survivor
     * as the lowest vault id so every device agrees without coordinating.
     */
    private fun absorbDuplicates(sessions: List<VaultSession>): VaultSession {
        val survivor = sessions.minByOrNull { it.vaultId }!!

        for (other in sessions) {
            if (other.vaultId == survivor.vaultId) continue
            for (stored in db.entriesOf(other.vaultId)) {
                val service = Crypto.openText(other.dataKey, stored.service) ?: continue
                val login = Crypto.openText(other.dataKey, stored.login) ?: continue
                val password = Crypto.openText(other.dataKey, stored.password) ?: continue
                db.putEntry(
                    survivor.vaultId,
                    Database.derivedUuid(survivor.vaultId, stored.uuid),
                    Crypto.sealText(survivor.dataKey, service),
                    Crypto.sealText(survivor.dataKey, login),
                    Crypto.sealText(survivor.dataKey, password))
                db.deleteEntry(stored.uuid)
            }
            db.retireMethod(other.vaultId, UnlockMethod.MASTER, "")
        }
        return survivor
    }

    fun verifyMasterPassword(session: VaultSession, password: String): Boolean {
        val method = db.methodsOf(session.vaultId)
            .firstOrNull { it.method == UnlockMethod.MASTER } ?: return false
        val kek = Crypto.deriveKek(password, Crypto.fromHex(method.salt))
        val dataKey = Crypto.unwrapDataKey(kek, method.wrappedDataKey) ?: return false
        return dataKey.contentEquals(session.dataKey)
    }

    /** Re-wraps the data key under a new password. Entries are untouched. */
    fun changeMasterPassword(session: VaultSession, newPassword: String) =
        storeMaster(session.vaultId, newPassword, session.dataKey)

    private fun storeMaster(vaultId: String, password: String, dataKey: ByteArray) {
        val salt = Crypto.randomBytes(Crypto.SALT_LENGTH)
        val kek = Crypto.deriveKek(password, salt)
        db.replaceMethod(vaultId, UnlockMethod.MASTER, "",
                         Crypto.toHex(salt), Crypto.wrapDataKey(kek, dataKey))
    }

    // ── Entries ───────────────────────────────────────────────────

    fun entries(session: VaultSession): List<Entry> =
        db.entriesOf(session.vaultId).mapNotNull { stored ->
            val service = Crypto.openText(session.dataKey, stored.service)
            val login = Crypto.openText(session.dataKey, stored.login)
            val password = Crypto.openText(session.dataKey, stored.password)
            if (service == null || login == null || password == null) null
            else Entry(stored.uuid, service, login, password)
        }

    fun addEntry(session: VaultSession, service: String, login: String, password: String) {
        db.putEntry(session.vaultId, Database.newUuid(),
                    Crypto.sealText(session.dataKey, service),
                    Crypto.sealText(session.dataKey, login),
                    Crypto.sealText(session.dataKey, password))
    }

    fun updateEntry(session: VaultSession, uuid: String,
                    service: String, login: String, password: String) {
        db.putEntry(session.vaultId, uuid,
                    Crypto.sealText(session.dataKey, service),
                    Crypto.sealText(session.dataKey, login),
                    Crypto.sealText(session.dataKey, password))
    }

    fun deleteEntry(uuid: String) = db.deleteEntry(uuid)
}
