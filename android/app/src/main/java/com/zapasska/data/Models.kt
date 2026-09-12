package com.zapasska.data

/** An entry as it is stored: every field still encrypted. */
data class StoredEntry(
    val uuid: String,
    val vaultId: String,
    val service: ByteArray,
    val login: ByteArray,
    val password: ByteArray,
    val updatedAt: String,
    val deleted: Boolean,
)

/** An entry the user can read. */
data class Entry(
    val uuid: String,
    val service: String,
    val login: String,
    val password: String,
)

/** One way of opening a vault. Only "master" is supported on Android. */
data class UnlockMethod(
    val vaultId: String,
    val method: String,
    val identity: String,
    val salt: String,
    val wrappedDataKey: ByteArray,
    val updatedAt: String,
    val deleted: Boolean,
) {
    companion object {
        const val MASTER = "master"
        const val AD = "ad"
    }
}

/** An opened vault. The data key lives here and nowhere else. */
data class VaultSession(
    val vaultId: String,
    val dataKey: ByteArray,
)
