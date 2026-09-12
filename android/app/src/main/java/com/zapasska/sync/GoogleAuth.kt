package com.zapasska.sync

import android.content.Context
import android.net.Uri
import android.util.Base64
import com.zapasska.BuildConfig
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import org.json.JSONObject

/**
 * The browser half of the Google authorization, matching what the desktop
 * client does: authorization code with PKCE, no client secret. An Android
 * OAuth client is identified by the package name and signing certificate
 * instead, and Google redirects back to the reversed client id.
 */
object GoogleAuth {

    private const val AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
    private const val TOKEN_URI = "https://oauth2.googleapis.com/token"
    private const val REVOKE_URI = "https://oauth2.googleapis.com/revoke"
    const val SCOPE = "https://www.googleapis.com/auth/drive.appdata"

    private const val PREFS = "google_auth"
    private const val KEY_REFRESH = "refresh_token"
    private const val KEY_ACCESS = "access_token"
    private const val KEY_EXPIRES = "expires_at"
    private const val KEY_VERIFIER = "code_verifier"
    private const val KEY_STATE = "state"

    class AuthError(message: String) : IOException(message)

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun clientId(): String = BuildConfig.GOOGLE_CLIENT_ID

    fun isConfigured(): Boolean = clientId().isNotEmpty()

    fun redirectUri(): String = "${BuildConfig.OAUTH_REDIRECT_SCHEME}:/oauth2redirect"

    fun isConnected(context: Context): Boolean =
        !prefs(context).getString(KEY_REFRESH, null).isNullOrEmpty()

    fun disconnect(context: Context) {
        val refresh = prefs(context).getString(KEY_REFRESH, null)
        if (!refresh.isNullOrEmpty()) {
            runCatching { post(REVOKE_URI, mapOf("token" to refresh)) }
        }
        prefs(context).edit().clear().apply()
    }

    /** The page to open in the browser; the verifier is kept for the exchange. */
    fun authorizationUrl(context: Context): Uri {
        if (!isConfigured()) throw AuthError("No Google client is built into this app.")

        val verifier = randomUrlSafe(48)
        val state = randomUrlSafe(24)
        prefs(context).edit()
            .putString(KEY_VERIFIER, verifier)
            .putString(KEY_STATE, state)
            .apply()

        val challenge = Base64.encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

        val query = mapOf(
            "client_id" to clientId(),
            "redirect_uri" to redirectUri(),
            "response_type" to "code",
            "scope" to SCOPE,
            "code_challenge" to challenge,
            "code_challenge_method" to "S256",
            "state" to state,
            "access_type" to "offline",
            "prompt" to "consent",
        ).entries.joinToString("&") { "${it.key}=${encode(it.value)}" }

        return Uri.parse("$AUTH_URI?$query")
    }

    /** Called with the redirect the browser sent back. */
    fun completeAuthorization(context: Context, redirect: Uri) {
        val error = redirect.getQueryParameter("error")
        if (error != null) throw AuthError("Authorization refused: $error")

        val code = redirect.getQueryParameter("code")
            ?: throw AuthError("The redirect carried no authorization code.")
        val state = redirect.getQueryParameter("state")
        if (state != prefs(context).getString(KEY_STATE, null)) {
            throw AuthError("Authorization state mismatch, request discarded.")
        }
        val verifier = prefs(context).getString(KEY_VERIFIER, null)
            ?: throw AuthError("This device did not start that authorization.")

        val payload = post(TOKEN_URI, mapOf(
            "code" to code,
            "client_id" to clientId(),
            "redirect_uri" to redirectUri(),
            "grant_type" to "authorization_code",
            "code_verifier" to verifier,
        ))
        val refresh = payload.optString("refresh_token")
        if (refresh.isEmpty()) throw AuthError("Google returned no refresh token.")

        prefs(context).edit()
            .putString(KEY_REFRESH, refresh)
            .putString(KEY_ACCESS, payload.optString("access_token"))
            .putLong(KEY_EXPIRES, expiryOf(payload))
            .remove(KEY_VERIFIER)
            .remove(KEY_STATE)
            .apply()
    }

    /** A valid access token, refreshing it when the stored one has aged out. */
    fun accessToken(context: Context): String {
        val store = prefs(context)
        val refresh = store.getString(KEY_REFRESH, null)
            ?: throw AuthError("Google Drive is not connected.")

        val cached = store.getString(KEY_ACCESS, null)
        if (!cached.isNullOrEmpty() && System.currentTimeMillis() < store.getLong(KEY_EXPIRES, 0)) {
            return cached
        }

        val payload = post(TOKEN_URI, mapOf(
            "client_id" to clientId(),
            "refresh_token" to refresh,
            "grant_type" to "refresh_token",
        ))
        val token = payload.optString("access_token")
        if (token.isEmpty()) throw AuthError("Google refused to refresh the token, reconnect.")

        store.edit()
            .putString(KEY_ACCESS, token)
            .putLong(KEY_EXPIRES, expiryOf(payload))
            .apply()
        return token
    }

    private fun expiryOf(payload: JSONObject): Long =
        System.currentTimeMillis() + (payload.optLong("expires_in", 0) - 60) * 1000

    private fun post(url: String, fields: Map<String, String>): JSONObject {
        val body = fields.entries.joinToString("&") { "${it.key}=${encode(it.value)}" }
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 20_000
            readTimeout = 20_000
            setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        }
        connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

        val code = connection.responseCode
        val text = (if (code in 200..299) connection.inputStream else connection.errorStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()
        connection.disconnect()

        if (code !in 200..299) throw AuthError("Google returned $code: ${text.take(300)}")
        return if (text.isEmpty()) JSONObject() else JSONObject(text)
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")

    private fun randomUrlSafe(bytes: Int): String {
        val raw = ByteArray(bytes).also { SecureRandom().nextBytes(it) }
        return Base64.encodeToString(raw, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }
}
