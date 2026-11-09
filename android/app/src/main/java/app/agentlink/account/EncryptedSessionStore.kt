package app.agentlink.account

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

/** Refresh token and the rest of the session live in EncryptedSharedPreferences. */
class EncryptedSessionStore(context: Context) : SessionStore {
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        "agentlink.session",
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context.applicationContext,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    override fun load(): UserAccount? {
        val refresh = prefs.getString("refresh_token", null) ?: return null
        if (refresh.isEmpty()) return null
        return UserAccount(
            server = prefs.getString("server", DEFAULT_RELAY) ?: DEFAULT_RELAY,
            fingerprint = prefs.getString("fingerprint", "") ?: "",
            user = prefs.getString("user", "") ?: "",
            role = prefs.getString("role", "user") ?: "user",
            deviceId = prefs.getString("device_id", "") ?: "",
            accessToken = prefs.getString("access_token", "") ?: "",
            accessExpiresUnix = prefs.getLong("access_expires_unix", 0L),
            refreshToken = refresh,
            refreshExpiresUnix = prefs.getLong("refresh_expires_unix", 0L),
        )
    }

    override fun save(account: UserAccount) {
        // commit, not apply: a killed process must persist the replacement
        // before it exits. If it dies first, the relay still accepts the
        // previous refresh token until this replacement is used.
        val saved = prefs.edit()
            .putString("server", account.server)
            .putString("fingerprint", account.fingerprint)
            .putString("user", account.user)
            .putString("role", account.role)
            .putString("device_id", account.deviceId)
            .putString("access_token", account.accessToken)
            .putLong("access_expires_unix", account.accessExpiresUnix)
            .putString("refresh_token", account.refreshToken)
            .putLong("refresh_expires_unix", account.refreshExpiresUnix)
            .commit()
        if (!saved) throw IllegalStateException("couldn't save the session")
    }

    override fun clear() {
        if (!prefs.edit().clear().commit()) {
            throw IllegalStateException("couldn't clear the session")
        }
    }
}
