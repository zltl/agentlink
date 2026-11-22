package app.agentlink.account

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.Security

private const val SESSION_PREFS = "agentlink.session"
private const val MASTER_KEY_ALIAS = "_androidx_security_master_key_"

/**
 * Open [EncryptedSharedPreferences] with automatic recovery when the Tink
 * keyset or Android Keystore master key is corrupted (e.g., after an OS update
 * or partial backup restore), so app startup never bricks.
 */
internal fun openEncryptedPrefs(context: Context, name: String): SharedPreferences {
    val app = context.applicationContext
    if (Security.getProvider("AndroidKeyStore") == null) {
        // Pure-JVM / Robolectric unit tests without AndroidKeyStore registered.
        return app.getSharedPreferences(name, Context.MODE_PRIVATE)
    }
    return try {
        createEncryptedPrefs(app, name)
    } catch (_: GeneralSecurityException) {
        recoverEncryptedPrefs(app, name)
    } catch (_: IOException) {
        recoverEncryptedPrefs(app, name)
    } catch (_: SecurityException) {
        recoverEncryptedPrefs(app, name)
    }
}

private fun createEncryptedPrefs(app: Context, name: String): SharedPreferences {
    return EncryptedSharedPreferences.create(
        name,
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        app,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}

private fun recoverEncryptedPrefs(app: Context, name: String): SharedPreferences {
    runCatching { app.deleteSharedPreferences(name) }
    return try {
        createEncryptedPrefs(app, name)
    } catch (_: Exception) {
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(MASTER_KEY_ALIAS)) {
                ks.deleteEntry(MASTER_KEY_ALIAS)
            }
        }
        runCatching { app.deleteSharedPreferences(name) }
        createEncryptedPrefs(app, name)
    }
}

/** Refresh token and the rest of the session live in EncryptedSharedPreferences. */
class EncryptedSessionStore(context: Context) : SessionStore {
    private val appContext = context.applicationContext
    @Volatile
    private var prefs: SharedPreferences = openEncryptedPrefs(appContext, SESSION_PREFS)

    override fun load(): UserAccount? {
        return try {
            readAccount(prefs)
        } catch (_: GeneralSecurityException) {
            resetStore()
            null
        } catch (_: SecurityException) {
            resetStore()
            null
        } catch (_: IOException) {
            resetStore()
            null
        }
    }

    private fun readAccount(source: SharedPreferences): UserAccount? {
        val refresh = source.getString("refresh_token", null) ?: return null
        if (refresh.isEmpty()) return null
        return UserAccount(
            server = source.getString("server", DEFAULT_RELAY) ?: DEFAULT_RELAY,
            fingerprint = source.getString("fingerprint", "") ?: "",
            user = source.getString("user", "") ?: "",
            role = source.getString("role", "user") ?: "user",
            deviceId = source.getString("device_id", "") ?: "",
            accessToken = source.getString("access_token", "") ?: "",
            accessExpiresUnix = source.getLong("access_expires_unix", 0L),
            refreshToken = refresh,
            refreshExpiresUnix = source.getLong("refresh_expires_unix", 0L),
        )
    }

    override fun save(account: UserAccount) {
        // commit, not apply: a killed process must persist the replacement
        // before it exits. If it dies first, the relay still accepts the
        // previous refresh token until this replacement is used.
        val saved = try {
            writeAccount(prefs, account)
        } catch (_: Exception) {
            resetStore()
            writeAccount(prefs, account)
        }
        if (!saved) throw IllegalStateException("couldn't save the session")
    }

    private fun writeAccount(target: SharedPreferences, account: UserAccount): Boolean {
        return target.edit()
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
    }

    override fun clear() {
        val ok = try {
            prefs.edit().clear().commit()
        } catch (_: Exception) {
            resetStore()
            true
        }
        if (!ok) {
            throw IllegalStateException("couldn't clear the session")
        }
    }

    private fun resetStore() {
        prefs = recoverEncryptedPrefs(appContext, SESSION_PREFS)
    }
}
