package app.agentlink.node

import android.content.Context
import app.agentlink.account.DEFAULT_RELAY
import app.agentlink.account.openEncryptedPrefs
import app.agentlink.model.ConsentChoices
import app.agentlink.model.ConsentStep

data class NodeSetup(
    val relay: String,
    val fingerprint: String,
    val token: String,
    val name: String,
    val choices: ConsentChoices,
)

class ConsentStore(context: Context) {
    private val app = context.applicationContext
    private val prefs = app.getSharedPreferences("agentlink_node", Context.MODE_PRIVATE)
    private val secrets by lazy { openEncryptedPrefs(app, "agentlink.node.secret") }

    fun save(setup: NodeSetup) {
        val visited = setup.choices.visited.joinToString(",") { it.name }
        prefs.edit()
            .putString("relay", setup.relay)
            .putString("fingerprint", setup.fingerprint)
            .remove("token")
            .putString("name", setup.name)
            .putBoolean("notifications", setup.choices.notifications)
            .putBoolean("app_storage", setup.choices.appStorage)
            .putBoolean("commands", setup.choices.commands)
            .putBoolean("folders", setup.choices.folders)
            .putBoolean("all_files", setup.choices.allFiles)
            .putBoolean("screen", setup.choices.screenCapture)
            .putBoolean("live", setup.choices.liveStream)
            .putBoolean("accessibility", setup.choices.accessibility)
            .putBoolean("shizuku", setup.choices.shizuku)
            .putBoolean("root", setup.choices.root)
            .putString("visited", visited)
            .apply()
        runCatching {
            if (setup.token.isBlank()) {
                secrets.edit().remove("token").apply()
            } else {
                secrets.edit().putString("token", setup.token).apply()
            }
        }
    }

    fun clearToken() {
        prefs.edit().remove("token").apply()
        runCatching { secrets.edit().remove("token").apply() }
    }

    fun load(): NodeSetup? {
        val relay = prefs.getString("relay", null) ?: return null
        val visited = prefs.getString("visited", "").orEmpty()
            .split(',')
            .mapNotNull { raw -> ConsentStep.entries.firstOrNull { it.name == raw } }
            .toSet()
        // One-time migration of any legacy plaintext pairing token into encrypted storage.
        val legacyToken = prefs.getString("token", null)
        val token = if (!legacyToken.isNullOrEmpty()) {
            runCatching { secrets.edit().putString("token", legacyToken).apply() }
            prefs.edit().remove("token").apply()
            legacyToken
        } else {
            runCatching { secrets.getString("token", "").orEmpty() }.getOrDefault("")
        }
        return NodeSetup(
            relay = relay,
            fingerprint = prefs.getString("fingerprint", "").orEmpty(),
            token = token,
            name = prefs.getString("name", "").orEmpty(),
            choices = ConsentChoices(
                notifications = prefs.getBoolean("notifications", false),
                appStorage = prefs.getBoolean("app_storage", false),
                commands = prefs.getBoolean("commands", false),
                folders = prefs.getBoolean("folders", false),
                allFiles = prefs.getBoolean("all_files", false),
                screenCapture = prefs.getBoolean("screen", false),
                liveStream = prefs.getBoolean("live", false),
                accessibility = prefs.getBoolean("accessibility", false),
                shizuku = prefs.getBoolean("shizuku", false),
                root = prefs.getBoolean("root", false),
                visited = visited,
            ),
        )
    }
}

class ClientStore(context: Context) {
    private val app = context.applicationContext
    private val legacy = app.getSharedPreferences("agentlink_client", Context.MODE_PRIVATE)
    private val prefs by lazy {
        val enc = openEncryptedPrefs(app, "agentlink.client.enc")
        // Migrate any legacy plaintext admin token into encrypted prefs and remove plaintext copy.
        val oldToken = legacy.getString("token", null)
        if (!oldToken.isNullOrEmpty()) {
            val oldRelay = legacy.getString("relay", DEFAULT_RELAY).orEmpty()
            val oldFp = legacy.getString("fingerprint", "").orEmpty()
            enc.edit()
                .putString("relay", oldRelay)
                .putString("token", oldToken)
                .putString("fingerprint", oldFp)
                .apply()
            legacy.edit().clear().apply()
        }
        enc
    }

    fun save(relay: String, token: String, fingerprint: String) {
        prefs.edit()
            .putString("relay", relay)
            .putString("token", token)
            .putString("fingerprint", fingerprint)
            .apply()
    }

    fun relay(): String = runCatching { prefs.getString("relay", DEFAULT_RELAY).orEmpty() }.getOrDefault(DEFAULT_RELAY)
    fun token(): String = runCatching { prefs.getString("token", "").orEmpty() }.getOrDefault("")
    fun fingerprint(): String = runCatching { prefs.getString("fingerprint", "").orEmpty() }.getOrDefault("")
}
