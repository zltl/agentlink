package app.agentlink.node

import android.content.Context
import app.agentlink.account.DEFAULT_RELAY
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
    private val prefs = context.applicationContext.getSharedPreferences("agentlink_node", Context.MODE_PRIVATE)

    fun save(setup: NodeSetup) {
        val visited = setup.choices.visited.joinToString(",") { it.name }
        prefs.edit()
            .putString("relay", setup.relay)
            .putString("fingerprint", setup.fingerprint)
            .putString("token", setup.token)
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
    }

    fun load(): NodeSetup? {
        val relay = prefs.getString("relay", null) ?: return null
        val visited = prefs.getString("visited", "").orEmpty()
            .split(',')
            .mapNotNull { raw -> ConsentStep.entries.firstOrNull { it.name == raw } }
            .toSet()
        return NodeSetup(
            relay = relay,
            fingerprint = prefs.getString("fingerprint", "").orEmpty(),
            token = prefs.getString("token", "").orEmpty(),
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
    private val prefs = context.applicationContext.getSharedPreferences("agentlink_client", Context.MODE_PRIVATE)

    fun save(relay: String, token: String, fingerprint: String) {
        prefs.edit()
            .putString("relay", relay)
            .putString("token", token)
            .putString("fingerprint", fingerprint)
            .apply()
    }

    fun relay(): String = prefs.getString("relay", DEFAULT_RELAY).orEmpty()
    fun token(): String = prefs.getString("token", "").orEmpty()
    fun fingerprint(): String = prefs.getString("fingerprint", "").orEmpty()
}
