package app.agentlink.node

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Environment
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import app.agentlink.BuildConfig
import app.agentlink.MainActivity
import app.agentlink.R
import app.agentlink.model.auditRecord
import app.agentlink.model.ceilingOf
import app.agentlink.model.jsonString
import app.agentlink.model.resolveJoin
import kotlinx.coroutines.flow.MutableStateFlow
import uniffi.agentlink_ffi.MobileNode
import uniffi.agentlink_ffi.NodeOptions
import java.io.File
import java.time.Instant

object NodeRuntime {
    val status = MutableStateFlow("{\"state\":\"stopped\",\"detail\":\"not started\"}")
    val nodeId = MutableStateFlow("")
    val running = MutableStateFlow(false)
    var capture: ScreenGrabber = ScreenGrabber()
    private var node: MobileNode? = null

    fun bind(started: MobileNode) {
        node = started
        running.value = true
        nodeId.value = started.nodeId()
    }

    fun current(): MobileNode? = node

    fun tail(limit: Int): String = node?.auditTail(limit.toUInt()).orEmpty()

    fun clear() {
        node = null
        running.value = false
    }
}

class NodeForegroundService : Service() {
    private var host: AndroidHost? = null
    private var shells: ShellSessions? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null || intent.action == ACTION_STOP) {
            stopNode()
            return START_NOT_STICKY
        }
        val projection = projectionExtra(intent)
        val resultCode = intent.getIntExtra(EXTRA_RESULT, 0)
        val baseType = if (Build.VERSION.SDK_INT >= 34) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING
        } else {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        }
        val type = if (projection != null && resultCode == android.app.Activity.RESULT_OK) {
            baseType or ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION
        } else {
            baseType
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification("Connecting"), type)
        if (projection != null && resultCode == android.app.Activity.RESULT_OK) {
            NodeRuntime.capture.attach(this, resultCode, projection)
        }
        if (NodeRuntime.current() == null && !startNode()) {
            stopSelf()
            return START_NOT_STICKY
        }
        return START_NOT_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        NodeRuntime.status.value = "{\"state\":\"stopped\",\"detail\":\"foreground service timed out by Android\"}"
        stopNode()
    }

    override fun onDestroy() {
        stopNode()
        super.onDestroy()
    }

    private fun startNode(): Boolean {
        val consentStore = ConsentStore(this)
        val setup = consentStore.load()
        if (setup == null || !setup.choices.appStorage) {
            NodeRuntime.status.value = "{\"state\":\"fatal\",\"detail\":\"app storage was not allowed\"}"
            return false
        }
        val resolved = resolveJoin(setup.relay, setup.fingerprint, setup.token, setup.name)
            .getOrElse { err ->
                val detail = jsonString(err.message ?: "invite was refused")
                NodeRuntime.status.value = "{\"state\":\"fatal\",\"detail\":$detail}"
                return false
            }
        val ceiling = ceilingOf(setup.choices)
        val dataDir = File(noBackupFilesDir, "node")
        val filesDir = File(filesDir, "shared")
        val nodeCacheDir = File(cacheDir, "node-cache")
        dataDir.mkdirs()
        filesDir.mkdirs()
        nodeCacheDir.mkdirs()
        val audit = File(dataDir, "audit.log")
        val now = Instant.now().toString()
        appendAudit(audit, auditRecord(now, "consent", "node start", true, null, null))
        val storage = if (setup.choices.allFiles && allFilesGranted()) {
            @Suppress("DEPRECATION")
            Environment.getExternalStorageDirectory().absolutePath
        } else {
            ""
        }
        val shellSessions = ShellSessions()
        shells = shellSessions
        var tokenCleared = false
        host = AndroidHost(
            context = this,
            saf = SafStore(this),
            shells = shellSessions,
            capture = NodeRuntime.capture,
            allowShizuku = setup.choices.shizuku,
            allowRoot = setup.choices.root,
            statusCallback = { json ->
                NodeRuntime.status.value = json
                val state = app.agentlink.model.jsonField(json, "state") ?: "node"
                val detail = app.agentlink.model.jsonField(json, "detail").orEmpty()
                if (!tokenCleared && state == "online") {
                    tokenCleared = true
                    consentStore.clearToken()
                }
                val manager = getSystemService(NotificationManager::class.java)
                manager.notify(NOTIFICATION_ID, notification("$state: $detail"))
            },
            stageCacheDir = nodeCacheDir,
        )
        val options = NodeOptions(
            relayUrl = resolved.relay,
            fingerprint = resolved.fingerprint,
            dataDir = dataDir.absolutePath,
            filesDir = filesDir.absolutePath,
            cacheDir = nodeCacheDir.absolutePath,
            storageDir = storage,
            name = resolved.name.ifBlank { setup.name.ifBlank { Build.MODEL ?: "android" } },
            pairingToken = resolved.token,
            hostname = Build.MODEL ?: "android",
            arch = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64",
            version = BuildConfig.VERSION_NAME,
            allowRead = ceiling.allowRead,
            allowWrite = ceiling.allowWrite,
            allowExec = ceiling.allowExec,
            allowDesktop = ceiling.allowDesktop,
            allowDesktopStream = ceiling.allowDesktopStream,
            allowRemoteView = ceiling.allowRemoteView,
            allowRemoteControl = ceiling.allowRemoteControl,
        )
        return try {
            val node = MobileNode.start(options, host!!)
            NodeRuntime.bind(node)
            true
        } catch (err: Exception) {
            shellSessions.closeAll()
            shells = null
            host = null
            val detail = jsonString(err.message ?: "start failed")
            NodeRuntime.status.value = "{\"state\":\"fatal\",\"detail\":$detail}"
            false
        }
    }

    private fun stopNode() {
        val activeNode = NodeRuntime.current()
        val activeShells = shells
        NodeRuntime.clear()
        NodeRuntime.capture.release()
        shells = null
        host = null
        if (activeNode != null || activeShells != null) {
            kotlin.concurrent.thread(name = "agentlink-node-stop", isDaemon = true) {
                runCatching { activeShells?.closeAll() }
                runCatching { activeNode?.stop() }
                runCatching { activeNode?.close() }
            }
        }
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun notification(text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "agentlink node", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Stays up while this phone is an agentlink node"
                },
            )
        }
        val pending = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_node)
            .setContentTitle("agentlink node")
            .setContentText(text)
            .setContentIntent(pending)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    companion object {
        private const val CHANNEL = "agentlink-node"
        private const val NOTIFICATION_ID = 7
        const val EXTRA_PROJECTION = "projection"
        private const val EXTRA_RESULT = "result"
        const val ACTION_STOP = "app.agentlink.STOP_NODE"

        fun start(context: Context, resultCode: Int = 0, projection: Intent? = null) {
            val intent = Intent(context, NodeForegroundService::class.java)
            if (projection != null) {
                intent.putExtra(EXTRA_PROJECTION, projection)
                intent.putExtra(EXTRA_RESULT, resultCode)
            }
            androidx.core.content.ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, NodeForegroundService::class.java))
        }
    }
}

@Suppress("DEPRECATION")
private fun projectionExtra(intent: Intent?): Intent? {
    if (intent == null) return null
    return if (Build.VERSION.SDK_INT >= 33) {
        intent.getParcelableExtra(NodeForegroundService.EXTRA_PROJECTION, Intent::class.java)
    } else {
        intent.getParcelableExtra(NodeForegroundService.EXTRA_PROJECTION)
    }
}

fun allFilesGranted(): Boolean {
    return Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager()
}
