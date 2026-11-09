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

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopNode()
            return START_NOT_STICKY
        }
        val projection = projectionExtra(intent)
        val resultCode = intent?.getIntExtra(EXTRA_RESULT, 0) ?: 0
        val type = if (projection != null && resultCode == android.app.Activity.RESULT_OK) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC or
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION
        } else {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification("Connecting"), type)
        if (projection != null && resultCode == android.app.Activity.RESULT_OK) {
            NodeRuntime.capture.attach(this, resultCode, projection)
        }
        if (NodeRuntime.current() == null) {
            startNode()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopNode()
        super.onDestroy()
    }

    private fun startNode() {
        val setup = ConsentStore(this).load()
        if (setup == null || !setup.choices.appStorage) {
            NodeRuntime.status.value = "{\"state\":\"fatal\",\"detail\":\"app storage was not allowed\"}"
            stopSelf()
            return
        }
        val ceiling = ceilingOf(setup.choices)
        val dataDir = File(noBackupFilesDir, "node")
        val filesDir = File(filesDir, "shared")
        val cacheDir = cacheDir
        dataDir.mkdirs()
        filesDir.mkdirs()
        val audit = File(dataDir, "audit.log")
        val now = Instant.now().toString()
        appendAudit(audit, auditRecord(now, "consent", "node start", true, null, null))
        val storage = if (setup.choices.allFiles && allFilesGranted()) {
            @Suppress("DEPRECATION")
            Environment.getExternalStorageDirectory().absolutePath
        } else {
            ""
        }
        host = AndroidHost(
            context = this,
            saf = SafStore(this),
            shells = ShellSessions(),
            capture = NodeRuntime.capture,
            allowShizuku = setup.choices.shizuku,
            allowRoot = setup.choices.root,
            onStatus = { json ->
                NodeRuntime.status.value = json
                val state = app.agentlink.model.jsonField(json, "state") ?: "node"
                val detail = app.agentlink.model.jsonField(json, "detail").orEmpty()
                val manager = getSystemService(NotificationManager::class.java)
                manager.notify(NOTIFICATION_ID, notification("$state: $detail"))
            },
        )
        val options = NodeOptions(
            relayUrl = setup.relay,
            fingerprint = setup.fingerprint,
            dataDir = dataDir.absolutePath,
            filesDir = filesDir.absolutePath,
            cacheDir = cacheDir.absolutePath,
            storageDir = storage,
            name = setup.name.ifBlank { Build.MODEL ?: "android" },
            pairingToken = setup.token,
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
        try {
            val node = MobileNode.start(options, host!!)
            NodeRuntime.bind(node)
        } catch (err: Exception) {
            val detail = app.agentlink.model.jsonString(err.message ?: "start failed")
            NodeRuntime.status.value = "{\"state\":\"fatal\",\"detail\":$detail}"
            stopSelf()
        }
    }

    private fun stopNode() {
        NodeRuntime.current()?.stop()
        NodeRuntime.current()?.close()
        NodeRuntime.clear()
        NodeRuntime.capture.release()
        host = null
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
            val intent = Intent(context, NodeForegroundService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
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
