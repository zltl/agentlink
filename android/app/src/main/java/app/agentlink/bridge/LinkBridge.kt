package app.agentlink.bridge

data class MachineRow(
    val id: String,
    val name: String,
    val hostname: String,
    val os: String,
    val arch: String,
    val version: String,
    val online: Boolean,
    val preset: String,
    val allowRead: Boolean,
    val allowWrite: Boolean,
    val allowExec: Boolean,
    val allowDesktop: Boolean,
    val allowDesktopStream: Boolean,
    val allowRemoteView: Boolean,
    val allowRemoteControl: Boolean,
)

data class FileRow(
    val name: String,
    val isDir: Boolean,
    val isFile: Boolean,
    val isSymlink: Boolean,
    val size: ULong,
    val modifiedUnixMs: Long,
)

data class TransferResult(
    val logicalBytes: ULong,
    val payloadBytes: ULong,
    val skipped: Boolean,
    val files: UInt,
    val transport: String,
    val resumedBytes: ULong,
)

data class ExecResult(val exitCode: Int, val truncated: Boolean)

fun interface ProgressListener {
    fun onProgress(transferred: ULong, total: ULong)
}

fun interface OutputListener {
    /** Return false to cancel the remote command. */
    fun onOutput(stream: String, data: ByteArray): Boolean
}

interface PtySession {
    fun poll(): String
    fun write(data: ByteArray)
    fun resize(rows: Int, cols: Int)
    fun close()
}

data class LiveInfo(
    val sessionId: String,
    val codec: String,
    val encoder: String,
    val hardware: Boolean,
    val width: Int,
    val height: Int,
    val control: Boolean,
)

data class LiveFrame(
    val annexB: ByteArray,
    val keyframe: Boolean,
    val capturedUnixMs: Long,
    val width: Int,
    val height: Int,
)

data class LiveCursor(val x: Int, val y: Int, val shape: String)

data class LiveStats(val frames: ULong, val bytes: ULong, val loss: Double, val latencyMs: Long)

interface LiveDesktop {
    fun info(): LiveInfo
    fun pollFrame(timeoutMs: UInt): LiveFrame?
    fun pollCursor(): LiveCursor?
    fun stats(): LiveStats
    fun sendControl(json: String): Boolean
    fun requestKeyframe()
    fun failed(): Boolean
    fun close()
}

interface ClientSession {
    fun listMachines(): List<MachineRow>
    fun listDir(node: String, path: String): List<FileRow>
    fun readBytes(node: String, path: String, offset: ULong, maxBytes: ULong): ByteArray
    fun writeBytes(node: String, path: String, data: ByteArray)
    fun mkdir(node: String, path: String, recursive: Boolean)
    fun remove(node: String, path: String, recursive: Boolean)
    fun rename(node: String, from: String, to: String)
    fun exec(
        node: String,
        program: String,
        args: List<String>,
        cwd: String?,
        env: List<String>,
        shell: Boolean,
        timeoutMs: ULong,
        sink: OutputListener,
    ): ExecResult
    fun transferUp(
        node: String,
        remote: String,
        local: String,
        preferDirect: Boolean,
        sink: ProgressListener,
    ): TransferResult
    fun transferDown(
        node: String,
        remote: String,
        local: String,
        preferDirect: Boolean,
        sink: ProgressListener,
    ): TransferResult
    fun extension(node: String, name: String, payloadJson: String): String
    fun openLive(node: String, maxFps: UInt, bitrate: UInt, monitor: UInt): LiveDesktop? = null
    fun openPty(node: String, command: String?, rows: Int, cols: Int): PtySession
    fun createPairing(
        name: String,
        allowRead: Boolean,
        allowWrite: Boolean,
        allowExec: Boolean,
        allowDesktop: Boolean,
        allowDesktopStream: Boolean,
        allowRemoteView: Boolean,
        allowRemoteControl: Boolean,
        ttlSecs: ULong,
    ): PairingTicket
    fun close()
}

data class PairingTicket(val token: String, val name: String, val expiresUnix: Long)

interface NodeSession {
    fun stop()
    fun status(): String
    fun nodeId(): String
    fun auditTail(limit: Int): String
    fun close()
}

interface LinkBridge {
    fun protocolVersion(): UInt
    fun extensionNames(): List<String>
    fun connect(relay: String, token: String, fingerprint: String, identityDir: String): ClientSession
}
