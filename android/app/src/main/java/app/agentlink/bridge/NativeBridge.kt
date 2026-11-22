package app.agentlink.bridge

import uniffi.agentlink_ffi.DesktopLive
import uniffi.agentlink_ffi.FfiPolicy
import uniffi.agentlink_ffi.FfiStats
import uniffi.agentlink_ffi.LinkException
import uniffi.agentlink_ffi.MachineInfo
import uniffi.agentlink_ffi.MobileClient
import uniffi.agentlink_ffi.OutputSink
import uniffi.agentlink_ffi.ProgressSink
import uniffi.agentlink_ffi.PtyHandle
import uniffi.agentlink_ffi.extensionNames
import uniffi.agentlink_ffi.protocolVersion

class LinkFailure(message: String) : Exception(message)

class NativeBridge : LinkBridge {
    override fun protocolVersion(): UInt = call { protocolVersion() }

    override fun extensionNames(): List<String> = call { extensionNames() }

    override fun connect(
        relay: String,
        token: String,
        fingerprint: String,
        identityDir: String,
    ): ClientSession {
        val client = call { MobileClient.connect(relay, token, fingerprint, identityDir) }
        return NativeClient(client)
    }
}

internal class NativeClient(private val client: MobileClient) : ClientSession {
    override fun updateAccessToken(token: String) {
        call { client.updateAccessToken(token) }
    }

    override fun setIceServers(iceServersJson: String) {
        call { client.setIceServers(iceServersJson) }
    }

    override fun refreshIceServers(): String = call { client.refreshIceServers() }

    override fun listMachines(): List<MachineRow> = call {
        client.listMachines().map { it.toRow() }
    }

    override fun listDir(node: String, path: String): List<FileRow> = call {
        client.listDir(node, path).map { entry ->
            FileRow(
                name = entry.name,
                isDir = entry.isDir,
                isFile = entry.isFile,
                isSymlink = entry.isSymlink,
                size = entry.size,
                modifiedUnixMs = entry.modifiedUnixMs,
            )
        }
    }

    override fun readBytes(node: String, path: String, offset: ULong, maxBytes: ULong): ByteArray =
        call { client.readBytes(node, path, offset, maxBytes) }

    override fun writeBytes(node: String, path: String, data: ByteArray) {
        call { client.writeBytes(node, path, data) }
    }

    override fun mkdir(node: String, path: String, recursive: Boolean) {
        call { client.mkdir(node, path, recursive) }
    }

    override fun remove(node: String, path: String, recursive: Boolean) {
        call { client.remove(node, path, recursive) }
    }

    override fun rename(node: String, from: String, to: String) {
        call { client.rename(node, from, to) }
    }

    override fun findFiles(
        node: String,
        path: String,
        pattern: String,
        regex: Boolean,
        includeHidden: Boolean,
        caseInsensitive: Boolean,
        limit: UInt,
    ): String = call {
        client.findFiles(node, path, pattern, regex, includeHidden, caseInsensitive, limit)
    }

    override fun searchContent(
        node: String,
        path: String,
        pattern: String,
        literal: Boolean,
        includeHidden: Boolean,
        caseInsensitive: Boolean,
        limit: UInt,
    ): String = call {
        client.searchContent(node, path, pattern, literal, includeHidden, caseInsensitive, limit)
    }

    override fun queryAudit(nodeId: String, limit: UInt): String = call {
        client.queryAudit(nodeId, limit)
    }

    override fun sysInfo(node: String): String = call {
        client.sysInfo(node)
    }

    override fun listNodePins(): List<NodePinRow> = call {
        client.listNodePins().map { NodePinRow(name = it.name, nodeId = it.nodeId) }
    }

    override fun clearNodePin(name: String): Boolean = call {
        client.clearNodePin(name)
    }

    override fun nodePinWarnings(): List<String> = call {
        client.nodePinWarnings()
    }

    override fun listGrants(): List<GrantRow> = call {
        client.listGrants().map {
            GrantRow(
                nodeId = it.nodeId,
                granteeId = it.granteeId,
                issuerId = it.issuerId,
                jti = it.jti,
                nbfUnix = it.nbfUnix,
                expUnix = it.expUnix,
                preset = it.preset,
            )
        }
    }

    override fun importGrant(grantJson: String): GrantRow = call {
        val g = client.importGrant(grantJson)
        GrantRow(
            nodeId = g.nodeId,
            granteeId = g.granteeId,
            issuerId = g.issuerId,
            jti = g.jti,
            nbfUnix = g.nbfUnix,
            expUnix = g.expUnix,
            preset = g.preset,
        )
    }

    override fun deleteGrant(nodeId: String): Boolean = call {
        client.deleteGrant(nodeId)
    }

    override fun revokeDevice(deviceId: String) {
        call { client.revokeDevice(deviceId) }
    }

    override fun exec(
        node: String,
        program: String,
        args: List<String>,
        cwd: String?,
        env: List<String>,
        shell: Boolean,
        timeoutMs: ULong,
        sink: OutputListener,
    ): ExecResult = call {
        val done = client.exec(
            node,
            program,
            args,
            cwd,
            env,
            shell,
            timeoutMs,
            object : OutputSink {
                override fun onOutput(stream: String, data: ByteArray): Boolean = sink.onOutput(stream, data)
            },
        )
        ExecResult(done.exitCode, done.truncated)
    }

    override fun transferUp(
        node: String,
        remote: String,
        local: String,
        preferDirect: Boolean,
        sink: ProgressListener,
    ): TransferResult = call {
        client.transferUp(node, remote, local, preferDirect, object : ProgressSink {
            override fun onProgress(transferred: ULong, total: ULong) {
                sink.onProgress(transferred, total)
            }
        }).toResult()
    }

    override fun transferDown(
        node: String,
        remote: String,
        local: String,
        preferDirect: Boolean,
        sink: ProgressListener,
    ): TransferResult = call {
        client.transferDown(node, remote, local, preferDirect, object : ProgressSink {
            override fun onProgress(transferred: ULong, total: ULong) {
                sink.onProgress(transferred, total)
            }
        }).toResult()
    }

    override fun extension(node: String, name: String, payloadJson: String): String =
        call { client.extension(node, name, payloadJson) }

    override fun openLive(node: String, maxFps: UInt, bitrate: UInt, monitor: UInt): LiveDesktop =
        call { NativeLive(client.openLive(node, maxFps, bitrate, monitor)) }

    override fun openPty(node: String, command: String?, rows: Int, cols: Int): PtySession = call {
        NativePty(client.ptyOpen(node, command, rows.toUShort(), cols.toUShort()))
    }

    override fun createPairing(
        name: String,
        allowRead: Boolean,
        allowWrite: Boolean,
        allowExec: Boolean,
        allowDesktop: Boolean,
        allowDesktopStream: Boolean,
        allowRemoteView: Boolean,
        allowRemoteControl: Boolean,
        ttlSecs: ULong,
    ): PairingTicket = call {
        val issued = client.createPairing(
            name,
            policyOf(
                allowRead,
                allowWrite,
                allowExec,
                allowDesktop,
                allowDesktopStream,
                allowRemoteView,
                allowRemoteControl,
            ),
            ttlSecs,
        )
        PairingTicket(issued.token, issued.name, issued.expiresUnix)
    }

    override fun close() {
        client.close()
    }
}

private class NativeLive(private val live: DesktopLive) : LiveDesktop {
    override fun info(): LiveInfo {
        val info = call { live.info() }
        return LiveInfo(
            sessionId = info.sessionId,
            codec = info.codec,
            encoder = info.encoder,
            hardware = info.hardware,
            width = info.width.toInt(),
            height = info.height.toInt(),
            control = info.control,
            srcWidth = info.srcWidth.toInt(),
            srcHeight = info.srcHeight.toInt(),
            cursorPresentation = info.cursorPresentation,
        )
    }

    override fun pollFrame(timeoutMs: UInt): LiveFrame? {
        val frame = call { live.pollFrame(timeoutMs) } ?: return null
        return LiveFrame(
            annexB = frame.annexB,
            keyframe = frame.keyframe,
            capturedUnixMs = frame.capturedUnixMs,
            width = frame.width.toInt(),
            height = frame.height.toInt(),
        )
    }

    override fun pollCursor(): LiveCursor? {
        val cursor = call { live.pollCursor() } ?: return null
        return LiveCursor(
            x = cursor.x,
            y = cursor.y,
            shape = cursor.shape,
            visible = cursor.visible,
            hotspotX = cursor.hotspotX.toInt(),
            hotspotY = cursor.hotspotY.toInt(),
        )
    }

    override fun pollClipboard(): LiveClipboardRow? {
        val clip = call { live.pollClipboard() } ?: return null
        return LiveClipboardRow(text = clip.text, truncated = clip.truncated)
    }

    override fun stats(): LiveStats {
        val stats = call { live.stats() }
        return LiveStats(stats.frames, stats.bytes, stats.loss, stats.latencyMs)
    }

    override fun sendControl(json: String): Boolean = call { live.sendControl(json) }

    override fun sendClipboard(text: String): Boolean = call { live.sendClipboard(text) }

    override fun requestKeyframe() {
        call { live.requestKeyframe() }
    }

    override fun failed(): Boolean = call { live.failed() }

    override fun close() {
        call { live.shutdown() }
        live.destroy()
    }
}

private class NativePty(private val handle: PtyHandle) : PtySession {
    override fun poll(): String = call { handle.poll() }
    override fun write(data: ByteArray) {
        call { handle.write(data) }
    }
    override fun resize(rows: Int, cols: Int) {
        call { handle.resize(rows.toUShort(), cols.toUShort()) }
    }
    override fun close() {
        handle.shutdown()
        handle.destroy()
    }
}

private fun MachineInfo.toRow() = MachineRow(
    id = id,
    name = name,
    hostname = hostname,
    os = os,
    arch = arch,
    version = version,
    online = online,
    preset = preset,
    allowRead = policy.allowRead,
    allowWrite = policy.allowWrite,
    allowExec = policy.allowExec,
    allowDesktop = policy.allowDesktop,
    allowDesktopStream = policy.allowDesktopStream,
    allowRemoteView = policy.allowRemoteView,
    allowRemoteControl = policy.allowRemoteControl,
)

private fun FfiStats.toResult() = TransferResult(
    logicalBytes = logicalBytes,
    payloadBytes = payloadBytes,
    skipped = skipped,
    files = files,
    transport = transport,
    resumedBytes = resumedBytes,
)

internal fun policyOf(
    read: Boolean,
    write: Boolean,
    exec: Boolean,
    desktop: Boolean,
    stream: Boolean,
    view: Boolean,
    control: Boolean,
): FfiPolicy = FfiPolicy(read, write, exec, desktop, stream, view, control)

private fun <T> call(block: () -> T): T {
    try {
        return block()
    } catch (err: LinkException.Fail) {
        throw LinkFailure(err.detail)
    }
}
