package app.agentlink.ui

import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.SystemClock
import android.provider.OpenableColumns
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.FileProvider
import app.agentlink.account.AccountApi
import app.agentlink.account.looksLikeSessionExpiry
import app.agentlink.bridge.FileRow
import app.agentlink.bridge.LiveCursor
import app.agentlink.bridge.LiveDesktop
import app.agentlink.bridge.MachineRow
import app.agentlink.bridge.PtySession
import app.agentlink.model.DirItem
import app.agentlink.model.PtyKey
import app.agentlink.model.DesktopViewport
import app.agentlink.model.LIVE_BITRATE
import app.agentlink.model.LIVE_MAX_FPS
import app.agentlink.model.childPath
import app.agentlink.model.controllerKeyFromRejection
import app.agentlink.model.decorateGrantFailure
import app.agentlink.model.isGrantFixNote
import app.agentlink.model.isSignedGrantFailure
import app.agentlink.model.jsonField
import app.agentlink.model.liveControlMessages
import app.agentlink.model.liveFailureNote
import app.agentlink.model.liveFailureShouldRetry
import app.agentlink.model.liveStatus
import app.agentlink.model.looksTextual
import app.agentlink.model.parentPath
import app.agentlink.model.ptySequence
import app.agentlink.model.ptyText
import app.agentlink.model.searchFiles
import app.agentlink.model.webrtcFallsBackToScreenshot
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext
import org.json.JSONObject
import java.io.File

private enum class ShellPhase { Opening, Connected, Closed, Failed }

@Composable
internal fun FilesPane(model: ClientViewModel, machine: MachineRow) {
    val context = LocalContext.current
    var path by remember { mutableStateOf("app:/") }
    var entries by remember { mutableStateOf<List<FileRow>>(emptyList()) }
    var query by remember { mutableStateOf("") }
    var hits by remember { mutableStateOf<List<String>>(emptyList()) }
    var editor by remember { mutableStateOf<String?>(null) }
    var draft by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf<String?>(null) }
    fun showProgress(value: String?) {
        onMain { progress = value }
    }
    var askFolder by remember { mutableStateOf(false) }
    var folderName by remember { mutableStateOf("") }
    val canRead = machine.online && machine.allowRead
    val canWrite = machine.online && machine.allowWrite
    fun load(target: String) {
        if (!machine.online || !machine.allowRead) return
        loading = true
        model.work({ it.listDir(machine.id, target) }) { result ->
            loading = false
            result.onSuccess {
                path = target
                entries = it.sortedWith(compareBy<FileRow> { !it.isDir }.thenBy { it.name.lowercase() })
                note = null
            }.onFailure { note = it.message ?: "Couldn't list that folder." }
        }
    }
    fun openFile(file: String, size: ULong) {
        if (size > 262144u) {
            note = "That file is too large to edit here. Download it instead."
            return
        }
        model.work({ it.readBytes(machine.id, file, 0u, 262144u) }) { result ->
            result.onSuccess { bytes ->
                if (looksTextual(bytes)) {
                    editor = file
                    draft = bytes.decodeToString()
                    note = null
                } else {
                    note = "This file is not shown as text. Download it instead."
                }
            }.onFailure { note = it.message ?: "Couldn't open that file." }
        }
    }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val remote = childPath(path, safeFileName(displayName(context, uri)))
        model.work({ session ->
            val dest = File(context.cacheDir, "upload-${System.currentTimeMillis()}.bin")
            context.contentResolver.openInputStream(uri)?.use { input ->
                dest.outputStream().use { input.copyTo(it) }
            } ?: error("Could not read the picked file")
            session.transferUp(machine.id, remote, dest.absolutePath, true) { done, total ->
                showProgress(progressLabel(done, total))
            }
        }) { result ->
            progress = null
            result.onSuccess {
                note = "Uploaded ${it.logicalBytes} bytes via ${it.transport}"
                load(path)
            }.onFailure { note = it.message ?: "Upload failed." }
        }
    }
    LaunchedEffect(machine.id, machine.online, machine.allowRead) {
        if (canRead) load(path)
    }
    if (editor != null) {
        FileEditor(
            machine = machine,
            file = editor!!,
            draft = draft,
            onDraft = { draft = it },
            canWrite = canWrite,
            note = note,
            onClose = { editor = null },
            onSave = {
                val file = editor ?: return@FileEditor
                model.work({ it.writeBytes(machine.id, file, draft.encodeToByteArray()) }) { result ->
                    result.onSuccess { note = "Saved $file" }.onFailure { note = it.message ?: "Couldn't save that file." }
                }
            },
        )
        return
    }
    Column(modifier = Modifier.fillMaxSize()) {
        if (!machine.online) {
            AgentBanner(
                "This machine is offline. Browsing stays off until it reconnects.",
                BannerTone.Info,
                Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
        } else if (!machine.allowRead) {
            AgentBanner(
                "Reading files is turned off for this machine.",
                BannerTone.Info,
                Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
        LazyColumn(modifier = Modifier.fillMaxSize().testTag("file-browser")) {
            item {
                Column(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    MachineContextLine(machine)
                    PathBar(path, canRead) { load(it) }
                    if (loading) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    progress?.let { SupportingText(it) }
                    note?.let { FileNote(it) }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        AgentField(query, { query = it }, "Search names", Modifier.weight(1f))
                        IconButton(
                            onClick = {
                                if (!canRead) return@IconButton
                                if (query.isBlank()) {
                                    hits = emptyList()
                                    note = "Enter a name to search."
                                    return@IconButton
                                }
                                model.work({ session ->
                                    searchFiles(path, query) { dir ->
                                        session.listDir(machine.id, dir).map { DirItem(it.name, it.isDir) }
                                    }
                                }) { result ->
                                    result.onSuccess { hits = it }.onFailure { note = it.message ?: "Search failed." }
                                }
                            },
                            enabled = canRead,
                            modifier = Modifier.size(48.dp),
                        ) {
                            Icon(Icons.Filled.Search, contentDescription = "Search")
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (canRead) {
                            IconButton(onClick = { load(path) }, modifier = Modifier.size(48.dp)) {
                                Icon(Icons.Filled.Refresh, contentDescription = "Refresh folder")
                            }
                        }
                        if (canWrite) {
                            IconButton(onClick = { pick.launch("*/*") }, modifier = Modifier.size(48.dp).testTag("upload-file")) {
                                Icon(Icons.Filled.Upload, contentDescription = "Upload")
                            }
                            IconButton(
                                onClick = {
                                    folderName = ""
                                    askFolder = true
                                },
                                modifier = Modifier.size(48.dp),
                            ) {
                                Icon(Icons.Filled.CreateNewFolder, contentDescription = "New folder")
                            }
                        } else if (machine.online && machine.allowRead) {
                            SupportingText("This machine is read only.")
                        }
                    }
                }
            }
            if (canRead && !loading && entries.isEmpty()) {
                item {
                    SupportingText(
                        "This folder is empty.",
                        Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                }
            }
            items(entries, key = { "${path}/${it.name}" }) { entry ->
                FileRowItem(
                    entry = entry,
                    canDownload = canRead && !entry.isDir,
                    onOpen = {
                        val child = childPath(path, entry.name)
                        if (entry.isDir) load(child) else openFile(child, entry.size)
                    },
                    onDownload = {
                        downloadRemote(context, model, machine.id, childPath(path, entry.name), true, { progress = it }) {
                            progress = null
                            note = it
                        }
                    },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            if (hits.isNotEmpty()) {
                item {
                    SectionLabel("Search results", Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
                }
                items(hits) { hit ->
                    Text(
                        hit,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val parent = parentPath(hit) ?: path
                                val name = hit.substringAfterLast('/')
                                model.work({ session ->
                                    session.listDir(machine.id, parent).firstOrNull { it.name == name }
                                }) { result ->
                                    result.onSuccess { found ->
                                        when {
                                            found == null -> note = "Couldn't find $hit"
                                            found.isDir -> load(hit)
                                            else -> openFile(hit, found.size)
                                        }
                                    }.onFailure { note = it.message ?: "Couldn't open $hit" }
                                }
                            }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
        }
    }
    if (askFolder) {
        AlertDialog(
            onDismissRequest = { askFolder = false },
            title = { Text("New folder") },
            text = {
                AgentField(folderName, { folderName = it }, "Folder name", Modifier.fillMaxWidth())
            },
            confirmButton = {
                TextButton(onClick = {
                    val name = safeFileName(folderName)
                    askFolder = false
                    model.work({ it.mkdir(machine.id, childPath(path, name), true) }) { result ->
                        result.onSuccess {
                            note = "Created $name"
                            load(path)
                        }.onFailure { note = it.message ?: "Couldn't create the folder." }
                    }
                }) { Text("Create") }
            },
            dismissButton = {
                TextButton(onClick = { askFolder = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun PathBar(path: String, enabled: Boolean, onOpen: (String) -> Unit) {
    val crumbs = pathCrumbs(path)
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        crumbs.forEachIndexed { index, (full, label) ->
            TextButton(
                onClick = { onOpen(full) },
                enabled = enabled,
            ) {
                Text(label, fontFamily = FontFamily.Monospace)
            }
            if (index < crumbs.lastIndex) {
                Text("/", style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun FileRowItem(entry: FileRow, canDownload: Boolean, onOpen: () -> Unit, onDownload: () -> Unit) {
    val meta = buildList {
        if (entry.isSymlink) add("Link")
        if (!entry.isDir) add(formatBytes(entry.size))
        if (entry.isDir) add("Folder")
    }.joinToString(" · ")
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 64.dp).clickable(onClick = onOpen).padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            imageVector = when {
                entry.isSymlink -> Icons.Filled.Link
                entry.isDir -> Icons.Filled.Folder
                else -> Icons.Filled.Description
            },
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
        )
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(entry.name, style = MaterialTheme.typography.bodyLarge)
            if (meta.isNotEmpty()) {
                Text(meta, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (canDownload) {
            IconButton(onClick = onDownload, modifier = Modifier.size(48.dp)) {
                Icon(Icons.Filled.Download, contentDescription = "Download ${entry.name}")
            }
        }
    }
}

@Composable
private fun FileEditor(
    machine: MachineRow,
    file: String,
    draft: String,
    onDraft: (String) -> Unit,
    canWrite: Boolean,
    note: String?,
    onClose: () -> Unit,
    onSave: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose, modifier = Modifier.size(48.dp)) {
                Icon(Icons.Filled.Close, contentDescription = "Close editor")
            }
            Text(file, modifier = Modifier.weight(1f), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
        }
        MachineContextLine(machine)
        if (!canWrite) {
            AgentBanner("Read only on this machine. You can view the file, not save it.", BannerTone.Info)
        }
        note?.let { FileNote(it) }
        AgentField(
            draft,
            onDraft,
            label = "Contents",
            modifier = Modifier.fillMaxWidth().height(280.dp),
            singleLine = false,
            enabled = canWrite,
        )
        PrimaryButton("Save", onSave, Modifier.fillMaxWidth(), enabled = canWrite)
    }
}

@Composable
private fun FileNote(text: String) {
    val hint = permissionHint(text)
    if (looksLikeProblem(text) || text.contains("Couldn't", ignoreCase = true) || text.contains("failed", ignoreCase = true)) {
        ErrorNote(text)
    } else {
        SupportingText(text)
    }
    if (hint != null) SupportingText(hint)
}

@Composable
internal fun TerminalPane(model: ClientViewModel, machine: MachineRow, account: AccountApi) {
    var pty by remember { mutableStateOf<PtySession?>(null) }
    var phase by remember { mutableStateOf(ShellPhase.Closed) }
    var note by remember { mutableStateOf<String?>(null) }
    var grantRetry by remember { mutableIntStateOf(0) }
    var grantHelp by remember(machine.id) { mutableStateOf(false) }
    var deviceKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var view by remember { mutableStateOf<TerminalView?>(null) }
    var viewReady by remember { mutableStateOf(false) }
    var sizeLabel by remember { mutableStateOf("") }
    var scrolledAway by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val identityDir = context.filesDir
    val allowed = machine.online && machine.allowExec
    LaunchedEffect(machine.id, account) {
        deviceKey = withContext(Dispatchers.IO) {
            runCatching { account.devicePublicHex() }.getOrNull()
        }?.takeIf { it.isNotBlank() }
    }
    fun grantNote(message: String): String {
        if (!isSignedGrantFailure(message)) return message
        val checked = controllerKeyFromRejection(message)
        if (checked.isNotEmpty()) {
            grantKey = checked
        } else if (grantKey.isNullOrBlank()) {
            grantKey = deviceKey?.trim()?.lowercase()?.ifBlank { null }
        }
        return decorateGrantFailure(message, machine.id, deviceKey, identityDir.absolutePath)
    }
    fun writePty(bytes: ByteArray) {
        val handle = pty ?: return
        scope.launch(Dispatchers.IO) {
            runCatching { handle.write(bytes) }.onFailure {
                note = it.message ?: "Couldn't send that keystroke."
            }
        }
    }
    fun openShell() {
        if (!machine.online || !machine.allowExec || phase == ShellPhase.Opening) return
        phase = ShellPhase.Opening
        note = null
        val rows = view?.rows() ?: 24
        val cols = view?.cols() ?: 80
        model.work({ it.openPty(machine.id, null, rows, cols) }) { result ->
            result.onSuccess {
                pty?.close()
                pty = it
                phase = ShellPhase.Connected
                view?.showKeyboard()
            }.onFailure {
                phase = ShellPhase.Failed
                note = grantNote(it.message ?: "Couldn't open the shell.")
            }
        }
    }
    DisposableEffect(Unit) {
        onDispose { pty?.close() }
    }
    LaunchedEffect(copied) {
        if (copied) {
            delay(1500)
            copied = false
        }
    }
    LaunchedEffect(machine.id, viewReady, allowed, grantRetry) {
        if (viewReady && allowed && pty == null && phase != ShellPhase.Opening && phase != ShellPhase.Failed) {
            openShell()
        }
    }
    LaunchedEffect(pty, view) {
        val handle = pty ?: return@LaunchedEffect
        val terminal = view ?: return@LaunchedEffect
        while (isActive) {
            val polled = withContext(Dispatchers.IO) { runCatching { handle.poll() } }
            if (polled.isFailure) {
                note = grantNote(polled.exceptionOrNull()?.message ?: "The shell connection dropped.")
                phase = ShellPhase.Failed
                break
            }
            val event = polled.getOrThrow()
            when (jsonField(event, "event")) {
                "data" -> {
                    val raw = jsonField(event, "data_b64").orEmpty()
                    if (raw.isNotEmpty()) {
                        val bytes = Base64.decode(raw, Base64.DEFAULT)
                        withContext(Dispatchers.Main) { terminal.feed(bytes) }
                    }
                }
                "exit" -> {
                    val code = runCatching { JSONObject(event).optInt("code") }.getOrDefault(-1)
                    phase = ShellPhase.Closed
                    note = "Shell exited ($code)"
                    handle.close()
                    pty = null
                    withContext(Dispatchers.Main) { terminal.feed("\r\n[exit $code]\r\n".encodeToByteArray()) }
                    break
                }
                "error" -> {
                    val message = grantNote(
                        jsonField(event, "message").orEmpty().ifBlank { "The shell reported an error." },
                    )
                    phase = ShellPhase.Failed
                    note = message
                    withContext(Dispatchers.Main) { terminal.feed("\r\n$message\r\n".encodeToByteArray()) }
                }
            }
            delay(30)
        }
    }
    Column(modifier = Modifier.fillMaxSize()) {
        ShellStatusBar(
            phase = phase,
            note = note,
            sizeLabel = sizeLabel,
            copied = copied,
            blocked = if (!machine.online) {
                "This machine is offline. The shell stays off until it reconnects."
            } else if (!machine.allowExec) {
                "Needs exec permission. Pairing or the node ceiling did not allow a shell."
            } else {
                null
            },
            onImportGrant = if (isGrantFixNote(note)) {
                { grantHelp = true }
            } else {
                null
            },
        )
        if (grantHelp) {
            GrantFixDialog(
                node = machine.id,
                pubkey = grantKey ?: deviceKey,
                identityDir = identityDir,
                onClose = { grantHelp = false },
                onImported = {
                    grantHelp = false
                    pty?.close()
                    pty = null
                    phase = ShellPhase.Closed
                    note = "Grant imported. Opening the shell."
                    grantRetry += 1
                },
            )
        }
        if (!allowed) {
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                MachineContextLine(machine)
            }
            return@Column
        }
        AndroidView(
            factory = { context ->
                TerminalView(context).apply {
                    onBytes = { bytes -> writePty(bytes) }
                    onResize = { rows, cols ->
                        sizeLabel = "${cols}×${rows}"
                        val handle = pty
                        if (handle != null) {
                            scope.launch(Dispatchers.IO) { runCatching { handle.resize(rows, cols) } }
                        }
                    }
                    onScrolledAway = { scrolledAway = it }
                }
            },
            update = { terminal ->
                view = terminal
                terminal.onBytes = { bytes -> writePty(bytes) }
                terminal.onResize = { rows, cols ->
                    sizeLabel = "${cols}×${rows}"
                    val handle = pty
                    if (handle != null) {
                        scope.launch(Dispatchers.IO) { runCatching { handle.resize(rows, cols) } }
                    }
                }
                terminal.onScrolledAway = { scrolledAway = it }
                if (!viewReady) viewReady = true
            },
            modifier = Modifier.fillMaxWidth().weight(1f).testTag("terminal-view"),
        )
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 8.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            SecondaryButton("Keyboard", onClick = { view?.showKeyboard() })
            SecondaryButton("Copy", onClick = {
                val text = view?.transcript().orEmpty()
                if (text.isNotBlank()) {
                    copyPlainText(context, "Terminal", text)
                    copied = true
                }
            })
            SecondaryButton(
                text = when {
                    phase == ShellPhase.Opening -> "Connecting"
                    pty == null -> "Open shell"
                    else -> "Reconnect"
                },
                onClick = {
                    pty?.close()
                    pty = null
                    view?.clearTranscript()
                    phase = ShellPhase.Closed
                    openShell()
                },
                enabled = phase != ShellPhase.Opening,
            )
            if (scrolledAway) {
                SecondaryButton("Latest", onClick = { view?.jumpToLatest() })
            }
            SecondaryButton("Esc", onClick = { writePty(ptySequence(PtyKey.Escape, false)) })
            SecondaryButton("Tab", onClick = { writePty(ptySequence(PtyKey.Tab, false)) })
            SecondaryButton("Ctrl-C", onClick = { writePty(ptyText("c", ctrl = true)) })
            SecondaryButton("Ctrl-D", onClick = { writePty(ptyText("d", ctrl = true)) })
            SecondaryButton("Up", onClick = { writePty(ptySequence(PtyKey.Up, view?.screen?.applicationCursor == true)) })
            SecondaryButton("Down", onClick = { writePty(ptySequence(PtyKey.Down, view?.screen?.applicationCursor == true)) })
            SecondaryButton("Left", onClick = { writePty(ptySequence(PtyKey.Left, view?.screen?.applicationCursor == true)) })
            SecondaryButton("Right", onClick = { writePty(ptySequence(PtyKey.Right, view?.screen?.applicationCursor == true)) })
        }
    }
}

@Composable
private fun ShellStatusBar(
    phase: ShellPhase,
    note: String?,
    sizeLabel: String,
    copied: Boolean,
    blocked: String?,
    onImportGrant: (() -> Unit)? = null,
) {
    val scheme = MaterialTheme.colorScheme
    val noteScroll = rememberScrollState()
    val label = when {
        copied -> "Copied"
        blocked != null -> "Unavailable"
        phase == ShellPhase.Opening -> "Connecting"
        phase == ShellPhase.Connected -> "Connected"
        phase == ShellPhase.Failed -> "Disconnected"
        else -> "Not connected"
    }
    val detail = blocked ?: note
    Column {
        Row(
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 16.dp).testTag("terminal-status"),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .background(
                        color = when (phase) {
                            ShellPhase.Connected -> scheme.tertiary
                            ShellPhase.Failed -> scheme.error
                            else -> scheme.outline
                        },
                        shape = androidx.compose.foundation.shape.CircleShape,
                    ),
            )
            Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
            if (sizeLabel.isNotEmpty() && blocked == null) {
                Text(sizeLabel, style = MaterialTheme.typography.bodyLarge, color = scheme.onSurfaceVariant)
            }
        }
        if (detail != null) {
            Text(
                detail,
                modifier = Modifier
                    .heightIn(max = 160.dp)
                    .verticalScroll(noteScroll)
                    .padding(horizontal = 16.dp, vertical = 4.dp)
                    .testTag("terminal-note"),
                style = MaterialTheme.typography.bodyLarge,
                color = if (phase == ShellPhase.Failed || blocked != null) scheme.onSurface else scheme.onSurfaceVariant,
            )
        }
        if (onImportGrant != null) {
            SecondaryButton(
                "Import grant",
                onImportGrant,
                Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("import-grant"),
            )
        }
    }
}

@Composable
internal fun TransferPane(model: ClientViewModel, machine: MachineRow) {
    val context = LocalContext.current
    var remote by remember { mutableStateOf("app:/files/from-phone.bin") }
    var direct by remember { mutableStateOf(true) }
    var note by remember { mutableStateOf("Tries a direct connection, then the relay.") }
    val progress = remember { MutableStateFlow("idle") }
    var progressText by remember { mutableStateOf("idle") }
    val online = machine.online
    val canRead = online && machine.allowRead
    val canWrite = online && machine.allowWrite
    LaunchedEffect(progress) { progress.collect { progressText = it } }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null || !canWrite) return@rememberLauncherForActivityResult
        model.work({ session ->
            val dest = File(context.cacheDir, "upload-${System.currentTimeMillis()}.bin")
            context.contentResolver.openInputStream(uri)?.use { input ->
                dest.outputStream().use { input.copyTo(it) }
            } ?: error("Could not read the picked file")
            session.transferUp(machine.id, remote, dest.absolutePath, direct) { done, total ->
                progress.value = progressLabel(done, total)
            }
        }) { result ->
            result.onSuccess { note = "Uploaded ${it.logicalBytes} bytes via ${it.transport}" }
                .onFailure { note = it.message ?: "Upload failed." }
        }
    }
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        MachineContextLine(machine)
        if (!online) {
            AgentBanner("This machine is offline. Transfer stays off until it reconnects.", BannerTone.Info)
        } else if (!canRead && !canWrite) {
            AgentBanner("File transfer is turned off for this machine.", BannerTone.Info)
        }
        AgentField(remote, { remote = it }, "Remote path", Modifier.fillMaxWidth(), enabled = online)
        Row(
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Try a direct connection", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            AgentSwitch(direct, { direct = it })
        }
        if (progressText != "idle") {
            SupportingText(progressText)
            val fraction = progressFraction(progressText)
            if (fraction != null) {
                LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
            }
        }
        FileNote(note)
        PrimaryButton("Upload to the machine", onClick = { pick.launch("*/*") }, enabled = canWrite, modifier = Modifier.fillMaxWidth())
        PrimaryButton(
            "Download to the phone",
            onClick = {
                downloadRemote(context, model, machine.id, remote, direct, { progress.value = it }) { message ->
                    note = message
                }
            },
            enabled = canRead,
            modifier = Modifier.fillMaxWidth(),
        )
        if (online && !canWrite) SupportingText("Uploads need write permission.")
        if (online && !canRead) SupportingText("Downloads need read permission.")
    }
}

@Composable
internal fun AuditPane(model: ClientViewModel, machine: MachineRow) {
    var text by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    fun load() {
        if (!machine.online || !machine.allowRead) return
        loading = true
        model.work({ it.readBytes(machine.id, "app:/audit.log", 0u, 512000u) }) { result ->
            loading = false
            result.onSuccess { bytes ->
                note = null
                text = bytes.decodeToString().lineSequence().toList().takeLast(80).joinToString("\n")
            }.onFailure {
                note = it.message ?: "Couldn't read the audit log."
                text = ""
            }
        }
    }
    LaunchedEffect(machine.id, machine.online, machine.allowRead) { load() }
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        MachineContextLine(machine)
        if (!machine.online) {
            AgentBanner("This machine is offline. The audit log stays unread until it reconnects.", BannerTone.Info)
        } else if (!machine.allowRead) {
            AgentBanner("Reading files is turned off, so the audit log is hidden.", BannerTone.Info)
        } else {
            SecondaryButton("Refresh", onClick = { load() }, modifier = Modifier.fillMaxWidth(), enabled = !loading)
        }
        if (loading) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        note?.let { FileNote(it) }
        AgentCard(modifier = Modifier.weight(1f)) {
            Text(
                text.ifBlank { if (loading) "Loading" else "No audit lines yet." },
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyLarge,
                color = if (text.isBlank()) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(12.dp).verticalScroll(rememberScrollState()),
            )
        }
    }
}

@Composable
internal fun DesktopPane(
    model: ClientViewModel,
    machine: MachineRow,
    account: AccountApi,
) {
    val capability = desktopCapability(machine)
    if (!capability.available) {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            MachineContextLine(machine)
            DesktopUnavailable(capability.reason)
        }
    } else {
        DesktopSession(model, machine, capability, account)
    }
}

private enum class LiveEnd { Retry, Fallback, Stopped }

@Composable
private fun DesktopSession(
    model: ClientViewModel,
    machine: MachineRow,
    capability: DesktopCapability,
    account: AccountApi,
) {
    var note by remember(machine.id) { mutableStateOf(capability.reason) }
    var bitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var shotW by remember { mutableIntStateOf(1) }
    var shotH by remember { mutableIntStateOf(1) }
    var watch by remember(machine.id) { mutableStateOf(capability.screenshots || capability.live) }
    var retryToken by remember(machine.id) { mutableIntStateOf(0) }
    var typed by remember { mutableStateOf("") }
    var fullscreen by rememberSaveable(machine.id) { mutableStateOf(false) }
    var viewport by remember(machine.id) { mutableStateOf(DesktopViewport()) }
    var live by remember { mutableStateOf<LiveDesktop?>(null) }
    var player by remember { mutableStateOf<H264Player?>(null) }
    var usingJpeg by remember { mutableStateOf(false) }
    var connecting by remember { mutableStateOf(false) }
    var cursor by remember { mutableStateOf<LiveCursor?>(null) }
    var decoderLabel by remember { mutableStateOf("decoder") }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val identityDir = context.filesDir
    var deviceKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantHelp by remember(machine.id) { mutableStateOf(false) }
    LaunchedEffect(machine.id, account) {
        deviceKey = withContext(Dispatchers.IO) {
            runCatching { account.devicePublicHex() }.getOrNull()
        }?.takeIf { it.isNotBlank() }
    }
    fun grantNote(message: String): String {
        if (!isSignedGrantFailure(message)) return message
        val checked = controllerKeyFromRejection(message)
        if (checked.isNotEmpty()) {
            grantKey = checked
        } else if (grantKey.isNullOrBlank()) {
            grantKey = deviceKey?.trim()?.lowercase()?.ifBlank { null }
        }
        return decorateGrantFailure(message, machine.id, deviceKey, identityDir.absolutePath)
    }
    fun grab() {
        model.work({ it.extension(machine.id, "screenshot", """{"quality":55}""") }) { result ->
            result.onSuccess { body ->
                if (webrtcFallsBackToScreenshot(body)) {
                    note = "Live video is not available. Showing screenshots."
                }
                val parsed = runCatching { JSONObject(body) }.getOrNull()
                val encoded = parsed?.optString("data_b64").orEmpty()
                if (encoded.isNotEmpty()) {
                    val bytes = Base64.decode(encoded, Base64.DEFAULT)
                    val decoded = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    bitmap = decoded
                    val reportedW = parsed?.optInt("width") ?: 0
                    val reportedH = parsed?.optInt("height") ?: 0
                    shotW = if (reportedW > 0) reportedW else decoded?.width?.takeIf { it > 0 } ?: 1
                    shotH = if (reportedH > 0) reportedH else decoded?.height?.takeIf { it > 0 } ?: 1
                    note = "Screenshot ${shotW}×${shotH}"
                } else if (!webrtcFallsBackToScreenshot(body)) {
                    note = shortNote(body)
                }
            }.onFailure {
                val message = it.message ?: "Screenshot failed."
                note = grantNote(message)
                if (fatalDesktopMessage(message) || looksLikeSessionExpiry(message)) watch = false
            }
        }
    }
    fun send(payload: JSONObject) {
        if (!capability.control) return
        scope.launch {
            model.work({ it.extension(machine.id, "inject_input", payload.toString()) }) { result ->
                result.onFailure { note = grantNote(it.message ?: "Couldn't send input.") }
            }
        }
    }
    fun sendLive(
        kind: String,
        x: Float = 0f,
        y: Float = 0f,
        x2: Float = 0f,
        y2: Float = 0f,
        text: String = "",
        name: String = "",
    ): Boolean {
        val current = live ?: return false
        val messages = liveControlMessages(kind, shotW, shotH, x, y, x2, y2, text, name)
        if (messages.isEmpty()) return false
        return messages.all { current.sendControl(it) }
    }
    fun deliver(payload: JSONObject) {
        val kind = payload.optString("action")
        val sent = when (kind) {
            "tap" -> sendLive("tap", x = payload.optDouble("x").toFloat(), y = payload.optDouble("y").toFloat())
            "swipe" -> sendLive(
                "swipe",
                x = payload.optDouble("x").toFloat(),
                y = payload.optDouble("y").toFloat(),
                x2 = payload.optDouble("x2").toFloat(),
                y2 = payload.optDouble("y2").toFloat(),
            )
            "type" -> sendLive("type", text = payload.optString("text"))
            "key" -> sendLive("key", name = payload.optString("name"))
            else -> false
        }
        if (!sent) send(payload)
    }
    suspend fun runLive(autoRetry: Boolean): LiveEnd {
        val session = model.session ?: return LiveEnd.Stopped
        connecting = true
        val opened = try {
            withContext(Dispatchers.IO) {
                session.openLive(machine.id, LIVE_MAX_FPS.toUInt(), LIVE_BITRATE.toUInt(), 0u)
                    ?: throw IllegalStateException("live video is not available; fallback screenshot")
            }
        } catch (cancel: CancellationException) {
            connecting = false
            throw cancel
        } catch (err: Exception) {
            connecting = false
            val message = err.message ?: "Live video did not start."
            note = if (isSignedGrantFailure(message)) {
                grantNote(message)
            } else {
                liveFailureNote(message, capability.screenshots)
            }
            if (fatalDesktopMessage(message) || looksLikeSessionExpiry(message)) {
                watch = false
                return LiveEnd.Stopped
            }
            if (autoRetry && liveFailureShouldRetry(message)) return LiveEnd.Retry
            return LiveEnd.Fallback
        }
        connecting = false
        val decoder = H264Player(context)
        live = opened
        player = decoder
        val info = opened.info()
        if (info.width > 0) shotW = info.width
        if (info.height > 0) shotH = info.height
        decoder.setVideoSize(shotW, shotH)
        note = liveStatus(info.codec, info.encoder, info.hardware, shotW, shotH, decoder.decoderLabel(), 0.0)
        val started = SystemClock.elapsedRealtime()
        var sawFrame = false
        var end = LiveEnd.Fallback
        try {
            while (coroutineContext.isActive && watch) {
                if (opened.failed()) {
                    end = if (!sawFrame && autoRetry) LiveEnd.Retry else LiveEnd.Fallback
                    if (end == LiveEnd.Fallback) note = liveFailureNote("connection failed", capability.screenshots)
                    break
                }
                val frame = withContext(Dispatchers.IO) { opened.pollFrame(40u) }
                val failure = decoder.failure()
                if (failure != null) {
                    note = if (isSignedGrantFailure(failure)) {
                        grantNote(failure)
                    } else {
                        liveFailureNote(failure, capability.screenshots)
                    }
                    end = LiveEnd.Fallback
                    break
                }
                if (frame != null) {
                    if (!sawFrame) sawFrame = true
                    if (frame.width > 0 && frame.height > 0 && (frame.width != shotW || frame.height != shotH)) {
                        shotW = frame.width
                        shotH = frame.height
                        decoder.setVideoSize(shotW, shotH)
                    }
                    decoder.submit(frame.annexB, frame.keyframe)
                    decoderLabel = decoder.decoderLabel()
                    val stats = opened.stats()
                    val next = liveStatus(info.codec, info.encoder, info.hardware, shotW, shotH, decoderLabel, stats.loss)
                    if (next != note) note = next
                } else if (!sawFrame && SystemClock.elapsedRealtime() - started > 8_000) {
                    end = if (autoRetry) LiveEnd.Retry else LiveEnd.Fallback
                    if (end == LiveEnd.Fallback) note = liveFailureNote("timed out", capability.screenshots)
                    break
                }
                cursor = opened.pollCursor()
            }
            if (!watch) end = LiveEnd.Stopped
        } finally {
            withContext(NonCancellable) {
                withContext(Dispatchers.IO) { opened.close() }
            }
            if (live === opened) live = null
            player = null
            cursor = null
        }
        return end
    }
    DisposableEffect(player) {
        val current = player
        onDispose { current?.dispose() }
    }
    LaunchedEffect(watch, machine.id, retryToken, capability.live, capability.screenshots) {
        live?.close()
        live = null
        player = null
        usingJpeg = false
        cursor = null
        bitmap = null
        if (!watch) return@LaunchedEffect
        if (capability.live) {
            var autoRetry = true
            while (isActive && watch) {
                when (val end = runLive(autoRetry)) {
                    LiveEnd.Retry -> autoRetry = false
                    LiveEnd.Fallback -> break
                    LiveEnd.Stopped -> return@LaunchedEffect
                }
            }
        }
        if (!isActive || !watch || !capability.screenshots) return@LaunchedEffect
        usingJpeg = true
        while (isActive && watch) {
            grab()
            delay(700)
        }
    }
    val frame = remember(bitmap) { bitmap?.asImageBitmap() }
    val connected = live != null && !usingJpeg
    val waiting = when {
        connecting -> "Connecting live view."
        capability.live && !usingJpeg && watch -> "Waiting for a picture."
        capability.screenshots -> "Waiting for a screenshot."
        else -> "No picture yet."
    }
    DesktopView(
        machine = machine,
        capability = capability,
        note = note,
        frame = frame,
        shotW = shotW,
        shotH = shotH,
        stream = watch,
        onStream = { watch = it },
        typed = typed,
        onTyped = { typed = it },
        onLive = {
            if (connected) {
                live?.requestKeyframe()
            } else {
                watch = true
                retryToken += 1
            }
        },
        onInject = { payload -> deliver(payload) },
        fullscreen = fullscreen,
        onFullscreenChange = { fullscreen = it },
        viewport = viewport,
        onViewportChange = { viewport = it },
        livePlayer = if (connected) player else null,
        cursor = cursor,
        emptyText = waiting,
        liveButton = if (connected) "Request keyframe" else "Retry live view",
        liveButtonEnabled = !connecting,
        onFixGrant = if (isGrantFixNote(note)) {
            { grantHelp = true }
        } else {
            null
        },
    )
    if (grantHelp) {
        GrantFixDialog(
            node = machine.id,
            pubkey = grantKey ?: deviceKey,
            identityDir = identityDir,
            onClose = { grantHelp = false },
            onImported = {
                grantHelp = false
                note = "Grant imported. Reconnecting."
                if (capability.live || capability.screenshots) {
                    watch = true
                    retryToken += 1
                }
            },
        )
    }
}

@Composable
internal fun DesktopUnavailable(reason: String) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            Icons.Filled.DesktopWindows,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text("Desktop unavailable", style = MaterialTheme.typography.headlineSmall)
        SupportingText(reason)
    }
}

private fun downloadRemote(
    context: Context,
    model: ClientViewModel,
    node: String,
    remote: String,
    direct: Boolean,
    onProgress: (String) -> Unit,
    onNote: (String) -> Unit,
) {
    model.work({ session ->
        val name = safeFileName(remote.substringAfterLast('/'))
        val dest = File(context.cacheDir, name)
        val stats = session.transferDown(node, remote, dest.absolutePath, direct) { done, total ->
            onProgress(progressLabel(done, total))
        }
        dest to stats
    }) { result ->
        result.onSuccess { (file, stats) ->
            onNote("Downloaded ${stats.logicalBytes} bytes via ${stats.transport}")
            shareFile(context, file)
        }.onFailure { onNote(it.message ?: "Download failed.") }
    }
}

private fun progressLabel(done: ULong, total: ULong): String {
    return if (total == 0uL) formatBytes(done) else "${formatBytes(done)} / ${formatBytes(total)}"
}

private fun progressFraction(label: String): Float? {
    val parts = label.split(" / ")
    if (parts.size != 2) return null
    fun parse(part: String): Double? {
        val bits = part.trim().split(' ')
        val number = bits.firstOrNull()?.toDoubleOrNull() ?: return null
        val scale = when (bits.getOrNull(1)) {
            "KB" -> 1024.0
            "MB" -> 1024.0 * 1024.0
            "GB" -> 1024.0 * 1024.0 * 1024.0
            "TB" -> 1024.0 * 1024.0 * 1024.0 * 1024.0
            else -> 1.0
        }
        return number * scale
    }
    val done = parse(parts[0]) ?: return null
    val total = parse(parts[1]) ?: return null
    if (total <= 0.0) return null
    return (done / total).toFloat().coerceIn(0f, 1f)
}

private fun onMain(block: () -> Unit) {
    val main = android.os.Looper.getMainLooper()
    if (android.os.Looper.myLooper() == main) block() else android.os.Handler(main).post(block)
}

internal fun displayName(context: Context, uri: Uri): String {
    val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
    context.contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) {
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0) {
                val name = cursor.getString(index)
                if (!name.isNullOrBlank()) return name
            }
        }
    }
    return uri.lastPathSegment ?: "upload.bin"
}

private fun shareFile(context: Context, file: File) {
    val uri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.files", file)
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "application/octet-stream"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, "Downloaded file"))
}
