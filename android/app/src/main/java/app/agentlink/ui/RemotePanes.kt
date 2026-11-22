package app.agentlink.ui

import android.content.ClipboardManager
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
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
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
import app.agentlink.model.defaultRootPath
import app.agentlink.model.defaultTransferPath
import app.agentlink.model.isGrantFixNote
import app.agentlink.model.isSignedGrantFailure
import app.agentlink.model.jsonField
import app.agentlink.model.liveControlMessages
import app.agentlink.model.liveFailureNote
import app.agentlink.model.liveFailureShouldRetry
import app.agentlink.model.liveStatus
import app.agentlink.model.looksTextual
import app.agentlink.model.parentPath
import app.agentlink.model.PTY_WRITE_CLOSED_MESSAGE
import app.agentlink.model.PTY_WRITE_FULL_MESSAGE
import app.agentlink.model.PtyClientPolicy
import app.agentlink.model.PtyWriteOffer
import app.agentlink.model.offerPtyWrite
import app.agentlink.model.ptySequence
import app.agentlink.model.ptyText
import app.agentlink.model.searchFiles
import app.agentlink.model.webrtcFallsBackToScreenshot
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.coroutineContext
import org.json.JSONObject
import java.io.File

private enum class ShellPhase { Opening, Connected, Closed, Failed }

@Composable
internal fun FilesPane(model: ClientViewModel, machine: MachineRow, account: AccountApi? = null) {
    val context = LocalContext.current
    val identityDir = context.filesDir
    var path by rememberSaveable(machine.id) { mutableStateOf(defaultRootPath(machine.os)) }
    var pathInput by rememberSaveable(machine.id) { mutableStateOf(path) }
    var entries by remember { mutableStateOf<List<FileRow>>(emptyList()) }
    var query by remember { mutableStateOf("") }
    var searchContentMode by remember { mutableStateOf(false) }
    var hits by remember { mutableStateOf<List<String>>(emptyList()) }
    var editor by remember { mutableStateOf<String?>(null) }
    var draft by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf<String?>(null) }
    var deviceKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantHelp by remember(machine.id) { mutableStateOf(false) }
    LaunchedEffect(machine.id, account) {
        deviceKey = withContext(Dispatchers.IO) {
            runCatching { account?.devicePublicHex() }.getOrNull()
        }?.takeIf { it.isNotBlank() }
    }
    fun grantNote(message: String): String {
        if (!isSignedGrantFailure(message)) return message
        val checked = controllerKeyFromRejection(message)
        if (checked.isNotEmpty()) grantKey = checked
        else if (grantKey.isNullOrBlank()) grantKey = deviceKey?.trim()?.lowercase()?.ifBlank { null }
        return decorateGrantFailure(message, machine.id, deviceKey, identityDir.absolutePath)
    }
    fun showProgress(value: String?) {
        onMain { progress = value }
    }
    var askFolder by remember { mutableStateOf(false) }
    var folderName by remember { mutableStateOf("") }
    var renameTarget by remember { mutableStateOf<FileRow?>(null) }
    var renameInput by remember { mutableStateOf("") }
    var deleteTarget by remember { mutableStateOf<FileRow?>(null) }
    val canRead = machine.online && machine.allowRead
    val canWrite = machine.online && machine.allowWrite
    fun load(target: String) {
        if (!machine.online || !machine.allowRead) return
        val cleaned = target.trim().ifBlank { defaultRootPath(machine.os) }
        loading = true
        model.work({ it.listDir(machine.id, cleaned) }) { result ->
            loading = false
            result.onSuccess {
                path = cleaned
                pathInput = cleaned
                entries = it.sortedWith(compareBy<FileRow> { !it.isDir }.thenBy { it.name.lowercase() })
                note = null
            }.onFailure { note = grantNote(it.message ?: "Couldn't list that folder.") }
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
            }.onFailure { note = grantNote(it.message ?: "Couldn't open that file.") }
        }
    }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val remote = childPath(path, safeFileName(displayName(context, uri)))
        model.work({ session ->
            val xferDir = File(context.cacheDir, "client-xfer").apply { mkdirs() }
            val dest = File(xferDir, "upload-${System.currentTimeMillis()}-${java.util.UUID.randomUUID()}.bin")
            try {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    dest.outputStream().use { input.copyTo(it) }
                } ?: error("Could not read the picked file")
                session.transferUp(machine.id, remote, dest.absolutePath, true) { done, total ->
                    showProgress(progressLabel(done, total))
                }
            } finally {
                runCatching { dest.delete() }
            }
        }) { result ->
            progress = null
            result.onSuccess {
                note = "Uploaded ${it.logicalBytes} bytes via ${it.transport}"
                load(path)
            }.onFailure { note = grantNote(it.message ?: "Upload failed.") }
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
                    result.onSuccess { note = "Saved $file" }.onFailure { note = grantNote(it.message ?: "Couldn't save that file.") }
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
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        val up = parentPath(path)
                        IconButton(
                            onClick = { if (up != null) load(up) },
                            enabled = canRead && up != null,
                            modifier = Modifier.size(48.dp).testTag("path-up"),
                        ) {
                            Icon(Icons.Filled.ArrowUpward, contentDescription = "Up folder")
                        }
                        AgentField(pathInput, { pathInput = it }, "Path", Modifier.weight(1f).testTag("path-input"), enabled = canRead)
                        SecondaryButton("Go", onClick = { load(pathInput) }, enabled = canRead)
                    }
                    PathBar(path, canRead) { load(it) }
                    if (loading) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    progress?.let { SupportingText(it) }
                    note?.let {
                        FileNote(it)
                        if (isGrantFixNote(it)) {
                            SecondaryButton("Import grant", { grantHelp = true }, Modifier.testTag("import-grant"))
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        AgentFilterChip(!searchContentMode, "Names", { searchContentMode = false })
                        AgentFilterChip(searchContentMode, "Content", { searchContentMode = true })
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        AgentField(
                            query,
                            { query = it },
                            if (searchContentMode) "Search file contents" else "Search names",
                            Modifier.weight(1f),
                        )
                        IconButton(
                            onClick = {
                                if (!canRead) return@IconButton
                                if (query.isBlank()) {
                                    hits = emptyList()
                                    note = "Enter a query to search."
                                    return@IconButton
                                }
                                model.work({ session ->
                                    if (searchContentMode) {
                                        val raw = session.searchContent(machine.id, path, query.trim())
                                        parseSearchHits(raw, isContent = true)
                                    } else {
                                        val raw = runCatching {
                                            session.findFiles(machine.id, path, query.trim())
                                        }.getOrDefault("")
                                        val serverHits = parseSearchHits(raw, isContent = false)
                                        if (raw.isNotBlank()) serverHits
                                        else searchFiles(path, query) { dir ->
                                            session.listDir(machine.id, dir).map { DirItem(it.name, it.isDir) }
                                        }
                                    }
                                }) { result ->
                                    result.onSuccess {
                                        hits = it
                                        note = if (it.isEmpty()) "No matches." else "${it.size} match(es)."
                                    }.onFailure { note = grantNote(it.message ?: "Search failed.") }
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
                    canWrite = canWrite,
                    onOpen = {
                        val child = childPath(path, entry.name)
                        if (entry.isDir) load(child) else openFile(child, entry.size)
                    },
                    onDownload = {
                        downloadRemote(context, model, machine.id, childPath(path, entry.name), true, { progress = it }) {
                            progress = null
                            note = grantNote(it)
                        }
                    },
                    onRename = {
                        renameTarget = entry
                        renameInput = entry.name
                    },
                    onDelete = { deleteTarget = entry },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            if (hits.isNotEmpty()) {
                item {
                    SectionLabel("Search results", Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
                }
                items(hits) { hit ->
                    val hitPath = hit.substringBefore(": ")
                    Text(
                        hit,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val parent = parentPath(hitPath) ?: path
                                val name = hitPath.substringAfterLast('/')
                                model.work({ session ->
                                    session.listDir(machine.id, parent).firstOrNull { it.name == name }
                                }) { result ->
                                    result.onSuccess { found ->
                                        when {
                                            found == null -> note = "Couldn't find $hitPath"
                                            found.isDir -> load(hitPath)
                                            else -> openFile(hitPath, found.size)
                                        }
                                    }.onFailure { note = grantNote(it.message ?: "Couldn't open $hitPath") }
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
    if (grantHelp) {
        GrantFixDialog(
            node = machine.id,
            pubkey = grantKey ?: deviceKey,
            identityDir = identityDir,
            onClose = { grantHelp = false },
            onImported = {
                grantHelp = false
                note = "Grant imported. Reloading folder."
                load(path)
            },
        )
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
                        }.onFailure { note = grantNote(it.message ?: "Couldn't create the folder.") }
                    }
                }) { Text("Create") }
            },
            dismissButton = {
                TextButton(onClick = { askFolder = false }) { Text("Cancel") }
            },
        )
    }
    renameTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { renameTarget = null },
            title = { Text("Rename ${target.name}") },
            text = {
                AgentField(renameInput, { renameInput = it }, "New name", Modifier.fillMaxWidth())
            },
            confirmButton = {
                TextButton(onClick = {
                    val nextName = safeFileName(renameInput)
                    renameTarget = null
                    model.work({
                        it.rename(machine.id, childPath(path, target.name), childPath(path, nextName))
                    }) { result ->
                        result.onSuccess {
                            note = "Renamed to $nextName"
                            load(path)
                        }.onFailure { note = grantNote(it.message ?: "Couldn't rename.") }
                    }
                }) { Text("Rename") }
            },
            dismissButton = {
                TextButton(onClick = { renameTarget = null }) { Text("Cancel") }
            },
        )
    }
    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Delete ${target.name}?") },
            text = {
                Text(
                    if (target.isDir) "This deletes the folder and everything inside it."
                    else "This permanently deletes ${target.name} on ${machine.name}.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    deleteTarget = null
                    model.work({
                        it.remove(machine.id, childPath(path, target.name), target.isDir)
                    }) { result ->
                        result.onSuccess {
                            note = "Deleted ${target.name}"
                            load(path)
                        }.onFailure { note = grantNote(it.message ?: "Couldn't delete.") }
                    }
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text("Cancel") }
            },
        )
    }
}

private fun parseSearchHits(rawJson: String, isContent: Boolean): List<String> {
    if (rawJson.isBlank()) return emptyList()
    return runCatching {
        val obj = JSONObject(rawJson)
        val out = mutableListOf<String>()
        if (isContent) {
            val matches = obj.optJSONArray("matches") ?: return emptyList()
            for (i in 0 until matches.length()) {
                val item = matches.optJSONObject(i) ?: continue
                val p = item.optString("path")
                if (p.isBlank()) continue
                val line = item.optInt("line", 0)
                val text = item.optString("text").trim()
                out += if (line > 0) "$p: L$line $text" else "$p: $text"
            }
        } else {
            val files = obj.optJSONArray("files") ?: obj.optJSONArray("matches") ?: return emptyList()
            for (i in 0 until files.length()) {
                val elem = files.opt(i)
                when (elem) {
                    is String -> if (elem.isNotBlank()) out += elem
                    is JSONObject -> {
                        val p = elem.optString("path").ifBlank { elem.optString("name") }
                        if (p.isNotBlank()) out += p
                    }
                }
            }
        }
        out
    }.getOrDefault(emptyList())
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
private fun FileRowItem(
    entry: FileRow,
    canDownload: Boolean,
    canWrite: Boolean,
    onOpen: () -> Unit,
    onDownload: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
) {
    val meta = buildList {
        if (entry.isSymlink) add("Link")
        if (!entry.isDir) add(formatBytes(entry.size))
        if (entry.isDir) add("Folder")
    }.joinToString(" · ")
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 64.dp).clickable(onClick = onOpen).padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
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
        if (canWrite) {
            IconButton(onClick = onRename, modifier = Modifier.size(48.dp)) {
                Icon(Icons.Filled.Edit, contentDescription = "Rename ${entry.name}")
            }
            IconButton(onClick = onDelete, modifier = Modifier.size(48.dp)) {
                Icon(Icons.Filled.Delete, contentDescription = "Delete ${entry.name}")
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
    val existingPty = remember(machine.id) { model.retainedPty(machine.id) }
    var pty by remember(machine.id) { mutableStateOf<PtySession?>(existingPty) }
    var phase by remember(machine.id) {
        mutableStateOf(if (existingPty != null) ShellPhase.Connected else ShellPhase.Closed)
    }
    var note by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantRetry by remember { mutableIntStateOf(0) }
    var grantHelp by remember(machine.id) { mutableStateOf(false) }
    var deviceKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var view by remember { mutableStateOf<TerminalView?>(null) }
    var viewReady by remember { mutableStateOf(false) }
    var sizeLabel by remember { mutableStateOf("") }
    var scrolledAway by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    var stickyCtrl by remember { mutableStateOf(false) }
    var stickyAlt by remember { mutableStateOf(false) }
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
    val ptyRef = remember { AtomicReference<PtySession?>(null) }
    ptyRef.set(pty)
    // Tie write queue lifecycle to the active PTY handle so Reconnect gets a fresh open channel.
    val ptyWrites = remember(pty) { Channel<ByteArray>(PtyClientPolicy.WRITE_QUEUE_CAP) }
    LaunchedEffect(pty, ptyWrites) {
        val handle = pty ?: return@LaunchedEffect
        withContext(Dispatchers.IO) {
            for (bytes in ptyWrites) {
                if (ptyRef.get() !== handle) break
                runCatching { handle.write(bytes) }.onFailure {
                    val message = it.message ?: PTY_WRITE_FULL_MESSAGE
                    withContext(Dispatchers.Main) {
                        if (pty === handle) {
                            note = message
                            phase = ShellPhase.Failed
                            ptyWrites.close()
                            model.releasePty(machine.id, handle)
                            pty = null
                        }
                    }
                }
            }
        }
    }
    fun failWrite(message: String) {
        val current = pty
        note = message
        phase = ShellPhase.Failed
        ptyWrites.close()
        if (current != null) model.releasePty(machine.id, current)
        pty = null
    }
    fun writePty(bytes: ByteArray) {
        if (bytes.isEmpty() || ptyRef.get() == null) return
        when (offerPtyWrite(ptyWrites, bytes)) {
            PtyWriteOffer.Queued, PtyWriteOffer.Empty -> Unit
            PtyWriteOffer.Full -> failWrite(PTY_WRITE_FULL_MESSAGE)
            PtyWriteOffer.Closed -> failWrite(PTY_WRITE_CLOSED_MESSAGE)
        }
    }
    fun sendExtra(bytes: ByteArray) {
        view?.flushOrDiscardComposing()
        val payload = if (stickyAlt && bytes.isNotEmpty()) byteArrayOf(0x1b) + bytes else bytes
        stickyCtrl = false
        stickyAlt = false
        writePty(payload)
    }
    fun openShell() {
        if (!machine.online || !machine.allowExec || phase == ShellPhase.Opening) return
        phase = ShellPhase.Opening
        note = null
        val rows = view?.rows() ?: 24
        val cols = view?.cols() ?: 80
        model.work({ it.openPty(machine.id, null, rows, cols) }) { result ->
            result.onSuccess {
                model.retainPty(machine.id, it)
                pty = it
                phase = ShellPhase.Connected
                view?.showKeyboard()
            }.onFailure {
                phase = ShellPhase.Failed
                note = grantNote(it.message ?: "Couldn't open the shell.")
            }
        }
    }
    DisposableEffect(ptyWrites) {
        onDispose {
            // Only close the UI-local write channel on pane switch; the PTY
            // itself stays alive in ClientViewModel until Reconnect/Exit/Disconnect.
            ptyWrites.close()
        }
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
        var finished = false
        while (isActive && !finished) {
            var pending = false
            var drained = 0
            do {
                val polled = withContext(Dispatchers.IO) { runCatching { handle.poll() } }
                if (polled.isFailure) {
                    note = grantNote(polled.exceptionOrNull()?.message ?: "The shell connection dropped.")
                    phase = ShellPhase.Failed
                    model.releasePty(machine.id, handle)
                    pty = null
                    finished = true
                    break
                }
                val event = polled.getOrThrow()
                when (jsonField(event, "event")) {
                    "pending" -> pending = true
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
                        model.releasePty(machine.id, handle)
                        pty = null
                        withContext(Dispatchers.Main) { terminal.feed("\r\n[exit $code]\r\n".encodeToByteArray()) }
                        finished = true
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
                drained++
            } while (
                isActive &&
                    !finished &&
                    !pending &&
                    drained < PtyClientPolicy.MAX_DRAIN_EVENTS
            )
            if (finished || !isActive) break
            if (pending) delay(PtyClientPolicy.POLL_IDLE_MS)
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
                    model.releasePty(machine.id)
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
            factory = { ctx ->
                TerminalView(ctx).apply {
                    onBytes = { bytes -> writePty(bytes) }
                    onResize = { rows, cols ->
                        sizeLabel = "${cols}×${rows}"
                        val handle = pty
                        if (handle != null) {
                            scope.launch(Dispatchers.IO) { runCatching { handle.resize(rows, cols) } }
                        }
                    }
                    onScrolledAway = { scrolledAway = it }
                    onModifiersConsumed = {
                        stickyCtrl = false
                        stickyAlt = false
                    }
                }
            },
            update = { terminal ->
                view = terminal
                terminal.stickyCtrl = stickyCtrl
                terminal.stickyAlt = stickyAlt
                terminal.onBytes = { bytes -> writePty(bytes) }
                terminal.onResize = { rows, cols ->
                    sizeLabel = "${cols}×${rows}"
                    val handle = pty
                    if (handle != null) {
                        scope.launch(Dispatchers.IO) { runCatching { handle.resize(rows, cols) } }
                    }
                }
                terminal.onScrolledAway = { scrolledAway = it }
                terminal.onModifiersConsumed = {
                    stickyCtrl = false
                    stickyAlt = false
                }
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
            AgentFilterChip(stickyCtrl, "Ctrl", { stickyCtrl = !stickyCtrl }, Modifier.testTag("key-ctrl"))
            AgentFilterChip(stickyAlt, "Alt", { stickyAlt = !stickyAlt }, Modifier.testTag("key-alt"))
            SecondaryButton("Paste", onClick = {
                view?.flushOrDiscardComposing()
                val cm = context.getSystemService(ClipboardManager::class.java)
                val clip = cm?.primaryClip?.takeIf { it.itemCount > 0 }
                    ?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
                if (clip.isNotEmpty()) writePty(clip.encodeToByteArray())
            })
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
                    model.releasePty(machine.id)
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
            SecondaryButton("Esc", onClick = { sendExtra(ptySequence(PtyKey.Escape, false)) })
            SecondaryButton("Tab", onClick = { sendExtra(ptySequence(PtyKey.Tab, false)) })
            SecondaryButton("Ctrl-C", onClick = { sendExtra(ptyText("c", ctrl = true)) })
            SecondaryButton("Ctrl-D", onClick = { sendExtra(ptyText("d", ctrl = true)) })
            SecondaryButton("Up", onClick = { sendExtra(ptySequence(PtyKey.Up, view?.screen?.applicationCursor == true)) })
            SecondaryButton("Down", onClick = { sendExtra(ptySequence(PtyKey.Down, view?.screen?.applicationCursor == true)) })
            SecondaryButton("Left", onClick = { sendExtra(ptySequence(PtyKey.Left, view?.screen?.applicationCursor == true)) })
            SecondaryButton("Right", onClick = { sendExtra(ptySequence(PtyKey.Right, view?.screen?.applicationCursor == true)) })
            SecondaryButton("Home", onClick = { sendExtra(ptySequence(PtyKey.Home, false)) })
            SecondaryButton("End", onClick = { sendExtra(ptySequence(PtyKey.End, false)) })
            SecondaryButton("PgUp", onClick = { sendExtra(ptySequence(PtyKey.PageUp, false)) })
            SecondaryButton("PgDn", onClick = { sendExtra(ptySequence(PtyKey.PageDown, false)) })
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
internal fun TransferPane(model: ClientViewModel, machine: MachineRow, account: AccountApi? = null) {
    val context = LocalContext.current
    val identityDir = context.filesDir
    var remote by rememberSaveable(machine.id) { mutableStateOf(defaultTransferPath(machine.os)) }
    var direct by remember { mutableStateOf(true) }
    var note by remember { mutableStateOf("Tries a direct connection, then the relay.") }
    val progress = remember { MutableStateFlow("idle") }
    var progressText by remember { mutableStateOf("idle") }
    var deviceKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantHelp by remember(machine.id) { mutableStateOf(false) }
    LaunchedEffect(machine.id, account) {
        deviceKey = withContext(Dispatchers.IO) {
            runCatching { account?.devicePublicHex() }.getOrNull()
        }?.takeIf { it.isNotBlank() }
    }
    fun grantNote(message: String): String {
        if (!isSignedGrantFailure(message)) return message
        val checked = controllerKeyFromRejection(message)
        if (checked.isNotEmpty()) grantKey = checked
        else if (grantKey.isNullOrBlank()) grantKey = deviceKey?.trim()?.lowercase()?.ifBlank { null }
        return decorateGrantFailure(message, machine.id, deviceKey, identityDir.absolutePath)
    }
    val online = machine.online
    val canRead = online && machine.allowRead
    val canWrite = online && machine.allowWrite
    LaunchedEffect(progress) { progress.collect { progressText = it } }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null || !canWrite) return@rememberLauncherForActivityResult
        model.work({ session ->
            val xferDir = File(context.cacheDir, "client-xfer").apply { mkdirs() }
            val dest = File(xferDir, "upload-${System.currentTimeMillis()}-${java.util.UUID.randomUUID()}.bin")
            try {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    dest.outputStream().use { input.copyTo(it) }
                } ?: error("Could not read the picked file")
                session.transferUp(machine.id, remote, dest.absolutePath, direct) { done, total ->
                    progress.value = progressLabel(done, total)
                }
            } finally {
                runCatching { dest.delete() }
            }
        }) { result ->
            result.onSuccess { note = "Uploaded ${it.logicalBytes} bytes via ${it.transport}" }
                .onFailure { note = grantNote(it.message ?: "Upload failed.") }
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
        if (isGrantFixNote(note)) {
            SecondaryButton("Import grant", { grantHelp = true }, Modifier.testTag("import-grant"))
        }
        PrimaryButton("Upload to the machine", onClick = { pick.launch("*/*") }, enabled = canWrite, modifier = Modifier.fillMaxWidth())
        PrimaryButton(
            "Download to the phone",
            onClick = {
                downloadRemote(context, model, machine.id, remote, direct, { progress.value = it }) { message ->
                    note = grantNote(message)
                }
            },
            enabled = canRead,
            modifier = Modifier.fillMaxWidth(),
        )
        if (online && !canWrite) SupportingText("Uploads need write permission.")
        if (online && !canRead) SupportingText("Downloads need read permission.")
    }
    if (grantHelp) {
        GrantFixDialog(
            node = machine.id,
            pubkey = grantKey ?: deviceKey,
            identityDir = identityDir,
            onClose = { grantHelp = false },
            onImported = {
                grantHelp = false
                note = "Grant imported. Try the transfer again."
            },
        )
    }
}

@Composable
internal fun AuditPane(model: ClientViewModel, machine: MachineRow, account: AccountApi? = null) {
    val context = LocalContext.current
    val identityDir = context.filesDir
    var text by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    var deviceKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantKey by remember(machine.id) { mutableStateOf<String?>(null) }
    var grantHelp by remember(machine.id) { mutableStateOf(false) }
    LaunchedEffect(machine.id, account) {
        deviceKey = withContext(Dispatchers.IO) {
            runCatching { account?.devicePublicHex() }.getOrNull()
        }?.takeIf { it.isNotBlank() }
    }
    fun grantNote(message: String): String {
        if (!isSignedGrantFailure(message)) return message
        val checked = controllerKeyFromRejection(message)
        if (checked.isNotEmpty()) grantKey = checked
        else if (grantKey.isNullOrBlank()) grantKey = deviceKey?.trim()?.lowercase()?.ifBlank { null }
        return decorateGrantFailure(message, machine.id, deviceKey, identityDir.absolutePath)
    }
    val isAndroidNode = "android" in machine.os.lowercase()
    fun load() {
        if (!machine.online || !machine.allowRead) return
        loading = true
        model.work({ session ->
            val queried = runCatching { session.queryAudit(machine.id, 80u) }.getOrDefault("")
            val formatted = formatAuditQuery(queried)
            if (formatted.isNotBlank()) {
                formatted
            } else if (isAndroidNode) {
                session.readBytes(machine.id, "app:/audit.log", 0u, 512000u)
                    .decodeToString().lineSequence().toList().takeLast(80).joinToString("\n")
            } else {
                ""
            }
        }) { result ->
            loading = false
            result.onSuccess { lines ->
                note = null
                text = lines
            }.onFailure {
                note = grantNote(it.message ?: "Couldn't read the audit log.")
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
        note?.let {
            FileNote(it)
            if (isGrantFixNote(it)) {
                SecondaryButton("Import grant", { grantHelp = true }, Modifier.testTag("import-grant"))
            }
        }
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
    if (grantHelp) {
        GrantFixDialog(
            node = machine.id,
            pubkey = grantKey ?: deviceKey,
            identityDir = identityDir,
            onClose = { grantHelp = false },
            onImported = {
                grantHelp = false
                note = "Grant imported. Reloading audit log."
                load()
            },
        )
    }
}

private fun formatAuditQuery(raw: String): String {
    if (raw.isBlank()) return ""
    return runCatching {
        val trimmed = raw.trim()
        val arr = if (trimmed.startsWith("[")) org.json.JSONArray(trimmed)
        else JSONObject(trimmed).optJSONArray("entries") ?: JSONObject(trimmed).optJSONArray("events")
        if (arr == null) return trimmed
        val lines = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            lines += arr.opt(i)?.toString().orEmpty()
        }
        lines.filter { it.isNotBlank() }.joinToString("\n")
    }.getOrDefault(raw)
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
    var srcW by remember { mutableIntStateOf(1) }
    var srcH by remember { mutableIntStateOf(1) }
    var cursorPresentation by remember { mutableStateOf("embedded") }
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
    var lastRemoteClip by remember { mutableStateOf("") }
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
    suspend fun grab() {
        val session = model.session ?: return
        val result = withContext(Dispatchers.IO) {
            runCatching { session.extension(machine.id, "screenshot", """{"quality":55}""") }
        }
        result.onSuccess { body ->
            if (webrtcFallsBackToScreenshot(body)) {
                note = "Live video is not available. Showing screenshots."
            }
            val parsed = runCatching { JSONObject(body) }.getOrNull()
            val encoded = parsed?.optString("data_b64").orEmpty()
            if (encoded.isNotEmpty()) {
                val decoded = withContext(Dispatchers.Default) {
                    val bytes = Base64.decode(encoded, Base64.DEFAULT)
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                }
                bitmap = decoded
                val reportedW = parsed?.optInt("width") ?: 0
                val reportedH = parsed?.optInt("height") ?: 0
                shotW = if (reportedW > 0) reportedW else decoded?.width?.takeIf { it > 0 } ?: 1
                shotH = if (reportedH > 0) reportedH else decoded?.height?.takeIf { it > 0 } ?: 1
                srcW = shotW
                srcH = shotH
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
    fun send(payload: JSONObject) {
        if (!capability.control) return
        model.work({ it.extension(machine.id, "inject_input", payload.toString()) }) { result ->
            result.onFailure { note = grantNote(it.message ?: "Couldn't send input.") }
        }
    }
    fun deliver(payload: JSONObject) {
        if (!capability.control) return
        val current = live
        val kind = payload.optString("action")
        val targetW = if (srcW > 0) srcW else shotW
        val targetH = if (srcH > 0) srcH else shotH
        val messages = if (current != null) {
            when (kind) {
                "tap" -> liveControlMessages("tap", targetW, targetH, x = payload.optDouble("x").toFloat(), y = payload.optDouble("y").toFloat())
                "right_click" -> liveControlMessages("right_click", targetW, targetH, x = payload.optDouble("x").toFloat(), y = payload.optDouble("y").toFloat())
                "scroll" -> liveControlMessages(
                    "scroll",
                    targetW,
                    targetH,
                    x = payload.optDouble("x").toFloat(),
                    y = payload.optDouble("y").toFloat(),
                    dx = payload.optDouble("dx").toFloat(),
                    dy = payload.optDouble("dy").toFloat(),
                )
                "swipe" -> liveControlMessages(
                    "swipe",
                    targetW,
                    targetH,
                    x = payload.optDouble("x").toFloat(),
                    y = payload.optDouble("y").toFloat(),
                    x2 = payload.optDouble("x2").toFloat(),
                    y2 = payload.optDouble("y2").toFloat(),
                )
                "type" -> liveControlMessages("type", targetW, targetH, text = payload.optString("text"))
                "key" -> liveControlMessages("key", targetW, targetH, name = payload.optString("name"))
                else -> emptyList()
            }
        } else {
            emptyList()
        }
        if (current != null && messages.isNotEmpty()) {
            scope.launch(Dispatchers.IO) {
                val ok = runCatching { messages.all { current.sendControl(it) } }.getOrDefault(false)
                if (!ok) {
                    withContext(Dispatchers.Main) { send(payload) }
                }
            }
        } else {
            send(payload)
        }
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
        val decoder = H264Player(context, onRequestKeyframe = {
            scope.launch(Dispatchers.IO) { runCatching { opened.requestKeyframe() } }
        })
        live = opened
        player = decoder
        val info = withContext(Dispatchers.IO) { opened.info() }
        if (info.width > 0) shotW = info.width
        if (info.height > 0) shotH = info.height
        srcW = if (info.srcWidth > 0) info.srcWidth else shotW
        srcH = if (info.srcHeight > 0) info.srcHeight else shotH
        cursorPresentation = info.cursorPresentation
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
                val remoteClip = opened.pollClipboard()
                if (remoteClip != null && remoteClip.text.isNotEmpty() && remoteClip.text != lastRemoteClip) {
                    lastRemoteClip = remoteClip.text
                    copyPlainText(context, "Remote clipboard", remoteClip.text)
                }
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
        val oldLive = live
        live = null
        if (oldLive != null) {
            withContext(Dispatchers.IO) { runCatching { oldLive.close() } }
        }
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
        srcWidth = srcW,
        srcHeight = srcH,
        cursorPresentation = cursorPresentation,
        stream = watch,
        onStream = { watch = it },
        typed = typed,
        onTyped = { typed = it },
        onLive = {
            if (connected) {
                val active = live
                if (active != null) {
                    scope.launch(Dispatchers.IO) { runCatching { active.requestKeyframe() } }
                }
            } else {
                watch = true
                retryToken += 1
            }
        },
        onInject = { payload -> deliver(payload) },
        onSendClipboard = if (connected) {
            { clipText ->
                val active = live
                if (active != null) {
                    scope.launch(Dispatchers.IO) {
                        val sent = runCatching { active.sendClipboard(clipText) }.getOrDefault(false)
                        if (sent) {
                            withContext(Dispatchers.Main) { note = "Sent clipboard to ${machine.name}" }
                        }
                    }
                }
            }
        } else {
            null
        },
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
        val shareDir = File(context.cacheDir, "share").apply { mkdirs() }
        val dest = File(shareDir, name)
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
