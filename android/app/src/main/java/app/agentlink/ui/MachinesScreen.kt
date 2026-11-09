@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package app.agentlink.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.material.icons.filled.Laptop
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.agentlink.bridge.MachineRow

@Composable
fun ClientHome(
    model: ClientViewModel,
    onOpen: (MachineRow) -> Unit,
    onPair: () -> Unit,
    showHeader: Boolean = true,
) {
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            model.refreshIfConnected()
        }
    }
    val loading = !model.loadedOnce && model.machines.isEmpty() && model.error == null
    MachinesBody(
        machines = model.machines,
        error = model.error,
        refreshing = model.refreshing,
        loading = loading,
        onRefresh = { model.refresh() },
        onOpen = onOpen,
        onPair = onPair,
        showHeader = showHeader,
    )
}

@Composable
fun MachinesBody(
    machines: List<MachineRow>,
    error: String?,
    refreshing: Boolean,
    loading: Boolean,
    onRefresh: () -> Unit,
    onOpen: (MachineRow) -> Unit,
    onPair: () -> Unit,
    showHeader: Boolean = true,
) {
    val context = LocalContext.current
    val ordered = remember(machines) {
        machines.sortedWith(compareByDescending<MachineRow> { it.online }.thenBy { it.name.lowercase() })
    }
    val pinNote = remember(ordered) { nodePinWarning(context, ordered) }
    val online = ordered.count { it.online }
    val offline = ordered.size - online
    Column(modifier = Modifier.fillMaxSize().testTag("machines-root")) {
        if (showHeader) {
            Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                ScreenIntro("Machines")
            }
        }
        PullToRefreshBox(
            isRefreshing = refreshing,
            onRefresh = onRefresh,
            modifier = Modifier.weight(1f).fillMaxWidth(),
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (pinNote != null) {
                    item {
                        AgentBanner(
                            text = pinNote,
                            tone = BannerTone.Error,
                            modifier = Modifier.testTag("node-pin-warning"),
                        )
                    }
                }
                if (error != null) {
                    item {
                        AgentBanner(
                            text = error,
                            tone = BannerTone.Error,
                            action = "Retry",
                            onAction = onRefresh,
                            modifier = Modifier.testTag("machines-error"),
                        )
                    }
                }
                if (loading) {
                    item { LoadingMachines() }
                } else if (ordered.isEmpty()) {
                    item { EmptyMachines(onPair) }
                } else {
                    item {
                        Text(
                            "$online online · $offline offline",
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.testTag("machines-summary"),
                        )
                    }
                    items(ordered, key = { it.id }) { machine ->
                        MachineCard(machine, onClick = { onOpen(machine) })
                    }
                }
            }
        }
        if (!loading && ordered.isNotEmpty()) {
            SecondaryButton(
                "Pair a machine",
                onPair,
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp).testTag("pair-machine"),
            )
        }
    }
}

@Composable
private fun LoadingMachines() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        Text("Loading machines", style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun EmptyMachines(onPair: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        BrandMark(size = 88.dp)
        Text(
            "No machines yet",
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        SupportingText(
            "Pair a machine and it shows up here. Pull down to refresh once it is online.",
            modifier = Modifier.padding(horizontal = 8.dp),
        )
        PrimaryButton(
            "Pair a machine",
            onPair,
            Modifier.fillMaxWidth().testTag("pair-machine"),
        )
    }
}

@Composable
private fun MachineCard(machine: MachineRow, onClick: () -> Unit) {
    AgentCard(onClick = onClick, modifier = Modifier.testTag("machine-${machine.id}")) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OsMark(machine.os)
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(machine.name, style = MaterialTheme.typography.titleMedium)
                    if (machine.hostname.isNotBlank()) {
                        Text(
                            machine.hostname,
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                ConnectionStatus(machine.online)
                Icon(
                    Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                platformLabel(machine),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                capabilityLabels(machine),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (!machine.online) {
                Text(
                    "Offline. Open it to see which actions are paused.",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
internal fun OsMark(os: String) {
    val scheme = MaterialTheme.colorScheme
    Surface(
        modifier = Modifier.size(40.dp),
        shape = CircleShape,
        color = scheme.secondaryContainer,
        contentColor = scheme.onSecondaryContainer,
    ) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Icon(osIcon(os), contentDescription = null, modifier = Modifier.size(22.dp))
        }
    }
}

internal fun copyPlainText(context: Context, label: String, text: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    clipboard?.setPrimaryClip(ClipData.newPlainText(label, text))
}

internal fun osIcon(os: String): ImageVector {
    val key = os.lowercase()
    return when {
        "mac" in key || "darwin" in key || "ios" in key -> Icons.Filled.Laptop
        "win" in key -> Icons.Filled.DesktopWindows
        "android" in key -> Icons.Filled.PhoneAndroid
        else -> Icons.Filled.Computer
    }
}

@Composable
internal fun PairMachineScreen(model: ClientViewModel) {
    var name by rememberSaveable { mutableStateOf("laptop") }
    var ticket by remember { mutableStateOf<String?>(null) }
    var note by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val context = LocalContext.current
    PairBody(
        name = name,
        onName = { name = it },
        ticket = ticket,
        busy = busy,
        note = note,
        onCreate = {
            val flags = pairFlags()
            val chosen = name.trim().ifBlank { "machine" }
            busy = true
            note = null
            model.work({
                it.createPairing(
                    chosen,
                    flags.allowRead,
                    flags.allowWrite,
                    flags.allowExec,
                    flags.allowDesktop,
                    flags.allowDesktopStream,
                    flags.allowRemoteView,
                    flags.allowRemoteControl,
                    flags.ttlSecs,
                )
            }) { result ->
                busy = false
                result.onSuccess {
                    ticket = it.token
                    note = null
                }.onFailure {
                    note = it.message ?: "Couldn't create a pairing token."
                }
            }
        },
        onCopy = {
            val token = ticket ?: return@PairBody
            copyPlainText(context, "Pairing token", token)
            note = "Copied. Paste it as the pairing token on the machine. It works once."
        },
    )
}

@Composable
internal fun PairBody(
    name: String,
    onName: (String) -> Unit,
    ticket: String?,
    busy: Boolean,
    note: String?,
    onCreate: () -> Unit,
    onCopy: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SupportingText("Creates a one-time token. On the machine, start the node with this token. Once it is connected, the owner has full access: shell, files, and desktop.")
        AgentField(name, onName, "Name", Modifier.fillMaxWidth().testTag("pair-name"))
        PrimaryButton(
            text = if (busy) "Creating token" else "Create pairing token",
            onClick = onCreate,
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().testTag("create-pairing"),
        )
        if (note != null) {
            val problem = looksLikeProblem(note) || note.contains("Couldn't", ignoreCase = true)
            if (problem) ErrorNote(note) else SupportingText(note)
        }
        if (ticket != null) {
            SectionLabel("Pairing token")
            AgentCard {
                Text(
                    ticket,
                    modifier = Modifier.padding(16.dp).testTag("pair-token"),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
            SecondaryButton("Copy token", onCopy, Modifier.fillMaxWidth().testTag("copy-token"))
            SupportingText("Expires in about an hour. The machine keeps its own key after this token is used.")
        }
    }
}

private const val NODE_PINS = "agentlink.nodePins"

/** Trust-on-first-use for node name → Ed25519 id. A later id change is shown, not silently accepted. */
private fun nodePinWarning(context: Context, machines: List<MachineRow>): String? {
    if (machines.isEmpty()) return null
    val prefs = context.getSharedPreferences(NODE_PINS, Context.MODE_PRIVATE)
    val editor = prefs.edit()
    val warnings = mutableListOf<String>()
    for (machine in machines) {
        if (machine.name.isBlank() || machine.id.isBlank()) continue
        val key = "name." + machine.name
        val pinned = prefs.getString(key, null)
        if (pinned == null) {
            editor.putString(key, machine.id)
        } else if (pinned != machine.id) {
            warnings += "${machine.name} changed its id. The saved pin was kept."
        }
    }
    editor.apply()
    return warnings.takeIf { it.isNotEmpty() }?.joinToString(" ")
}
