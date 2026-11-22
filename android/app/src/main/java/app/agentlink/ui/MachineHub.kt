@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package app.agentlink.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.SwapVert
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import app.agentlink.bridge.MachineRow

@Composable
internal fun MachineHub(
    machine: MachineRow,
    error: String?,
    refreshing: Boolean,
    onRefresh: () -> Unit,
    onOpen: (MachineAction) -> Unit,
    onManageGrant: (() -> Unit)? = null,
) {
    val actions = machineActions(machine)
    PullToRefreshBox(
        isRefreshing = refreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize().testTag("machine-hub"),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { MachineSummary(machine) }
            if (!machine.online) {
                item {
                    AgentBanner(
                        text = "This machine is offline. Actions stay off until it reconnects.",
                        tone = BannerTone.Info,
                    )
                }
            }
            if (error != null) {
                item {
                    AgentBanner(text = error, tone = BannerTone.Error, action = "Retry", onAction = onRefresh)
                }
            }
            item { SectionLabel("Actions") }
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                ) {
                    Column {
                        actions.forEachIndexed { index, state ->
                            if (index > 0) {
                                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            }
                            ActionRow(state, onOpen)
                        }
                    }
                }
            }
            if (onManageGrant != null) {
                item {
                    SecondaryButton(
                        text = "Manage signed grant",
                        onClick = onManageGrant,
                        modifier = Modifier.fillMaxWidth().testTag("machine-manage-grant"),
                    )
                }
            }
        }
    }
}

@Composable
private fun MachineSummary(machine: MachineRow) {
    AgentCard {
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
                    Text(machine.name, style = MaterialTheme.typography.headlineSmall)
                    if (machine.hostname.isNotBlank()) {
                        Text(
                            machine.hostname,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                ConnectionStatus(machine.online)
            }
            Text(platformLabel(machine), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (machine.version.isNotBlank()) {
                Text(
                    "Version ${machine.version}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ActionRow(state: ActionState, onOpen: (MachineAction) -> Unit) {
    val scheme = MaterialTheme.colorScheme
    val click = if (state.enabled) {
        Modifier.clickable { onOpen(state.action) }
    } else {
        Modifier
    }
    Row(
        modifier = click
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 14.dp)
            .testTag("action-${state.action.pane}"),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            actionIcon(state.action),
            contentDescription = null,
            tint = if (state.enabled) scheme.primary else scheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp),
        )
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                state.action.title,
                style = MaterialTheme.typography.titleMedium,
                color = if (state.enabled) scheme.onSurface else scheme.onSurfaceVariant,
            )
            Text(
                state.detail,
                style = MaterialTheme.typography.bodySmall,
                color = scheme.onSurfaceVariant,
            )
        }
        Icon(
            imageVector = if (state.enabled) Icons.AutoMirrored.Filled.KeyboardArrowRight else Icons.Filled.Lock,
            contentDescription = if (state.enabled) null else "Unavailable",
            tint = scheme.onSurfaceVariant,
        )
    }
}

private fun actionIcon(action: MachineAction): ImageVector = when (action) {
    MachineAction.Terminal -> Icons.Filled.Terminal
    MachineAction.Files -> Icons.Filled.Folder
    MachineAction.Desktop -> Icons.Filled.DesktopWindows
    MachineAction.Transfer -> Icons.Filled.SwapVert
    MachineAction.Audit -> Icons.Filled.History
}

@Composable
internal fun MachineContextLine(machine: MachineRow) {
    Text(
        "${machine.name} · ${if (machine.online) "Online" else "Offline"} · ${machine.preset}",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
internal fun MissingMachine(onBack: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("That machine is not in the list.", style = MaterialTheme.typography.bodyLarge)
        SupportingText("It may have been removed. Go back and refresh.")
        SecondaryButton("Back", onBack, Modifier.fillMaxWidth())
    }
}
