package app.agentlink.ui

import app.agentlink.bridge.MachineRow
import app.agentlink.model.childPath
import java.util.Locale

enum class MachineAction(val title: String, val pane: String) {
    Terminal("Terminal", "terminal"),
    Files("Files", "files"),
    Desktop("Desktop", "desktop"),
    Transfer("Transfer", "transfer"),
    Audit("Audit", "audit"),
}

fun machineActionFromPane(pane: String): MachineAction? {
    return MachineAction.entries.firstOrNull { it.pane == pane }
}

fun paneTitle(pane: String?): String = machineActionFromPane(pane.orEmpty())?.title ?: "Machine"

data class ActionState(val action: MachineAction, val enabled: Boolean, val detail: String)

data class DesktopCapability(
    val available: Boolean,
    val screenshots: Boolean,
    val control: Boolean,
    val live: Boolean,
    val reason: String,
)

data class PairFlags(
    val allowRead: Boolean,
    val allowWrite: Boolean,
    val allowExec: Boolean,
    val allowDesktop: Boolean,
    val allowDesktopStream: Boolean,
    val allowRemoteView: Boolean,
    val allowRemoteControl: Boolean,
    val ttlSecs: ULong = 3600uL,
)

fun pairFlags(): PairFlags = PairFlags(true, true, true, true, true, true, true)

/**
 * Mirrors `NodePolicy` helpers in agentlink-core. The machine list carries
 * `node.effective` flags from the backend; this UI must not invent access.
 */
fun allowsRemoteView(machine: MachineRow): Boolean =
    machine.allowRemoteView || machine.allowDesktopStream

fun allowsScreenshot(machine: MachineRow): Boolean =
    machine.allowDesktop || allowsRemoteView(machine)

fun allowsDesktopInput(machine: MachineRow): Boolean =
    machine.allowDesktop || machine.allowRemoteControl

fun hasDesktopCapability(machine: MachineRow): Boolean =
    allowsScreenshot(machine) || allowsDesktopInput(machine) || allowsRemoteView(machine)

fun desktopCapability(machine: MachineRow): DesktopCapability {
    if (!machine.online) {
        return DesktopCapability(
            available = false,
            screenshots = false,
            control = false,
            live = false,
            reason = "This machine is offline. Desktop stays off until it reconnects.",
        )
    }
    val screenshots = allowsScreenshot(machine)
    val control = allowsDesktopInput(machine)
    val live = allowsRemoteView(machine)
    val available = screenshots || control || live
    val reason = when {
        !available -> "Needs desktop permission."
        live && control -> "Live view and input are allowed."
        live && !control -> "Live view is allowed. Input is not."
        screenshots && control -> "Screenshots and input are allowed. Live stream is not."
        screenshots -> "Screenshots are allowed. Live stream and input are not."
        control -> "Input is allowed. Live stream is not."
        else -> "Desktop view is allowed."
    }
    return DesktopCapability(
        available = available,
        screenshots = screenshots,
        control = control,
        live = live,
        reason = reason,
    )
}

fun machineActions(machine: MachineRow): List<ActionState> {
    val offline = !machine.online
    fun line(allowed: Boolean, ready: String, blocked: String): Pair<Boolean, String> {
        if (offline) return false to "Unavailable while offline"
        if (!allowed) return false to blocked
        return true to ready
    }
    val files = line(machine.allowRead, "Browse, open, and download", "Reading files is turned off")
    val terminal = line(machine.allowExec, "Open a shell on this machine", "Needs exec permission")
    val desktop = desktopCapability(machine)
    val desktopDetail = if (offline) "Unavailable while offline" else desktop.reason
    val transfer = when {
        offline -> false to "Unavailable while offline"
        machine.allowRead && machine.allowWrite -> true to "Upload and download whole files"
        machine.allowRead -> true to "Download is allowed. Upload is turned off"
        machine.allowWrite -> true to "Upload is allowed. Download is turned off"
        else -> false to "File transfer is turned off"
    }
    val audit = line(machine.allowRead, "Recent lines from the audit log", "Reading files is turned off")
    return listOf(
        ActionState(MachineAction.Terminal, terminal.first, terminal.second),
        ActionState(MachineAction.Files, files.first, files.second),
        ActionState(MachineAction.Desktop, desktop.available, desktopDetail),
        ActionState(MachineAction.Transfer, transfer.first, transfer.second),
        ActionState(MachineAction.Audit, audit.first, audit.second),
    )
}

fun capabilityLabels(machine: MachineRow): String {
    if (!machine.online) return "Offline"
    val parts = buildList {
        if (machine.allowRead) add("Files")
        if (machine.allowExec) add("Terminal")
        if (machine.allowWrite) add("Upload")
        if (hasDesktopCapability(machine)) add("Desktop")
    }
    return if (parts.isEmpty()) "No actions allowed" else parts.joinToString(" · ")
}

fun platformLabel(machine: MachineRow): String {
    return listOf(machine.os, machine.arch, machine.preset).filter { it.isNotBlank() }.joinToString(" · ")
}

fun pathCrumbs(path: String): List<Pair<String, String>> {
    val trimmed = path.trim()
    if (trimmed.isEmpty()) return emptyList()
    val schemeIndex = trimmed.indexOf(":/")
    if (schemeIndex < 0) return listOf(trimmed to trimmed)
    val root = trimmed.substring(0, schemeIndex + 2)
    val crumbs = mutableListOf(root to root.removeSuffix("/"))
    val rest = trimmed.removePrefix(root).trim('/')
    if (rest.isEmpty()) return crumbs
    var acc = root
    for (part in rest.split('/')) {
        if (part.isEmpty()) continue
        acc = childPath(acc, part)
        crumbs += acc to part
    }
    return crumbs
}

fun formatBytes(size: ULong): String {
    val n = size.toLong().coerceAtLeast(0)
    if (n < 1024) return "$n B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var value = n.toDouble()
    var unit = "B"
    for (name in units) {
        value /= 1024.0
        unit = name
        if (value < 1024.0 || name == units.last()) break
    }
    val rounded = if (value >= 10 || value == value.toInt().toDouble()) {
        value.toInt().toString()
    } else {
        String.format(Locale.US, "%.1f", value)
    }
    return "$rounded $unit"
}

fun safeFileName(name: String): String {
    val base = name.substringAfterLast('/').substringAfterLast('\\').trim()
    if (base.isEmpty() || base == "." || base == ".." || base.contains('\u0000')) return "upload.bin"
    return base
}

fun permissionHint(message: String?): String? {
    val text = message?.lowercase() ?: return null
    val denied = text.contains("denied") ||
        text.contains("not allowed") ||
        text.contains("forbidden") ||
        text.contains("permission")
    if (!denied) return null
    return "The machine refused this."
}

fun fatalDesktopMessage(message: String): Boolean {
    val text = message.lowercase()
    return text.contains("signed grant required") ||
        text.contains("denied") ||
        text.contains("headless") ||
        text.contains("no display") ||
        text.contains("not available") ||
        text.contains("unavailable") ||
        text.contains("permission") ||
        text.contains("not allowed")
}

fun shortNote(body: String): String = if (body.length > 180) body.take(180) + "…" else body
