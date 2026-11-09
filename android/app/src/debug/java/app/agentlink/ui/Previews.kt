package app.agentlink.ui

import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import app.agentlink.model.DesktopViewport
import app.agentlink.account.AccountApi
import app.agentlink.account.DeviceRow
import app.agentlink.account.NodeRow
import app.agentlink.account.SessionStore
import app.agentlink.account.UserAccount
import app.agentlink.bridge.ClientSession
import app.agentlink.bridge.MachineRow

private class PreviewSessions : SessionStore {
    override fun load(): UserAccount? = null
    override fun save(account: UserAccount) = Unit
    override fun clear() = Unit
}

private class PreviewAccount : AccountApi {
    override fun login(
        server: String,
        fingerprint: String,
        username: String,
        password: String,
        totp: String,
        deviceName: String,
    ): UserAccount = error("preview")

    override fun refresh(account: UserAccount): UserAccount = account
    override fun logout(account: UserAccount) = Unit
    override fun listNodes(account: UserAccount): List<NodeRow> = emptyList()
    override fun listDevices(account: UserAccount): List<DeviceRow> = emptyList()
    override fun enrollAsNode(account: UserAccount, name: String) = Unit
    override fun connect(account: UserAccount): ClientSession = error("preview")
}

@Composable
private fun LoginPreviewForm() {
    UserLogin(
        api = PreviewAccount(),
        sessions = PreviewSessions(),
        onConnected = {},
        onActAsNode = {},
        onAdmin = {},
    )
}

@Preview(name = "Login light", widthDp = 360, heightDp = 1100, showBackground = true, backgroundColor = 0xFFF4F7FB)
@Composable
fun LoginPreviewLight() {
    AgentTheme(darkTheme = false) { LoginPreviewForm() }
}

@Preview(
    name = "Login dark",
    widthDp = 360,
    heightDp = 1100,
    showBackground = true,
    backgroundColor = 0xFF101820,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
fun LoginPreviewDark() {
    AgentTheme(darkTheme = true) { LoginPreviewForm() }
}

private fun sampleMachines() = listOf(
    MachineRow(
        id = "m1",
        name = "studio",
        hostname = "studio.local",
        os = "linux",
        arch = "amd64",
        version = "0.1.0",
        online = true,
        preset = "trusted",
        allowRead = true,
        allowWrite = true,
        allowExec = true,
        allowDesktop = true,
        allowDesktopStream = false,
        allowRemoteView = true,
        allowRemoteControl = false,
    ),
    MachineRow(
        id = "m2",
        name = "laptop",
        hostname = "laptop.local",
        os = "macos",
        arch = "arm64",
        version = "0.1.0",
        online = false,
        preset = "read-only",
        allowRead = true,
        allowWrite = false,
        allowExec = false,
        allowDesktop = false,
        allowDesktopStream = false,
        allowRemoteView = false,
        allowRemoteControl = false,
    ),
)

@Composable
private fun MachinesPreviewForm() {
    MachinesBody(
        machines = sampleMachines(),
        error = null,
        refreshing = false,
        loading = false,
        onRefresh = {},
        onOpen = {},
        onPair = {},
    )
}

@Composable
private fun MachineHubPreviewForm() {
    MachineHub(
        machine = sampleMachines().first(),
        error = null,
        refreshing = false,
        onRefresh = {},
        onOpen = {},
    )
}

@Preview(name = "Machine hub light", widthDp = 360, heightDp = 900, showBackground = true, backgroundColor = 0xFFF4F7FB)
@Composable
fun MachineHubPreviewLight() {
    AgentTheme(darkTheme = false) { MachineHubPreviewForm() }
}

@Preview(name = "Desktop off light", widthDp = 360, heightDp = 640, showBackground = true, backgroundColor = 0xFFF4F7FB)
@Composable
fun DesktopOffPreviewLight() {
    AgentTheme(darkTheme = false) {
        Column(Modifier.padding(16.dp)) {
            DesktopUnavailable("Desktop is turned off. This machine may be headless, or its preset does not include desktop, remote view, or remote control.")
        }
    }
}

@Composable
private fun DesktopPreview() {
    val machine = sampleMachines().first()
    val frame = remember {
        Bitmap.createBitmap(160, 90, Bitmap.Config.ARGB_8888).apply {
            eraseColor(0xFF1B3A4B.toInt())
        }.asImageBitmap()
    }
    var fullscreen by remember { mutableStateOf(false) }
    var viewport by remember { mutableStateOf(DesktopViewport()) }
    var stream by remember { mutableStateOf(true) }
    var typed by remember { mutableStateOf("") }
    DesktopView(
        machine = machine,
        capability = desktopCapability(machine),
        note = "Screenshot 1920×1080",
        frame = frame,
        shotW = 1920,
        shotH = 1080,
        stream = stream,
        onStream = { stream = it },
        typed = typed,
        onTyped = { typed = it },
        onLive = {},
        onInject = {},
        fullscreen = fullscreen,
        onFullscreenChange = { fullscreen = it },
        viewport = viewport,
        onViewportChange = { viewport = it },
    )
}

@Preview(name = "Desktop portrait", widthDp = 360, heightDp = 640, showBackground = true, backgroundColor = 0xFFF4F7FB)
@Composable
fun DesktopPortraitPreview() {
    AgentTheme(darkTheme = false) { DesktopPreview() }
}

@Preview(name = "Desktop landscape", widthDp = 800, heightDp = 360, showBackground = true, backgroundColor = 0xFF101820)
@Composable
fun DesktopLandscapePreview() {
    AgentTheme(darkTheme = true) { DesktopPreview() }
}

@Preview(name = "Machines light", widthDp = 360, heightDp = 1100, showBackground = true, backgroundColor = 0xFFF4F7FB)
@Composable
fun MachinesPreviewLight() {
    AgentTheme(darkTheme = false) { MachinesPreviewForm() }
}

@Preview(
    name = "Machines dark",
    widthDp = 360,
    heightDp = 1100,
    showBackground = true,
    backgroundColor = 0xFF101820,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
fun MachinesPreviewDark() {
    AgentTheme(darkTheme = true) { MachinesPreviewForm() }
}
