package app.agentlink.ui

import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import app.agentlink.account.AccountApi
import app.agentlink.account.DeviceRow
import app.agentlink.account.NodeRow
import app.agentlink.account.SESSION_EXPIRED_MESSAGE
import app.agentlink.account.SessionStore
import app.agentlink.account.UserAccount
import app.agentlink.account.clearRememberedRefreshes
import app.agentlink.bridge.ClientSession
import app.agentlink.bridge.ExecResult
import app.agentlink.bridge.FileRow
import app.agentlink.bridge.LinkBridge
import app.agentlink.bridge.MachineRow
import app.agentlink.bridge.OutputListener
import app.agentlink.bridge.PairingTicket
import app.agentlink.bridge.ProgressListener
import app.agentlink.bridge.PtySession
import app.agentlink.bridge.TransferResult
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ShellNavTest {
    @get:Rule
    val rule = createComposeRule()

    @Before
    fun resetRotations() {
        clearRememberedRefreshes()
    }

    @Test
    fun signedOutLoginCanReachAdminAndPairingAndBack() {
        val sessions = MemorySession()
        rule.setContent {
            AgentTheme {
                AgentApp(bridge = UnusedBridge, account = ShellAccount(), enroll = null, store = sessions)
            }
        }
        rule.waitForTag("top-title")
        rule.onNodeWithTag("top-title").assertTextEquals("Sign in")
        rule.onNodeWithText("Admin token").assertExists()
        assertEquals(0, rule.onAllNodesWithTag("nav-settings").fetchSemanticsNodes().size)

        rule.onNodeWithText("Admin token").performScrollTo().performClick()
        rule.onNodeWithTag("top-title").assertTextEquals("Admin token")
        rule.onNodeWithText("Connect").assertExists()
        rule.onNodeWithTag("top-back").performClick()
        rule.onNodeWithTag("top-title").assertTextEquals("Sign in")

        rule.onNodeWithText("Pair this phone").performScrollTo().performClick()
        rule.onNodeWithTag("top-title").assertTextEquals("Pair this phone")
        rule.onNodeWithText("Review permissions").assertExists()
        rule.onNodeWithTag("top-back").performClick()
        rule.onNodeWithTag("top-title").assertTextEquals("Sign in")
    }

    @Test
    fun freshSessionShowsShellAndLogoutReturnsToLogin() {
        val sessions = MemorySession()
        val saved = sampleAccount(accessToken = "atk-fresh", accessExpiresUnix = FAR_FUTURE)
        sessions.save(saved)
        val api = ShellAccount(session = StubSession(listOf(sampleMachine("studio"))))
        rule.setContent {
            AgentTheme { AgentApp(UnusedBridge, api, store = sessions) }
        }
        rule.waitForText("studio")
        rule.onNodeWithTag("top-title").assertTextEquals("Machines")
        rule.onNodeWithTag("nav-settings").assertExists()
        rule.onNodeWithTag("nav-phone").assertExists()
        assertEquals(0, api.refreshCalls)
        assertEquals(listOf("atk-fresh"), api.connectedTokens)

        rule.onNodeWithTag("nav-settings").performClick()
        rule.onNodeWithTag("settings-user").assertTextEquals("alice")
        rule.onNodeWithText("Log out").performScrollTo().assertExists()

        rule.onNodeWithTag("nav-phone").performClick()
        rule.onNodeWithTag("pair-phone").assertExists()
        rule.onNodeWithTag("top-title").assertTextEquals("This phone")

        rule.onNodeWithTag("nav-machines").performClick()
        rule.onNodeWithText("studio").performClick()
        rule.onNodeWithTag("top-title").assertTextEquals("studio")
        rule.onNodeWithText("Files").assertExists()
        rule.onNodeWithText("Needs exec permission").assertExists()
        rule.onNodeWithText("Files").performClick()
        rule.onNodeWithTag("top-title").assertTextEquals("Files")
        rule.onNodeWithTag("top-back").performClick()
        rule.onNodeWithTag("top-title").assertTextEquals("studio")
        rule.onNodeWithTag("top-back").performClick()
        rule.onNodeWithTag("top-title").assertTextEquals("Machines")
        rule.onNodeWithText("studio").assertExists()

        rule.onNodeWithTag("nav-settings").performClick()
        rule.onNodeWithTag("logout").performScrollTo().performClick()
        rule.waitForTag("username")
        rule.onNodeWithTag("top-title").assertTextEquals("Sign in")
        rule.onNodeWithTag("status").assertTextEquals("logged out")
        assertNull(sessions.load())
        assertEquals(0, rule.onAllNodesWithTag("nav-settings").fetchSemanticsNodes().size)
    }

    @Test
    fun expiredRefreshOpensLoginWithAClearMessage() {
        val sessions = MemorySession()
        sessions.save(sampleAccount(accessExpiresUnix = 1, refreshExpiresUnix = 1))
        val api = ShellAccount()
        rule.setContent {
            AgentTheme { AgentApp(UnusedBridge, api, store = sessions) }
        }
        rule.waitForTag("status")
        rule.onNodeWithTag("status").assertTextEquals(SESSION_EXPIRED_MESSAGE)
        rule.onNodeWithTag("top-title").assertTextEquals("Sign in")
        assertEquals(0, api.refreshCalls)
        assertNull(sessions.load())
        assertEquals(0, rule.onAllNodesWithTag("nav-machines").fetchSemanticsNodes().size)
    }

    @Test
    fun expiredAccessRefreshesOnceAndOpensTheShell() {
        val sessions = MemorySession()
        sessions.save(sampleAccount(accessToken = "atk-old", accessExpiresUnix = 1, refreshExpiresUnix = FAR_FUTURE))
        val api = ShellAccount(session = StubSession(listOf(sampleMachine("studio"))))
        api.onRefresh = { account ->
            account.copy(accessToken = "atk-new", refreshToken = "rt-new", accessExpiresUnix = FAR_FUTURE)
        }
        rule.setContent {
            AgentTheme { AgentApp(UnusedBridge, api, store = sessions) }
        }
        rule.waitForText("studio")
        assertEquals(1, api.refreshCalls)
        assertEquals(listOf("atk-new"), api.connectedTokens)
        assertEquals("atk-new", sessions.load()?.accessToken)
        assertEquals("rt-new", sessions.load()?.refreshToken)
    }

    @Test
    fun connectAuthFailureRefreshesOnceThenSignsOut() {
        val sessions = MemorySession()
        sessions.save(sampleAccount(accessToken = "atk-stale", accessExpiresUnix = FAR_FUTURE))
        val api = ShellAccount()
        api.connectError = IllegalStateException("session expired or revoked")
        api.onRefresh = { account ->
            account.copy(accessToken = "atk-still-bad", refreshToken = "rt-rotated", accessExpiresUnix = FAR_FUTURE)
        }
        rule.setContent {
            AgentTheme { AgentApp(UnusedBridge, api, store = sessions) }
        }
        rule.waitForTag("status")
        rule.onNodeWithTag("status").assertTextEquals(SESSION_EXPIRED_MESSAGE)
        assertEquals(1, api.refreshCalls)
        assertEquals(listOf("atk-stale", "atk-still-bad"), api.connectedTokens)
        assertNull(sessions.load())
        rule.waitForIdle()
        assertEquals(1, api.refreshCalls)
        assertNull(sessions.load())
    }

    @Test
    fun signInAgainLeavesASlowRefresh() {
        val sessions = MemorySession()
        sessions.save(sampleAccount(accessToken = "atk-old", accessExpiresUnix = 1, refreshExpiresUnix = FAR_FUTURE))
        val release = CountDownLatch(1)
        val started = CountDownLatch(1)
        val finished = AtomicBoolean(false)
        val api = ShellAccount()
        api.onRefresh = { account ->
            started.countDown()
            assertTrue(release.await(5, TimeUnit.SECONDS))
            finished.set(true)
            account.copy(accessToken = "should-not-apply", accessExpiresUnix = FAR_FUTURE, refreshToken = "rt-new")
        }
        rule.setContent {
            AgentTheme { AgentApp(UnusedBridge, api, store = sessions) }
        }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        rule.onNodeWithText("Checking session").assertExists()
        rule.onNodeWithTag("sign-in-again").performClick()
        release.countDown()
        rule.waitUntil(5_000) { finished.get() }
        rule.waitForIdle()
        rule.onNodeWithTag("username").assertExists()
        rule.onNodeWithTag("top-title").assertTextEquals("Sign in")
        assertNull(sessions.load())
        rule.waitForIdle()
        assertNull(sessions.load())
    }

    @Test
    fun networkBlipWhileRefreshingKeepsTheSavedSignIn() {
        val sessions = MemorySession()
        sessions.save(sampleAccount(accessToken = "atk-old", accessExpiresUnix = 1, refreshExpiresUnix = FAR_FUTURE))
        val api = ShellAccount()
        api.refreshError = IOException("connection refused")
        api.connectError = IOException("connection refused")
        rule.setContent {
            AgentTheme { AgentApp(UnusedBridge, api, store = sessions) }
        }
        rule.waitForTag("machines-error")
        rule.onNodeWithTag("top-title").assertTextEquals("Machines")
        assertEquals("atk-old", sessions.load()?.accessToken)
        assertEquals("rt", sessions.load()?.refreshToken)
        assertTrue(api.refreshCalls >= 1)
        assertEquals(0, rule.onAllNodesWithTag("username").fetchSemanticsNodes().size)
    }

    @Test
    fun reconnectNetworkFailureAfterRefreshKeepsTheNewTokens() {
        val sessions = MemorySession()
        sessions.save(sampleAccount(accessToken = "atk-old", accessExpiresUnix = FAR_FUTURE, refreshExpiresUnix = FAR_FUTURE))
        val api = ShellAccount(session = StubSession(listOf(sampleMachine("studio"))))
        api.connectScript.add(IllegalStateException("session expired or revoked"))
        api.connectScript.add(IOException("connection refused"))
        api.onRefresh = { account ->
            account.copy(accessToken = "atk-new", refreshToken = "rt-new", accessExpiresUnix = FAR_FUTURE)
        }
        rule.setContent {
            AgentTheme { AgentApp(UnusedBridge, api, store = sessions) }
        }
        rule.waitForTag("machines-error")
        rule.onNodeWithText("connection refused").assertExists()
        rule.onNodeWithTag("top-title").assertTextEquals("Machines")
        assertEquals(1, api.refreshCalls)
        assertEquals("atk-new", sessions.load()?.accessToken)
        assertEquals("rt-new", sessions.load()?.refreshToken)
        assertEquals(listOf("atk-old", "atk-new"), api.connectedTokens)
    }

    @Test
    fun openSocketSessionExpiryRefreshesInsteadOfSigningOut() {
        val sessions = MemorySession()
        sessions.save(sampleAccount(accessToken = "atk-live", accessExpiresUnix = FAR_FUTURE))
        var lists = 0
        val session = StubSession(emptyList()) {
            lists += 1
            if (lists == 1) throw IllegalStateException("session revoked")
            listOf(sampleMachine("studio"))
        }
        val api = ShellAccount(session = session)
        api.onRefresh = { account ->
            account.copy(accessToken = "atk-rotated", refreshToken = "rt-rotated", accessExpiresUnix = FAR_FUTURE)
        }
        rule.setContent {
            AgentTheme { AgentApp(UnusedBridge, api, store = sessions) }
        }
        rule.waitForText("studio")
        assertEquals(1, api.refreshCalls)
        assertEquals("atk-rotated", sessions.load()?.accessToken)
        assertEquals("rt-rotated", sessions.load()?.refreshToken)
        assertNotNull(sessions.load())
    }

    private fun androidx.compose.ui.test.junit4.ComposeContentTestRule.waitForText(text: String) {
        waitUntil(timeoutMillis = 8_000) {
            onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun androidx.compose.ui.test.junit4.ComposeContentTestRule.waitForTag(tag: String) {
        waitUntil(timeoutMillis = 8_000) {
            onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
        }
    }
}

private const val FAR_FUTURE = 4_000_000_000L

private fun sampleAccount(
    accessToken: String = "atk",
    accessExpiresUnix: Long = FAR_FUTURE,
    refreshExpiresUnix: Long = FAR_FUTURE,
) = UserAccount(
    server = "wss://relay.example.com",
    fingerprint = "",
    user = "alice",
    role = "user",
    deviceId = "dev",
    accessToken = accessToken,
    accessExpiresUnix = accessExpiresUnix,
    refreshToken = "rt",
    refreshExpiresUnix = refreshExpiresUnix,
)

private fun sampleMachine(name: String) = MachineRow(
    id = "m1",
    name = name,
    hostname = "$name.local",
    os = "linux",
    arch = "amd64",
    version = "0.1.0",
    online = true,
    preset = "trusted",
    allowRead = true,
    allowWrite = false,
    allowExec = false,
    allowDesktop = false,
    allowDesktopStream = false,
    allowRemoteView = false,
    allowRemoteControl = false,
)

private class MemorySession : SessionStore {
    private var account: UserAccount? = null
    override fun load(): UserAccount? = account
    override fun save(account: UserAccount) { this.account = account }
    override fun clear() { account = null }
}

private class ShellAccount(
    private val session: ClientSession = StubSession(emptyList()),
) : AccountApi {
    var refreshCalls = 0
    var onRefresh: (UserAccount) -> UserAccount = { it }
    var connectError: Exception? = null
    var refreshError: Exception? = null
    val connectScript = mutableListOf<Exception?>()
    val connectedTokens = mutableListOf<String>()

    override fun refresh(account: UserAccount): UserAccount {
        refreshCalls += 1
        refreshError?.let { throw it }
        return onRefresh(account)
    }

    override fun connect(account: UserAccount): ClientSession {
        connectedTokens += account.accessToken
        if (connectScript.isNotEmpty()) {
            connectScript.removeAt(0)?.let { throw it }
        }
        connectError?.let { throw it }
        return session
    }

    override fun login(
        server: String,
        fingerprint: String,
        username: String,
        password: String,
        totp: String,
        deviceName: String,
    ): UserAccount = error("unused")

    override fun logout(account: UserAccount) = Unit
    override fun listNodes(account: UserAccount): List<NodeRow> = emptyList()
    override fun listDevices(account: UserAccount): List<DeviceRow> = emptyList()
    override fun enrollAsNode(account: UserAccount, name: String) = Unit
}

private object UnusedBridge : LinkBridge {
    override fun protocolVersion(): UInt = 1u
    override fun extensionNames(): List<String> = emptyList()
    override fun connect(relay: String, token: String, fingerprint: String, identityDir: String): ClientSession {
        error("admin connect is not used here")
    }
}

private class StubSession(
    private val machines: List<MachineRow>,
    private val onList: (() -> List<MachineRow>)? = null,
) : ClientSession {
    override fun listMachines(): List<MachineRow> = onList?.invoke() ?: machines
    override fun listDir(node: String, path: String): List<FileRow> = emptyList()
    override fun readBytes(node: String, path: String, offset: ULong, maxBytes: ULong): ByteArray = ByteArray(0)
    override fun writeBytes(node: String, path: String, data: ByteArray) = Unit
    override fun mkdir(node: String, path: String, recursive: Boolean) = Unit
    override fun remove(node: String, path: String, recursive: Boolean) = Unit
    override fun rename(node: String, from: String, to: String) = Unit
    override fun exec(
        node: String,
        program: String,
        args: List<String>,
        cwd: String?,
        env: List<String>,
        shell: Boolean,
        timeoutMs: ULong,
        sink: OutputListener,
    ): ExecResult = ExecResult(0, false)

    override fun transferUp(
        node: String,
        remote: String,
        local: String,
        preferDirect: Boolean,
        sink: ProgressListener,
    ): TransferResult = TransferResult(0u, 0u, true, 0u, "relay", 0u)

    override fun transferDown(
        node: String,
        remote: String,
        local: String,
        preferDirect: Boolean,
        sink: ProgressListener,
    ): TransferResult = TransferResult(0u, 0u, true, 0u, "relay", 0u)

    override fun extension(node: String, name: String, payloadJson: String): String = "{}"
    override fun openPty(node: String, command: String?, rows: Int, cols: Int): PtySession = error("unused")
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
    ): PairingTicket = PairingTicket("ticket", name, 0)

    override fun close() = Unit
}
