package app.agentlink

import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import app.agentlink.account.AccountApi
import app.agentlink.account.DeviceRow
import app.agentlink.account.NodeRow
import app.agentlink.account.SessionStore
import app.agentlink.account.UserAccount
import app.agentlink.account.parseEnroll
import app.agentlink.bridge.ClientSession
import app.agentlink.ui.AgentTheme
import app.agentlink.ui.UserLogin
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
@OptIn(ExperimentalCoroutinesApi::class)
class LoginFlowTest {
    @get:Rule
    val rule = createComposeRule()

    private val api = FakeAccount()
    private val sessions = MemorySession()
    private val immediate = Dispatchers.Unconfined

    @Before
    fun setMainDispatcher() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
    }

    @After
    fun resetMainDispatcher() {
        Dispatchers.resetMain()
    }

    @Test
    fun loginShowsOwnAndSharedNodesAndActAsNodeUsesNoPairingToken() {
        rule.setContent {
            AgentTheme {
                UserLogin(
                    api,
                    sessions,
                    onConnected = {},
                    onActAsNode = {},
                    onAdmin = {},
                    background = immediate,
                    ui = immediate,
                )
            }
        }
        assertAbsent("server")
        assertAbsent("fingerprint")
        assertAbsent("totp")
        rule.onNodeWithTag("username").performTextInput("alice")
        rule.onNodeWithTag("password").performTextInput("password-alice")
        rule.onNodeWithTag("login").activate()
        assertEquals(1, api.loginCalls)
        assertEquals("", api.lastServer)
        assertEquals("", api.lastFingerprint)
        assertEquals("android", api.lastDevice)
        assertEquals("alice", sessions.load()?.user)
        rule.onNodeWithTag("session-user").assertTextEquals("alice")
        rule.onNodeWithTag("nodes").assertTextContains("laptop", substring = true)
        rule.onNodeWithTag("nodes").assertTextContains("shared", substring = true)
        rule.onNodeWithTag("act-node").activate()
        assertEquals(1, api.enrollAsNodeCalls)
        assertNull(api.lastPairingToken)
        rule.onNodeWithTag("devices-button").activate()
        assertEquals(1, api.deviceListCalls)
        rule.onNodeWithTag("devices").performScrollTo().assertIsDisplayed()
        rule.onNodeWithTag("logout").activate()
        assertNull(sessions.load())
        rule.onNodeWithTag("status").assertTextEquals("logged out")
        assertEquals(1, api.logoutCalls)
    }

    @Test
    fun totpRequiredFocusesTheCodeField() {
        api.requireTotp = true
        rule.setContent {
            AgentTheme {
                UserLogin(
                    api,
                    sessions,
                    onConnected = {},
                    onActAsNode = {},
                    onAdmin = {},
                    background = immediate,
                    ui = immediate,
                )
            }
        }
        assertAbsent("totp")
        rule.onNodeWithTag("username").performTextInput("alice")
        rule.onNodeWithTag("password").performTextInput("password-alice")
        rule.onNodeWithTag("login").activate()
        rule.onNodeWithTag("status").assertTextEquals("This account needs the 6-digit authenticator code.")
        rule.onNodeWithTag("totp").assertIsFocused()
        rule.onNodeWithTag("totp").performTextInput("123456")
        rule.onNodeWithTag("login").activate()
        assertEquals("alice", sessions.load()?.user)
        rule.onNodeWithTag("session-user").assertTextEquals("alice")
        assertEquals("123456", api.lastTotp)
    }

    @Test
    fun selfHostedRelayIsSentWhenOpened() {
        rule.setContent {
            AgentTheme {
                UserLogin(
                    api,
                    sessions,
                    onConnected = {},
                    onActAsNode = {},
                    onAdmin = {},
                    background = immediate,
                    ui = immediate,
                )
            }
        }
        rule.onNodeWithTag("advanced-relay").performScrollTo().activate()
        val server = rule.onNodeWithTag("server").fetchSemanticsNode().config.getOrNull(SemanticsProperties.EditableText)?.text
        assertEquals("", server)
        rule.onNodeWithTag("server").performTextReplacement("wss://relay.example:7443")
        rule.onNodeWithTag("fingerprint").performTextInput("webpki")
        rule.onNodeWithTag("username").performTextInput("alice")
        rule.onNodeWithTag("password").performTextInput("password-alice")
        rule.onNodeWithTag("login").performScrollTo().activate()
        assertEquals("wss://relay.example:7443", api.lastServer)
        assertEquals("webpki", api.lastFingerprint)
        assertEquals("alice", sessions.load()?.user)
    }

    @Test
    fun enrollLinkCarriesTheToken() {
        val link = parseEnroll(
            Uri.parse("agentlink://enroll?relay=wss://relay.example.com&fingerprint=&token=enroll-1&name=phone&access=read-only"),
        )
        assertEquals("enroll-1", link?.token)
        assertEquals("wss://relay.example.com", link?.server)
        assertEquals("phone", link?.name)
        assertNull(parseEnroll(Uri.parse("https://relay.example.com/view")))
    }
}

private class MemorySession : SessionStore {
    private var account: UserAccount? = null
    override fun load(): UserAccount? = account
    override fun save(account: UserAccount) { this.account = account }
    override fun clear() { account = null }
}

private class FakeAccount : AccountApi {
    var enrollAsNodeCalls = 0
    var lastPairingToken: String? = null
    var logoutCalls = 0
    var deviceListCalls = 0
    var requireTotp = false
    var loginCalls = 0
    var lastServer: String? = null
    var lastFingerprint: String? = null
    var lastTotp: String? = null
    var lastDevice: String? = null

    override fun login(
        server: String,
        fingerprint: String,
        username: String,
        password: String,
        totp: String,
        deviceName: String,
    ): UserAccount {
        loginCalls += 1
        lastServer = server
        lastFingerprint = fingerprint
        lastTotp = totp
        lastDevice = deviceName
        if (requireTotp && totp.isBlank()) throw IllegalStateException("totp code required")
        return UserAccount(server, fingerprint, username, "user", "device-key", "atk.test", 0, "rtk.test")
    }

    override fun refresh(account: UserAccount): UserAccount = account

    override fun logout(account: UserAccount) {
        logoutCalls += 1
    }

    override fun listNodes(account: UserAccount): List<NodeRow> = listOf(
        NodeRow("n1", "laptop", account.user, "owner", "read-only", true),
        NodeRow("n2", "shared-box", "bob", "shared", "read-only", false),
    )

    override fun listDevices(account: UserAccount): List<DeviceRow> {
        deviceListCalls += 1
        return listOf(DeviceRow(account.deviceId, "android", false))
    }

    override fun enrollAsNode(account: UserAccount, name: String) {
        enrollAsNodeCalls += 1
        lastPairingToken = null
    }

    override fun connect(account: UserAccount): ClientSession {
        throw UnsupportedOperationException("connect")
    }
}

private fun SemanticsNodeInteraction.activate() = performSemanticsAction(SemanticsActions.OnClick)

private fun LoginFlowTest.assertAbsent(tag: String) {
    assertEquals(0, rule.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
}
