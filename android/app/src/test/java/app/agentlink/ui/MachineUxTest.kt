package app.agentlink.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import app.agentlink.bridge.MachineRow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class MachineUxTest {
    @get:Rule
    val rule = createComposeRule()

    @Test
    fun pairingIsFullAccess() {
        val flags = pairFlags()
        assertTrue(flags.allowRead && flags.allowWrite && flags.allowExec)
        assertTrue(flags.allowDesktop && flags.allowDesktopStream)
        assertTrue(flags.allowRemoteView && flags.allowRemoteControl)
        assertEquals(3600uL, flags.ttlSecs)
    }

    @Test
    fun offlineMachinesDisableActionsAndOnlineOnesAreFull() {
        val offline = sample(online = false, read = true, exec = true, desktop = true)
        assertTrue(machineActions(offline).none { it.enabled })
        assertFalse(desktopCapability(offline).available)

        val online = sample(online = true, read = false, exec = false, desktop = false)
        val desktop = machineActions(online).first { it.action == MachineAction.Desktop }
        assertTrue(desktop.enabled)
        assertTrue(desktop.detail.contains("Live view"))
        assertTrue(machineActions(online).first { it.action == MachineAction.Terminal }.enabled)
        assertTrue(machineActions(online).first { it.action == MachineAction.Files }.enabled)
        val drive = desktopCapability(online)
        assertTrue(drive.screenshots && drive.control && drive.live)
    }

    @Test
    fun pathCrumbsAndByteSizesStayStable() {
        assertEquals(listOf("app:/" to "app:"), pathCrumbs("app:/"))
        assertEquals(
            listOf("app:/" to "app:", "app:/docs" to "docs", "app:/docs/a" to "a"),
            pathCrumbs("app:/docs/a"),
        )
        assertEquals("0 B", formatBytes(0u))
        assertEquals("1 KB", formatBytes(1024u))
        assertEquals("1.5 KB", formatBytes(1536u))
        assertEquals("upload.bin", safeFileName("../"))
        assertEquals("notes.txt", safeFileName("dir/notes.txt"))
        assertEquals("The machine refused this.", permissionHint("permission denied"))
        assertNull(permissionHint("no such file"))
    }

    @Test
    fun machinesListShowsStatusEmptyAndError() {
        rule.setContent {
            AgentTheme {
                MachinesBody(
                    machines = listOf(
                        sample(name = "studio", online = true, read = true, exec = true, desktop = true),
                        sample(name = "laptop", id = "m2", online = false, read = true, exec = false, desktop = false),
                    ),
                    error = "Relay unreachable",
                    refreshing = false,
                    loading = false,
                    onRefresh = {},
                    onOpen = {},
                    onPair = {},
                    showHeader = false,
                )
            }
        }
        rule.onNodeWithText("studio").assertIsDisplayed()
        rule.onNodeWithText("Online").assertIsDisplayed()
        rule.onNodeWithText("Offline").assertIsDisplayed()
        rule.onNodeWithText("1 online · 1 offline").assertIsDisplayed()
        rule.onNodeWithText("Relay unreachable").assertIsDisplayed()
        rule.onNodeWithText("Pair a machine").assertIsDisplayed()
    }

    @Test
    fun emptyAndLoadingStatesStayDistinct() {
        rule.setContent {
            AgentTheme {
                MachinesBody(
                    machines = emptyList(),
                    error = null,
                    refreshing = false,
                    loading = true,
                    onRefresh = {},
                    onOpen = {},
                    onPair = {},
                    showHeader = false,
                )
            }
        }
        rule.onNodeWithText("Loading machines").assertIsDisplayed()
        rule.onNodeWithText("No machines yet").assertDoesNotExist()
    }

    @Test
    fun hubOpensEnabledFilesAndExplainsDisabledShell() {
        var opened: MachineAction? = null
        rule.setContent {
            AgentTheme {
                MachineHub(
                    machine = sample(online = true, read = true, exec = false, desktop = false),
                    error = null,
                    refreshing = false,
                    onRefresh = {},
                    onOpen = { opened = it },
                )
            }
        }
        rule.onNodeWithText("Needs exec permission").assertIsDisplayed()
        rule.onNodeWithText("Files").performClick()
        assertEquals(MachineAction.Files, opened)
    }

    private fun sample(
        name: String = "studio",
        id: String = "m1",
        online: Boolean,
        read: Boolean,
        exec: Boolean,
        desktop: Boolean,
        remoteView: Boolean = false,
        remoteControl: Boolean = false,
        desktopStream: Boolean = false,
    ) = MachineRow(
        id = id,
        name = name,
        hostname = "$name.local",
        os = "linux",
        arch = "amd64",
        version = "0.1.0",
        online = online,
        preset = "exec",
        allowRead = read,
        allowWrite = false,
        allowExec = exec,
        allowDesktop = desktop,
        allowDesktopStream = desktopStream,
        allowRemoteView = remoteView,
        allowRemoteControl = remoteControl,
    )
}
