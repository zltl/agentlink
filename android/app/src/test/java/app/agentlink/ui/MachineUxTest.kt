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
    fun offlineMachinesDisableActions() {
        val offline = sample(online = false, read = true, exec = true, desktop = true)
        assertTrue(machineActions(offline).none { it.enabled })
        assertFalse(desktopCapability(offline).available)
        assertEquals("Offline", capabilityLabels(offline))
    }

    @Test
    fun actionsFollowEffectivePolicyFlags() {
        // Backend NodePolicy::allows: PtyOpen needs allow_exec; list/read needs
        // allow_read; screenshots are allow_desktop or remote view.
        val none = sample(online = true, read = false, exec = false, desktop = false)
        assertTrue(machineActions(none).none { it.enabled })
        assertEquals("Needs exec permission", machineActions(none).first { it.action == MachineAction.Terminal }.detail)
        assertEquals("Reading files is turned off", machineActions(none).first { it.action == MachineAction.Files }.detail)
        assertEquals("Needs desktop permission.", machineActions(none).first { it.action == MachineAction.Desktop }.detail)
        assertEquals("File transfer is turned off", machineActions(none).first { it.action == MachineAction.Transfer }.detail)
        assertEquals("No actions allowed", capabilityLabels(none))
        val drive = desktopCapability(none)
        assertFalse(drive.available || drive.screenshots || drive.control || drive.live)

        val shell = sample(online = true, read = true, exec = true, desktop = false, write = true)
        assertTrue(machineActions(shell).first { it.action == MachineAction.Terminal }.enabled)
        assertTrue(machineActions(shell).first { it.action == MachineAction.Files }.enabled)
        assertTrue(machineActions(shell).first { it.action == MachineAction.Transfer }.enabled)
        assertFalse(machineActions(shell).first { it.action == MachineAction.Desktop }.enabled)
        assertEquals("Files · Terminal · Upload", capabilityLabels(shell))
    }

    @Test
    fun desktopCapabilityMatchesNodePolicyHelpers() {
        val shots = sample(online = true, read = true, exec = false, desktop = true)
        val cap = desktopCapability(shots)
        assertTrue(cap.available && cap.screenshots && cap.control)
        assertFalse(cap.live)
        assertTrue(cap.reason.contains("Screenshots and input"))

        val view = sample(online = true, read = true, exec = false, desktop = false, remoteView = true)
        val live = desktopCapability(view)
        assertTrue(live.available && live.screenshots && live.live)
        assertFalse(live.control)
        assertTrue(live.reason.contains("Live view is allowed"))
        assertFalse(live.reason.contains("and input are allowed"))
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
        write: Boolean = false,
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
        allowWrite = write,
        allowExec = exec,
        allowDesktop = desktop,
        allowDesktopStream = desktopStream,
        allowRemoteView = remoteView,
        allowRemoteControl = remoteControl,
    )
}
