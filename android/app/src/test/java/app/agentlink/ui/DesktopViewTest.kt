package app.agentlink.ui

import android.graphics.Bitmap
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.click
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.unit.dp
import app.agentlink.bridge.MachineRow
import app.agentlink.model.DesktopViewport
import app.agentlink.model.decorateGrantFailure
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class DesktopViewTest {
    @get:Rule
    val rule = createComposeRule()

    @Test
    fun fullscreenHidesChromeAndCloses() {
        rule.setContent {
            AgentTheme {
                Box(Modifier.size(360.dp, 640.dp)) {
                    ViewerHarness(control = true, live = true)
                }
            }
        }
        rule.onNodeWithText("Stream screenshots").assertIsDisplayed()
        rule.onNodeWithText("Fullscreen").performClick()
        rule.onNodeWithTag("desktop-fullscreen-root").assertIsDisplayed()
        rule.onNodeWithTag("desktop-close").assertIsDisplayed()
        rule.onNodeWithContentDescription("Remote screen").assertIsDisplayed()
        rule.onNodeWithText("Stream screenshots").assertDoesNotExist()
        rule.onNodeWithText("Fullscreen").assertDoesNotExist()
        rule.onNodeWithTag("desktop-close").performClick()
        rule.onNodeWithText("Fullscreen").assertIsDisplayed()
        rule.onNodeWithText("Stream screenshots").assertIsDisplayed()
        rule.onNodeWithTag("desktop-close").assertDoesNotExist()
    }

    @Test
    fun unavailableDesktopHasNoFullscreen() {
        rule.setContent {
            AgentTheme {
                DesktopUnavailable("Desktop is turned off. This machine may be headless.")
            }
        }
        rule.onNodeWithText("Desktop unavailable").assertIsDisplayed()
        rule.onNodeWithText("Fullscreen").assertDoesNotExist()
    }

    @Test
    @Config(sdk = [28], qualifiers = "w800dp-h360dp")
    fun landscapeImageFillsThePane() {
        rule.setContent {
            AgentTheme {
                ViewerHarness(control = true, live = false)
            }
        }
        rule.onNodeWithText("Fullscreen").assertIsDisplayed()
        val view = rule.onNodeWithTag("desktop-view").getUnclippedBoundsInRoot()
        val image = rule.onNodeWithTag("desktop-viewport").getUnclippedBoundsInRoot()
        assertEquals((view.right - view.left).value, (image.right - image.left).value, 1f)
        assertEquals((view.bottom - view.top).value, (image.bottom - image.top).value, 1f)
        assertTrue(view.right - view.left > view.bottom - view.top)
    }

    @Test
    fun portraitKeepsRoomForControls() {
        rule.setContent {
            AgentTheme {
                Box(Modifier.size(360.dp, 640.dp)) {
                    ViewerHarness(control = true, live = false)
                }
            }
        }
        rule.onNodeWithText("Type into the focused field").assertIsDisplayed()
        val view = rule.onNodeWithTag("desktop-view").getUnclippedBoundsInRoot()
        val image = rule.onNodeWithTag("desktop-viewport").getUnclippedBoundsInRoot()
        val viewHeight = view.bottom - view.top
        val imageHeight = image.bottom - image.top
        assertTrue(imageHeight < viewHeight)
        assertTrue(imageHeight > 80.dp)
    }

    @Test
    fun tapAtFitInjectsTheCenter() {
        val injected = mutableListOf<JSONObject>()
        rule.setContent {
            AgentTheme {
                Box(Modifier.size(360.dp, 640.dp)) {
                    ViewerHarness(control = true, live = false, onInject = { injected += it })
                }
            }
        }
        rule.onNodeWithTag("desktop-screen").performTouchInput { click(center) }
        rule.waitForIdle()
        assertEquals(1, injected.size)
        val payload = injected.single()
        assertEquals("tap", payload.getString("action"))
        assertEquals(0.5, payload.getDouble("x"), 0.08)
        assertEquals(0.5, payload.getDouble("y"), 0.08)
    }

    @Test
    fun watchOnlyDoesNotInject() {
        val injected = mutableListOf<JSONObject>()
        rule.setContent {
            AgentTheme {
                Box(Modifier.size(360.dp, 640.dp)) {
                    ViewerHarness(control = false, live = false, onInject = { injected += it })
                }
            }
        }
        rule.onNodeWithText("Input stays off for this preset.").assertIsDisplayed()
        rule.onNodeWithTag("desktop-screen").performTouchInput { click(center) }
        rule.waitForIdle()
        assertTrue(injected.isEmpty())
        rule.onNodeWithText("Fullscreen").assertIsDisplayed()
    }

    @Test
    fun signedGrantNoteNamesTheControllerKeyAndOffersImport() {
        val key = "cd".repeat(32)
        val note = decorateGrantFailure(
            "authentication failed: signed grant required (owner keys configured)",
            "ab".repeat(32),
            key,
        )
        rule.setContent {
            AgentTheme {
                Box(Modifier.size(360.dp, 640.dp)) {
                    ViewerHarness(control = false, live = false, note = note, onFixGrant = {})
                }
            }
        }
        rule.onNodeWithText(key, substring = true).assertIsDisplayed()
        rule.onNodeWithText("Fix grant").assertIsDisplayed()
        rule.onNodeWithText("does not paste a grant", substring = true).assertDoesNotExist()
    }
}

@androidx.compose.runtime.Composable
private fun ViewerHarness(
    control: Boolean,
    live: Boolean,
    onInject: (JSONObject) -> Unit = {},
    note: String = "Screenshot 32×18",
    onFixGrant: (() -> Unit)? = null,
) {
    val machine = MachineRow(
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
        allowRemoteView = live,
        allowRemoteControl = control,
    )
    val frame = remember {
        Bitmap.createBitmap(32, 18, Bitmap.Config.ARGB_8888).asImageBitmap()
    }
    var fullscreen by remember { mutableStateOf(false) }
    var viewport by remember { mutableStateOf(DesktopViewport()) }
    var stream by remember { mutableStateOf(true) }
    var typed by remember { mutableStateOf("") }
    DesktopView(
        machine = machine,
        capability = DesktopCapability(
            available = true,
            screenshots = true,
            control = control,
            live = live,
            reason = "Screenshots are allowed.",
        ),
        note = note,
        frame = frame,
        shotW = 32,
        shotH = 18,
        stream = stream,
        onStream = { stream = it },
        typed = typed,
        onTyped = { typed = it },
        onLive = {},
        onInject = onInject,
        fullscreen = fullscreen,
        onFullscreenChange = { fullscreen = it },
        viewport = viewport,
        onViewportChange = { viewport = it },
        onFixGrant = onFixGrant,
    )
}
