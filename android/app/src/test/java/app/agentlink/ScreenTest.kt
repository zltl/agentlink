package app.agentlink

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import app.agentlink.model.ConsentChoices
import app.agentlink.model.ConsentStep
import app.agentlink.ui.AgentTheme
import app.agentlink.ui.ConsentPage
import app.agentlink.ui.NodeStatusPage
import app.agentlink.ui.ReviewPage
import app.agentlink.ui.RoleScreen
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ScreenTest {
    @get:Rule
    val rule = createComposeRule()

    @Test
    fun roleScreenOffersBothModes() {
        var node = false
        var client = false
        rule.setContent {
            AgentTheme {
                RoleScreen(onNode = { node = true }, onClient = { client = true })
            }
        }
        rule.onNodeWithText("This phone").assertIsDisplayed().performClick()
        rule.onNodeWithText("Control a machine").performClick()
        assertTrue(node && client)
    }

    @Test
    fun eachConsentScreenNamesThePermission() {
        val steps = ConsentStep.entries.filter { it != ConsentStep.Review && it != ConsentStep.AppStorage }
        var step by mutableStateOf(steps.first())
        rule.setContent {
            AgentTheme {
                ConsentPage(step, onAllow = {}, onSkip = {})
            }
        }
        steps.forEach { next ->
            step = next
            rule.waitForIdle()
            rule.onNodeWithText(next.title).assertIsDisplayed()
            rule.onNodeWithText("Allow").assertIsDisplayed()
            rule.onNodeWithText("Skip").assertIsDisplayed()
        }
    }

    @Test
    fun appStorageHasNoSilentSkip() {
        rule.setContent {
            AgentTheme { ConsentPage(ConsentStep.AppStorage, onAllow = {}, onSkip = null) }
        }
        rule.onNodeWithText("Allow app storage").assertIsDisplayed()
        assertEquals(0, rule.onAllNodesWithText("Skip").fetchSemanticsNodes().size)
    }

    @Test
    fun reviewShowsTheCeilingBeforeStart() {
        rule.setContent {
            AgentTheme {
                ReviewPage(
                    choices = ConsentChoices(appStorage = true, commands = false, notifications = true),
                    canStart = true,
                    onStart = {},
                    onBack = {},
                )
            }
        }
        rule.onNodeWithText("Commands: off.").assertIsDisplayed()
        rule.onNodeWithText("Start node").assertIsDisplayed()
    }

    @Test
    fun nodePageShowsStatusAndAudit() {
        rule.setContent {
            AgentTheme {
                NodeStatusPage(
                    status = "{\"state\":\"reconnecting\"}",
                    nodeId = "abc",
                    audit = "{\"op\":\"exec\"}",
                    onStop = {},
                )
            }
        }
        rule.onNodeWithText("{\"state\":\"reconnecting\"}").assertIsDisplayed()
        rule.onNodeWithText("Stop node").assertIsDisplayed()
    }
}
