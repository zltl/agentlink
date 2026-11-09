package app.agentlink

import app.agentlink.model.ConsentChoices
import app.agentlink.model.ConsentStep
import app.agentlink.model.DirItem
import app.agentlink.model.auditRecord
import app.agentlink.model.ceilingOf
import app.agentlink.model.ceilingSummary
import app.agentlink.model.childPath
import app.agentlink.model.consentBody
import app.agentlink.model.consentSteps
import app.agentlink.model.decisionsComplete
import app.agentlink.model.fingerprintProblem
import app.agentlink.model.DESKTOP_MAX_SCALE
import app.agentlink.model.DesktopViewport
import app.agentlink.model.OneFingerRelease
import app.agentlink.model.displayedFrame
import app.agentlink.model.gestureFromDrag
import app.agentlink.model.jsonField
import app.agentlink.model.letterbox
import app.agentlink.model.mapDesktopTouch
import app.agentlink.model.mapTouch
import app.agentlink.model.oneFingerRelease
import app.agentlink.model.panViewport
import app.agentlink.model.zoomViewport
import app.agentlink.model.parentPath
import app.agentlink.model.parseSafGuest
import app.agentlink.model.PtyKey
import app.agentlink.model.TerminalScreen
import app.agentlink.model.planCommand
import app.agentlink.model.ptySequence
import app.agentlink.model.ptyText
import app.agentlink.model.rawKeysForName
import app.agentlink.model.rawKeysForText
import app.agentlink.model.relayProblem
import app.agentlink.model.searchFiles
import app.agentlink.model.webrtcFallsBackToScreenshot
import android.view.KeyEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ModelTest {
    @Test
    fun everyPermissionHasItsOwnExplanation() {
        val bodies = consentSteps().map { consentBody(it) }
        assertEquals(ConsentStep.entries.size, bodies.size)
        assertEquals(bodies.size, bodies.toSet().size)
        assertTrue(bodies.all { it.length > 40 })
    }

    @Test
    fun ceilingFollowsExplicitChoices() {
        val skipped = ConsentChoices(appStorage = true, visited = ConsentStep.entries.toSet())
        val ceiling = ceilingOf(skipped)
        assertTrue(ceiling.allowRead)
        assertTrue(ceiling.allowWrite)
        assertFalse(ceiling.allowExec)
        assertFalse(ceiling.allowDesktop)
        assertFalse(ceiling.allowDesktopStream)
        assertFalse(ceiling.allowRemoteView)
        assertFalse(ceiling.allowRemoteControl)
        assertFalse(decisionsComplete(ConsentChoices(appStorage = false, visited = ConsentStep.entries.toSet())))
        assertTrue(decisionsComplete(skipped))
        val chosen = ConsentChoices(
            appStorage = true,
            commands = true,
            screenCapture = true,
            liveStream = true,
            accessibility = true,
            root = true,
        )
        val full = ceilingOf(chosen)
        assertTrue(full.allowExec && full.allowDesktop && full.allowDesktopStream)
        assertTrue(full.allowRemoteView && full.allowRemoteControl)
        assertTrue(ceilingSummary(chosen).any { it.contains("Root was opted in") })
    }

    @Test
    fun touchMapsTheLetterboxedImage() {
        val box = letterbox(200f, 400f, 100f, 100f)
        assertEquals(0f, box.imageLeft, 0.01f)
        assertEquals(100f, box.imageTop, 0.01f)
        val center = mapTouch(box, 100f, 200f)
        assertEquals(0.5f, center!!.first, 0.01f)
        assertEquals(0.5f, center.second, 0.01f)
        assertNull(mapTouch(box, 100f, 10f))
        assertEquals("tap", gestureFromDrag(0.5f to 0.5f, 0.51f to 0.5f))
        assertEquals("swipe", gestureFromDrag(0.2f to 0.8f, 0.2f to 0.2f))
    }

    @Test
    fun desktopZoomKeepsFitMappingAndThePinchFocus() {
        val fitted = displayedFrame(200f, 400f, 100f, 100f, DesktopViewport())
        val box = letterbox(200f, 400f, 100f, 100f)
        assertEquals(box.imageLeft, fitted.imageLeft, 0.01f)
        assertEquals(box.imageTop, fitted.imageTop, 0.01f)
        assertEquals(box.imageWidth, fitted.imageWidth, 0.01f)
        assertEquals(box.imageHeight, fitted.imageHeight, 0.01f)
        val center = mapDesktopTouch(200f, 400f, 100f, 100f, DesktopViewport(), 100f, 200f)
        assertEquals(0.5f, center!!.first, 0.01f)
        assertEquals(0.5f, center.second, 0.01f)

        // 2× about a point left of center. The image overflows horizontally, so that point stays put.
        val zoomed = zoomViewport(200f, 400f, 100f, 100f, DesktopViewport(), 50f, 200f, 2f)
        assertEquals(2f, zoomed.scale, 0.01f)
        val focused = mapDesktopTouch(200f, 400f, 100f, 100f, zoomed, 50f, 200f)
        assertEquals(0.25f, focused!!.first, 0.02f)
        assertEquals(0.5f, focused.second, 0.02f)

        val shrunk = zoomViewport(200f, 400f, 100f, 100f, zoomed, 100f, 200f, 0.1f)
        assertTrue(shrunk.isFitted())
        assertEquals(0f, shrunk.offsetX, 0.01f)
        assertEquals(0f, shrunk.offsetY, 0.01f)

        var maxed = DesktopViewport()
        repeat(6) { maxed = zoomViewport(200f, 200f, 100f, 100f, maxed, 100f, 100f, 2f) }
        assertEquals(DESKTOP_MAX_SCALE, maxed.scale, 0.001f)

        val wide = displayedFrame(200f, 200f, 100f, 50f, DesktopViewport())
        assertEquals(0f, wide.imageLeft, 0.01f)
        assertEquals(200f, wide.imageWidth, 0.01f)
        val wideZoom = zoomViewport(200f, 200f, 100f, 50f, DesktopViewport(), 100f, 100f, 2f)
        val wideCenter = mapDesktopTouch(200f, 200f, 100f, 50f, wideZoom, 100f, 100f)
        assertEquals(0.5f, wideCenter!!.first, 0.02f)
        assertEquals(0.5f, wideCenter.second, 0.02f)
    }

    @Test
    fun desktopPanStaysInsideTheZoomedFrame() {
        val zoomed = zoomViewport(200f, 400f, 100f, 100f, DesktopViewport(), 100f, 200f, 2f)
        val stayed = panViewport(200f, 400f, 100f, 100f, DesktopViewport(), 40f, 40f)
        assertTrue(stayed.isFitted())
        val tiny = panViewport(200f, 400f, 100f, 100f, DesktopViewport(scale = 1.01f), 4f, 0f)
        assertEquals(1.01f, tiny.scale, 0.001f)
        val pushed = panViewport(200f, 400f, 100f, 100f, zoomed, 10_000f, 0f)
        val frame = displayedFrame(200f, 400f, 100f, 100f, pushed)
        assertEquals(0f, frame.imageLeft, 0.5f)
        assertTrue(frame.imageLeft + frame.imageWidth >= 199.5f)
        val pulled = panViewport(200f, 400f, 100f, 100f, zoomed, -10_000f, 0f)
        val other = displayedFrame(200f, 400f, 100f, 100f, pulled)
        assertEquals(200f, other.imageLeft + other.imageWidth, 0.5f)
        assertTrue(other.imageLeft <= 0.5f)
    }

    @Test
    fun oneFingerPansOnlyWhileZoomed() {
        assertEquals(OneFingerRelease.Tap, oneFingerRelease(1f, 2f, 16f, 0.5f to 0.5f, 0.5f to 0.5f))
        assertEquals(OneFingerRelease.Swipe, oneFingerRelease(1f, 40f, 16f, 0.2f to 0.8f, 0.2f to 0.2f))
        assertEquals(OneFingerRelease.Pan, oneFingerRelease(2f, 40f, 16f, 0.2f to 0.8f, 0.2f to 0.2f))
        assertEquals(OneFingerRelease.Tap, oneFingerRelease(2f, 4f, 16f, 0.4f to 0.4f, 0.41f to 0.4f))
    }

    @Test
    fun searchAndGuestPathsStayInsideTheGrant() {
        val tree = mapOf(
            "app:/" to listOf(DirItem("files", true), DirItem("notes.txt", false)),
            "app:/files" to listOf(DirItem("a.log", false), DirItem("nest", true)),
            "app:/files/nest" to listOf(DirItem("deep.log", false)),
        )
        val hits = searchFiles("app:/", "log") { tree[it].orEmpty() }
        assertEquals(listOf("app:/files/a.log", "app:/files/nest/deep.log"), hits)
        assertEquals("app:/files", childPath("app:/", "files"))
        assertEquals("app:/", parentPath("app:/files"))
        assertNull(parseSafGuest("saf:/abc/../secret"))
        assertEquals("abc", parseSafGuest("saf:/abc/docs/a.txt")!!.id)
        assertEquals("docs/a.txt", parseSafGuest("saf:/abc/docs/a.txt")!!.relative)
    }

    @Test
    fun auditLineMatchesTheDesktopFields() {
        val line = auditRecord("2026-01-01T00:00:00Z", "exec", "echo", false, "denied", "peer-1")
        assertEquals("2026-01-01T00:00:00Z", jsonField(line, "ts"))
        assertEquals("exec", jsonField(line, "op"))
        assertEquals("echo", jsonField(line, "detail"))
        assertTrue(line.contains("\"ok\":false"))
        assertEquals("denied", jsonField(line, "error"))
        assertEquals("peer-1", jsonField(line, "peer"))
        assertFalse(auditRecord("t", "stat", "app:/", true).contains("error"))
    }

    @Test
    fun commandPlanStaysInTheSandboxUnlessOptedIn() {
        val sandboxed = planCommand("echo", listOf("hi"), shell = true, shizuku = false, root = false)
        assertEquals(listOf("/system/bin/sh", "-c", "'echo' 'hi'"), sandboxed.argv)
        assertEquals("shell", sandboxed.via)
        val rooted = planCommand("id", emptyList(), shell = false, shizuku = true, root = true)
        assertEquals("root", rooted.via)
        assertEquals("su", rooted.argv.first())
        assertNull(relayProblem("wss://relay.example:7443"))
        assertEquals("Relay URL must start with wss://", relayProblem("ws://relay.example"))
        val pin = "sha256:" + "ab".repeat(32)
        assertNull(fingerprintProblem(pin))
        assertNull(fingerprintProblem(""))
        assertNull(fingerprintProblem("system+webpki"))
        assertNull(fingerprintProblem("webpki"))
        assertTrue(fingerprintProblem("sha256:abcd")!!.contains("64"))
    }

    @Test
    fun terminalEmulatorRunsFullscreenSequences() {
        val screen = TerminalScreen(3, 4)
        screen.feed("abcdX".encodeToByteArray())
        assertEquals("abcd", screen.rowText(0))
        assertEquals("X", screen.rowText(1))
        screen.feed("\u001b[2J\u001b[Hkeep".encodeToByteArray())
        assertEquals("keep", screen.rowText(0))
        screen.feed("\u001b[?1049h".encodeToByteArray())
        assertEquals("", screen.text().trim())
        screen.feed("alt".encodeToByteArray())
        assertEquals("alt", screen.rowText(0))
        screen.feed("\u001b[?1049l".encodeToByteArray())
        assertEquals("keep", screen.rowText(0))
        screen.feed("\u001b[2;3H\u001b[31mZ".encodeToByteArray())
        assertEquals('Z', screen.charAt(1, 2))
        assertEquals(1, screen.fgAt(1, 2))
        val report = screen.feed("\u001b[6n".encodeToByteArray())
        assertEquals("\u001b[2;4R", report.decodeToString())
        screen.feed("\u001b[?1h".encodeToByteArray())
        assertTrue(screen.applicationCursor)
        assertEquals("\u001bOA".encodeToByteArray().toList(), ptySequence(PtyKey.Up, true).toList())
        assertEquals("\u001b[A".encodeToByteArray().toList(), ptySequence(PtyKey.Up, false).toList())
        assertEquals(listOf(3.toByte()), ptyText("c", ctrl = true).toList())
    }

    @Test
    fun terminalScrollbackKeepsLinesThatLeaveTheScreen() {
        val screen = TerminalScreen(2, 8)
        screen.feed("one\r\ntwo\r\nthree".encodeToByteArray())
        assertEquals("two", screen.rowText(0))
        assertEquals("three", screen.rowText(1))
        assertEquals(1, screen.scrollbackLineCount())
        assertEquals("one", screen.scrollbackLine(0))
        assertTrue(screen.transcript().startsWith("one"))
        screen.clearTranscript()
        assertEquals(0, screen.scrollbackLineCount())
        assertEquals("", screen.rowText(0))
    }

    @Test
    fun rawKeysCoverAsciiAndFallBackForOtherText() {
        val hi = rawKeysForText("Hi")
        assertEquals(KeyEvent.KEYCODE_H, hi!![0].code)
        assertEquals(KeyEvent.META_SHIFT_ON, hi[0].meta)
        assertEquals(KeyEvent.KEYCODE_I, hi[1].code)
        assertEquals(0, hi[1].meta)
        assertNull(rawKeysForText("héllo"))
        assertEquals(KeyEvent.KEYCODE_ENTER, rawKeysForName("enter")!!.single().code)
        assertEquals(KeyEvent.KEYCODE_DPAD_LEFT, rawKeysForName("left")!!.single().code)
        assertNull(rawKeysForName("volume"))
    }

    @Test
    fun webrtcSignalFallsBackToScreenshots() {
        val body = """{"status":"unavailable","fallback":"screenshot","reason":"phase 3"}"""
        assertTrue(webrtcFallsBackToScreenshot(body))
        assertFalse(webrtcFallsBackToScreenshot("""{"status":"ok"}"""))
    }
}
