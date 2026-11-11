package app.agentlink.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TerminalScreenPumpTest {
    @Test
    fun utf8CharacterSurvivesASplitFeed() {
        val screen = TerminalScreen(3, 8)
        val ni = "你".encodeToByteArray()
        assertEquals(3, ni.size)
        screen.feed(byteArrayOf(ni[0]))
        assertEquals("", screen.rowText(0))
        assertEquals(0, screen.cursorCol)
        screen.feed(byteArrayOf(ni[1], ni[2]))
        assertEquals("你", screen.rowText(0))
        assertEquals(1, screen.cursorCol)
    }

    @Test
    fun csiCursorAddressSurvivesASplitFeed() {
        val screen = TerminalScreen(3, 8)
        screen.feed(byteArrayOf(0x1b, '['.code.toByte()))
        assertEquals("", screen.rowText(0))
        screen.feed("2;3H".encodeToByteArray())
        screen.feed("Z".encodeToByteArray())
        assertEquals('Z', screen.charAt(1, 2))
        assertEquals(3, screen.cursorCol)
        assertEquals(1, screen.cursorRow)
    }

    @Test
    fun backspaceMovesTheCursorAndTheNextGlyphOverwrites() {
        val screen = TerminalScreen(3, 8)
        screen.feed("abc".encodeToByteArray())
        assertEquals(3, screen.cursorCol)
        screen.feed(byteArrayOf('\b'.code.toByte()))
        assertEquals(2, screen.cursorCol)
        assertEquals("abc", screen.rowText(0))
        screen.feed("X".encodeToByteArray())
        assertEquals("abX", screen.rowText(0))
        assertEquals(3, screen.cursorCol)
    }

    @Test
    fun resizeKeepsVisibleTextAndClampsTheCursor() {
        val screen = TerminalScreen(3, 8)
        screen.feed("hello".encodeToByteArray())
        screen.resize(10, 40)
        assertEquals(10, screen.rows)
        assertEquals(40, screen.cols)
        assertEquals("hello", screen.rowText(0))
        assertEquals(0, screen.cursorRow)
        assertEquals(5, screen.cursorCol)
        screen.resize(2, 3)
        assertEquals(2, screen.rows)
        assertEquals(3, screen.cols)
        assertEquals("hel", screen.rowText(0))
        assertEquals(0, screen.cursorRow)
        assertTrue(screen.cursorCol in 0 until screen.cols)
    }

    @Test
    fun pumpPolicyWaitsOnlyWhenIdle() {
        assertEquals(30L, PtyClientPolicy.POLL_IDLE_MS)
        assertEquals(32, PtyClientPolicy.MAX_DRAIN_EVENTS)
        assertEquals(256, PtyClientPolicy.WRITE_QUEUE_CAP)
    }
}

class ImeComposingTest {
    @Test
    fun cancelClearsPreviewWithoutACommit() {
        val ime = ImeComposing()
        assertTrue(ime.set("ni"))
        assertEquals("ni", ime.text)
        assertTrue(ime.set(""))
        assertEquals("", ime.text)
        assertEquals("", ime.finish())
    }

    @Test
    fun discardCancelsAndFinishAfterDiscardSendsNothing() {
        val ime = ImeComposing()
        ime.set("你")
        assertTrue(ime.discard())
        assertEquals("", ime.finish())
    }

    @Test
    fun commitReplacesPreviewOnce() {
        val ime = ImeComposing()
        ime.set("ni")
        ime.set("你")
        // commitText path: discard preview, send the committed glyph once
        ime.discard()
        assertEquals("", ime.text)
    }

    @Test
    fun finishSendsThePreview() {
        val ime = ImeComposing()
        ime.set("你好")
        assertEquals("你好", ime.finish())
        assertEquals("", ime.text)
    }

    @Test
    fun deleteEditsPreviewBeforeAnyBackspace() {
        val ime = ImeComposing()
        ime.set("你好")
        assertEquals(0, ime.delete(1))
        assertEquals("你", ime.text)
        assertEquals(0, ime.delete(1))
        assertEquals("", ime.text)
        assertEquals(2, ime.delete(2))
    }

    @Test
    fun chinesePinyinToCharacterStaysLocalUntilCommit() {
        val ime = ImeComposing()
        ime.set("n")
        ime.set("ni")
        ime.set("你")
        assertEquals("你", ime.text)
        ime.discard()
        // the view then sends only the committed "你"
        assertEquals("", ime.text)
    }
}

class PtyWriteOfferTest {
    @Test
    fun fullChannelIsRejectedAndDoesNotDropSilentlyIntoASuccess() {
        val channel = kotlinx.coroutines.channels.Channel<ByteArray>(1)
        assertEquals(PtyWriteOffer.Queued, offerPtyWrite(channel, byteArrayOf(1)))
        assertEquals(PtyWriteOffer.Full, offerPtyWrite(channel, byteArrayOf(2)))
        assertEquals(PtyWriteOffer.Empty, offerPtyWrite(channel, byteArrayOf()))
        val first = channel.tryReceive().getOrNull()
        assertEquals(1.toByte(), first!!.first())
        channel.close()
        assertEquals(PtyWriteOffer.Closed, offerPtyWrite(channel, byteArrayOf(3)))
    }
}
