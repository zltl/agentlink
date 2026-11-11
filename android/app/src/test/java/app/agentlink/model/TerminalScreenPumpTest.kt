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
        assertEquals(2, screen.cursorCol)
        assertEquals(2, screen.widthAt(0, 0))
        assertEquals(0, screen.widthAt(0, 1))
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

    @Test
    fun cjkIdeographOccupiesTwoCellsAndAsciiFollows() {
        val screen = TerminalScreen(3, 8)
        screen.feed("中A".encodeToByteArray())
        assertEquals("中A", screen.rowText(0))
        assertEquals(2, screen.widthAt(0, 0))
        assertEquals(0, screen.widthAt(0, 1))
        assertEquals(1, screen.widthAt(0, 2))
        assertEquals(3, screen.cursorCol)
        assertEquals('中', screen.charAt(0, 0))
        assertEquals('A', screen.charAt(0, 2))
    }

    @Test
    fun combiningMarkStaysInTheBaseCell() {
        val screen = TerminalScreen(3, 8)
        screen.feed("e".encodeToByteArray())
        screen.feed("\u0301".encodeToByteArray())
        assertEquals(1, screen.cursorCol)
        assertEquals(1, screen.widthAt(0, 0))
        assertEquals("\u0301", screen.combiningAt(0, 0))
        assertTrue(screen.rowText(0).startsWith("e"))
        assertTrue(screen.rowText(0).contains("\u0301") || screen.rowText(0).startsWith("é"))
    }

    @Test
    fun backspaceOverAWideCharacterLandsOnItsStart() {
        val screen = TerminalScreen(3, 8)
        screen.feed("中A".encodeToByteArray())
        assertEquals(3, screen.cursorCol)
        screen.feed(byteArrayOf('\b'.code.toByte()))
        assertEquals(2, screen.cursorCol)
        screen.feed(byteArrayOf('\b'.code.toByte()))
        assertEquals(0, screen.cursorCol)
        assertEquals(0, screen.cursorDisplayCol())
        assertEquals(2, screen.cursorDisplayWidth())
        screen.feed("X".encodeToByteArray())
        // Replacing a wide cell leaves a one-column gap, as in a typical VT.
        assertEquals('X', screen.charAt(0, 0))
        assertEquals('A', screen.charAt(0, 2))
        assertEquals(1, screen.cursorCol)
    }

    @Test
    fun enterMovesToTheNextLineAndKeepsWideText() {
        val screen = TerminalScreen(4, 8)
        screen.feed("你好".encodeToByteArray())
        assertEquals(4, screen.cursorCol)
        screen.feed(byteArrayOf('\r'.code.toByte(), '\n'.code.toByte()))
        assertEquals(1, screen.cursorRow)
        assertEquals(0, screen.cursorCol)
        assertEquals("你好", screen.rowText(0))
        screen.feed("ok".encodeToByteArray())
        assertEquals("ok", screen.rowText(1))
    }

    @Test
    fun resizeKeepsCjkAndRepairsADanglingWideCellAtTheEdge() {
        val screen = TerminalScreen(3, 8)
        screen.feed("你好世界".encodeToByteArray())
        assertEquals("你好世界", screen.rowText(0))
        screen.resize(3, 3)
        assertEquals(3, screen.cols)
        // A wide character cannot start in the last column.
        assertTrue(screen.cursorCol in 0 until screen.cols)
        val text = screen.rowText(0)
        assertTrue("row after shrink: $text", text.startsWith("你"))
        assertTrue(!text.contains("好") || screen.widthAt(0, 0) == 2)
    }
}

class CellWidthTest {
    @Test
    fun unicode16WideAndCombiningAndAmbiguous() {
        assertEquals(2, CellWidth.of('你'.code))
        assertEquals(2, CellWidth.of('中'.code))
        assertEquals(2, CellWidth.of('　'.code)) // fullwidth space
        assertEquals(1, CellWidth.of('A'.code))
        assertEquals(1, CellWidth.of('©'.code)) // ambiguous
        assertEquals(0, CellWidth.of(0x0301))
        assertEquals(0, CellWidth.of(0xFE0F))
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
