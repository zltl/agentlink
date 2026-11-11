package app.agentlink.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.text.InputType
import android.util.AttributeSet
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputMethodManager
import app.agentlink.model.CellWidth
import app.agentlink.model.ImeComposing
import app.agentlink.model.PtyKey
import app.agentlink.model.TerminalScreen
import app.agentlink.model.ptySequence
import app.agentlink.model.ptyText
import kotlin.math.abs

/**
 * In-tree terminal view. Termux's terminal-view is GPL, and this app is
 * MIT or Apache-2.0, so the emulator and the canvas live here instead.
 * It still speaks the sequences full-screen programs need and sends
 * keystrokes, including application cursor mode, back to the PTY.
 */
class TerminalView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    val screen = TerminalScreen()
    var onBytes: (ByteArray) -> Unit = {}
    var onResize: (rows: Int, cols: Int) -> Unit = { _, _ -> }
    var onScrolledAway: (Boolean) -> Unit = {}

    private val lock = Any()
    private var scrollOffset = 0
    private var scrolledAway = false
    /** Uncommitted IME text, drawn at the cursor and sent only on commit. */
    private val composing = ImeComposing()
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.MONOSPACE
        color = PALETTE[TerminalScreen.DEFAULT_FG]
        textSize = 15f * resources.displayMetrics.density * resources.configuration.fontScale
    }
    private val bgPaint = Paint()
    private var cellW = textPaint.measureText("M").coerceAtLeast(1f)
    private var cellH = (textPaint.fontSpacing).coerceAtLeast(1f)
    private var baseline = -textPaint.fontMetrics.ascent

    init {
        isFocusable = true
        isFocusableInTouchMode = true
        setBackgroundColor(PALETTE[TerminalScreen.DEFAULT_BG])
    }

    fun rows(): Int = synchronized(lock) { screen.rows }

    fun cols(): Int = synchronized(lock) { screen.cols }

    fun feed(bytes: ByteArray) {
        val reply = synchronized(lock) { screen.feed(bytes) }
        postInvalidateOnAnimation()
        if (reply.isNotEmpty()) onBytes(reply)
    }

    fun showKeyboard() {
        requestFocus()
        val imm = context.getSystemService(InputMethodManager::class.java)
        imm.showSoftInput(this, InputMethodManager.SHOW_IMPLICIT)
    }

    override fun performClick(): Boolean {
        super.performClick()
        showKeyboard()
        return true
    }

    fun transcript(): String = synchronized(lock) { screen.transcript() }

    fun clearTranscript() {
        synchronized(lock) { screen.clearTranscript() }
        scrollOffset = 0
        publishScrolledAway(false)
        invalidate()
    }

    fun jumpToLatest() {
        if (scrollOffset == 0) return
        scrollOffset = 0
        publishScrolledAway(false)
        invalidate()
    }

    private fun publishScrolledAway(away: Boolean) {
        if (away == scrolledAway) return
        scrolledAway = away
        post { onScrolledAway(away) }
    }

    private fun setScrollOffset(next: Int) {
        val max = synchronized(lock) { screen.scrollbackLineCount() }
        val coerced = next.coerceIn(0, max)
        if (coerced == scrollOffset) return
        scrollOffset = coerced
        publishScrolledAway(scrollOffset > 0)
        invalidate()
    }

    override fun onCheckIsTextEditor(): Boolean = true

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection {
        outAttrs.inputType = InputType.TYPE_CLASS_TEXT
        outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI or EditorInfo.IME_FLAG_NO_FULLSCREEN
        return object : BaseInputConnection(this, false) {
            override fun commitText(text: CharSequence, newCursorPosition: Int): Boolean {
                discardComposing()
                send(ptyText(text.toString(), ctrl = false))
                return true
            }

            override fun setComposingText(text: CharSequence, newCursorPosition: Int): Boolean {
                updateComposing(text.toString())
                return true
            }

            override fun finishComposingText(): Boolean {
                flushComposing()
                return true
            }

            override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
                var before = beforeLength.coerceAtLeast(0)
                if (composing.text.isNotEmpty() && before > 0) {
                    val left = composing.delete(before)
                    postInvalidateOnAnimation()
                    before = left
                }
                repeat(before) { send(ptySequence(PtyKey.Backspace, false)) }
                return true
            }

            override fun sendKeyEvent(event: KeyEvent): Boolean {
                if (event.action == KeyEvent.ACTION_DOWN) {
                    dispatchKeyEvent(event)
                }
                return true
            }
        }
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        if (composing.text.isNotEmpty() && keyCode == KeyEvent.KEYCODE_DEL) {
            composing.delete(1)
            postInvalidateOnAnimation()
            return true
        }
        val bytes = bytesFor(event) ?: return super.onKeyDown(keyCode, event)
        send(bytes)
        return true
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                downY = event.y
                lastY = event.y
                dragging = false
            }
            MotionEvent.ACTION_MOVE -> {
                val dy = event.y - lastY
                if (!dragging && abs(event.y - downY) > touchSlop) dragging = true
                if (dragging) {
                    val lines = (dy / cellH).toInt()
                    if (lines != 0) {
                        setScrollOffset(scrollOffset + lines)
                        lastY += lines * cellH
                    }
                }
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                if (!dragging && event.actionMasked == MotionEvent.ACTION_UP) performClick()
                dragging = false
            }
        }
        return true
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0 || h <= 0) return
        val cols = (w / cellW).toInt().coerceIn(2, 500)
        val rows = (h / cellH).toInt().coerceIn(2, 200)
        val changed = synchronized(lock) {
            val before = screen.rows to screen.cols
            screen.resize(rows, cols)
            before != (screen.rows to screen.cols)
        }
        if (changed) onResize(rows, cols)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        synchronized(lock) {
            val rows = screen.rows
            val cols = screen.cols
            val history = screen.scrollbackLineCount()
            val offset = scrollOffset.coerceAtMost(history)
            val first = history - offset
            for (viewRow in 0 until rows) {
                val source = first + viewRow
                if (source < history) {
                    drawPlain(canvas, viewRow, screen.scrollbackLine(source))
                } else {
                    drawGridRow(canvas, viewRow, source - history, cols)
                }
            }
            if (offset == 0 && screen.cursorVisible && composing.text.isEmpty()) {
                bgPaint.color = 0x66FFFFFF
                val col = screen.cursorDisplayCol()
                val width = screen.cursorDisplayWidth()
                val x = col * cellW
                val y = screen.cursorRow * cellH
                canvas.drawRect(x, y, x + cellW * width, y + cellH, bgPaint)
            }
            if (offset == 0 && composing.text.isNotEmpty()) {
                drawComposing(canvas, screen.cursorRow, screen.cursorCol)
            }
        }
    }

    private fun drawComposing(canvas: Canvas, startRow: Int, startCol: Int) {
        textPaint.color = PALETTE[TerminalScreen.DEFAULT_FG]
        textPaint.isFakeBoldText = false
        textPaint.isUnderlineText = true
        var col = startCol
        var row = startRow
        for (ch in composing.text) {
            if (row >= screen.rows) break
            val width = CellWidth.of(ch.code).coerceAtLeast(1)
            if (col + width > screen.cols) {
                col = 0
                row++
                if (row >= screen.rows) break
            }
            canvas.drawText(ch.toString(), col * cellW, row * cellH + baseline, textPaint)
            col += width
        }
        textPaint.isUnderlineText = false
        // Caret after the preview, not under the first composing cell.
        if (row < screen.rows) {
            if (col >= screen.cols) {
                col = 0
                row++
            }
            if (row < screen.rows) {
                bgPaint.color = 0x66FFFFFF
                val x = col * cellW
                val y = row * cellH
                canvas.drawRect(x, y, x + cellW, y + cellH, bgPaint)
            }
        }
    }

    private fun drawPlain(canvas: Canvas, viewRow: Int, text: String) {
        if (text.isEmpty()) return
        textPaint.color = PALETTE[TerminalScreen.DEFAULT_FG]
        textPaint.isFakeBoldText = false
        canvas.drawText(text, 0f, viewRow * cellH + baseline, textPaint)
    }

    private fun drawGridRow(canvas: Canvas, viewRow: Int, gridRow: Int, cols: Int) {
        var col = 0
        while (col < cols) {
            if (screen.isSpacer(gridRow, col)) {
                col++
                continue
            }
            val cellWidth = screen.widthAt(gridRow, col).coerceAtLeast(1)
            val fg = screen.fgAt(gridRow, col)
            val bg = screen.bgAt(gridRow, col)
            val bold = screen.boldAt(gridRow, col)
            var end = col + cellWidth
            if (cellWidth == 1) {
                while (
                    end < cols &&
                    !screen.isSpacer(gridRow, end) &&
                    screen.widthAt(gridRow, end) == 1 &&
                    screen.fgAt(gridRow, end) == fg &&
                    screen.bgAt(gridRow, end) == bg &&
                    screen.boldAt(gridRow, end) == bold
                ) {
                    end++
                }
            }
            val top = viewRow * cellH
            if (bg != TerminalScreen.DEFAULT_BG) {
                bgPaint.color = colorOf(bg)
                canvas.drawRect(col * cellW, top, end * cellW, top + cellH, bgPaint)
            }
            val text = buildString {
                var c = col
                while (c < end) {
                    if (screen.isSpacer(gridRow, c)) {
                        c++
                        continue
                    }
                    append(screen.charAt(gridRow, c))
                    append(screen.combiningAt(gridRow, c))
                    val w = screen.widthAt(gridRow, c).coerceAtLeast(1)
                    c += w
                }
            }
            if (text.any { it != ' ' }) {
                textPaint.color = colorOf(fg)
                textPaint.isFakeBoldText = bold
                canvas.drawText(text, col * cellW, top + baseline, textPaint)
            }
            col = end
        }
    }

    private var downY = 0f
    private var lastY = 0f
    private var dragging = false
    private val touchSlop = ViewConfiguration.get(context).scaledTouchSlop.toFloat()

    private fun updateComposing(text: String) {
        if (composing.set(text)) postInvalidateOnAnimation()
    }

    private fun discardComposing() {
        if (composing.discard()) postInvalidateOnAnimation()
    }

    private fun flushComposing() {
        val text = composing.finish()
        if (text.isNotEmpty()) {
            postInvalidateOnAnimation()
            onBytes(ptyText(text, ctrl = false))
        }
    }

    private fun send(bytes: ByteArray) {
        if (composing.text.isNotEmpty()) flushComposing()
        if (bytes.isNotEmpty()) onBytes(bytes)
    }

    private fun bytesFor(event: KeyEvent): ByteArray? {
        val app = synchronized(lock) { screen.applicationCursor }
        val ctrl = event.isCtrlPressed || event.metaState and KeyEvent.META_CTRL_ON != 0
        val named = when (event.keyCode) {
            KeyEvent.KEYCODE_ENTER -> PtyKey.Enter
            KeyEvent.KEYCODE_DEL -> PtyKey.Backspace
            KeyEvent.KEYCODE_FORWARD_DEL -> PtyKey.Delete
            KeyEvent.KEYCODE_TAB -> PtyKey.Tab
            KeyEvent.KEYCODE_ESCAPE -> PtyKey.Escape
            KeyEvent.KEYCODE_DPAD_UP -> PtyKey.Up
            KeyEvent.KEYCODE_DPAD_DOWN -> PtyKey.Down
            KeyEvent.KEYCODE_DPAD_LEFT -> PtyKey.Left
            KeyEvent.KEYCODE_DPAD_RIGHT -> PtyKey.Right
            KeyEvent.KEYCODE_MOVE_HOME -> PtyKey.Home
            KeyEvent.KEYCODE_MOVE_END -> PtyKey.End
            KeyEvent.KEYCODE_PAGE_UP -> PtyKey.PageUp
            KeyEvent.KEYCODE_PAGE_DOWN -> PtyKey.PageDown
            else -> null
        }
        if (named != null) return ptySequence(named, app)
        val unicode = event.unicodeChar
        if (unicode == 0) return null
        return ptyText(unicode.toChar().toString(), ctrl)
    }

    private fun colorOf(index: Int): Int {
        if (index in 0..15) return PALETTE[index]
        if (index in 16..231) {
            val n = index - 16
            val scale = intArrayOf(0, 95, 135, 175, 215, 255)
            val r = scale[n / 36]
            val g = scale[(n % 36) / 6]
            val b = scale[n % 6]
            return 0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
        }
        if (index in 232..255) {
            val gray = (8 + (index - 232) * 10).coerceIn(0, 255)
            return 0xFF000000.toInt() or (gray shl 16) or (gray shl 8) or gray
        }
        return PALETTE[TerminalScreen.DEFAULT_FG]
    }

    companion object {
        private val PALETTE = intArrayOf(
            0xFF1E1E1E.toInt(),
            0xFFCD3131.toInt(),
            0xFF0DBC79.toInt(),
            0xFFE5E510.toInt(),
            0xFF2472C8.toInt(),
            0xFFBC3FBC.toInt(),
            0xFF11A8CD.toInt(),
            0xFFD4D4D4.toInt(),
            0xFF808080.toInt(),
            0xFFF14C4C.toInt(),
            0xFF23D18B.toInt(),
            0xFFF5F543.toInt(),
            0xFF3B8EEA.toInt(),
            0xFFD670D6.toInt(),
            0xFF29B8DB.toInt(),
            0xFFFFFFFF.toInt(),
        )
    }
}
