package app.agentlink.model

/**
 * Visible xterm-style screen for the client terminal.
 *
 * The grid, alternate buffer, scroll region, and SGR colors are enough for a
 * shell and for full-screen programs (cursor addressing, erase, alt screen).
 * Replies such as a cursor-position report are returned from [feed] so the
 * caller can write them back to the PTY.
 *
 * East Asian Wide/Fullwidth characters occupy two cells; combining marks
 * attach to the preceding base cell and have width 0. See [CellWidth].
 */
class TerminalScreen(rows: Int = 24, cols: Int = 80) {
    var rows: Int = rows.coerceIn(2, 200)
        private set
    var cols: Int = cols.coerceIn(2, 500)
        private set
    var cursorRow: Int = 0
        private set
    var cursorCol: Int = 0
        private set
    var applicationCursor: Boolean = false
        private set
    var cursorVisible: Boolean = true
        private set

    private var useAlt = false
    private val primary = Grid(this.rows, this.cols)
    private val alternate = Grid(this.rows, this.cols)
    private var grid = primary
    private var scrollTop = 0
    private var scrollBottom = this.rows - 1
    private var fg = DEFAULT_FG
    private var bg = DEFAULT_BG
    private var bold = false
    private var wrap = true
    private var pendingWrap = false
    private var savedRow = 0
    private var savedCol = 0
    private val history = ArrayDeque<String>()
    private val parser = VtParser(::onCodePoint, ::onControl)

    fun scrollbackLineCount(): Int = history.size

    fun scrollbackLine(index: Int): String = history.elementAtOrElse(index) { "" }

    /** Scrollback plus the visible grid, for copy. */
    fun transcript(): String {
        val lines = ArrayList<String>(history.size + rows)
        lines.addAll(history)
        for (row in 0 until rows) lines.add(rowText(row))
        return lines.joinToString("\n").trimEnd()
    }

    fun clearTranscript() {
        history.clear()
        primary.clear()
        alternate.clear()
        cursorRow = 0
        cursorCol = 0
        pendingWrap = false
    }

    fun resize(newRows: Int, newCols: Int) {
        val nextRows = newRows.coerceIn(2, 200)
        val nextCols = newCols.coerceIn(2, 500)
        if (nextRows == rows && nextCols == cols) return
        primary.resize(nextRows, nextCols)
        alternate.resize(nextRows, nextCols)
        rows = nextRows
        cols = nextCols
        scrollTop = 0
        scrollBottom = rows - 1
        cursorRow = cursorRow.coerceIn(0, rows - 1)
        cursorCol = cursorCol.coerceIn(0, cols - 1)
        pendingWrap = false
        primary.repairWideAtEdge()
        alternate.repairWideAtEdge()
        if (grid.width[cursorRow][cursorCol].toInt() == 0 && cursorCol > 0) {
            cursorCol--
        }
    }

    /** Apply terminal bytes. The returned bytes are replies the PTY must see. */
    fun feed(bytes: ByteArray): ByteArray {
        val replies = ArrayList<Byte>(8)
        parser.feed(bytes, replies)
        return replies.toByteArray()
    }

    fun text(): String = (0 until rows).joinToString("\n") { rowText(it) }

    fun rowText(row: Int): String {
        if (row !in 0 until rows) return ""
        val out = StringBuilder()
        var col = 0
        while (col < cols) {
            val width = grid.width[row][col].toInt()
            if (width == 0) {
                col++
                continue
            }
            out.append(grid.ch[row][col])
            grid.marks[row][col]?.let { out.append(it) }
            col += if (width <= 0) 1 else width
        }
        return out.toString().trimEnd()
    }

    fun fgAt(row: Int, col: Int): Int = if (inGrid(row, col)) grid.fg[row][col] else DEFAULT_FG

    fun bgAt(row: Int, col: Int): Int = if (inGrid(row, col)) grid.bg[row][col] else DEFAULT_BG

    fun boldAt(row: Int, col: Int): Boolean = inGrid(row, col) && grid.bold[row][col]

    fun charAt(row: Int, col: Int): Char = if (inGrid(row, col)) grid.ch[row][col] else ' '

    fun widthAt(row: Int, col: Int): Int = if (inGrid(row, col)) grid.width[row][col].toInt() else 1

    fun isSpacer(row: Int, col: Int): Boolean = widthAt(row, col) == 0

    fun combiningAt(row: Int, col: Int): String = if (inGrid(row, col)) grid.marks[row][col] ?: "" else ""

    /** Column to draw the caret, snapped off a wide-character spacer. */
    fun cursorDisplayCol(): Int {
        var col = cursorCol.coerceIn(0, cols - 1)
        if (widthAt(cursorRow, col) == 0 && col > 0 && widthAt(cursorRow, col - 1) == 2) {
            col -= 1
        }
        return col
    }

    fun cursorDisplayWidth(): Int {
        val col = cursorDisplayCol()
        val width = widthAt(cursorRow, col)
        return if (width == 2) 2 else 1
    }

    private fun inGrid(row: Int, col: Int) = row in 0 until rows && col in 0 until cols

    private fun onControl(b: Int, replies: ArrayList<Byte>) {
        when (b) {
            0x1b -> parser.beginEscape()
            '\n'.code -> index()
            '\r'.code -> {
                cursorCol = 0
                pendingWrap = false
            }
            '\b'.code -> {
                backspace()
            }
            '\t'.code -> {
                val next = ((cursorCol / 8) + 1) * 8
                cursorCol = next.coerceAtMost(cols - 1)
                pendingWrap = false
            }
            else -> if (b >= 0x20) putChar(b, replies)
        }
    }

    private fun onCodePoint(cp: Int) {
        putChar(cp, ArrayList(0))
    }

    private fun putChar(cp: Int, @Suppress("UNUSED_PARAMETER") replies: ArrayList<Byte>) {
        val width = CellWidth.of(cp)
        if (width == 0) {
            attachCombining(cp)
            return
        }
        val ch = if (cp in 0x20..0xFFFF) cp.toChar() else '?'
        if (pendingWrap && wrap) {
            pendingWrap = false
            carriageReturn()
            index()
        }
        if (width == 2 && cursorCol + 2 > cols) {
            if (wrap) {
                pendingWrap = false
                carriageReturn()
                index()
            } else {
                return
            }
        }
        clearClusterAt(cursorRow, cursorCol)
        if (width == 2 && cursorCol + 1 < cols) {
            clearClusterAt(cursorRow, cursorCol + 1)
        }
        grid.ch[cursorRow][cursorCol] = ch
        grid.fg[cursorRow][cursorCol] = fg
        grid.bg[cursorRow][cursorCol] = bg
        grid.bold[cursorRow][cursorCol] = bold
        grid.width[cursorRow][cursorCol] = width.toByte()
        grid.marks[cursorRow][cursorCol] = null
        if (width == 2 && cursorCol + 1 < cols) {
            grid.ch[cursorRow][cursorCol + 1] = ' '
            grid.fg[cursorRow][cursorCol + 1] = fg
            grid.bg[cursorRow][cursorCol + 1] = bg
            grid.bold[cursorRow][cursorCol + 1] = bold
            grid.width[cursorRow][cursorCol + 1] = 0
            grid.marks[cursorRow][cursorCol + 1] = null
        }
        val next = cursorCol + width
        if (next >= cols) {
            pendingWrap = true
            cursorCol = cols - 1
        } else {
            cursorCol = next
        }
    }

    private fun attachCombining(cp: Int) {
        if (cp !in 0x20..0xFFFF) return
        val mark = cp.toChar().toString()
        val base = baseCellForCombining() ?: return
        val existing = grid.marks[base.first][base.second] ?: ""
        if (existing.length < 8) {
            grid.marks[base.first][base.second] = existing + mark
        }
    }

    private fun baseCellForCombining(): Pair<Int, Int>? {
        if (pendingWrap) {
            var col = cols - 1
            while (col >= 0 && grid.width[cursorRow][col].toInt() == 0) col--
            if (col >= 0) return cursorRow to col
        }
        var row = cursorRow
        var col = cursorCol - 1
        if (col < 0 && row > 0) {
            row--
            col = cols - 1
        }
        if (col < 0) return null
        if (grid.width[row][col].toInt() == 0 && col > 0) col--
        if (col < 0) return null
        return row to col
    }

    private fun clearClusterAt(row: Int, col: Int) {
        if (!inGrid(row, col)) return
        var start = col
        if (grid.width[row][col].toInt() == 0 && col > 0 && grid.width[row][col - 1].toInt() == 2) {
            start = col - 1
        }
        val width = grid.width[row][start].toInt().coerceAtLeast(1)
        for (c in start until (start + width).coerceAtMost(cols)) {
            grid.ch[row][c] = ' '
            grid.fg[row][c] = fg
            grid.bg[row][c] = bg
            grid.bold[row][c] = false
            grid.width[row][c] = 1
            grid.marks[row][c] = null
        }
    }

    private fun backspace() {
        pendingWrap = false
        if (cursorCol <= 0) return
        cursorCol--
        if (grid.width[cursorRow][cursorCol].toInt() == 0 && cursorCol > 0) {
            cursorCol--
        }
    }

    private fun carriageReturn() {
        cursorCol = 0
    }

    private fun index() {
        if (cursorRow == scrollBottom) {
            captureScrollLine()
            grid.scrollUp(scrollTop, scrollBottom)
        } else if (cursorRow < rows - 1) {
            cursorRow++
        }
    }

    /** Keep a line that is about to leave the top of the normal full-screen buffer. */
    private fun captureScrollLine() {
        if (useAlt) return
        if (scrollTop != 0 || scrollBottom != rows - 1) return
        history.addLast(rowText(scrollTop))
        while (history.size > SCROLLBACK) history.removeFirst()
    }

    private fun reverseIndex() {
        if (cursorRow == scrollTop) {
            grid.scrollDown(scrollTop, scrollBottom)
        } else if (cursorRow > 0) {
            cursorRow--
        }
    }

    private fun dispatchEscape(final: Int, replies: ArrayList<Byte>) {
        when (final) {
            '7'.code -> {
                savedRow = cursorRow
                savedCol = cursorCol
            }
            '8'.code -> {
                cursorRow = savedRow.coerceIn(0, rows - 1)
                cursorCol = savedCol.coerceIn(0, cols - 1)
            }
            'D'.code -> index()
            'M'.code -> reverseIndex()
            'c'.code -> reset()
            'E'.code -> {
                carriageReturn()
                index()
            }
            '['.code -> parser.beginCsi()
            ']'.code -> parser.beginOsc()
            else -> {}
        }
        if (final != '['.code && final != ']'.code) {
            parser.ground()
        }
        @Suppress("UNUSED_VARIABLE")
        val keep = replies
    }

    private fun dispatchCsi(privateMode: Boolean, params: IntArray, count: Int, final: Int, replies: ArrayList<Byte>) {
        fun p(index: Int, default: Int): Int {
            if (index >= count) return default
            val value = params[index]
            return if (value == 0) default else value
        }
        when (final) {
            'A'.code -> cursorRow = (cursorRow - p(0, 1)).coerceAtLeast(0)
            'B'.code -> cursorRow = (cursorRow + p(0, 1)).coerceAtMost(rows - 1)
            'C'.code -> cursorCol = (cursorCol + p(0, 1)).coerceAtMost(cols - 1)
            'D'.code -> cursorCol = (cursorCol - p(0, 1)).coerceAtLeast(0)
            'E'.code -> {
                cursorRow = (cursorRow + p(0, 1)).coerceAtMost(rows - 1)
                cursorCol = 0
            }
            'F'.code -> {
                cursorRow = (cursorRow - p(0, 1)).coerceAtLeast(0)
                cursorCol = 0
            }
            'G'.code -> cursorCol = (p(0, 1) - 1).coerceIn(0, cols - 1)
            'H'.code, 'f'.code -> {
                cursorRow = (p(0, 1) - 1).coerceIn(0, rows - 1)
                cursorCol = (p(1, 1) - 1).coerceIn(0, cols - 1)
                pendingWrap = false
            }
            'J'.code -> eraseDisplay(if (count == 0) 0 else params[0])
            'K'.code -> eraseLine(if (count == 0) 0 else params[0])
            'L'.code -> grid.insertLines(cursorRow, scrollBottom, p(0, 1))
            'M'.code -> grid.deleteLines(cursorRow, scrollBottom, p(0, 1))
            'P'.code -> grid.deleteChars(cursorRow, cursorCol, p(0, 1))
            '@'.code -> grid.insertChars(cursorRow, cursorCol, p(0, 1))
            'X'.code -> grid.eraseChars(cursorRow, cursorCol, p(0, 1))
            'S'.code -> repeat(p(0, 1)) {
                captureScrollLine()
                grid.scrollUp(scrollTop, scrollBottom)
            }
            'T'.code -> repeat(p(0, 1)) { grid.scrollDown(scrollTop, scrollBottom) }
            'm'.code -> sgr(params, count)
            'r'.code -> setScroll(p(0, 1), if (count < 2) rows else p(1, rows))
            's'.code -> {
                savedRow = cursorRow
                savedCol = cursorCol
            }
            'u'.code -> {
                cursorRow = savedRow.coerceIn(0, rows - 1)
                cursorCol = savedCol.coerceIn(0, cols - 1)
            }
            'n'.code -> report(params, count, replies)
            'c'.code -> reply(replies, "\u001b[?6c")
            'h'.code, 'l'.code -> {
                if (privateMode) setModes(params, count, final == 'h'.code)
            }
        }
        pendingWrap = false
        parser.ground()
    }

    private fun report(params: IntArray, count: Int, replies: ArrayList<Byte>) {
        val which = if (count == 0) 0 else params[0]
        when (which) {
            5 -> reply(replies, "\u001b[0n")
            6 -> reply(replies, "\u001b[${cursorRow + 1};${cursorCol + 1}R")
        }
    }

    private fun reply(replies: ArrayList<Byte>, text: String) {
        text.encodeToByteArray().forEach { replies += it }
    }

    private fun setModes(params: IntArray, count: Int, enable: Boolean) {
        val values = if (count == 0) intArrayOf(0) else params.copyOf(count)
        for (mode in values) {
            when (mode) {
                1 -> applicationCursor = enable
                7 -> wrap = enable
                25 -> cursorVisible = enable
                47, 1047, 1049 -> setAlt(enable)
                else -> {}
            }
        }
    }

    private fun setAlt(enable: Boolean) {
        if (enable == useAlt) return
        useAlt = enable
        grid = if (enable) alternate else primary
        if (enable) alternate.clear()
        cursorRow = 0
        cursorCol = 0
        pendingWrap = false
        scrollTop = 0
        scrollBottom = rows - 1
    }

    private fun setScroll(top: Int, bottom: Int) {
        val a = (top - 1).coerceIn(0, rows - 1)
        val b = (bottom - 1).coerceIn(0, rows - 1)
        if (a >= b) return
        scrollTop = a
        scrollBottom = b
        cursorRow = scrollTop
        cursorCol = 0
    }

    private fun eraseDisplay(mode: Int) {
        when (mode) {
            1 -> {
                clearRange(0, 0, cursorRow, cursorCol)
            }
            2, 3 -> grid.clear()
            else -> clearRange(cursorRow, cursorCol, rows - 1, cols - 1)
        }
    }

    private fun eraseLine(mode: Int) {
        when (mode) {
            1 -> clearRange(cursorRow, 0, cursorRow, cursorCol)
            2 -> clearRange(cursorRow, 0, cursorRow, cols - 1)
            else -> clearRange(cursorRow, cursorCol, cursorRow, cols - 1)
        }
    }

    private fun clearRange(r0: Int, c0: Int, r1: Int, c1: Int) {
        for (row in r0..r1) {
            val start = if (row == r0) c0 else 0
            val end = if (row == r1) c1 else cols - 1
            for (col in start..end) {
                grid.ch[row][col] = ' '
                grid.fg[row][col] = fg
                grid.bg[row][col] = bg
                grid.bold[row][col] = false
                grid.width[row][col] = 1
                grid.marks[row][col] = null
            }
            if (start > 0 && grid.width[row][start - 1].toInt() == 2) {
                // A wide character lost its spacer; drop the dangling start.
                grid.ch[row][start - 1] = ' '
                grid.width[row][start - 1] = 1
                grid.marks[row][start - 1] = null
            }
        }
    }

    private fun sgr(params: IntArray, count: Int) {
        if (count == 0) {
            resetSgr()
            return
        }
        var i = 0
        while (i < count) {
            when (val value = params[i]) {
                0 -> resetSgr()
                1 -> bold = true
                22 -> bold = false
                39 -> fg = DEFAULT_FG
                49 -> bg = DEFAULT_BG
                in 30..37 -> fg = value - 30
                in 40..47 -> bg = value - 40
                in 90..97 -> fg = value - 90 + 8
                in 100..107 -> bg = value - 100 + 8
                38, 48 -> {
                    if (i + 2 < count && params[i + 1] == 5) {
                        if (value == 38) fg = params[i + 2] else bg = params[i + 2]
                        i += 2
                    }
                }
            }
            i++
        }
    }

    private fun resetSgr() {
        fg = DEFAULT_FG
        bg = DEFAULT_BG
        bold = false
    }

    private fun reset() {
        history.clear()
        primary.clear()
        alternate.clear()
        useAlt = false
        grid = primary
        cursorRow = 0
        cursorCol = 0
        applicationCursor = false
        cursorVisible = true
        wrap = true
        pendingWrap = false
        scrollTop = 0
        scrollBottom = rows - 1
        resetSgr()
    }

    private inner class VtParser(
        private val onGraphic: (Int) -> Unit,
        private val onControl: (Int, ArrayList<Byte>) -> Unit,
    ) {
        private var state = State.Ground
        private var utf = 0
        private var utfNeed = 0
        private val params = IntArray(16)
        private var count = 0
        private var current = 0
        private var privateMode = false
        private var collecting = false
        private var osc = StringBuilder()

        fun ground() {
            state = State.Ground
        }

        fun beginEscape() {
            state = State.Escape
        }

        fun beginCsi() {
            params.fill(0)
            count = 0
            current = 0
            privateMode = false
            collecting = false
            state = State.Csi
        }

        fun beginOsc() {
            osc = StringBuilder()
            state = State.Osc
        }

        fun feed(bytes: ByteArray, replies: ArrayList<Byte>) {
            for (raw in bytes) {
                val b = raw.toInt() and 0xFF
                if (state == State.Ground && utfNeed == 0 && b < 0x20) {
                    onControl(b, replies)
                    continue
                }
                if (state == State.Ground) {
                    val cp = takeUtf(b) ?: continue
                    onGraphic(cp)
                    continue
                }
                when (state) {
                    State.Escape -> escapeByte(b, replies)
                    State.Csi -> csiByte(b, replies)
                    State.Osc -> oscByte(b)
                    State.OscEsc -> state = State.Ground
                    State.Ground -> {}
                }
            }
        }

        private fun takeUtf(b: Int): Int? {
            if (utfNeed == 0) {
                when {
                    b < 0x80 -> return b
                    b and 0xE0 == 0xC0 -> {
                        utf = b and 0x1F
                        utfNeed = 1
                    }
                    b and 0xF0 == 0xE0 -> {
                        utf = b and 0x0F
                        utfNeed = 2
                    }
                    b and 0xF8 == 0xF0 -> {
                        utf = b and 0x07
                        utfNeed = 3
                    }
                    else -> return 0xFFFD
                }
                return null
            }
            if (b and 0xC0 != 0x80) {
                utfNeed = 0
                return 0xFFFD
            }
            utf = (utf shl 6) or (b and 0x3F)
            utfNeed--
            return if (utfNeed == 0) utf else null
        }

        private fun escapeByte(b: Int, replies: ArrayList<Byte>) {
            if (b < 0x20) {
                onControl(b, replies)
                return
            }
            dispatchEscape(b, replies)
        }

        private fun csiByte(b: Int, replies: ArrayList<Byte>) {
            when {
                b in 0x30..0x39 -> {
                    current = (current * 10 + (b - 0x30)).coerceAtMost(9999)
                    collecting = true
                }
                b == ';'.code -> pushParam()
                b == '?'.code && count == 0 && !collecting -> privateMode = true
                b in 0x40..0x7E -> {
                    pushParam()
                    dispatchCsi(privateMode, params, count, b, replies)
                }
                b < 0x20 -> onControl(b, replies)
                else -> state = State.Ground
            }
        }

        private fun pushParam() {
            if (count < params.size) {
                params[count] = if (collecting) current else 0
                count++
            }
            current = 0
            collecting = false
        }

        private fun oscByte(b: Int) {
            when (b) {
                0x07 -> state = State.Ground
                0x1b -> state = State.OscEsc
                else -> if (osc.length < 200) osc.append(b.toChar())
            }
        }
    }

    private enum class State { Ground, Escape, Csi, Osc, OscEsc }

    private class Grid(rows: Int, cols: Int) {
        var ch: Array<CharArray> = Array(rows) { CharArray(cols) { ' ' } }
        var fg: Array<IntArray> = Array(rows) { IntArray(cols) { DEFAULT_FG } }
        var bg: Array<IntArray> = Array(rows) { IntArray(cols) { DEFAULT_BG } }
        var bold: Array<BooleanArray> = Array(rows) { BooleanArray(cols) }
        var width: Array<ByteArray> = Array(rows) { ByteArray(cols) { 1 } }
        var marks: Array<Array<String?>> = Array(rows) { arrayOfNulls(cols) }

        fun resize(rows: Int, cols: Int) {
            val nextCh = Array(rows) { r -> CharArray(cols) { c -> if (r < ch.size && c < ch[r].size) ch[r][c] else ' ' } }
            val nextFg = Array(rows) { r -> IntArray(cols) { c -> if (r < fg.size && c < fg[r].size) fg[r][c] else DEFAULT_FG } }
            val nextBg = Array(rows) { r -> IntArray(cols) { c -> if (r < bg.size && c < bg[r].size) bg[r][c] else DEFAULT_BG } }
            val nextBold = Array(rows) { r -> BooleanArray(cols) { c -> r < bold.size && c < bold[r].size && bold[r][c] } }
            val nextWidth = Array(rows) { r -> ByteArray(cols) { c -> if (r < width.size && c < width[r].size) width[r][c] else 1 } }
            val nextMarks = Array(rows) { r -> Array(cols) { c -> if (r < marks.size && c < marks[r].size) marks[r][c] else null } }
            ch = nextCh
            fg = nextFg
            bg = nextBg
            bold = nextBold
            width = nextWidth
            marks = nextMarks
            repairWideAtEdge()
        }

        fun repairWideAtEdge() {
            for (row in ch.indices) {
                val last = ch[row].lastIndex
                if (last >= 0 && width[row][last].toInt() == 2) {
                    ch[row][last] = ' '
                    width[row][last] = 1
                    marks[row][last] = null
                }
            }
        }

        fun clear() {
            for (row in ch.indices) {
                ch[row].fill(' ')
                fg[row].fill(DEFAULT_FG)
                bg[row].fill(DEFAULT_BG)
                bold[row].fill(false)
                width[row].fill(1)
                marks[row].fill(null)
            }
        }

        fun scrollUp(top: Int, bottom: Int) {
            if (top !in ch.indices || bottom !in ch.indices || top > bottom) return
            val savedCh = ch[top]
            val savedFg = fg[top]
            val savedBg = bg[top]
            val savedBold = bold[top]
            val savedWidth = width[top]
            val savedMarks = marks[top]
            for (row in top until bottom) {
                ch[row] = ch[row + 1]
                fg[row] = fg[row + 1]
                bg[row] = bg[row + 1]
                bold[row] = bold[row + 1]
                width[row] = width[row + 1]
                marks[row] = marks[row + 1]
            }
            ch[bottom] = savedCh
            fg[bottom] = savedFg
            bg[bottom] = savedBg
            bold[bottom] = savedBold
            width[bottom] = savedWidth
            marks[bottom] = savedMarks
            blank(bottom)
        }

        fun scrollDown(top: Int, bottom: Int) {
            if (top !in ch.indices || bottom !in ch.indices || top > bottom) return
            val savedCh = ch[bottom]
            val savedFg = fg[bottom]
            val savedBg = bg[bottom]
            val savedBold = bold[bottom]
            val savedWidth = width[bottom]
            val savedMarks = marks[bottom]
            for (row in bottom downTo top + 1) {
                ch[row] = ch[row - 1]
                fg[row] = fg[row - 1]
                bg[row] = bg[row - 1]
                bold[row] = bold[row - 1]
                width[row] = width[row - 1]
                marks[row] = marks[row - 1]
            }
            ch[top] = savedCh
            fg[top] = savedFg
            bg[top] = savedBg
            bold[top] = savedBold
            width[top] = savedWidth
            marks[top] = savedMarks
            blank(top)
        }

        fun insertLines(row: Int, bottom: Int, count: Int) {
            repeat(count.coerceAtMost(bottom - row + 1)) { scrollDown(row, bottom) }
        }

        fun deleteLines(row: Int, bottom: Int, count: Int) {
            repeat(count.coerceAtMost(bottom - row + 1)) { scrollUp(row, bottom) }
        }

        fun deleteChars(row: Int, col: Int, count: Int) {
            if (row !in ch.indices) return
            var start = col.coerceIn(0, ch[row].lastIndex)
            if (width[row][start].toInt() == 0 && start > 0) start--
            val n = count.coerceAtLeast(0)
            val line = ch[row]
            for (c in start until line.size) {
                val src = c + n
                line[c] = if (src < line.size) line[src] else ' '
                fg[row][c] = if (src < line.size) fg[row][src] else DEFAULT_FG
                bg[row][c] = if (src < line.size) bg[row][src] else DEFAULT_BG
                bold[row][c] = src < line.size && bold[row][src]
                width[row][c] = if (src < line.size) width[row][src] else 1
                marks[row][c] = if (src < line.size) marks[row][src] else null
            }
            repairWideAtEdge()
            if (start > 0 && width[row][start].toInt() == 0) {
                ch[row][start - 1] = ' '
                width[row][start - 1] = 1
                marks[row][start - 1] = null
            }
        }

        fun insertChars(row: Int, col: Int, count: Int) {
            if (row !in ch.indices) return
            val start = col.coerceIn(0, ch[row].size)
            val n = count.coerceAtLeast(0)
            val line = ch[row]
            for (c in line.lastIndex downTo start) {
                val src = c - n
                line[c] = if (src >= start) line[src] else ' '
                fg[row][c] = if (src >= start) fg[row][src] else DEFAULT_FG
                bg[row][c] = if (src >= start) bg[row][src] else DEFAULT_BG
                bold[row][c] = src >= start && bold[row][src]
                width[row][c] = if (src >= start) width[row][src] else 1
                marks[row][c] = if (src >= start) marks[row][src] else null
            }
            for (c in start until (start + n).coerceAtMost(line.size)) {
                line[c] = ' '
                fg[row][c] = DEFAULT_FG
                bg[row][c] = DEFAULT_BG
                bold[row][c] = false
                width[row][c] = 1
                marks[row][c] = null
            }
            repairWideAtEdge()
        }

        fun eraseChars(row: Int, col: Int, count: Int) {
            if (row !in ch.indices) return
            var start = col.coerceAtLeast(0)
            if (start < ch[row].size && width[row][start].toInt() == 0 && start > 0) start--
            val end = (start + count).coerceAtMost(ch[row].size)
            for (c in start until end) {
                ch[row][c] = ' '
                fg[row][c] = DEFAULT_FG
                bg[row][c] = DEFAULT_BG
                bold[row][c] = false
                width[row][c] = 1
                marks[row][c] = null
            }
            if (end < ch[row].size && width[row][end].toInt() == 0) {
                ch[row][end] = ' '
                width[row][end] = 1
                marks[row][end] = null
            }
        }

        private fun blank(row: Int) {
            ch[row] = CharArray(ch[row].size) { ' ' }
            fg[row] = IntArray(fg[row].size) { DEFAULT_FG }
            bg[row] = IntArray(bg[row].size) { DEFAULT_BG }
            bold[row] = BooleanArray(bold[row].size)
            width[row] = ByteArray(width[row].size) { 1 }
            marks[row] = arrayOfNulls(marks[row].size)
        }
    }

    companion object {
        const val DEFAULT_FG = 7
        const val DEFAULT_BG = 0
        private const val SCROLLBACK = 500
    }
}

enum class PtyKey {
    Enter,
    Backspace,
    Tab,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Delete,
}

/** Bytes a terminal emulator sends for a special key. */
fun ptySequence(key: PtyKey, applicationCursor: Boolean): ByteArray {
    fun csi(body: String) = "\u001b[$body".encodeToByteArray()
    fun ss3(body: String) = "\u001b$body".encodeToByteArray()
    val app = applicationCursor
    return when (key) {
        PtyKey.Enter -> byteArrayOf('\r'.code.toByte())
        PtyKey.Backspace -> byteArrayOf(0x7f)
        PtyKey.Tab -> byteArrayOf('\t'.code.toByte())
        PtyKey.Escape -> byteArrayOf(0x1b)
        PtyKey.Up -> if (app) ss3("OA") else csi("A")
        PtyKey.Down -> if (app) ss3("OB") else csi("B")
        PtyKey.Right -> if (app) ss3("OC") else csi("C")
        PtyKey.Left -> if (app) ss3("OD") else csi("D")
        PtyKey.Home -> csi("H")
        PtyKey.End -> csi("F")
        PtyKey.PageUp -> csi("5~")
        PtyKey.PageDown -> csi("6~")
        PtyKey.Delete -> csi("3~")
    }
}

/** Ctrl+letter becomes the corresponding C0 byte. Other text is sent as UTF-8. */
fun ptyText(text: String, ctrl: Boolean): ByteArray {
    if (ctrl && text.length == 1) {
        val ch = text[0].lowercaseChar()
        if (ch in 'a'..'z') return byteArrayOf((ch.code - 96).toByte())
    }
    return text.encodeToByteArray()
}
