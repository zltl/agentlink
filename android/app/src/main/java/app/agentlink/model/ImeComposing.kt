package app.agentlink.model

/**
 * Local IME composing state for the in-tree terminal.
 *
 * Uncommitted text is previewed only. It is written to the PTY on [commit] or
 * [finish], never on [set]. Cancel is [set] to empty or [discard]. This is not
 * optimistic echo of PTY output.
 */
class ImeComposing {
    var text: String = ""
        private set

    /** Replace the preview. Empty text cancels the composition. */
    fun set(value: String): Boolean {
        if (text == value) return false
        text = value
        return true
    }

    fun discard(): Boolean {
        if (text.isEmpty()) return false
        text = ""
        return true
    }

    /** Commit remaining preview to be sent to the PTY. */
    fun finish(): String {
        val value = text
        text = ""
        return value
    }

    /**
     * Delete [count] characters from the preview first. Returns how many
     * deletions still need to be sent as PTY backspaces.
     */
    fun delete(count: Int): Int {
        val before = count.coerceAtLeast(0)
        if (text.isEmpty() || before == 0) return before
        val drop = minOf(before, text.length)
        text = text.dropLast(drop)
        return before - drop
    }
}
