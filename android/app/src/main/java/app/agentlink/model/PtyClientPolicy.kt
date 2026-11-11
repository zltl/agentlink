package app.agentlink.model

/**
 * Client-side PTY pump policy for the Android controller (t443).
 *
 * [PtyHandle.poll] is non-blocking and returns `pending` when the queue is
 * empty, so the UI may wait [POLL_IDLE_MS] only after a pending result.
 * Back-to-back data/exit/error events are drained without that wait, up to
 * [MAX_DRAIN_EVENTS] per turn, so bursts do not add 30 ms per chunk.
 * Keystrokes are written in arrival order through a single channel; there is
 * no write debounce and no optimistic echo.
 */
object PtyClientPolicy {
    const val POLL_IDLE_MS = 30L
    const val MAX_DRAIN_EVENTS = 32
    const val WRITE_QUEUE_CAP = 256
}
