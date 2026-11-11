package app.agentlink.model

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ChannelResult

/**
 * Result of offering a keystroke to the bounded PTY write queue.
 * A full or closed queue must not look like a successful send.
 */
enum class PtyWriteOffer {
    Queued,
    Empty,
    Full,
    Closed,
}

fun offerPtyWrite(channel: Channel<ByteArray>, bytes: ByteArray): PtyWriteOffer {
    if (bytes.isEmpty()) return PtyWriteOffer.Empty
    val result: ChannelResult<Unit> = channel.trySend(bytes)
    return when {
        result.isSuccess -> PtyWriteOffer.Queued
        result.isClosed -> PtyWriteOffer.Closed
        else -> PtyWriteOffer.Full
    }
}

const val PTY_WRITE_FULL_MESSAGE =
    "Shell input queue is full. The session was stopped so keystrokes are not silently dropped."

const val PTY_WRITE_CLOSED_MESSAGE = "The shell session is closed."
