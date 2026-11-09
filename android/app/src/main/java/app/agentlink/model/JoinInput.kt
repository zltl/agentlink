package app.agentlink.model

import org.json.JSONObject
import java.util.Base64

const val INVITE_PREFIX = "agentlink-invite:v1:"

const val JOIN_TOO_SHORT =
    "that text is too short to be an invite or a pairing token. Paste the invite from agentlink pair. Nothing was paired."

/**
 * Enrollment material from the Invite field.
 *
 * This is not a grant. A parsed invite does not allow exec, files, or
 * desktop, and it does not skip the end-to-end handshake. The node still
 * checks its own signed grant.
 */
sealed class JoinInput {
    data object Absent : JoinInput()
    data class Token(val token: String) : JoinInput()
    data class Invite(val invite: InviteParts) : JoinInput()
}

data class InviteParts(
    val relay: String,
    val fingerprint: String,
    val token: String,
    val name: String,
)

data class ResolvedJoin(
    val relay: String,
    val fingerprint: String,
    val token: String,
    val name: String,
)

fun decodeInvite(text: String): Result<InviteParts> {
    val trimmed = text.trim()
    if (trimmed.isEmpty()) {
        return Result.failure(IllegalArgumentException("invite is empty"))
    }
    if (!trimmed.startsWith(INVITE_PREFIX)) {
        return Result.failure(
            IllegalArgumentException(
                "invite must start with $INVITE_PREFIX (print one with `agentlink pair`)",
            ),
        )
    }
    val payload = trimmed.removePrefix(INVITE_PREFIX)
    val bytes = decodeUrl(payload)
        ?: return Result.failure(IllegalArgumentException("invite is damaged (not valid base64)"))
    val obj = try {
        JSONObject(String(bytes, Charsets.UTF_8))
    } catch (_: Exception) {
        return Result.failure(IllegalArgumentException("invite is damaged (not valid JSON)"))
    }
    val relay = normalizeRelay(jsonText(obj, "relay"))
    val token = jsonText(obj, "token").lowercase()
    if (relay.isEmpty() || token.isEmpty()) {
        return Result.failure(IllegalArgumentException("invite is missing a relay or token"))
    }
    relayProblem(relay)?.let { problem ->
        return Result.failure(IllegalArgumentException(problem))
    }
    if (!isPairingToken(token)) {
        return Result.failure(
            IllegalArgumentException("invite pairing token is not a one-time token"),
        )
    }
    val pin = combinedPin(jsonText(obj, "fingerprint"), jsonText(obj, "trust"))
    if (pin.isEmpty()) {
        return Result.failure(IllegalArgumentException("invite is missing certificate trust"))
    }
    fingerprintProblem(pin)?.let { problem ->
        return Result.failure(
            IllegalArgumentException("invite certificate trust is not valid ($problem)"),
        )
    }
    return Result.success(
        InviteParts(
            relay = relay,
            fingerprint = pin,
            token = token,
            name = jsonText(obj, "name"),
        ),
    )
}

fun parseJoinInput(raw: String): Result<JoinInput> {
    val text = raw.trim()
    if (text.isEmpty()) return Result.success(JoinInput.Absent)
    if (text.lowercase().startsWith("agentlink-invite")) {
        return decodeInvite(text).map { JoinInput.Invite(it) }
    }
    if (text.any { it.isWhitespace() || it.isISOControl() }) {
        return Result.failure(
            IllegalArgumentException("that text is not an invite or a pairing token"),
        )
    }
    if (text.length < 64) {
        return Result.failure(IllegalArgumentException(JOIN_TOO_SHORT))
    }
    if (!isPairingToken(text)) {
        return Result.failure(
            IllegalArgumentException("that text is not an invite or a pairing token"),
        )
    }
    return Result.success(JoinInput.Token(text.lowercase()))
}

/**
 * Apply the Invite field onto the setup the node will dial.
 *
 * Failure leaves the caller on the current screen. Success still has to pass
 * the node grant and the end-to-end handshake; this only checks the text.
 */
fun resolveJoin(
    relay: String,
    fingerprint: String,
    token: String,
    name: String,
): Result<ResolvedJoin> {
    val parsed = parseJoinInput(token).getOrElse { return Result.failure(it) }
    val resolved = when (parsed) {
        JoinInput.Absent -> ResolvedJoin(relay.trim(), fingerprint.trim(), "", name.trim())
        is JoinInput.Token -> ResolvedJoin(relay.trim(), fingerprint.trim(), parsed.token, name.trim())
        is JoinInput.Invite -> ResolvedJoin(
            relay = parsed.invite.relay,
            fingerprint = parsed.invite.fingerprint,
            token = parsed.invite.token,
            name = name.trim().ifBlank { parsed.invite.name },
        )
    }
    relayProblem(resolved.relay)?.let { problem ->
        return Result.failure(IllegalArgumentException(problem))
    }
    fingerprintProblem(resolved.fingerprint)?.let { problem ->
        return Result.failure(IllegalArgumentException(problem))
    }
    return Result.success(resolved)
}

private fun isPairingToken(text: String): Boolean {
    val trimmed = text.trim()
    return trimmed.length == 64 && trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
}

private fun combinedPin(fingerprint: String, trust: String): String =
    listOf(fingerprint, trust).map { it.trim() }.filter { it.isNotEmpty() }.joinToString("+")

private fun normalizeRelay(url: String): String {
    val trimmed = url.trim()
    return if (trimmed.startsWith("https://", ignoreCase = true)) {
        "wss://" + trimmed.substring("https://".length)
    } else {
        trimmed
    }
}

private fun jsonText(obj: JSONObject, key: String): String {
    if (!obj.has(key) || obj.isNull(key)) return ""
    val value = obj.opt(key)
    return if (value is String) value.trim() else ""
}

private fun decodeUrl(payload: String): ByteArray? {
    if (payload.isEmpty()) return null
    if (payload.any { !(it.isLetterOrDigit() || it == '-' || it == '_') }) return null
    if (payload.length % 4 == 1) return null
    val pad = (4 - payload.length % 4) % 4
    val padded = payload + "=".repeat(pad)
    return runCatching { Base64.getUrlDecoder().decode(padded) }.getOrNull()
}
