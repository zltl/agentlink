package app.agentlink.account

import java.util.LinkedHashMap
import java.util.concurrent.CancellationException

/** Refresh the access token this many seconds before it expires. Matches the desktop client. */
const val ACCESS_REFRESH_SKEW_SECONDS = 60L

/**
 * Inactivity the relay guarantees before a refresh token dies.
 * The relay adds clock-skew slack on top. Keep this aligned with
 * `REFRESH_IDLE_SECS` in `agentlink-core`. The phone does not invent a shorter cutoff.
 */
const val MIN_REFRESH_IDLE_SECONDS = 30L * 24 * 60 * 60

/**
 * How far past the stored refresh deadline the phone will still ask the relay.
 * A handset clock that jumps ahead must not skip that call. The relay decides.
 */
const val REFRESH_LOCAL_SLACK_SECONDS = 2L * 24 * 60 * 60

const val SESSION_EXPIRED_MESSAGE = "Your session expired. Sign in again."

const val SESSION_OFFLINE_MESSAGE = "Couldn't reach the relay. Your saved sign-in is still here."

private val refreshLock = Any()

/** Refresh token that was already rotated -> the account the relay issued for it. */
private val rememberedRefreshes = object : LinkedHashMap<String, UserAccount>(8, 0.75f, true) {
    override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, UserAccount>?): Boolean = size > 8
}

/** Tests share a process. Drop rotations so one case cannot satisfy the next. */
internal fun clearRememberedRefreshes() {
    synchronized(refreshLock) { rememberedRefreshes.clear() }
}

fun sessionNowUnix(): Long = System.currentTimeMillis() / 1000

fun accessIsFresh(account: UserAccount, nowUnix: Long = sessionNowUnix()): Boolean {
    return account.accessToken.isNotBlank() && account.accessExpiresUnix > nowUnix + ACCESS_REFRESH_SKEW_SECONDS
}

/**
 * A missing expiry (`0`) is an older saved session. Try the refresh token instead of signing out.
 * A deadline only a day or two in the past is still tried: the handset clock is not the relay clock.
 */
fun refreshIsUsable(account: UserAccount, nowUnix: Long = sessionNowUnix()): Boolean {
    if (account.refreshToken.isBlank()) return false
    if (account.refreshExpiresUnix <= 0L) return true
    return account.refreshExpiresUnix + REFRESH_LOCAL_SLACK_SECONDS > nowUnix
}

/**
 * Refresh of [failed] failed. If disk already holds a different refresh token, that one
 * was saved by a rotation this call did not see. Keep it.
 */
fun newerStoredSession(failed: UserAccount, stored: UserAccount?): UserAccount? {
    val saved = stored ?: return null
    if (saved.refreshToken.isBlank() || saved.refreshToken == failed.refreshToken) return null
    return saved
}

/**
 * True when the relay rejected the credential.
 * Transport failures stay false even when the text says "invalid" or "expired",
 * so a blip does not clear the saved sign-in.
 */
fun isAuthFailure(message: String?): Boolean {
    val text = message?.lowercase() ?: return false
    if (isTransportFailure(text)) return false
    if (looksLikeSessionExpiry(text)) return true
    return text.contains("refresh token") ||
        text.contains("device is revoked") ||
        text.contains("device key") ||
        text.contains("account is disabled") ||
        text.contains("invalid username or password") ||
        text.contains("invalid totp") ||
        text.contains("totp code required") ||
        text.contains("signature rejected") ||
        text.contains("account is temporarily locked")
}

private fun isTransportFailure(text: String): Boolean {
    return text.contains("timed out") ||
        text.contains("timeout") ||
        text.contains("connection") ||
        text.contains("websocket") ||
        text.contains("tls:") ||
        text.contains("unreachable") ||
        text.contains("network") ||
        text.startsWith("io:") ||
        text.contains(" io:")
}

/**
 * Narrower than [isAuthFailure]. File paths and presets can be "invalid" without
 * the sign-in being dead, so machine calls use this before forcing a new login.
 */
fun looksLikeSessionExpiry(message: String?): Boolean {
    val text = message?.lowercase() ?: return false
    if (text.contains("unauthorized") || text.contains("login required")) return true
    val tokenish = text.contains("token") || text.contains("session") || text.contains("access")
    if (text.contains("expired") && tokenish) return true
    if (text.contains("revoked") && tokenish) return true
    if (text.contains("invalid") && tokenish) return true
    return false
}

sealed interface SessionMaintain {
    data class Ready(val account: UserAccount) : SessionMaintain
    data class Offline(val account: UserAccount, val message: String) : SessionMaintain
    data class SignedOut(val message: String) : SessionMaintain
}

/**
 * Keep a saved sign-in usable. Refresh rotates the refresh token, so the caller must
 * persist [SessionMaintain.Ready] when the account changes. A network failure does not
 * clear a session that can still be refreshed later.
 *
 * Overlapping callers share one rotation. The second one must not present the refresh
 * token the first call already consumed, or the relay's rejection would sign the user out.
 */
fun maintainSession(
    account: UserAccount,
    api: AccountApi,
    nowUnix: Long = sessionNowUnix(),
): SessionMaintain {
    if (accessIsFresh(account, nowUnix)) return SessionMaintain.Ready(account)
    synchronized(refreshLock) {
        val current = rememberedRefreshes[account.refreshToken] ?: account
        if (accessIsFresh(current, nowUnix)) return SessionMaintain.Ready(current)
        if (!refreshIsUsable(current, nowUnix)) return SessionMaintain.SignedOut(SESSION_EXPIRED_MESSAGE)
        val outcome = try {
            SessionMaintain.Ready(api.refresh(current))
        } catch (error: Exception) {
            if (error is CancellationException) throw error
            when {
                isAuthFailure(error.message) -> SessionMaintain.SignedOut(SESSION_EXPIRED_MESSAGE)
                current.accessExpiresUnix > nowUnix -> SessionMaintain.Ready(current)
                else -> SessionMaintain.Offline(current, SESSION_OFFLINE_MESSAGE)
            }
        }
        if (outcome is SessionMaintain.Ready && outcome.account.refreshToken != current.refreshToken) {
            rememberedRefreshes[current.refreshToken] = outcome.account
        }
        return outcome
    }
}
