package app.agentlink.account

import app.agentlink.bridge.ClientSession
import java.io.IOException
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SessionMaintainTest {
    private val now = 1_700_000_000L

    @Before
    fun resetRotations() {
        clearRememberedRefreshes()
    }

    @Test
    fun freshAccessDoesNotRefresh() {
        val api = FakeApi()
        val saved = account(accessExpiresUnix = now + 3600)
        val outcome = maintainSession(saved, api, now)
        assertTrue(outcome is SessionMaintain.Ready)
        assertSame(saved, (outcome as SessionMaintain.Ready).account)
        assertEquals(0, api.refreshCalls)
    }

    @Test
    fun expiredAccessWithValidRefreshReturnsNewTokens() {
        val api = FakeApi()
        val saved = account(accessExpiresUnix = now - 10, refreshExpiresUnix = now + 86_400)
        val issued = saved.copy(accessToken = "atk-new", refreshToken = "rt-new", accessExpiresUnix = now + 900)
        api.refreshed = issued
        val outcome = maintainSession(saved, api, now)
        assertEquals(issued, (outcome as SessionMaintain.Ready).account)
        assertEquals(1, api.refreshCalls)
    }

    @Test
    fun unknownRefreshExpiryStillRefreshes() {
        val api = FakeApi()
        val saved = account(accessExpiresUnix = now - 10, refreshExpiresUnix = 0)
        api.refreshed = saved.copy(accessToken = "atk-new", accessExpiresUnix = now + 900)
        val outcome = maintainSession(saved, api, now)
        assertEquals("atk-new", (outcome as SessionMaintain.Ready).account.accessToken)
        assertEquals(1, api.refreshCalls)
    }

    @Test
    fun clockSkewPastTheStoredDeadlineStillRefreshes() {
        val api = FakeApi()
        val saved = account(accessExpiresUnix = now - 10, refreshExpiresUnix = now - 24 * 60 * 60)
        val issued = saved.copy(
            accessToken = "atk-new",
            refreshToken = "rt-new",
            accessExpiresUnix = now + 900,
            refreshExpiresUnix = now + MIN_REFRESH_IDLE_SECONDS,
        )
        api.refreshed = issued
        val outcome = maintainSession(saved, api, now)
        assertEquals(issued, (outcome as SessionMaintain.Ready).account)
        assertEquals(1, api.refreshCalls)
    }

    @Test
    fun refreshBeyondClockSlackSignsOutWithoutCallingRefresh() {
        val api = FakeApi()
        val saved = account(
            accessExpiresUnix = now - 10,
            refreshExpiresUnix = now - REFRESH_LOCAL_SLACK_SECONDS - 1,
        )
        val outcome = maintainSession(saved, api, now)
        assertEquals(SessionMaintain.SignedOut(SESSION_EXPIRED_MESSAGE), outcome)
        assertEquals(0, api.refreshCalls)
    }

    @Test
    fun newerStoredRefreshTokenIsKeptWhenAnOlderOneFails() {
        val failed = account(refreshToken = "rt-old")
        val saved = failed.copy(refreshToken = "rt-new", accessToken = "atk-new")
        assertEquals(saved, newerStoredSession(failed, saved))
        assertEquals(null, newerStoredSession(saved, saved))
        assertEquals(null, newerStoredSession(failed, null))
    }

    @Test
    fun blankRefreshSignsOut() {
        val api = FakeApi()
        val saved = account(refreshToken = "  ", accessExpiresUnix = now - 10)
        val outcome = maintainSession(saved, api, now)
        assertTrue(outcome is SessionMaintain.SignedOut)
        assertEquals(0, api.refreshCalls)
    }

    @Test
    fun refreshAuthErrorSignsOut() {
        val api = FakeApi()
        api.refreshError = IllegalStateException("session expired or revoked")
        val saved = account(accessExpiresUnix = now - 10, refreshExpiresUnix = now + 86_400)
        val outcome = maintainSession(saved, api, now)
        assertEquals(SessionMaintain.SignedOut(SESSION_EXPIRED_MESSAGE), outcome)
        assertEquals(1, api.refreshCalls)
    }

    @Test
    fun refreshNetworkErrorKeepsUnexpiredAccess() {
        val api = FakeApi()
        api.refreshError = IOException("connection refused")
        val saved = account(accessExpiresUnix = now + 30, refreshExpiresUnix = now + 86_400)
        val outcome = maintainSession(saved, api, now)
        assertEquals(SessionMaintain.Ready(saved), outcome)
    }

    @Test
    fun refreshNetworkErrorAfterAccessExpiryStaysOffline() {
        val api = FakeApi()
        api.refreshError = IOException("connection refused")
        val saved = account(accessExpiresUnix = now - 5, refreshExpiresUnix = now + 86_400)
        val outcome = maintainSession(saved, api, now)
        assertEquals(SessionMaintain.Offline(saved, SESSION_OFFLINE_MESSAGE), outcome)
        assertEquals(1, api.refreshCalls)
    }

    @Test
    fun sessionExpiryDoesNotTreatOrdinaryInvalidPathsAsLoginFailure() {
        assertTrue(looksLikeSessionExpiry("session expired or revoked"))
        assertTrue(looksLikeSessionExpiry("unauthorized"))
        assertTrue(looksLikeSessionExpiry("invalid token"))
        assertTrue(!looksLikeSessionExpiry("invalid path"))
        assertTrue(!looksLikeSessionExpiry("permission denied"))
    }

    @Test
    fun monthOfInactivityStillRefreshes() {
        val api = FakeApi()
        val saved = account(
            accessExpiresUnix = now - MIN_REFRESH_IDLE_SECONDS,
            refreshExpiresUnix = now + MIN_REFRESH_IDLE_SECONDS,
        )
        val issued = saved.copy(
            accessToken = "atk-new",
            refreshToken = "rt-new",
            accessExpiresUnix = now + 15 * 60,
            refreshExpiresUnix = now + MIN_REFRESH_IDLE_SECONDS + 2 * 24 * 60 * 60,
        )
        api.refreshed = issued
        val outcome = maintainSession(saved, api, now)
        assertEquals(issued, (outcome as SessionMaintain.Ready).account)
        assertEquals(1, api.refreshCalls)
    }

    @Test
    fun transportFailureKeepsTheRefreshToken() {
        val api = FakeApi()
        api.refreshError = IllegalStateException("tls: invalid peer certificate: certificate expired")
        val saved = account(accessExpiresUnix = now - 5, refreshExpiresUnix = now + MIN_REFRESH_IDLE_SECONDS)
        val outcome = maintainSession(saved, api, now)
        assertEquals(SessionMaintain.Offline(saved, SESSION_OFFLINE_MESSAGE), outcome)
        assertTrue(!isAuthFailure("tls: invalid peer certificate: certificate expired"))
        assertTrue(!isAuthFailure("io: connection reset by peer"))
        assertTrue(!isAuthFailure("connection refused"))
        assertTrue(isAuthFailure("authentication failed: refresh token is invalid or revoked"))
        assertTrue(isAuthFailure("device is revoked"))
        assertTrue(!isAuthFailure("invalid path"))
    }

    @Test
    fun secondCallerReusesTheRotatedSession() {
        val api = FakeApi()
        val saved = account(accessExpiresUnix = now - 10, refreshExpiresUnix = now + MIN_REFRESH_IDLE_SECONDS)
        val issued = saved.copy(
            accessToken = "atk-new",
            refreshToken = "rt-new",
            accessExpiresUnix = now + 900,
            refreshExpiresUnix = now + MIN_REFRESH_IDLE_SECONDS,
        )
        api.refreshed = issued
        val first = maintainSession(saved, api, now)
        val second = maintainSession(saved, api, now)
        assertEquals(issued, (first as SessionMaintain.Ready).account)
        assertEquals(issued, (second as SessionMaintain.Ready).account)
        assertEquals(1, api.refreshCalls)
    }

    @Test
    fun overlappingRefreshCallsTheRelayOnce() {
        val api = FakeApi()
        val saved = account(accessExpiresUnix = now - 10, refreshExpiresUnix = now + MIN_REFRESH_IDLE_SECONDS)
        val issued = saved.copy(
            accessToken = "atk-new",
            refreshToken = "rt-new",
            accessExpiresUnix = now + 900,
            refreshExpiresUnix = now + MIN_REFRESH_IDLE_SECONDS,
        )
        val entered = AtomicInteger(0)
        val inside = CountDownLatch(1)
        val release = CountDownLatch(1)
        api.onRefresh = {
            entered.incrementAndGet()
            inside.countDown()
            assertTrue(release.await(5, TimeUnit.SECONDS))
            issued
        }
        val results = ConcurrentLinkedQueue<SessionMaintain>()
        val done = CountDownLatch(2)
        repeat(2) {
            Thread {
                try {
                    results.add(maintainSession(saved, api, now))
                } finally {
                    done.countDown()
                }
            }.start()
        }
        assertTrue(inside.await(5, TimeUnit.SECONDS))
        release.countDown()
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals(1, entered.get())
        assertEquals(1, api.refreshCalls)
        assertEquals(2, results.size)
        assertTrue(results.all { (it as SessionMaintain.Ready).account.refreshToken == "rt-new" })
    }

    private fun account(
        accessExpiresUnix: Long = now + 3600,
        refreshExpiresUnix: Long = now + 86_400,
        refreshToken: String = "rt",
    ) = UserAccount(
        server = "wss://relay.example",
        fingerprint = "",
        user = "alice",
        role = "user",
        deviceId = "dev",
        accessToken = "atk",
        accessExpiresUnix = accessExpiresUnix,
        refreshToken = refreshToken,
        refreshExpiresUnix = refreshExpiresUnix,
    )

    private class FakeApi : AccountApi {
        var refreshCalls = 0
        var refreshed: UserAccount? = null
        var refreshError: Exception? = null

        var onRefresh: ((UserAccount) -> UserAccount)? = null

        override fun refresh(account: UserAccount): UserAccount {
            refreshCalls += 1
            refreshError?.let { throw it }
            onRefresh?.let { return it(account) }
            return refreshed ?: account
        }

        override fun login(
            server: String,
            fingerprint: String,
            username: String,
            password: String,
            totp: String,
            deviceName: String,
        ): UserAccount = error("unused")

        override fun logout(account: UserAccount) = Unit
        override fun listNodes(account: UserAccount) = emptyList<app.agentlink.account.NodeRow>()
        override fun listDevices(account: UserAccount) = emptyList<app.agentlink.account.DeviceRow>()
        override fun enrollAsNode(account: UserAccount, name: String) = Unit
        override fun connect(account: UserAccount): ClientSession = error("unused")
    }
}
